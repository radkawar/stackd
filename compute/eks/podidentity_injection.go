package eks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
)

const podIdentityTokenPath = "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount"

// The control-plane webhook only projects a Kubernetes-issued token and SDK
// environment. Credential serving belongs to the actual upstream node agent.
func (c *nativeCluster) ensurePodIdentity(ctx context.Context) error {
	if c.bridgeURL() == "" || len(c.bridgeCA()) == 0 {
		return errors.New("eks: pod identity requires the owned TLS bridge")
	}
	const name = "stackd-pod-identity"
	path := "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"
	var current struct{ Metadata podIdentityObjectMeta }
	err := c.podIdentityRequest(ctx, http.MethodGet, path+"/"+name, nil, &current)
	if err != nil && !errors.Is(err, ErrPodIdentityToken) {
		return err
	}
	metadata := map[string]any{"name": name, "labels": map[string]string{ownerLabel: c.state.Token[:32], idLabel: c.state.ID}}
	method, target := http.MethodPost, path
	if err == nil {
		if current.Metadata.Labels[ownerLabel] != c.state.Token[:32] || current.Metadata.Labels[idLabel] != c.state.ID {
			return errors.New("eks: refusing unowned pod identity webhook")
		}
		metadata["resourceVersion"] = current.Metadata.ResourceVersion
		method, target = http.MethodPut, path+"/"+name
	}
	webhook := map[string]any{
		"name": "podidentity.stackd.eks", "admissionReviewVersions": []string{"v1"}, "sideEffects": "None", "failurePolicy": "Fail", "matchPolicy": "Equivalent", "reinvocationPolicy": "Never", "timeoutSeconds": 10,
		"clientConfig": map[string]any{"url": c.bridgeURL() + "/podidentity/" + c.bridgeCapability("podidentity") + "/mutate", "caBundle": base64.StdEncoding.EncodeToString(c.bridgeCA())},
		"rules":        []any{map[string]any{"operations": []string{"CREATE"}, "apiGroups": []string{""}, "apiVersions": []string{"v1"}, "resources": []string{"pods"}, "scope": "Namespaced"}},
	}
	return c.podIdentityRequest(ctx, method, target, map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingWebhookConfiguration", "metadata": metadata, "webhooks": []any{webhook}}, nil)
}

type podIdentityAdmission struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Request    *struct {
		UID       string          `json:"uid"`
		Namespace string          `json:"namespace"`
		Operation string          `json:"operation"`
		Object    json.RawMessage `json:"object"`
	} `json:"request,omitempty"`
	Response *podIdentityAdmissionResponse `json:"response,omitempty"`
}
type podIdentityAdmissionResponse struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	Status  *struct {
		Message string `json:"message"`
	} `json:"status,omitempty"`
	PatchType string `json:"patchType,omitempty"`
	Patch     []byte `json:"patch,omitempty"`
}
type podIdentityLookupResponse struct {
	header http.Header
	status int
}

func (r *podIdentityLookupResponse) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}
func (r *podIdentityLookupResponse) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}
func (r *podIdentityLookupResponse) Write(b []byte) (int, error) {
	r.WriteHeader(200)
	return len(b), nil
}
func (k *K3d) podIdentityHandler(c *nativeCluster) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mutate" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var review podIdentityAdmission
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&review); err != nil || review.Request == nil || review.APIVersion != "admission.k8s.io/v1" {
			http.Error(w, "Invalid AdmissionReview", 400)
			return
		}
		response := &podIdentityAdmissionResponse{UID: review.Request.UID, Allowed: true}
		mutate := func() error {
			if review.Request.Operation != "CREATE" {
				return nil
			}
			var pod workloadIdentityPod
			if err := json.Unmarshal(review.Request.Object, &pod); err != nil {
				return err
			}
			if pod.Spec == nil {
				return errors.New("missing pod spec")
			}
			patch, err := k.workloadIdentityPatch(r.Context(), c, review.Request.Namespace, pod)
			if err != nil {
				return err
			}
			if len(patch) != 0 {
				response.PatchType = "JSONPatch"
				response.Patch = patch
			}
			return nil
		}
		if err := mutate(); err != nil {
			response.Allowed = false
			response.Status = &struct {
				Message string `json:"message"`
			}{err.Error()}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(podIdentityAdmission{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Response: response})
	})
}

func (k *K3d) podIdentityAdmissionPatch(ctx context.Context, c *nativeCluster, namespace, sa string, pod workloadIdentityPod, service http.Handler) ([]byte, error) {
	if service == nil || pod.Metadata.Labels["eks.amazonaws.com/compute-type"] == "fargate" {
		return nil, nil
	}
	// Admission ordering is not an authority. Match current owned profiles even
	// when the Fargate webhook has not yet attached the compute-type label.
	policies, err := k.currentFargateProfiles(ctx, c)
	if err != nil {
		return nil, err
	}
	requested := pod.Metadata.Labels[fargateProfileLabel]
	for _, policy := range policies {
		if policy.Delete || policy.AdmissionDenied || requested != "" && requested != policy.Name {
			continue
		}
		for _, selector := range policy.Selectors {
			if MatchFargateSelector(selector, namespace, pod.Metadata.Labels) {
				return nil, nil
			}
		}
	}
	lookup, err := http.NewRequestWithContext(ctx, http.MethodGet, "/association?"+url.Values{"namespace": {namespace}, "serviceAccount": {sa}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	result := &podIdentityLookupResponse{}
	service.ServeHTTP(result, lookup)
	switch result.status {
	case http.StatusNoContent:
		return podIdentityPatch(pod.Spec, workloadIdentitySkippedContainers(pod.Metadata.Annotations))
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, errors.New("pod identity association authority is unavailable")
	}
}
func podIdentityAppend(values []any, name string, value any) []any {
	for _, item := range values {
		if entry, ok := item.(map[string]any); ok && entry["name"] == name {
			return values
		}
	}
	return append(values, value)
}
func podIdentityPatch(spec map[string]any, skip []string) ([]byte, error) {
	volumes, _ := spec["volumes"].([]any)
	for _, raw := range volumes {
		v, ok := raw.(map[string]any)
		if ok && v["name"] == "eks-pod-identity-token" {
			return nil, errors.New("reserved pod identity token volume name")
		}
	}
	volumes = append(volumes, map[string]any{"name": "eks-pod-identity-token", "projected": map[string]any{"defaultMode": 420, "sources": []any{map[string]any{"serviceAccountToken": map[string]any{"audience": PodIdentityAudience, "expirationSeconds": 86400, "path": "eks-pod-identity-token"}}}}})
	patches := []map[string]any{{"op": "add", "path": "/spec/volumes", "value": volumes}}
	for _, field := range []string{"containers", "initContainers"} {
		containers, _ := spec[field].([]any)
		if len(containers) == 0 {
			continue
		}
		for _, raw := range containers {
			container, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid container")
			}
			name, _ := container["name"].(string)
			if slices.Contains(skip, name) {
				continue
			}
			env, _ := container["env"].([]any)
			env = podIdentityAppend(env, "AWS_CONTAINER_CREDENTIALS_FULL_URI", map[string]any{"name": "AWS_CONTAINER_CREDENTIALS_FULL_URI", "value": "http://169.254.170.23/v1/credentials"})
			env = podIdentityAppend(env, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", map[string]any{"name": "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "value": podIdentityTokenPath + "/eks-pod-identity-token"})
			container["env"] = env
			mounts, _ := container["volumeMounts"].([]any)
			container["volumeMounts"] = append(mounts, map[string]any{"name": "eks-pod-identity-token", "mountPath": podIdentityTokenPath, "readOnly": true})
		}
		patches = append(patches, map[string]any{"op": "add", "path": "/spec/" + field, "value": containers})
	}
	return json.Marshal(patches)
}
