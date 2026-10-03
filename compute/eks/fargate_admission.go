package eks

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
)

const fargateProfileLabel = "eks.amazonaws.com/fargate-profile"
const fargateSlotLabel = "stackd.eks.fargate-pod"
const fargateIDLabel = "stackd.eks.fargate-id"

type fargatePod struct {
	Metadata componentMetadata `json:"metadata"`
	Spec     struct {
		NodeName                      string            `json:"nodeName,omitempty"`
		NodeSelector                  map[string]string `json:"nodeSelector,omitempty"`
		Tolerations                   []map[string]any  `json:"tolerations,omitempty"`
		Affinity                      map[string]any    `json:"affinity,omitempty"`
		HostNetwork, HostPID, HostIPC bool
		Containers                    []struct {
			Image           string `json:"image"`
			SecurityContext struct {
				Privileged bool `json:"privileged"`
			} `json:"securityContext"`
		} `json:"containers"`
		InitContainers []struct {
			Image           string `json:"image"`
			SecurityContext struct {
				Privileged bool `json:"privileged"`
			} `json:"securityContext"`
		} `json:"initContainers"`
		Volumes []struct {
			HostPath json.RawMessage `json:"hostPath"`
		} `json:"volumes"`
	} `json:"spec"`
}

func (k *K3d) currentFargateProfiles(ctx context.Context, c *nativeCluster) ([]FargateSpecification, error) {
	k.mu.RLock()
	source := c.fargateProfiles
	k.mu.RUnlock()
	if source == nil {
		return nil, errors.New("eks: Fargate profile owner is unavailable")
	}
	return source(ctx)
}
func (k *K3d) fargateAdmission(id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Request    *struct {
				UID, Namespace, Operation string
				Object                    json.RawMessage `json:"object"`
				DryRun                    bool            `json:"dryRun"`
			} `json:"request"`
		}
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&review); err != nil || review.Request == nil {
			http.Error(w, "invalid admission review", 400)
			return
		}
		response := map[string]any{"uid": review.Request.UID, "allowed": true}
		err := func() error {
			c, err := k.componentCluster(id)
			if err != nil {
				return err
			}
			policies, err := k.currentFargateProfiles(r.Context(), c)
			if err != nil {
				return err
			}
			var pod fargatePod
			if err = json.Unmarshal(review.Request.Object, &pod); err != nil {
				return err
			}
			var selected *FargateSpecification
			requested := pod.Metadata.Labels[fargateProfileLabel]
			compute := pod.Metadata.Annotations["eks.amazonaws.com/compute-type"]
			if compute != "ec2" {
				for i := range policies {
					p := &policies[i]
					if p.Delete || p.AdmissionDenied {
						continue
					}
					if requested != "" && p.Name != requested {
						continue
					}
					for _, selector := range p.Selectors {
						if MatchFargateSelector(selector, review.Request.Namespace, pod.Metadata.Labels) {
							selected = p
							break
						}
					}
					if selected != nil {
						break
					}
				}
			}
			if selected == nil {
				if compute == "fargate" || requested != "" || pod.Metadata.Labels[fargateSlotLabel] != "" || pod.Spec.NodeSelector[fargateSlotLabel] != "" || pod.Spec.NodeSelector[fargateIDLabel] != "" || strings.HasPrefix(pod.Spec.NodeName, fargateAgentName(c.state, "")) {
					return errors.New("the requested Fargate profile does not match this pod")
				}
				if len(policies) > 0 {
					affinity := excludeFargateNodes(pod.Spec.Affinity)
					data, err := json.Marshal([]map[string]any{{"op": "add", "path": "/spec/affinity", "value": affinity}})
					if err != nil {
						return err
					}
					response["patchType"] = "JSONPatch"
					response["patch"] = base64.StdEncoding.EncodeToString(data)
				}
				return nil
			}
			k.mu.RLock()
			authorize := c.fargateAuthorize
			k.mu.RUnlock()
			if authorize == nil {
				return errors.New("fargate execution-role authorization is unavailable")
			}
			if err = authorize(r.Context(), selected.ID); err != nil {
				return err
			}
			if pod.Spec.NodeName != "" || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
				return errors.New("fargate pods cannot select nodeName or host namespaces")
			}
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext.Privileged {
					return errors.New("fargate does not support privileged containers")
				}
			}
			for _, container := range pod.Spec.InitContainers {
				if container.SecurityContext.Privileged {
					return errors.New("fargate does not support privileged init containers")
				}
			}
			for _, volume := range pod.Spec.Volumes {
				if len(volume.HostPath) > 0 {
					return errors.New("fargate does not support hostPath volumes")
				}
			}
			labels := maps.Clone(pod.Metadata.Labels)
			if labels == nil {
				labels = map[string]string{}
			}
			labels[fargateProfileLabel] = selected.Name
			hash := sha256.Sum256([]byte(review.Request.UID))
			slot := hex.EncodeToString(hash[:16])
			labels[fargateSlotLabel] = slot
			labels[fargateIDLabel] = selected.ID
			labels["eks.amazonaws.com/compute-type"] = "fargate"
			selector := maps.Clone(pod.Spec.NodeSelector)
			if selector == nil {
				selector = map[string]string{}
			}
			selector[fargateSlotLabel] = slot
			selector[fargateIDLabel] = selected.ID
			tolerations := pod.Spec.Tolerations
			hasToleration := false
			for _, t := range tolerations {
				if t["key"] == "eks.amazonaws.com/compute-type" && t["value"] == "fargate" {
					hasToleration = true
				}
			}
			if !hasToleration {
				tolerations = append(tolerations, map[string]any{"key": "eks.amazonaws.com/compute-type", "operator": "Equal", "value": "fargate", "effect": "NoSchedule"})
			}
			patch := []map[string]any{{"op": "add", "path": "/metadata/labels", "value": labels}, {"op": "add", "path": "/spec/nodeSelector", "value": selector}, {"op": "add", "path": "/spec/tolerations", "value": tolerations}}
			data, err := json.Marshal(patch)
			if err != nil {
				return err
			}
			response["patchType"] = "JSONPatch"
			response["patch"] = base64.StdEncoding.EncodeToString(data)
			return nil
		}()
		if err != nil {
			response["allowed"] = false
			response["status"] = map[string]any{"code": 403, "message": err.Error()}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response})
	})
}
func (c *nativeCluster) ensureFargateWebhook(ctx context.Context) error {
	name := "stackd-fargate-" + c.state.Token[:16]
	webhook := map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingWebhookConfiguration", "metadata": map[string]any{"name": name, "labels": map[string]string{ownerLabel: c.state.Token[:32]}}, "webhooks": []any{map[string]any{"name": "fargate.eks.stackd.local", "admissionReviewVersions": []string{"v1"}, "sideEffects": "None", "failurePolicy": "Fail", "reinvocationPolicy": "IfNeeded", "timeoutSeconds": 10, "clientConfig": map[string]any{"url": c.bridgeURL() + "/fargate/" + c.bridgeCapability("fargate") + "/mutate", "caBundle": base64.StdEncoding.EncodeToString(c.bridgeCA())}, "rules": []any{map[string]any{"operations": []string{"CREATE"}, "apiGroups": []string{""}, "apiVersions": []string{"v1"}, "resources": []string{"pods"}, "scope": "Namespaced"}}}}}
	if c.bridgeURL() == "" {
		return fmt.Errorf("eks: Fargate admission bridge is unavailable")
	}
	return c.componentApply(ctx, "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/"+name, "stackd-eks-fargate", false, webhook)
}
func excludeFargateNodes(affinity map[string]any) map[string]any {
	if affinity == nil {
		affinity = map[string]any{}
	}
	nodeAffinity, ok := affinity["nodeAffinity"].(map[string]any)
	if !ok {
		nodeAffinity = map[string]any{}
		affinity["nodeAffinity"] = nodeAffinity
	}
	required, ok := nodeAffinity["requiredDuringSchedulingIgnoredDuringExecution"].(map[string]any)
	if !ok {
		required = map[string]any{}
		nodeAffinity["requiredDuringSchedulingIgnoredDuringExecution"] = required
	}
	terms, ok := required["nodeSelectorTerms"].([]any)
	if !ok {
		terms = []any{map[string]any{}}
	}
	for _, value := range terms {
		term, ok := value.(map[string]any)
		if !ok {
			continue
		}
		expressions, _ := term["matchExpressions"].([]any)
		found := false
		for _, expr := range expressions {
			if e, ok := expr.(map[string]any); ok && e["key"] == "eks.amazonaws.com/compute-type" && e["operator"] == "NotIn" {
				values, _ := e["values"].([]any)
				for _, v := range values {
					if v == "fargate" {
						found = true
					}
				}
			}
		}
		if !found {
			term["matchExpressions"] = append(expressions, map[string]any{"key": "eks.amazonaws.com/compute-type", "operator": "NotIn", "values": []string{"fargate"}})
		}
	}
	required["nodeSelectorTerms"] = terms
	return affinity
}
