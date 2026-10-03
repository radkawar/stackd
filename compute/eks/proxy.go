package eks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"
)

const grantGroupPrefix = "stackd:eks:grant:"

// Proxy accepts only an identity authenticated by the service on this request.
// Native RBAC, not URL matching, decides authorization for every Kubernetes API.
func (k *K3d) Proxy(w http.ResponseWriter, request *http.Request, id string, identity Identity) {
	if identity.Username == "" || strings.HasPrefix(identity.Username, "stackd:") || strings.ContainsAny(identity.Username, "\r\n") {
		http.Error(w, "invalid Kubernetes identity", http.StatusUnauthorized)
		return
	}
	for _, group := range identity.Groups {
		if strings.HasPrefix(group, "stackd:") || strings.ContainsAny(group, "\r\n") {
			http.Error(w, "reserved Kubernetes group", http.StatusForbidden)
			return
		}
	}
	k.mu.RLock()
	cluster := k.clusters[id]
	k.mu.RUnlock()
	if cluster == nil {
		http.Error(w, "Kubernetes cluster is not attached", http.StatusServiceUnavailable)
		return
	}
	targetIdentity, impersonating, err := cluster.impersonatedIdentity(request.Context(), request.Header, identity)
	if err != nil {
		http.Error(w, "Forbidden: "+err.Error(), http.StatusForbidden)
		return
	}
	if impersonating {
		identity = targetIdentity
	} else {
		groups, err := cluster.policyGroups(request.Context(), identity)
		if err != nil {
			http.Error(w, "cannot establish Kubernetes policy bindings", http.StatusServiceUnavailable)
			return
		}
		identity.Groups = append(identity.Groups, groups...)
	}
	target, _ := url.Parse(cluster.nativeURL())
	proxy := httputil.ReverseProxy{
		Transport:     cluster.transport,
		FlushInterval: -1,
		Rewrite: func(proxy *httputil.ProxyRequest) {
			proxy.SetURL(target)
			proxy.Out.Host = target.Host
			// The private certificate only transports a fully admitted identity.
			// Neither caller front-proxy claims nor unchecked impersonation headers
			// may reach the native administrator connection.
			sanitizeIdentityHeaders(proxy.Out.Header)
			setIdentityHeaders(proxy.Out.Header, identity)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Kubernetes upstream unavailable", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, request)
}

type bindingSubject struct {
	Kind     string `json:"kind"`
	APIGroup string `json:"apiGroup"`
	Name     string `json:"name"`
}
type bindingRole struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}
type policyBinding struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace,omitempty"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Subjects []bindingSubject `json:"subjects"`
	RoleRef  bindingRole      `json:"roleRef"`
}

func (c *nativeCluster) policyGroups(ctx context.Context, identity Identity) ([]string, error) {
	c.grantMu.Lock()
	defer c.grantMu.Unlock()
	groups := make([]string, 0, len(identity.Grants))
	for _, grant := range identity.Grants {
		roleName, err := c.ensurePolicyRole(ctx, grant.Role)
		if err != nil {
			return nil, err
		}
		var namespaces []string
		if len(grant.Namespaces) != 0 {
			namespaces, err = c.resolveNamespaces(ctx, grant.Namespaces)
			if err != nil {
				return nil, err
			}
			if len(namespaces) == 0 {
				continue
			}
		}
		// Scope and request identity are part of the group. Removing a grant or
		// narrowing its scope immediately removes the old authority on new requests,
		// even though its inert native binding remains until cluster deletion.
		key, err := json.Marshal(struct {
			Token, Username, Role string
			Namespaces            []string
		}{c.state.Token, identity.Username, roleName, namespaces})
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(key)
		suffix := hex.EncodeToString(hash[:])
		group := grantGroupPrefix + suffix
		binding := policyBinding{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Subjects: []bindingSubject{{Kind: "Group", APIGroup: "rbac.authorization.k8s.io", Name: group}}, RoleRef: bindingRole{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: roleName}}
		binding.Metadata.Name = "stackd-eks-" + suffix
		binding.Metadata.Labels = map[string]string{ownerLabel: c.state.Token[:32]}
		if len(namespaces) == 0 {
			if err = c.ensureBinding(ctx, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", binding); err != nil {
				return nil, err
			}
		} else {
			binding.Kind = "RoleBinding"
			for _, namespace := range namespaces {
				binding.Metadata.Namespace = namespace
				if err = c.ensureBinding(ctx, "/apis/rbac.authorization.k8s.io/v1/namespaces/"+namespace+"/rolebindings", binding); err != nil {
					return nil, err
				}
			}
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (c *nativeCluster) ensureBinding(ctx context.Context, path string, binding policyBinding) error {
	get := func() (int, policyBinding, error) {
		var existing policyBinding
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.nativeURL()+path+"/"+binding.Metadata.Name, nil)
		if err != nil {
			return 0, existing, err
		}
		response, err := c.client.Do(request)
		if err != nil {
			return 0, existing, err
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusOK {
			err = json.NewDecoder(response.Body).Decode(&existing)
		} else {
			_, err = io.Copy(io.Discard, response.Body)
		}
		return response.StatusCode, existing, err
	}
	status, existing, err := get()
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		data, err := json.Marshal(binding)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.nativeURL()+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := c.client.Do(request)
		if err != nil {
			return err
		}
		// EKS associations can precede namespace creation. An absent namespace
		// grants nothing now; the binding is materialized on a later request.
		if response.StatusCode == http.StatusNotFound && binding.Kind == "RoleBinding" {
			var status struct{ Details struct{ Kind, Name string } }
			err = json.NewDecoder(response.Body).Decode(&status)
			response.Body.Close()
			if err != nil {
				return err
			}
			if status.Details.Kind == "namespaces" && status.Details.Name == binding.Metadata.Namespace {
				return nil
			}
		} else {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		if response.StatusCode == http.StatusCreated {
			return c.waitPolicyBinding(ctx, binding)
		}
		if response.StatusCode != http.StatusConflict {
			return fmt.Errorf("eks: native RBAC create returned %d", response.StatusCode)
		}
		status, existing, err = get()
		if err != nil {
			return err
		}
	}
	if status != http.StatusOK {
		return fmt.Errorf("eks: native RBAC query returned %d", status)
	}
	if existing.Kind != binding.Kind || existing.Metadata.Labels[ownerLabel] != binding.Metadata.Labels[ownerLabel] || existing.RoleRef != binding.RoleRef || !slices.Equal(existing.Subjects, binding.Subjects) {
		return errors.New("eks: native policy binding no longer matches exact ownership and authority")
	}
	return c.waitPolicyBinding(ctx, binding)
}

// The API write acknowledgement precedes RBAC informer observation. Wait for an
// actual native authorization decision for a permission shared by our policies,
// never the caller's operation (which may correctly be forbidden). The probe has
// only this request-derived group, not the private admin client's authority.
func (c *nativeCluster) waitPolicyBinding(ctx context.Context, binding policyBinding) error {
	namespace := binding.Metadata.Namespace
	if namespace == "" {
		namespace = "default"
	}
	review := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			User               string   `json:"user"`
			Groups             []string `json:"groups"`
			ResourceAttributes struct {
				Namespace string `json:"namespace"`
				Verb      string `json:"verb"`
				Resource  string `json:"resource"`
			} `json:"resourceAttributes"`
		} `json:"spec"`
	}{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}
	review.Spec.User = "stackd:eks:binding-probe:" + c.state.Token[:32]
	review.Spec.Groups = []string{binding.Subjects[0].Name}
	review.Spec.ResourceAttributes.Namespace = namespace
	review.Spec.ResourceAttributes.Verb = "list"
	review.Spec.ResourceAttributes.Resource = "pods"
	data, err := json.Marshal(review)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.nativeURL()+"/apis/authorization.k8s.io/v1/subjectaccessreviews", bytes.NewReader(data))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := c.client.Do(request)
		if err != nil {
			return err
		}
		var result struct{ Status struct{ Allowed bool } }
		err = json.NewDecoder(response.Body).Decode(&result)
		response.Body.Close()
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusCreated {
			return fmt.Errorf("eks: native RBAC readiness returned %d", response.StatusCode)
		}
		if result.Status.Allowed {
			return nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("eks: native RBAC binding not ready: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
