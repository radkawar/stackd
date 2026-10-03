package eks

import (
	"encoding/json"
	"net/url"
	"strings"

	"stackd/journal"
)

// Only the API server's successful response establishes admitted subjects. The
// request may have been rejected or changed by admission; never substitute it.
func decodeKubernetesBinding(event *journal.KubernetesAuditObserved, raw json.RawMessage) error {
	if event.Stage != "ResponseComplete" || event.Verb != "create" || event.ResponseCode < 200 || event.ResponseCode >= 300 || event.Subresource != "" || len(raw) == 0 {
		return nil
	}
	const group = "rbac.authorization.k8s.io"
	uri, err := url.ParseRequestURI(event.RequestURI)
	if err != nil {
		return err
	}
	for _, value := range uri.Query()["dryRun"] {
		if value != "" {
			return nil
		}
	}
	if !strings.HasPrefix(uri.Path, "/apis/"+group+"/v1/") {
		return nil
	}
	kind := ""
	switch event.Resource {
	case "rolebindings":
		kind = "RoleBinding"
	case "clusterrolebindings":
		kind = "ClusterRoleBinding"
	default:
		return nil
	}
	var binding struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		RoleRef struct {
			APIGroup string `json:"apiGroup"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
		} `json:"roleRef"`
		Subjects []struct {
			APIGroup  string `json:"apiGroup"`
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"subjects"`
	}
	if err := json.Unmarshal(raw, &binding); err != nil {
		return err
	}
	if binding.APIVersion != group+"/v1" || binding.Kind != kind || binding.Metadata.Name == "" || (event.Name != "" && binding.Metadata.Name != event.Name) || binding.Metadata.Namespace != event.Namespace || binding.RoleRef.APIGroup != group || binding.RoleRef.Name == "" {
		return nil
	}
	if binding.RoleRef.Kind != "ClusterRole" && (kind != "RoleBinding" || binding.RoleRef.Kind != "Role") {
		return nil
	}
	if kind == "ClusterRoleBinding" && event.Namespace != "" || kind == "RoleBinding" && event.Namespace == "" {
		return nil
	}
	// generateName requests can lack objectRef.name; the admitted response
	// supplies the real resource identity, never a guessed generated suffix.
	event.Name = binding.Metadata.Name
	event.RoleRefAPIGroup, event.RoleRefKind, event.RoleRefName = binding.RoleRef.APIGroup, binding.RoleRef.Kind, binding.RoleRef.Name
	if len(binding.Subjects) == 0 {
		return nil
	}
	event.Subjects = make([]journal.KubernetesSubject, len(binding.Subjects))
	for i, subject := range binding.Subjects {
		event.Subjects[i] = journal.KubernetesSubject{APIGroup: subject.APIGroup, Kind: subject.Kind, Name: subject.Name, Namespace: subject.Namespace}
	}
	return nil
}
