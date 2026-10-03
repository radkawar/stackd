package eks

import (
	"encoding/json"
	"net/url"

	"stackd/journal"
)

// Kubernetes decodes a nonempty DELETE body instead of the URI options and logs
// that decoded DeleteOptions object. At Metadata level its absence is ambiguous.
// https://github.com/kubernetes/kubernetes/blob/v1.33.3/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/delete.go
func decodeKubernetesDeleteOptions(event *journal.KubernetesAuditObserved, level string, raw json.RawMessage) error {
	if event.Stage != "ResponseComplete" || (event.Verb != "delete" && event.Verb != "deletecollection") ||
		event.ResponseCode < 200 || event.ResponseCode >= 300 || event.Subresource != "" ||
		(level != "Request" && level != "RequestResponse") {
		return nil
	}
	if len(raw) > 0 && string(raw) != "null" {
		var options struct {
			Kind   string   `json:"kind"`
			DryRun []string `json:"dryRun"`
		}
		if err := json.Unmarshal(raw, &options); err != nil {
			return err
		}
		if options.Kind != "DeleteOptions" {
			return nil
		}
		event.DeleteOptionsObserved = true
		event.DryRun = len(options.DryRun) > 0
		return nil
	}
	uri, err := url.ParseRequestURI(event.RequestURI)
	if err != nil {
		return nil
	}
	query, err := url.ParseQuery(uri.RawQuery)
	if err != nil {
		return nil
	}
	event.DeleteOptionsObserved = true
	event.DryRun = len(query["dryRun"]) > 0
	return nil
}
