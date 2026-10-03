package eks

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"stackd/journal"
)

// AuditSink receives actual native webhook metadata independently of log delivery.
// Errors withhold webhook acknowledgement; consumers must deduplicate audit IDs.
type AuditSink interface {
	PutKubernetesAudit(context.Context, string, []journal.KubernetesAuditObserved) error
}

// Decode original API server events. Only admitted RBAC binding responses and
// effective DeleteOptions have an object projection; secret values are ignored.
func decodeKubernetesAudit(items []json.RawMessage) ([]journal.KubernetesAuditObserved, error) {
	type user struct {
		Username string   `json:"username"`
		UID      string   `json:"uid"`
		Groups   []string `json:"groups"`
	}
	records := make([]journal.KubernetesAuditObserved, 0, len(items))
	for _, raw := range items {
		var event struct {
			Level                    string          `json:"level"`
			AuditID                  string          `json:"auditID"`
			Stage                    string          `json:"stage"`
			Verb                     string          `json:"verb"`
			RequestURI               string          `json:"requestURI"`
			UserAgent                string          `json:"userAgent"`
			User                     user            `json:"user"`
			ImpersonatedUser         *user           `json:"impersonatedUser"`
			SourceIPs                []string        `json:"sourceIPs"`
			StageTimestamp           time.Time       `json:"stageTimestamp"`
			RequestReceivedTimestamp time.Time       `json:"requestReceivedTimestamp"`
			RequestObject            json.RawMessage `json:"requestObject"`
			ResponseObject           json.RawMessage `json:"responseObject"`
			ObjectRef                struct {
				Resource    string `json:"resource"`
				Namespace   string `json:"namespace"`
				Name        string `json:"name"`
				Subresource string `json:"subresource"`
				APIVersion  string `json:"apiVersion"`
			} `json:"objectRef"`
			ResponseStatus struct {
				Code int32 `json:"code"`
			} `json:"responseStatus"`
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, err
		}
		at := event.StageTimestamp
		if at.IsZero() {
			at = event.RequestReceivedTimestamp
		}
		if event.AuditID == "" || at.IsZero() || event.Stage == "" {
			return nil, errors.New("invalid native audit identity")
		}
		effective := event.User
		if event.ImpersonatedUser != nil {
			effective = *event.ImpersonatedUser
		}
		observed := journal.KubernetesAuditObserved{AuditID: event.AuditID, Stage: event.Stage, Verb: event.Verb, RequestURI: event.RequestURI, UserAgent: event.UserAgent, NativeAt: at, UserName: effective.Username, UserUID: effective.UID, ActorUserName: event.User.Username, Groups: effective.Groups, Namespace: event.ObjectRef.Namespace, Resource: event.ObjectRef.Resource, Subresource: event.ObjectRef.Subresource, Name: event.ObjectRef.Name, APIVersion: event.ObjectRef.APIVersion, ResponseCode: event.ResponseStatus.Code}
		if len(event.SourceIPs) > 0 {
			observed.SourceIP = event.SourceIPs[0]
		}
		if err := decodeKubernetesBinding(&observed, event.ResponseObject); err != nil {
			return nil, err
		}
		if err := decodeKubernetesDeleteOptions(&observed, event.Level, event.RequestObject); err != nil {
			return nil, err
		}
		records = append(records, observed)
	}
	return records, nil
}
