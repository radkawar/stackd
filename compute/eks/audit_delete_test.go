package eks

import (
	"encoding/json"
	"testing"
)

func TestNativeDeleteOptionsRespectBodyPrecedence(t *testing.T) {
	for _, verb := range []string{"delete", "deletecollection"} {
		for _, tc := range []struct {
			name, level, query, body string
			observed, dryRun         bool
		}{
			{"body dry run", "Request", "", `{"kind":"DeleteOptions","apiVersion":"meta.k8s.io/__internal","dryRun":["All"]}`, true, true},
			{"query dry run", "Request", "?dryRun=All", "", true, true},
			{"body overrides query", "Request", "?dryRun=All", `{"kind":"DeleteOptions","apiVersion":"v1"}`, true, false},
			{"ordinary delete", "Request", "", "", true, false},
			{"request response level", "RequestResponse", "", `{"kind":"DeleteOptions","dryRun":["All"]}`, true, true},
			{"metadata unknown", "Metadata", "", "", false, false},
			{"metadata query not authoritative", "Metadata", "?dryRun=All", "", false, false},
			{"wrong kind", "Request", "", `{"kind":"Secret","data":{"dummy":"not-options"}}`, false, false},
		} {
			t.Run(verb+"/"+tc.name, func(t *testing.T) {
				raw := map[string]any{"auditID": "native-delete", "stage": "ResponseComplete", "stageTimestamp": "2031-01-02T03:04:05Z",
					"level": tc.level, "verb": verb, "requestURI": "/api/v1/namespaces/owned/configmaps/item" + tc.query,
					"objectRef":      map[string]string{"resource": "configmaps", "namespace": "owned", "name": "item"},
					"responseStatus": map[string]int{"code": 200}}
				if tc.body != "" {
					raw["requestObject"] = json.RawMessage(tc.body)
				}
				body, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				events, err := decodeKubernetesAudit([]json.RawMessage{body})
				if err != nil {
					t.Fatal(err)
				}
				if len(events) != 1 || events[0].DeleteOptionsObserved != tc.observed || events[0].DryRun != tc.dryRun {
					t.Fatalf("effective delete options = %+v; want observed=%t dryRun=%t", events, tc.observed, tc.dryRun)
				}
			})
		}
	}
}
