package eks

import (
	"encoding/json"
	"reflect"
	"testing"

	"stackd/journal"
)

func TestNativeBindingUsesAdmittedResponse(t *testing.T) {
	const body = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"binding","namespace":"owned"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"read-pods"},"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind":"User","name":"ordinary-user"},{"kind":"ServiceAccount","name":"reader","namespace":"owned"}]}`
	for _, tc := range []struct {
		name     string
		mutate   func(map[string]any)
		retained bool
	}{
		{"admitted-response", func(map[string]any) {}, true},
		{"generated-name", func(v map[string]any) { delete(v["objectRef"].(map[string]any), "name") }, true},
		{"missing-response", func(v map[string]any) { delete(v, "responseObject") }, false},
		{"failed-create", func(v map[string]any) { v["responseStatus"] = map[string]any{"code": 403} }, false},
		{"not-complete", func(v map[string]any) { v["stage"] = "ResponseStarted" }, false},
		{"patch", func(v map[string]any) { v["verb"] = "patch" }, false},
		{"custom-api-group", func(v map[string]any) { v["requestURI"] = "/apis/customer.example/v1/namespaces/owned/rolebindings" }, false},
		{"dry-run", func(v map[string]any) {
			v["requestURI"] = "/apis/rbac.authorization.k8s.io/v1/namespaces/owned/rolebindings?dryRun=&dryRun=All"
		}, false},
		{"wrong-object", func(v map[string]any) { v["responseObject"].(map[string]any)["kind"] = "Secret" }, false},
		{"wrong-name", func(v map[string]any) {
			v["responseObject"].(map[string]any)["metadata"].(map[string]any)["name"] = "different"
		}, false},
		{"wrong-role-group", func(v map[string]any) {
			v["responseObject"].(map[string]any)["roleRef"].(map[string]any)["apiGroup"] = "customer.example"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response map[string]any
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatal(err)
			}
			v := map[string]any{"auditID": "native-binding", "stage": "ResponseComplete", "verb": "create", "requestURI": "/apis/rbac.authorization.k8s.io/v1/namespaces/owned/rolebindings", "stageTimestamp": "2031-01-02T03:04:05Z", "user": map[string]any{"username": "operator"}, "objectRef": map[string]any{"resource": "rolebindings", "namespace": "owned", "name": "binding", "apiVersion": "v1"}, "responseStatus": map[string]any{"code": 201}, "responseObject": response,
				"requestObject": map[string]any{"subjects": []any{map[string]any{"kind": "User", "name": "system:anonymous", "apiGroup": "rbac.authorization.k8s.io"}}, "secret": "not-retained"}}
			tc.mutate(v)
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			events, err := decodeKubernetesAudit([]json.RawMessage{raw})
			if err != nil {
				t.Fatal(err)
			}
			event := events[0]
			if !tc.retained {
				if event.RoleRefName != "" || len(event.Subjects) != 0 {
					t.Fatalf("non-admitted response became evidence: %+v", event)
				}
				return
			}
			want := []journal.KubernetesSubject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: "ordinary-user"}, {Kind: "ServiceAccount", Name: "reader", Namespace: "owned"}}
			if event.Name != "binding" || event.RoleRefName != "read-pods" || event.RoleRefKind != "Role" || event.RoleRefAPIGroup != "rbac.authorization.k8s.io" || !reflect.DeepEqual(event.Subjects, want) {
				t.Fatalf("request substituted for admitted response: %+v", event)
			}
		})
	}
}
