package ram

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	api "stackd/internal/awsapi/ram"
)

// Replay token-relevant native transitions, not asynchronous AWS scheduling or
// unrelated response projections. Inputs are captured before SDK injection;
// fixtures also retain the actual transmitted requests and raw responses.
func TestNativeMutationTokenContracts(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		labels  []string
	}{
		{"native-share-token-identity.json", []string{
			"create-omitted", "repeat-create-omitted", "update-omitted", "update-explicit", "repeat-update-omitted", "replay-update-explicit", "delete-explicit", "replay-delete-explicit", "mismatch-delete-explicit",
		}},
		{"native-update-token-state.json", []string{
			"create-share", "update-name-explicit", "update-name-away", "update-name-back", "replay-name-after-away-and-back",
		}},
		{"native-mutation-tokens.json", []string{
			"create-advanced-parameter", "create-permission-1", "create-permission-2", "create-share-omitted",
			"associate-resource-omitted", "disassociate-resource-omitted", "associate-owner-explicit", "associate-owner-replay", "associate-owner-mismatch", "disassociate-owner-explicit", "disassociate-owner-replay",
			"associate-permission-omitted", "disassociate-permission-omitted", "associate-permission-explicit", "associate-permission-replay", "associate-permission-mismatch", "replace-permission-omitted", "disassociate-permission-explicit", "disassociate-permission-replay", "disassociate-permission-mismatch",
			"create-version-omitted", "set-default-omitted", "set-default-explicit", "set-default-replay", "set-default-mismatch", "restore-default-omitted", "delete-version-explicit", "delete-version-replay", "delete-version-mismatch", "recreate-version-omitted", "restore-default-before-delete", "delete-version-omitted", "cleanup-share", "cleanup-permission",
		}},
		{"native-mutation-token-boundaries.json", []string{
			"create-permission-1", "create-permission-2", "create-permission-3", "replace-explicit", "replace-replay", "replace-mismatch",
			"create-share-explicit", "create-share-replay", "create-share-mismatch", "update-explicit", "update-replay", "update-mismatch", "delete-share-replay",
			"delete-permission-explicit", "delete-permission-replay", "delete-permission-mismatch",
		}},
		{"native-promotion-tokens.json", []string{
			"empty-token-create", "promote-omitted", "promote-explicit", "promote-replay",
		}},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			type capture struct {
				Operation string
				Label     string
				Input     json.RawMessage
				Response  json.RawMessage
				Status    int `json:"http_status"`
			}
			var evidence struct {
				Account string
				Calls   []capture
				Cleanup []capture
			}
			if err = json.Unmarshal(data, &evidence); err != nil {
				t.Fatal(err)
			}
			s, _, resource := testRAM(t)
			owner := rootContext(evidence.Account)
			identities := map[string]string{}
			policyReady := false
			rows := append(evidence.Calls, evidence.Cleanup...)
			for _, label := range tc.labels {
				var step *capture
				for _, row := range rows {
					if row.Label == label {
						step = &row
						break
					}
				}
				if step == nil {
					t.Fatalf("missing native capture %q", label)
				}
				if step.Operation == "PutParameter" {
					var input struct{ Name string }
					if err = json.Unmarshal(step.Input, &input); err != nil {
						t.Fatal(err)
					}
					resource.AccountID = evidence.Account
					resource.ARN = "arn:aws:ssm:us-east-1:" + evidence.Account + ":parameter" + input.Name
					s.resources.(resourceOwner)[resource.ARN] = resource
					continue
				}
				if step.Operation == "PromotePermissionCreatedFromPolicy" && !policyReady {
					resource.AccountID = evidence.Account
					resource.ARN = "arn:aws:ssm:us-east-1:" + evidence.Account + ":parameter/promotion"
					if err = s.SyncResourcePolicy(owner, resource, "promotion", []string{evidence.Account}, `{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameterHistory"]}`); err != nil {
						t.Fatal(err)
					}
					permissions := invoke[api.ListPermissionsResponse](t, s, owner, "ListPermissions", &api.ListPermissionsRequest{PermissionType: new(api.PermissionTypeFilter("CUSTOMER_MANAGED"))})
					if len(permissions.Permissions) != 1 {
						t.Fatalf("expected one policy-created permission: %#v", permissions)
					}
					var input struct{ PermissionArn string }
					if err = json.Unmarshal(step.Input, &input); err != nil {
						t.Fatal(err)
					}
					identities[input.PermissionArn] = value(permissions.Permissions[0].Arn)
					policyReady = true
				}
				raw := step.Input
				for native, local := range identities {
					raw = bytes.ReplaceAll(raw, []byte(native), []byte(local))
				}
				input, err := api.NewInput(step.Operation)
				if err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(raw, input); err != nil {
					t.Fatal(err)
				}
				var expected map[string]any
				if err = json.Unmarshal(step.Response, &expected); err != nil {
					t.Fatal(err)
				}
				out, rejected := execute(s, owner, step.Operation, input)
				if step.Status != 200 {
					if rejected == nil || rejected.Code != expected["__type"] {
						t.Fatalf("%s: error=%v, native=%s", label, rejected, step.Response)
					}
					continue
				}
				if rejected != nil {
					t.Fatalf("%s: %v", label, rejected)
				}
				encoded, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				var actual map[string]any
				if err = json.Unmarshal(encoded, &actual); err != nil {
					t.Fatal(err)
				}
				for _, key := range []string{"clientToken", "returnValue", "permissionStatus"} {
					want, wantPresent := expected[key]
					got, gotPresent := actual[key]
					if wantPresent != gotPresent || !reflect.DeepEqual(got, want) {
						t.Fatalf("%s: %s=%#v (present %t), native=%#v (present %t)", label, key, got, gotPresent, want, wantPresent)
					}
				}
				for _, shape := range []struct {
					name, identity string
					fields         []string
				}{
					{"resourceShare", "resourceShareArn", []string{"name", "status"}},
					{"permission", "arn", []string{"version", "defaultVersion", "permission"}},
					{"replacePermissionAssociationsWork", "id", nil},
				} {
					want, exists := expected[shape.name].(map[string]any)
					if !exists {
						continue
					}
					got, exists := actual[shape.name].(map[string]any)
					if !exists {
						t.Fatalf("%s: missing %s", label, shape.name)
					}
					nativeID, localID := want[shape.identity].(string), got[shape.identity].(string)
					if previous, seen := identities[nativeID]; seen && previous != localID {
						t.Fatalf("%s: replay changed %s identity: %s -> %s", label, shape.name, previous, localID)
					}
					for other, mapped := range identities {
						if other != nativeID && mapped == localID {
							t.Fatalf("%s: distinct native identities collapsed to %s", label, localID)
						}
					}
					identities[nativeID] = localID
					for _, field := range shape.fields {
						if !reflect.DeepEqual(got[field], want[field]) {
							t.Fatalf("%s: %s.%s=%#v, native=%#v", label, shape.name, field, got[field], want[field])
						}
					}
				}
			}
		})
	}
}
