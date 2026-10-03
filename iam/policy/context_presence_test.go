package policy_test

import (
	"encoding/json"
	"os"
	"testing"

	"stackd/iam/policy"
)

func TestNativeMixedPrincipalConditionPresence(t *testing.T) {
	for _, file := range []string{"resource_policy_principal_mixed_native.json", "resource_policy_principal_sets_native.json", "resource_policy_principal_presence_native.json"} {
		data, err := os.ReadFile("../../testdata/lambda/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var capture struct {
			Cases []struct {
				Label     string
				Condition json.RawMessage
				Outcome   string
				Error     string
			}
		}
		if err := json.Unmarshal(data, &capture); err != nil {
			t.Fatal(err)
		}
		for _, row := range capture.Cases {
			t.Run(row.Label, func(t *testing.T) {
				if row.Outcome != "allowed" && row.Error != "AccessDeniedException" {
					t.Fatalf("native authorization outcome is not classified: %+v", row)
				}
				document := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"lambda:RemovePermission","Resource":"*","Condition":`+string(row.Condition)+`}}`)
				// Native mixed-kind principals have no scalar match but are not
				// null. A present empty value-set models those observed decisions;
				// this is not a claim about AWS's internal representation.
				request := policy.Request{Action: "lambda:RemovePermission", Resource: "*", Context: map[string][]string{"lambda:Principal": {}}}
				got, err := policy.Evaluate([]*policy.Document{document}, request)
				if err != nil || (got == policy.Allow) != (row.Outcome == "allowed") {
					t.Fatalf("condition %s: got %v, %v; native outcome=%s error=%s", row.Condition, got, err, row.Outcome, row.Error)
				}
			})
		}
	}
}

func TestNonNullEmptySetDoesNotSkipIfExistsComparison(t *testing.T) {
	// IfExists skips an absent key, not a non-null key without a scalar value.
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IfExists
	document := conditionDocument(t, "StringEqualsIfExists", "required")
	request := policy.Request{Action: "lambda:RemovePermission", Resource: "*"}
	if got, err := policy.Evaluate([]*policy.Document{document}, request); err != nil || got != policy.Allow {
		t.Fatalf("missing-key IfExists: got %v, %v", got, err)
	}
	request.Context = map[string][]string{"EXAMPLE:key": {}}
	if got, err := policy.Evaluate([]*policy.Document{document}, request); err != nil || got != policy.ImplicitDeny {
		t.Fatalf("present-empty IfExists bypassed comparison: got %v, %v", got, err)
	}
}
