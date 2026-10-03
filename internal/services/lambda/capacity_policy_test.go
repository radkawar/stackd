package lambda

import (
	"encoding/json"
	"os"
	"testing"

	"stackd/iam/policy"
)

func TestResourcePolicyNativeAdmission(t *testing.T) {
	for _, file := range []string{"resource_policy_native.json", "resource_policy_extended_native.json", "resource_policy_validation_native.json", "resource_policy_federation_native.json", "resource_policy_federation_shapes_native.json"} {
		raw, err := os.ReadFile("../../../testdata/lambda/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Cases []struct {
				Label, Operation string
				Request          struct{ ResourceArn, Policy string }
				Error            *struct{ Code string }
			}
		}
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, c := range fixture.Cases {
			if c.Operation != "put_resource_policy" || c.Error != nil && c.Error.Code != "InvalidParameterValueException" {
				continue
			}
			t.Run(c.Label, func(t *testing.T) {
				_, err := normalizeFunctionResourcePolicy(c.Request.Policy, c.Request.ResourceArn)
				if (err != nil) != (c.Error != nil) {
					t.Fatalf("native admission differs: error=%v, native=%+v", err, c.Error)
				}
			})
		}
	}
}

func TestResourcePolicyMutationPreservesAuthorization(t *testing.T) {
	const arn = "arn:aws:lambda:us-east-1:111111111111:function:retained"
	const original = `{"Version":"2012-10-17","Statement":[{"Sid":"grant","Effect":"Allow","Principal":{"AWS":["111111111111","222222222222"]},"Action":["lambda:InvokeFunction","lambda:GetFunction"],"Resource":["` + arn + `"],"Condition":{"StringEquals":{"aws:SourceAccount":["111111111111","222222222222"]}}},{"Sid":"transport","Effect":"Deny","NotPrincipal":{"AWS":"111111111111"},"NotAction":"lambda:DeleteFunction","Resource":"` + arn + `","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	var document permissionDocument
	if err := json.Unmarshal([]byte(original), &document); err != nil {
		t.Fatal(err)
	}
	document.Statements = append(document.Statements, permissionStatement{Sid: "added", Effect: "Deny", Principal: json.RawMessage(`"*"`), Action: "lambda:GetFunction", Resource: arn})
	check := func(action, account, source, transport string, want policy.Decision) {
		t.Helper()
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := policy.ParseResource(encoded)
		if err != nil {
			t.Fatal(err)
		}
		request := policy.Request{Action: action, Resource: arn, Context: map[string][]string{"aws:SourceAccount": {source}, "aws:SecureTransport": {transport}}}
		decision, err := policy.EvaluateResource(parsed, request, policy.Principal{Partition: "aws", AccountID: account, ARN: "arn:aws:iam::" + account + ":user/caller"})
		if err != nil || decision.Decision != want {
			t.Fatalf("%s account=%s source=%s transport=%s: decision=%v want=%v error=%v", action, account, source, transport, decision.Decision, want, err)
		}
	}
	check("lambda:InvokeFunction", "111111111111", "111111111111", "true", policy.Allow)
	check("lambda:InvokeFunction", "111111111111", "333333333333", "true", policy.ImplicitDeny)
	check("lambda:InvokeFunction", "222222222222", "222222222222", "false", policy.ExplicitDeny)
	check("lambda:GetFunction", "111111111111", "111111111111", "true", policy.ExplicitDeny)
	document.Statements = document.Statements[:len(document.Statements)-1]
	check("lambda:GetFunction", "111111111111", "111111111111", "true", policy.Allow)
}

func TestResourcePolicyPrincipalScopedIAM(t *testing.T) {
	const arn = "arn:aws:lambda:us-east-1:111111111111:function:principal"
	const root = "arn:aws:iam::111111111111:root"
	for _, c := range []struct {
		name, principal, condition, resource string
		want                                 policy.Decision
	}{
		{"root-ARN-grant", `{"AWS":"111111111111"}`, `{"StringEquals":{"lambda:Principal":"` + root + `"}}`, arn, policy.Allow},
		{"short-account-denied", `{"AWS":"111111111111"}`, `{"StringEquals":{"lambda:Principal":"111111111111"}}`, arn, policy.ImplicitDeny},
		{"other-resource-denied", `{"AWS":"111111111111"}`, `{"StringEquals":{"lambda:Principal":"` + root + `"}}`, arn + "-other", policy.ImplicitDeny},
		{"distinct-AWS-principals-empty-context", `{"AWS":["` + root + `","arn:aws:iam::111111111111:role/other"]}`, `{"StringEquals":{"lambda:Principal":""}}`, arn, policy.Allow},
		{"distinct-AWS-principals-not-root", `{"AWS":["` + root + `","arn:aws:iam::111111111111:role/other"]}`, `{"StringEquals":{"lambda:Principal":"` + root + `"}}`, arn, policy.ImplicitDeny},
		{"duplicate-account-normalized", `{"AWS":["111111111111","` + root + `"]}`, `{"StringEquals":{"lambda:Principal":"` + root + `"}}`, arn, policy.Allow},
		{"not-principal-context-absent", "", `{"Null":{"lambda:Principal":"true"}}`, arn, policy.Allow},
		{"mixed-principals-not-null", `{"AWS":"` + root + `","Service":"s3.amazonaws.com"}`, `{"Null":{"lambda:Principal":"true"}}`, arn, policy.ImplicitDeny},
		{"mixed-principals-no-any-match", `{"AWS":"` + root + `","Service":"s3.amazonaws.com"}`, `{"ForAnyValue:StringEquals":{"lambda:Principal":"s3.amazonaws.com"}}`, arn, policy.ImplicitDeny},
		{"mixed-principals-all-empty-values", `{"AWS":"` + root + `","Service":"s3.amazonaws.com"}`, `{"ForAllValues:StringEquals":{"lambda:Principal":["` + root + `","s3.amazonaws.com"]}}`, arn, policy.Allow},
	} {
		t.Run(c.name, func(t *testing.T) {
			principals, err := permissionPrincipalValues("aws", json.RawMessage(c.principal))
			if err != nil {
				t.Fatal(err)
			}
			identity, err := policy.Parse([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:RemovePermission","Resource":"` + arn + `","Condition":` + c.condition + `}]}`))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := policy.Evaluate([]*policy.Document{identity}, policy.Request{
				Action: "lambda:RemovePermission", Resource: c.resource,
				Context: map[string][]string{"lambda:Principal": principals},
			})
			if err != nil || decision != c.want {
				t.Fatalf("scoped IAM decision=%v want=%v error=%v", decision, c.want, err)
			}
		})
	}
}
