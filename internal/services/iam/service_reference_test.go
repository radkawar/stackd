package iam_test

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd/internal/services/iam"
)

func TestServiceAccessARNFormsAWSReplay(t *testing.T) {
	var fixture struct {
		Policies map[string]json.RawMessage `json:"policies"`
		Result   struct {
			PoliciesGrantingServiceAccess []struct {
				ServiceNamespace string
				Policies         []struct{ PolicyName, PolicyType string }
			}
		}
	}
	data, err := os.ReadFile("../../../testdata/aws/iam/service_reference.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("reference")})
	if err != nil {
		t.Fatal(err)
	}
	for name, document := range fixture.Policies {
		if _, err := client.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String(name), PolicyDocument: aws.String(string(document))}); err != nil {
			t.Fatal(err)
		}
	}
	var namespaces []string
	want := make(map[string][]string)
	for _, row := range fixture.Result.PoliciesGrantingServiceAccess {
		namespaces = append(namespaces, row.ServiceNamespace)
		want[row.ServiceNamespace] = []string{}
		for _, policy := range row.Policies {
			want[row.ServiceNamespace] = append(want[row.ServiceNamespace], policy.PolicyName+":"+policy.PolicyType)
		}
		slices.Sort(want[row.ServiceNamespace])
	}
	out, err := client.ListPoliciesGrantingServiceAccess(t.Context(), &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: user.User.Arn, ServiceNamespaces: namespaces})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string][]string)
	for _, row := range out.PoliciesGrantingServiceAccess {
		name := aws.ToString(row.ServiceNamespace)
		got[name] = []string{}
		for _, policy := range row.Policies {
			got[name] = append(got[name], aws.ToString(policy.PolicyName)+":"+string(policy.PolicyType))
		}
		slices.Sort(got[name])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy discovery differs from AWS: got %v want %v", got, want)
	}
}

func TestResourceHandlingAWSReplay(t *testing.T) {
	var fixture struct {
		Simulation []struct {
			Input  sdkiam.SimulateCustomPolicyInput
			Code   string
			Output sdkiam.SimulateCustomPolicyOutput
		}
	}
	data, err := os.ReadFile("../../../testdata/aws/iam/service_reference.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	for _, row := range fixture.Simulation {
		t.Run(row.Input.ActionNames[0]+"/"+aws.ToString(row.Input.ResourceHandlingOption), func(t *testing.T) {
			out, err := client.SimulateCustomPolicy(t.Context(), &row.Input)
			if row.Code != "Success" {
				requireCode(t, err, row.Code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(out.EvaluationResults) != len(row.Output.EvaluationResults) {
				t.Fatal("simulation result count differs from AWS")
			}
			for i, result := range out.EvaluationResults {
				want := row.Output.EvaluationResults[i]
				if aws.ToString(result.EvalActionName) != aws.ToString(want.EvalActionName) || aws.ToString(result.EvalResourceName) != aws.ToString(want.EvalResourceName) || result.EvalDecision != want.EvalDecision {
					t.Fatalf("simulation result differs: got %+v want %+v", result, want)
				}
			}
		})
	}
}
