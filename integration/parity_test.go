package stackd_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd"
)

// TestIAMSimulationDecisionParity replays a read-only AWS observation offline.
// It intentionally compares decisions only; fixture provenance records the
// diagnostic fields still awaiting implementation.
func TestIAMSimulationDecisionParity(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/simulate_custom_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input  iam.SimulateCustomPolicyInput  `json:"input"`
		Output iam.SimulateCustomPolicyOutput `json:"output"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	handler, err := stackd.New(stackd.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	actual, err := client.SimulateCustomPolicy(context.Background(), &fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	if len(actual.EvaluationResults) != len(fixture.Output.EvaluationResults) {
		t.Fatalf("got %d evaluations, want %d", len(actual.EvaluationResults), len(fixture.Output.EvaluationResults))
	}
	for i, expected := range fixture.Output.EvaluationResults {
		result := actual.EvaluationResults[i]
		if aws.ToString(result.EvalActionName) != aws.ToString(expected.EvalActionName) || result.EvalDecision != expected.EvalDecision {
			t.Fatalf("decision differs from AWS: got %#v, want %#v", result, expected)
		}
		if len(result.ResourceSpecificResults) != len(expected.ResourceSpecificResults) {
			t.Fatalf("got %d resources, want %d", len(result.ResourceSpecificResults), len(expected.ResourceSpecificResults))
		}
		for j, resource := range expected.ResourceSpecificResults {
			if aws.ToString(result.ResourceSpecificResults[j].EvalResourceName) != aws.ToString(resource.EvalResourceName) || result.ResourceSpecificResults[j].EvalResourceDecision != resource.EvalResourceDecision {
				t.Fatalf("resource decision differs from AWS: got %#v, want %#v", result.ResourceSpecificResults[j], resource)
			}
		}
	}
}
