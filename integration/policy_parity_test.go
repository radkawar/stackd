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
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd"
)

// TestIAMConditionDecisionParity replays live AWS observations entirely offline.
// Aggregate and individual resource decisions are separate assertions: an allowed
// resource does not imply that the aggregate request is allowed. Diagnostic
// positions, missing-context reporting, and aggregate ARN templates are preserved
// in the fixtures as evidence but are outside this test's compatibility claim.
func TestIAMConditionDecisionParity(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/conditions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name   string                         `json:"name"`
			Input  iam.SimulateCustomPolicyInput  `json:"input"`
			Output iam.SimulateCustomPolicyOutput `json:"output"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("AWS condition observations are empty")
	}
	handler, err := stackd.New(stackd.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := iam.New(iam.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:  server.Client(), RetryMaxAttempts: 1,
	})
	for _, observation := range fixture.Cases {
		t.Run(observation.Name, func(t *testing.T) {
			actual, err := client.SimulateCustomPolicy(context.Background(), &observation.Input)
			if err != nil {
				t.Fatal(err)
			}
			if len(actual.EvaluationResults) != len(observation.Output.EvaluationResults) {
				t.Fatalf("action count = %d, AWS returned %d", len(actual.EvaluationResults), len(observation.Output.EvaluationResults))
			}
			byAction := make(map[string]types.EvaluationResult, len(actual.EvaluationResults))
			for _, result := range actual.EvaluationResults {
				name := aws.ToString(result.EvalActionName)
				if _, duplicate := byAction[name]; duplicate {
					t.Fatalf("duplicate action evaluation %q", name)
				}
				byAction[name] = result
			}
			for _, expected := range observation.Output.EvaluationResults {
				action := aws.ToString(expected.EvalActionName)
				result, exists := byAction[action]
				if !exists {
					t.Fatalf("missing action evaluation %q", action)
				}
				if result.EvalDecision != expected.EvalDecision {
					t.Errorf("%s aggregate decision = %s, AWS returned %s", action, result.EvalDecision, expected.EvalDecision)
				}
				assertResourceDecisions(t, action, result.ResourceSpecificResults, expected.ResourceSpecificResults)
			}
		})
	}
}

func assertResourceDecisions(t *testing.T, action string, actual, expected []types.ResourceSpecificResult) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("%s resource count = %d, AWS returned %d", action, len(actual), len(expected))
	}
	byResource := make(map[string]types.PolicyEvaluationDecisionType, len(actual))
	for _, resource := range actual {
		name := aws.ToString(resource.EvalResourceName)
		if _, duplicate := byResource[name]; duplicate {
			t.Fatalf("%s returned duplicate resource %q", action, name)
		}
		byResource[name] = resource.EvalResourceDecision
	}
	for _, resource := range expected {
		name := aws.ToString(resource.EvalResourceName)
		decision, exists := byResource[name]
		if !exists {
			t.Errorf("%s missing resource evaluation %q", action, name)
			continue
		}
		if decision != resource.EvalResourceDecision {
			t.Errorf("%s %s decision = %s, AWS returned %s", action, name, decision, resource.EvalResourceDecision)
		}
	}
}
