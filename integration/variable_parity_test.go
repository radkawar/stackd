package stackd_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd"
)

// TestIAMVariableDecisionParity replays only the exact decision observations in
// the fixture. Context eligibility, diagnostics, and general IAM completeness
// are outside this compatibility claim; tests never contact AWS.
func TestIAMVariableDecisionParity(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/variables.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Scenarios []struct {
			Name    string          `json:"name"`
			Policy  json.RawMessage `json:"policy"`
			Request struct {
				Action   string              `json:"action"`
				Resource string              `json:"resource"`
				Context  map[string][]string `json:"context"`
			} `json:"request"`
			ExpectedDecision types.PolicyEvaluationDecisionType `json:"expectedDecision"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Scenarios) == 0 {
		t.Fatal("AWS variable observations are empty")
	}
	handler, err := stackd.New(stackd.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	for _, scenario := range fixture.Scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			input := &iam.SimulateCustomPolicyInput{ActionNames: []string{scenario.Request.Action}, ResourceArns: []string{scenario.Request.Resource}, PolicyInputList: []string{string(scenario.Policy)}}
			keys := make([]string, 0, len(scenario.Request.Context))
			for key := range scenario.Request.Context {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				values := scenario.Request.Context[key]
				kind := types.ContextKeyTypeEnumString
				if len(values) > 1 {
					kind = types.ContextKeyTypeEnumStringList
				}
				input.ContextEntries = append(input.ContextEntries, types.ContextEntry{ContextKeyName: aws.String(key), ContextKeyType: kind, ContextKeyValues: values})
			}
			out, err := client.SimulateCustomPolicy(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.EvaluationResults) != 1 {
				t.Fatalf("evaluations=%v", out.EvaluationResults)
			}
			if got := out.EvaluationResults[0].EvalDecision; got != scenario.ExpectedDecision {
				t.Fatalf("decision=%s, AWS returned %s", got, scenario.ExpectedDecision)
			}
		})
	}
}
