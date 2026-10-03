package iam_test

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

// The catalog capture establishes simulator action grouping and display names
// for one explicit-resource scenario. Its action coverage does not establish
// complete policy evaluation or the behavior of every resource combination.
type simulationCatalogFixture struct {
	SchemaVersion           int                            `json:"schema_version"`
	Operation               string                         `json:"operation"`
	Endpoint                string                         `json:"endpoint"`
	Region                  string                         `json:"region"`
	RequestCommon           json.RawMessage                `json:"request_common"`
	Actions                 []simulationCatalogAction      `json:"actions"`
	Requests                []simulationCatalogRequest     `json:"requests"`
	RepresentativeResponses []simulationFixtureObservation `json:"representative_responses"`
	Failures                []json.RawMessage              `json:"failures"`
	CaptureComplete         bool                           `json:"capture_complete"`
	NoResourceWrites        bool                           `json:"no_resource_writes"`
	CleanupVerified         bool                           `json:"cleanup_verified"`
}

type simulationCatalogAction struct {
	Action string `json:"action"`
	simulationCatalogResult
	DefaultResult *simulationCatalogResult `json:"default_result"`
	SingleResult  *simulationCatalogResult `json:"single_result"`
}

type simulationCatalogResult struct {
	Code                    string                             `json:"code"`
	EvalResourceName        string                             `json:"eval_resource_name"`
	EvalResourceNamePresent *bool                              `json:"eval_resource_name_present"`
	EvalDecision            types.PolicyEvaluationDecisionType `json:"eval_decision"`
	ResourceSpecificResults []simulationCatalogResource        `json:"resource_specific_results"`
}

type simulationCatalogResource struct {
	EvalResourceName     string
	EvalResourceDecision types.PolicyEvaluationDecisionType
}

type simulationCatalogRequest struct {
	ID         string          `json:"id"`
	Actions    []string        `json:"actions"`
	Code       string          `json:"code"`
	HTTPStatus int             `json:"http_status"`
	Purpose    string          `json:"purpose"`
	Profile    string          `json:"profile"`
	Input      json.RawMessage `json:"input"`
}

func loadSimulationCatalogFixture(t *testing.T) simulationCatalogFixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/simulation_catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture simulationCatalogFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != 1 || fixture.Operation != "SimulateCustomPolicy" || !fixture.CaptureComplete || !fixture.CleanupVerified || !fixture.NoResourceWrites || len(fixture.Failures) != 0 {
		t.Fatal("simulation catalog fixture is not a complete successful read-only AWS capture")
	}
	return fixture
}

func TestSimulateCustomPolicyAWSCatalog(t *testing.T) {
	ctx := t.Context()
	fixture := loadSimulationCatalogFixture(t)
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", fixture.Region)
	actions := make(map[string]simulationCatalogAction)
	for _, action := range fixture.Actions {
		actions[action.Action] = action
	}
	seen := make(map[string]bool)
	for _, request := range fixture.Requests {
		if request.Purpose == "representative" {
			// These vary more than ActionNames and retain a full response in
			// the separate representative test below.
			continue
		}
		t.Run(request.ID, func(t *testing.T) {
			var input sdkiam.SimulateCustomPolicyInput
			rawInput := fixture.RequestCommon
			if len(request.Input) != 0 {
				rawInput = request.Input
			}
			if err := json.Unmarshal(rawInput, &input); err != nil {
				t.Fatal(err)
			}
			input.ActionNames = slices.Clone(request.Actions)
			output, err := client.SimulateCustomPolicy(ctx, &input)
			if request.Code != "Success" {
				requireCode(t, err, request.Code)
				var response interface{ HTTPStatusCode() int }
				if !errors.As(err, &response) || response.HTTPStatusCode() != request.HTTPStatus || output != nil {
					t.Fatalf("catalog grouping error differs from AWS: %+v %v", output, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if output.IsTruncated || output.Marker != nil || len(output.EvaluationResults) != len(request.Actions) {
				t.Fatalf("action batch unexpectedly paginated or changed result count: %+v", output)
			}
			resultNames := make([]string, 0, len(output.EvaluationResults))
			for _, result := range output.EvaluationResults {
				name := aws.ToString(result.EvalActionName)
				action, exists := actions[name]
				if !exists || !slices.Contains(request.Actions, name) {
					t.Fatalf("SDK returned unrequested or uncaptured action %q", name)
				}
				expected := action.simulationCatalogResult
				switch request.Profile {
				case "":
				case "default":
					if action.DefaultResult == nil {
						t.Fatalf("default-resource request omitted captured result for %s", name)
					}
					expected = *action.DefaultResult
				case "single":
					if action.SingleResult == nil {
						t.Fatalf("single-resource request omitted captured result for %s", name)
					}
					expected = *action.SingleResult
				default:
					t.Fatalf("unknown simulation profile %q", request.Profile)
				}
				resultNames = append(resultNames, name)
				seen[name] = true
				resources := make([]simulationCatalogResource, 0, len(result.ResourceSpecificResults))
				for _, child := range result.ResourceSpecificResults {
					resources = append(resources, simulationCatalogResource{EvalResourceName: aws.ToString(child.EvalResourceName), EvalResourceDecision: child.EvalResourceDecision})
				}
				if (result.EvalResourceName != nil) != *expected.EvalResourceNamePresent || aws.ToString(result.EvalResourceName) != expected.EvalResourceName || result.EvalDecision != expected.EvalDecision || !slices.Equal(resources, expected.ResourceSpecificResults) {
					t.Errorf("%s differs from AWS: aggregate=(%q,%s), resources=%+v; expected=(%q,%s), resources=%+v", name, aws.ToString(result.EvalResourceName), result.EvalDecision, resources, expected.EvalResourceName, expected.EvalDecision, expected.ResourceSpecificResults)
				}
			}
			// Preserve multiplicity without guessing action ordering from the
			// compact per-action rows. Full representative outputs check order.
			expectedNames := slices.Clone(request.Actions)
			slices.Sort(expectedNames)
			slices.Sort(resultNames)
			if !slices.Equal(resultNames, expectedNames) {
				t.Fatalf("SDK action membership or multiplicity differs: got %v want %v", resultNames, expectedNames)
			}
		})
	}
	for _, action := range fixture.Actions {
		if action.Code == "Success" && !seen[action.Action] {
			t.Errorf("captured action %s was never exercised through an SDK request", action.Action)
		}
	}
}

func TestSimulateCustomPolicyAWSCatalogRepresentatives(t *testing.T) {
	ctx := t.Context()
	fixture := loadSimulationCatalogFixture(t)
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", fixture.Region)
	seen := make(map[string]bool)
	for _, observation := range fixture.RepresentativeResponses {
		if observation.Case == "" || seen[observation.Case] {
			t.Fatalf("missing or repeated representative case %q", observation.Case)
		}
		seen[observation.Case] = true
		t.Run(observation.Case, func(t *testing.T) {
			var input sdkiam.SimulateCustomPolicyInput
			if err := json.Unmarshal(observation.Input, &input); err != nil {
				t.Fatal(err)
			}
			output, err := client.SimulateCustomPolicy(ctx, &input)
			if observation.Code != "Success" {
				requireCode(t, err, observation.Code)
				if output != nil {
					t.Fatal("failed representative request returned partial results")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertSimulationFixtureOutput(t, observation.Output, output)
		})
	}
	if len(seen) == 0 {
		t.Fatal("catalog capture omitted representative resource scenarios")
	}
}
