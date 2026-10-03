package iam

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type simulationResourceFixture struct {
	CleanupVerified bool `json:"cleanup_verified"`
	Observations    []struct {
		Case  string `json:"case"`
		Code  string `json:"code"`
		Input struct {
			ActionNames            []string
			ResourceArns           []string
			ResourceHandlingOption string
		} `json:"input"`
		Output struct {
			EvaluationResults []struct {
				EvalActionName          string
				EvalResourceName        string
				ResourceSpecificResults []struct {
					EvalResourceName     string
					EvalResourceDecision string
				}
			}
		} `json:"output"`
	} `json:"observations"`
}

func TestSimulationResourceAWSFixture(t *testing.T) {
	for _, filename := range []string{"simulation_inputs.json", "simulation.json"} {
		data, err := os.ReadFile("../../../testdata/aws/iam/" + filename)
		if err != nil {
			t.Fatal(err)
		}
		var fixture simulationResourceFixture
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		if !fixture.CleanupVerified {
			t.Fatal("AWS capture cleanup is not verified")
		}
		for _, observation := range fixture.Observations {
			if !strings.HasPrefix(observation.Case, "input_resources_") && !strings.HasPrefix(observation.Case, "input_action_groups_") && !strings.HasPrefix(observation.Case, "resource_handling_") {
				continue
			}
			t.Run(observation.Case, func(t *testing.T) {
				t.Parallel()
				resources := observation.Input.ResourceArns
				if len(resources) == 0 {
					resources = []string{"*"}
				}
				apiErr := validateSimulationResources(resources, observation.Input.ResourceHandlingOption)
				if apiErr == nil {
					apiErr = validateSimulationActions(observation.Input.ActionNames, resources)
				}
				if apiErr == nil {
					apiErr = validateSimulationHandling(observation.Input.ActionNames, resources, observation.Input.ResourceHandlingOption)
				}
				if observation.Code != "Success" {
					if apiErr == nil || apiErr.Code != observation.Code {
						t.Fatalf("validation = %v, want %s", apiErr, observation.Code)
					}
					return
				}
				if apiErr != nil {
					t.Fatal(apiErr)
				}
				for _, result := range observation.Output.EvaluationResults {
					simulation := compiledSimulation{resources: resources}
					name := simulation.aggregateResource(result.EvalActionName)
					if name == nil || *name != result.EvalResourceName {
						t.Errorf("%s aggregate = %v; want %q", result.EvalActionName, name, result.EvalResourceName)
					}
					for _, resource := range result.ResourceSpecificResults {
						compatible, apiErr := simulationResourceCompatible(result.EvalActionName, resource.EvalResourceName)
						want := resource.EvalResourceDecision == "allowed"
						if apiErr != nil || compatible != want {
							t.Errorf("%s compatibility with %s = %v, %v; want %v", result.EvalActionName, resource.EvalResourceName, compatible, apiErr, want)
						}
					}
				}
			})
		}
	}
}

func TestSimulationResourceValidation(t *testing.T) {
	for _, resource := range []string{"", "bucket", "arn:aws:s3", "arn::s3:::bucket", "arn:aws::::bucket", "arn:aws:s3:::"} {
		if apiErr := validateSimulationResources([]string{resource}, ""); apiErr == nil || apiErr.Code != "InvalidInput" {
			t.Errorf("invalid resource %q accepted: %v", resource, apiErr)
		}
	}
	for _, resource := range []string{"*", "arn:aws:s3:::bucket", "arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws-cn:sqs:cn-north-1:123456789012:queue"} {
		if apiErr := validateSimulationResources([]string{resource}, ""); apiErr != nil {
			t.Errorf("resource %q rejected: %v", resource, apiErr)
		}
	}
	if apiErr := validateSimulationActions([]string{"GetObject"}, []string{"*"}); apiErr == nil {
		t.Error("action without namespace accepted")
	}
	for _, action := range []string{"madeup:Action", "s3:MadeUp", "s3:*", "s3:", "s3:Get Object"} {
		if apiErr := validateSimulationActions([]string{action}, []string{"*"}); apiErr != nil {
			t.Errorf("literal action %q rejected: %v", action, apiErr)
		}
	}
}
