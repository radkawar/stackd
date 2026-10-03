package iam_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/services/iam"
)

// The original inputs include the placeholder-discovery statements, exact
// repeated confirmations, scalar/list controls, caller ARN defaults and explicit
// overrides. Replay the full SDK response, including source positions and
// missing-key diagnostics, rather than only the final permission decision.
func TestSimulateCustomPolicyDefaultsAWSReplay(t *testing.T) {
	replaySimulationContextFixture(t, "simulation_defaults.json", func(string) bool { return true })
}

func TestSimulateCustomPolicyTypedContextAWSReplay(t *testing.T) {
	replaySimulationContextFixture(t, "simulation_inputs.json", func(name string) bool {
		return strings.HasPrefix(name, "input_type_match_") || strings.HasPrefix(name, "input_coercion_") || strings.HasPrefix(name, "input_canonical_")
	})
}

func replaySimulationContextFixture(t *testing.T, name string, include func(string) bool) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ResourceWrites  bool                           `json:"resource_writes"`
		CleanupVerified bool                           `json:"cleanup_verified"`
		CaptureComplete bool                           `json:"capture_complete"`
		Observations    []simulationFixtureObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ResourceWrites || !fixture.CleanupVerified || !fixture.CaptureComplete || len(fixture.Observations) == 0 {
		t.Fatal("expected a completed read-only AWS defaults capture")
	}
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	count := 0
	for _, observation := range fixture.Observations {
		if !include(observation.Case) {
			continue
		}
		count++
		t.Run(observation.Case, func(t *testing.T) {
			if observation.Operation != "SimulateCustomPolicy" {
				t.Fatalf("unhandled captured result: %s / %s", observation.Operation, observation.Code)
			}
			var input sdkiam.SimulateCustomPolicyInput
			if err := json.Unmarshal(observation.Input, &input); err != nil {
				t.Fatal(err)
			}
			output, err := client.SimulateCustomPolicy(t.Context(), &input)
			if observation.Code != "Success" {
				requireCode(t, err, observation.Code)
				if output != nil {
					t.Fatal("invalid context returned a simulation result")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertSimulationFixtureOutput(t, observation.Output, output)
		})
	}
	if count == 0 {
		t.Fatal("fixture contains no matching context cases")
	}
}
