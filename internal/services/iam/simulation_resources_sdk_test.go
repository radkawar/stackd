package iam_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/services/iam"
)

func TestSimulateCustomPolicyAWSResourceMatrix(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/simulation_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CleanupVerified bool                           `json:"cleanup_verified"`
		Observations    []simulationFixtureObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.CleanupVerified {
		t.Fatal("resource matrix capture cleanup is not verified")
	}
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	// AWS captured hypothetical resource accounts distinct from its caller;
	// identity-only simulation must still evaluate their policy permissions.
	client := clientFor(t, service, "999999999999", "us-east-1")
	count := 0
	for _, observation := range fixture.Observations {
		if !strings.HasPrefix(observation.Case, "input_resources_") && !strings.HasPrefix(observation.Case, "input_action_groups_") {
			continue
		}
		count++
		t.Run(observation.Case, func(t *testing.T) {
			var input sdkiam.SimulateCustomPolicyInput
			if err := json.Unmarshal(observation.Input, &input); err != nil {
				t.Fatal(err)
			}
			output, err := client.SimulateCustomPolicy(t.Context(), &input)
			if observation.Code != "Success" {
				requireCode(t, err, observation.Code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertSimulationFixtureOutput(t, observation.Output, output)
		})
	}
	if count == 0 {
		t.Fatal("no resource matrix observations selected")
	}
}
