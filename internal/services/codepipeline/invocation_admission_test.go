package codepipeline

import (
	"testing"

	api "stackd/internal/awsapi/codepipeline"
)

func TestLambdaAdmissionArtifactBoundsAndConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name            string
		inputs, outputs int
		function        string
		extra           bool
		wantError       bool
	}{
		{name: "no-artifacts", function: "not-created-yet"},
		{name: "five-inputs-and-outputs", inputs: 5, outputs: 5, function: "transform"},
		{name: "six-inputs", inputs: 6, function: "transform", wantError: true},
		{name: "six-outputs", outputs: 6, function: "transform", wantError: true},
		{name: "missing-function", wantError: true},
		{name: "unknown-configuration", function: "transform", extra: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx, _, d, _ := invocationFixture(t)
			s.roles = approvalAdmissionRoles{}
			names := []string{"One", "Two", "Three", "Four", "Five", "Six"}
			source := d.Declaration.Stages[0].Actions[0]
			source.Configuration = api.ActionConfigurationMap{"S3Bucket": "source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}
			d.Declaration.Stages[0].Actions = nil
			for _, name := range names {
				a := source
				a.Name = new(api.ActionName(name))
				a.OutputArtifacts = api.OutputArtifactList{{Name: new(api.ArtifactName("Source" + name))}}
				d.Declaration.Stages[0].Actions = append(d.Declaration.Stages[0].Actions, a)
			}
			a := &d.Declaration.Stages[1].Actions[0]
			a.Configuration = api.ActionConfigurationMap{"FunctionName": api.ActionConfigurationValue(tc.function)}
			if tc.extra {
				a.Configuration["Unsupported"] = "value"
			}
			for _, name := range names[:tc.inputs] {
				a.InputArtifacts = append(a.InputArtifacts, api.InputArtifact{Name: new(api.ArtifactName("Source" + name))})
			}
			for _, name := range names[:tc.outputs] {
				a.OutputArtifacts = append(a.OutputArtifacts, api.OutputArtifact{Name: new(api.ArtifactName("Produced" + name))})
			}
			err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.admitDefinition(tx, &d.Declaration, 1)
				return err
			})
			if tc.wantError {
				if err == nil || wireError(err).Code != "InvalidActionDeclarationException" {
					t.Fatalf("invalid Lambda declaration accepted: %v", err)
				}
			} else if err != nil {
				t.Fatalf("valid Lambda declaration rejected: %v", err)
			}
		})
	}
}
