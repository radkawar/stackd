package codepipeline

import (
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

func TestDeniedStartDoesNotAdmitExecution(t *testing.T) {
	s, ctx, pipeline, _ := kernelFixture(t, "QUEUED")
	metadata := awsctx.FromContext(ctx)
	metadata.PrincipalARN = "arn:aws:iam::111122223333:user/ungranted"
	metadata.PrincipalID = "AIDAUNGRANTED"
	metadata.UserName = "ungranted"
	ctx = awsctx.WithMetadata(ctx, metadata)
	model, _ := awscatalog.LookupService("codepipeline")
	operation, _ := model.Operation("StartPipelineExecution")
	_, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{
		Operation: operation, Protocol: model.Protocol,
		Input: &api.StartPipelineExecutionInput{Name: new(api.PipelineName(pipeline.Name))},
	})
	// Native Scheduler delivery retains this CodePipeline error in its DLQ:
	// testdata/aws/scheduler/codepipeline_native_observed.json.
	if rejected == nil || rejected.Code != "AccessDeniedException" || rejected.StatusCode != 403 {
		t.Fatalf("denied start returned %v", rejected)
	}
	if err := s.repository.View(ctx, func(reader Reader) error {
		executions, err := reader.Executions(pipeline.Scope, pipeline.Incarnation)
		if err != nil {
			return err
		}
		if len(executions) != 0 {
			t.Fatalf("denied start admitted executions: %+v", executions)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
