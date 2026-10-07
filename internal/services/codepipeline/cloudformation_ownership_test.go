package codepipeline

import (
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awscatalog"
	"testing"
)

func TestCloudFormationRevisionReplayDoesNotInventPipelineVersions(t *testing.T) {
	service, ctx, pipeline, definition := kernelFixture(t, "SUPERSEDED")
	service.roles = approvalAdmissionRoles{}
	declaration := CloneDeclaration(definition.Declaration)
	declaration.Stages[0].Actions[0].Configuration = api.ActionConfigurationMap{"S3Bucket": "source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}
	declaration.Stages[0].Actions[0].OutputArtifacts = api.OutputArtifactList{{Name: new(api.ArtifactName("source"))}}
	model, _ := awscatalog.LookupService("codepipeline")
	operation, _ := model.Operation("UpdatePipeline")
	request := awsapi.DecodedRequest{Operation: operation, Input: &api.UpdatePipelineInput{Pipeline: &declaration}}
	for _, hash := range []string{"first-transition", "first-transition", "second-transition"} {
		result, rejected := service.ExecuteCommand(WithCloudFormationUpdate(ctx, hash), request)
		if rejected != nil {
			t.Fatal(rejected)
		}
		expected := int32(2)
		if hash == "second-transition" {
			expected = 3
		}
		if got := int32(*result.(*api.UpdatePipelineOutput).Pipeline.Version); got != expected {
			t.Fatalf("transition %s: version %d, want %d", hash, got, expected)
		}
	}
	// Out-of-band definition changes must invalidate an earlier replay fence.
	direct, rejected := service.ExecuteCommand(ctx, request)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if int32(*direct.(*api.UpdatePipelineOutput).Pipeline.Version) != 4 {
		t.Fatal("direct owner revision was not applied")
	}
	tagOperation, _ := model.Operation("TagResource")
	_, rejected = service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: tagOperation, Input: &api.TagResourceInput{ResourceArn: new(api.ResourceArn(ARN(pipeline.Scope, pipeline.Name))), Tags: api.TagList{{Key: new(api.TagKey("stackd:cloudformation:last-update")), Value: new(api.TagValue("second-transition"))}}}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	replay, rejected := service.ExecuteCommand(WithCloudFormationUpdate(ctx, "second-transition"), request)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if int32(*replay.(*api.UpdatePipelineOutput).Pipeline.Version) != 5 {
		t.Fatal("external revision did not invalidate the old CFN replay fence")
	}
	if err := service.repository.View(ctx, func(reader Reader) error {
		current, err := findPipeline(reader, pipeline.Scope, pipeline.Name)
		if err != nil {
			return err
		}
		if current.Version != 5 || current.LastUpdate != "second-transition" {
			t.Fatalf("wrong committed revision state: %#v", current)
		}
		_, exists, err := reader.Definition(current.Scope, current.Incarnation, 6)
		if exists {
			t.Fatal("replay invented an extra immutable revision")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
