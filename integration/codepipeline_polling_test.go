package stackd_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	cptypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"stackd"
	"stackd/clock"
)

func TestCodePipelineSourcePollingRetainsCursorAndCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account = "111122223333"
			manual := clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: manual})
			cp := clients.codepipeline("us-east-1", account, "test")
			objects := func() *s3.Client {
				return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			root := clients.iam(account, "test", "")
			role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("polling"), AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("polling"), PolicyName: new("artifacts"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:*","kms:*"],"Resource":"*"}}`)}); err != nil {
				t.Fatal(err)
			}
			for _, bucket := range []string{"polling-sources", "polling-artifacts"} {
				if _, err := objects().CreateBucket(ctx, &s3.CreateBucketInput{Bucket: new(bucket)}); err != nil {
					t.Fatal(err)
				}
				if _, err := objects().PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: new(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
					t.Fatal(err)
				}
			}
			put := func(key, content string) string {
				t.Helper()
				out, err := objects().PutObject(ctx, &s3.PutObjectInput{Bucket: new("polling-sources"), Key: new(key), Body: strings.NewReader(content)})
				if err != nil {
					t.Fatal(err)
				}
				return aws.ToString(out.VersionId)
			}
			firstRevision := put("source.txt", "initial source")
			definition := &cptypes.PipelineDeclaration{
				Name: new("polling"), RoleArn: role.Role.Arn, PipelineType: cptypes.PipelineTypeV2, ExecutionMode: cptypes.ExecutionModeQueued,
				ArtifactStore: &cptypes.ArtifactStore{Type: cptypes.ArtifactStoreTypeS3, Location: new("polling-artifacts")},
				Stages: []cptypes.StageDeclaration{
					{Name: new("Source"), Actions: []cptypes.ActionDeclaration{{Name: new("S3"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategorySource, Owner: cptypes.ActionOwnerAws, Provider: new("S3"), Version: new("1")}, Configuration: map[string]string{"S3Bucket": "polling-sources", "S3ObjectKey": "source.txt"}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("Source")}}}}},
					{Name: new("Approve"), Actions: []cptypes.ActionDeclaration{{Name: new("Review"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategoryApproval, Owner: cptypes.ActionOwnerAws, Provider: new("Manual"), Version: new("1")}}}},
				},
			}
			if _, err := cp.CreatePipeline(ctx, &codepipeline.CreatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			drain := func(d time.Duration) {
				t.Helper()
				if err := manual.Advance(d); err != nil {
					t.Fatal(err)
				}
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			count := func(want int) {
				t.Helper()
				out, err := cp.ListPipelineExecutions(ctx, &codepipeline.ListPipelineExecutionsInput{PipelineName: new("polling")})
				if err != nil {
					t.Fatal(err)
				}
				if len(out.PipelineExecutionSummaries) != want {
					t.Fatalf("executions = %+v, want %d", out.PipelineExecutionSummaries, want)
				}
			}
			approve := func(revision string) string {
				t.Helper()
				for range 30 {
					drain(time.Second)
					state, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: new("polling")})
					if err != nil {
						t.Fatal(err)
					}
					action := state.StageStates[1].ActionStates[0].LatestExecution
					if action == nil || aws.ToString(action.Token) == "" {
						continue
					}
					id := aws.ToString(state.StageStates[1].LatestExecution.PipelineExecutionId)
					execution, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("polling"), PipelineExecutionId: new(id)})
					if err != nil {
						t.Fatal(err)
					}
					if len(execution.PipelineExecution.ArtifactRevisions) != 1 || aws.ToString(execution.PipelineExecution.ArtifactRevisions[0].RevisionId) != revision {
						t.Fatalf("wrong observed revision: %+v", execution.PipelineExecution)
					}
					if execution.PipelineExecution.Trigger == nil || string(execution.PipelineExecution.Trigger.TriggerType) != "PollForSourceChanges" || aws.ToString(execution.PipelineExecution.Trigger.TriggerDetail) != "S3" {
						t.Fatalf("wrong polling attribution: %+v", execution.PipelineExecution.Trigger)
					}
					if _, err := cp.PutApprovalResult(ctx, &codepipeline.PutApprovalResultInput{PipelineName: new("polling"), StageName: new("Approve"), ActionName: new("Review"), Token: action.Token, Result: &cptypes.ApprovalResult{Status: cptypes.ApprovalStatusApproved, Summary: new("Actual polled source")}}); err != nil {
						t.Fatal(err)
					}
					drain(time.Second)
					return id
				}
				t.Fatal("polled source did not reach approval")
				return ""
			}
			initialExecution := approve(firstRevision)
			drain(2 * time.Minute)
			count(1)
			put("unrelated.txt", "not this source")
			drain(2 * time.Minute)
			count(1)
			secondRevision := put("source.txt", "changed while controller stopped")
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			root = clients.iam(account, "test", "")
			if _, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("polling"), PolicyName: new("deny-observation"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::polling-sources/source.txt"}}`)}); err != nil {
				t.Fatal(err)
			}
			drain(2 * time.Minute)
			count(1)
			deniedState, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: new("polling")})
			if err != nil {
				t.Fatal(err)
			}
			sourceState := deniedState.StageStates[0]
			denied := sourceState.ActionStates[0]
			if denied.LatestExecution == nil || denied.LatestExecution.ErrorDetails == nil || aws.ToString(denied.LatestExecution.ErrorDetails.Code) != "PermissionError" || denied.CurrentRevision != nil || aws.ToString(denied.LatestExecution.ActionExecutionId) != "" {
				t.Fatalf("poll denial lost native error projection: %+v", denied)
			}
			if sourceState.LatestExecution == nil || aws.ToString(sourceState.LatestExecution.PipelineExecutionId) != initialExecution || sourceState.LatestExecution.Status != cptypes.StageExecutionStatusSucceeded {
				t.Fatalf("poll denial replaced actual source execution: %+v", sourceState.LatestExecution)
			}
			if _, err := root.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: new("polling"), PolicyName: new("deny-observation")}); err != nil {
				t.Fatal(err)
			}
			drain(2 * time.Minute)
			approve(secondRevision)
			count(2)
			sameBytesRevision := put("source.txt", "changed while controller stopped")
			if sameBytesRevision == secondRevision {
				t.Fatal("versioned upload did not create a new version")
			}
			drain(2 * time.Minute)
			approve(sameBytesRevision)
			count(3)
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			drain(2 * time.Minute)
			count(3)
			definition.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = "false"
			if _, err := cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			drain(2 * time.Minute)
			count(3)
			definition.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = "true"
			if _, err := cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			drain(2 * time.Minute)
			count(3)
			reenabledRevision := put("source.txt", "changed after polling reenabled")
			drain(2 * time.Minute)
			approve(reenabledRevision)
			count(4)
			definition.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = "false"
			if _, err := cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			put("source.txt", "polling disabled")
			drain(2 * time.Minute)
			count(4)
			if _, err := cp.DeletePipeline(ctx, &codepipeline.DeletePipelineInput{Name: new("polling")}); err != nil {
				t.Fatal(err)
			}
			drain(2 * time.Minute)
			_, err = cp.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: new("polling")})
			assertAPIError(t, err, "PipelineNotFoundException")
			definition.Stages[0].Actions[0].Configuration["PollForSourceChanges"] = "true"
			definition.Stages[0].Actions[0].Configuration["S3ObjectKey"] = "missing.txt"
			if _, err := cp.CreatePipeline(ctx, &codepipeline.CreatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			drain(2 * time.Minute)
			count(0)
			missing, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: new("polling")})
			if err != nil {
				t.Fatal(err)
			}
			failed := missing.StageStates[0].ActionStates[0].LatestExecution
			if failed == nil || failed.Status != cptypes.ActionExecutionStatusFailed || failed.ErrorDetails == nil || aws.ToString(failed.ErrorDetails.Code) != "ConfigurationError" || aws.ToString(failed.ActionExecutionId) != "" {
				t.Fatalf("missing source invented execution or lost polling error: %+v", failed)
			}
			recoveredRevision := put("missing.txt", "new incarnation source")
			drain(2 * time.Minute)
			approve(recoveredRevision)
			count(1)
		})
	}
}
