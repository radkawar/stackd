package stackd_test

import (
	"archive/zip"
	"bytes"
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

func TestCodePipelineVariablesRetainExecutionBindings(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account = "111122223333"
			manual := clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: manual})
			cp := clients.codepipeline("us-east-1", account, "test")
			root := clients.iam(account, "test", "")
			role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("variables"), AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("variables"), PolicyName: new("artifacts"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:*","kms:*"],"Resource":"*"}}`)}); err != nil {
				t.Fatal(err)
			}
			objects := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			for _, bucket := range []string{"variable-sources", "variable-artifacts"} {
				if _, err := objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: new(bucket)}); err != nil {
					t.Fatal(err)
				}
				if _, err := objects.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: new(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
					t.Fatal(err)
				}
			}
			var source bytes.Buffer
			archive := zip.NewWriter(&source)
			member, err := archive.Create("config.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := member.Write([]byte(`{"value":17}`)); err != nil {
				t.Fatal(err)
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := objects.PutObject(ctx, &s3.PutObjectInput{Bucket: new("variable-sources"), Key: new("source.zip"), Body: bytes.NewReader(source.Bytes())}); err != nil {
				t.Fatal(err)
			}
			definition := &cptypes.PipelineDeclaration{
				Name: new("variables"), RoleArn: role.Role.Arn, PipelineType: cptypes.PipelineTypeV2, ExecutionMode: cptypes.ExecutionModeQueued,
				ArtifactStore: &cptypes.ArtifactStore{Type: cptypes.ArtifactStoreTypeS3, Location: new("variable-artifacts")},
				Variables:     []cptypes.PipelineVariableDeclaration{{Name: new("Label"), DefaultValue: new("initial"), Description: new("Release label")}},
				Stages: []cptypes.StageDeclaration{
					{Name: new("Source"), Actions: []cptypes.ActionDeclaration{{Name: new("S3"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategorySource, Owner: cptypes.ActionOwnerAws, Provider: new("S3"), Version: new("1")}, Configuration: map[string]string{"S3Bucket": "variable-sources", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("SourceZip")}}}}},
					{Name: new("Approve"), Actions: []cptypes.ActionDeclaration{{Name: new("Review"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategoryApproval, Owner: cptypes.ActionOwnerAws, Provider: new("Manual"), Version: new("1")}, Configuration: map[string]string{"CustomData": "Release #{variables.Label}"}}}},
				},
			}
			if _, err := cp.CreatePipeline(ctx, &codepipeline.CreatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			drain := func() {
				t.Helper()
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			gate := func() (string, string) {
				t.Helper()
				for range 20 {
					drain()
					state, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: new("variables")})
					if err != nil {
						t.Fatal(err)
					}
					if len(state.StageStates) == 2 && len(state.StageStates[1].ActionStates) == 1 {
						action := state.StageStates[1].ActionStates[0].LatestExecution
						if action != nil && aws.ToString(action.Token) != "" {
							return aws.ToString(state.StageStates[1].LatestExecution.PipelineExecutionId), aws.ToString(action.Token)
						}
					}
					if err := manual.Advance(time.Second); err != nil {
						t.Fatal(err)
					}
				}
				t.Fatal("variable pipeline did not reach approval")
				return "", ""
			}
			binding := func(id, expected string) {
				t.Helper()
				execution, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("variables"), PipelineExecutionId: new(id)})
				if err != nil {
					t.Fatal(err)
				}
				values := execution.PipelineExecution.Variables
				if len(values) != 1 || aws.ToString(values[0].Name) != "Label" || aws.ToString(values[0].ResolvedValue) != expected {
					t.Fatalf("execution %s lost admitted variable: %+v", id, values)
				}
				history, err := cp.ListActionExecutions(ctx, &codepipeline.ListActionExecutionsInput{PipelineName: new("variables"), Filter: &cptypes.ActionExecutionFilter{LatestInPipelineExecution: &cptypes.LatestInPipelineExecutionFilter{PipelineExecutionId: new(id), StartTimeRange: cptypes.StartTimeRangeLatest}}})
				if err != nil {
					t.Fatal(err)
				}
				for _, action := range history.ActionExecutionDetails {
					if aws.ToString(action.ActionName) == "Review" {
						if action.Input.ResolvedConfiguration["CustomData"] != "Release "+expected {
							t.Fatalf("action resolved against a different execution binding: %+v", action.Input)
						}
						return
					}
				}
				t.Fatal("missing admitted review action")
			}
			decide := func(token string, status cptypes.ApprovalStatus) {
				t.Helper()
				if _, err := cp.PutApprovalResult(ctx, &codepipeline.PutApprovalResultInput{PipelineName: new("variables"), StageName: new("Approve"), ActionName: new("Review"), Token: new(token), Result: &cptypes.ApprovalResult{Status: status, Summary: new("Reviewed resolved variables")}}); err != nil {
					t.Fatal(err)
				}
				drain()
			}
			initial, token := gate()
			binding(initial, "initial")
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			binding(initial, "initial")
			decide(token, cptypes.ApprovalStatusRejected)
			if _, err := cp.RetryStageExecution(ctx, &codepipeline.RetryStageExecutionInput{PipelineName: new("variables"), PipelineExecutionId: new(initial), StageName: new("Approve"), RetryMode: cptypes.StageRetryModeFailedActions}); err != nil {
				t.Fatal(err)
			}
			retried, retryToken := gate()
			if retried != initial || retryToken == token {
				t.Fatal("stage retry changed execution or reused completed action")
			}
			binding(initial, "initial")
			decide(retryToken, cptypes.ApprovalStatusApproved)
			started, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("variables"), ClientRequestToken: new("variable-replay"), Variables: []cptypes.PipelineVariable{{Name: new("Label"), Value: new("override")}}})
			if err != nil {
				t.Fatal(err)
			}
			overridden, overrideToken := gate()
			if overridden != aws.ToString(started.PipelineExecutionId) {
				t.Fatal("override was attached to another execution")
			}
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			replayed, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("variables"), ClientRequestToken: new("variable-replay"), Variables: []cptypes.PipelineVariable{{Name: new("Label"), Value: new("changed")}}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(replayed.PipelineExecutionId) != overridden {
				t.Fatal("retained client token admitted another variable execution")
			}
			_, err = cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("variables"), ClientRequestToken: new("variable-replay"), Variables: []cptypes.PipelineVariable{
				{Name: new("Label"), Value: new("one")}, {Name: new("Label"), Value: new("two")},
			}})
			assertAPIError(t, err, "ValidationException")
			binding(overridden, "override")
			decide(overrideToken, cptypes.ApprovalStatusApproved)
			definition.Variables[0].DefaultValue = new("later")
			if _, err := cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			if _, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("variables")}); err != nil {
				t.Fatal(err)
			}
			later, laterToken := gate()
			binding(later, "later")
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			binding(initial, "initial")
			binding(overridden, "override")
			binding(later, "later")
			decide(laterToken, cptypes.ApprovalStatusApproved)
			definition.Variables = append(definition.Variables, cptypes.PipelineVariableDeclaration{Name: new("Required")})
			if _, err := cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			missing, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("variables")})
			if err != nil {
				t.Fatalf("missing required value should create a failed execution, not reject the API: %v", err)
			}
			failed, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("variables"), PipelineExecutionId: missing.PipelineExecutionId})
			if err != nil {
				t.Fatal(err)
			}
			if failed.PipelineExecution.Status != cptypes.PipelineExecutionStatusFailed || len(failed.PipelineExecution.Variables) != 0 {
				t.Fatalf("missing required binding exposed a runnable or partially bound execution: %+v", failed.PipelineExecution)
			}
			provided, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("variables"), Variables: []cptypes.PipelineVariable{
				{Name: new("Required"), Value: new("present")}, {Name: new("Undeclared"), Value: new("ignored")},
			}})
			if err != nil {
				t.Fatal(err)
			}
			providedID, providedToken := gate()
			if providedID != aws.ToString(provided.PipelineExecutionId) {
				t.Fatal("required value bound another execution")
			}
			resolved, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("variables"), PipelineExecutionId: provided.PipelineExecutionId})
			if err != nil {
				t.Fatal(err)
			}
			values := make(map[string]string)
			for _, value := range resolved.PipelineExecution.Variables {
				values[aws.ToString(value.Name)] = aws.ToString(value.ResolvedValue)
			}
			if len(values) != 2 || values["Required"] != "present" || values["Label"] != "later" {
				t.Fatalf("required/default resolution retained an undeclared override: %+v", values)
			}
			decide(providedToken, cptypes.ApprovalStatusApproved)
		})
	}
}
