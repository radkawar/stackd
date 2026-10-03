package stackd_test

import (
	"archive/zip"
	"bytes"
	"io"
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

func TestCodePipelineRollbackRetainsArtifactsVariablesAndAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account = "111122223333"
			manual := clock.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: manual})
			cp := clients.codepipeline("us-east-1", account, "test")
			root := clients.iam(account, "test", "")
			objects := func() *s3.Client {
				return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("rollback"), AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("rollback"), PolicyName: new("artifacts"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			for _, bucket := range []string{"rollback-source", "rollback-artifacts", "rollback-destination"} {
				if _, err := objects().CreateBucket(ctx, &s3.CreateBucketInput{Bucket: new(bucket)}); err != nil {
					t.Fatal(err)
				}
				if _, err := objects().PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: new(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
					t.Fatal(err)
				}
			}
			upload := func(value string) string {
				t.Helper()
				var archive bytes.Buffer
				writer := zip.NewWriter(&archive)
				member, err := writer.Create("value.txt")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(member, value); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				out, err := objects().PutObject(ctx, &s3.PutObjectInput{Bucket: new("rollback-source"), Key: new("source.zip"), Body: bytes.NewReader(archive.Bytes())})
				if err != nil {
					t.Fatal(err)
				}
				return aws.ToString(out.VersionId)
			}
			v1Revision := upload("v1")
			typeID := func(category cptypes.ActionCategory, provider string) *cptypes.ActionTypeId {
				return &cptypes.ActionTypeId{Category: category, Owner: cptypes.ActionOwnerAws, Provider: new(provider), Version: new("1")}
			}
			definition := &cptypes.PipelineDeclaration{Name: new("rollback"), RoleArn: role.Role.Arn, PipelineType: cptypes.PipelineTypeV2, ExecutionMode: cptypes.ExecutionModeSuperseded,
				Variables:     []cptypes.PipelineVariableDeclaration{{Name: new("Release"), DefaultValue: new("v1")}},
				ArtifactStore: &cptypes.ArtifactStore{Type: cptypes.ArtifactStoreTypeS3, Location: new("rollback-artifacts")},
				Stages: []cptypes.StageDeclaration{
					{Name: new("Source"), Actions: []cptypes.ActionDeclaration{{Name: new("Source"), ActionTypeId: typeID(cptypes.ActionCategorySource, "S3"), Configuration: map[string]string{"S3Bucket": "rollback-source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("SourceZip")}}, Namespace: new("Src")}}},
					{Name: new("Deploy"), Actions: []cptypes.ActionDeclaration{{Name: new("Deploy"), ActionTypeId: typeID(cptypes.ActionCategoryDeploy, "S3"), Configuration: map[string]string{"BucketName": "rollback-destination", "Extract": "true", "ObjectKey": "#{variables.Release}/#{Src.VersionId}"}, InputArtifacts: []cptypes.InputArtifact{{Name: new("SourceZip")}}}}},
				}}
			if _, err := cp.CreatePipeline(ctx, &codepipeline.CreatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			drain := func() {
				t.Helper()
				if err := manual.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			wait := func(id string, status cptypes.PipelineExecutionStatus) *cptypes.PipelineExecution {
				t.Helper()
				for range 40 {
					drain()
					out, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: definition.Name, PipelineExecutionId: new(id)})
					if err != nil {
						t.Fatal(err)
					}
					if out.PipelineExecution.Status == status {
						return out.PipelineExecution
					}
				}
				t.Fatalf("execution %s did not reach %s", id, status)
				return nil
			}
			history, err := cp.ListPipelineExecutions(ctx, &codepipeline.ListPipelineExecutionsInput{PipelineName: definition.Name})
			if err != nil || len(history.PipelineExecutionSummaries) != 1 {
				t.Fatalf("initial history: %+v %v", history, err)
			}
			v1 := aws.ToString(history.PipelineExecutionSummaries[0].PipelineExecutionId)
			wait(v1, cptypes.PipelineExecutionStatusSucceeded)
			v2Revision := upload("v2")
			started, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: definition.Name, Variables: []cptypes.PipelineVariable{{Name: new("Release"), Value: new("v2")}}})
			if err != nil {
				t.Fatal(err)
			}
			v2 := aws.ToString(started.PipelineExecutionId)
			wait(v2, cptypes.PipelineExecutionStatusSucceeded)
			// Remove original source bytes: only the retained artifact remains available.
			if _, err := objects().DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: new("rollback-source"), Key: new("source.zip"), VersionId: new(v1Revision)}); err != nil {
				t.Fatal(err)
			}
			if _, err := objects().DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: new("rollback-destination"), Key: new("v1/" + v1Revision + "/value.txt")}); err != nil {
				t.Fatal(err)
			}
			// A fresh controller must recover rollback lineage and use current role authority.
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			root = clients.iam(account, "test", "")
			if _, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("rollback"), PolicyName: new("deny"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:PutObject","Resource":"arn:aws:s3:::rollback-destination/*"}}`)}); err != nil {
				t.Fatal(err)
			}
			rolled, err := cp.RollbackStage(ctx, &codepipeline.RollbackStageInput{PipelineName: definition.Name, StageName: new("Deploy"), TargetPipelineExecutionId: new(v1)})
			if err != nil {
				t.Fatal(err)
			}
			rb := aws.ToString(rolled.PipelineExecutionId)
			if rb == v1 || rb == v2 {
				t.Fatal("rollback reused standard execution identity")
			}
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			root = clients.iam(account, "test", "")
			failed := wait(rb, cptypes.PipelineExecutionStatusFailed)
			if failed.ExecutionType != cptypes.ExecutionTypeRollback || failed.RollbackMetadata == nil || aws.ToString(failed.RollbackMetadata.RollbackTargetPipelineExecutionId) != v1 || failed.Trigger.TriggerType != cptypes.TriggerTypeManualRollback {
				t.Fatalf("rollback lineage: %+v", failed)
			}
			if len(failed.ArtifactRevisions) != 1 || aws.ToString(failed.ArtifactRevisions[0].RevisionId) != v1Revision || len(failed.Variables) != 1 || aws.ToString(failed.Variables[0].ResolvedValue) != "v1" {
				t.Fatalf("rollback rebound inputs: %+v", failed)
			}
			if _, err := root.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: new("rollback"), PolicyName: new("deny")}); err != nil {
				t.Fatal(err)
			}
			if _, err := cp.RetryStageExecution(ctx, &codepipeline.RetryStageExecutionInput{PipelineName: definition.Name, StageName: new("Deploy"), PipelineExecutionId: new(rb), RetryMode: cptypes.StageRetryModeFailedActions}); err != nil {
				t.Fatal(err)
			}
			wait(rb, cptypes.PipelineExecutionStatusSucceeded)
			out, err := objects().GetObject(ctx, &s3.GetObjectInput{Bucket: new("rollback-destination"), Key: new("v1/" + v1Revision + "/value.txt")})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(out.Body)
			out.Body.Close()
			if err != nil || string(body) != "v1" {
				t.Fatalf("rollback bytes %q: %v", body, err)
			}
			actions, err := cp.ListActionExecutions(ctx, &codepipeline.ListActionExecutionsInput{PipelineName: definition.Name, Filter: &cptypes.ActionExecutionFilter{PipelineExecutionId: new(rb)}})
			if err != nil {
				t.Fatal(err)
			}
			if len(actions.ActionExecutionDetails) != 2 {
				t.Fatalf("rollback retry history: %+v", actions)
			}
			for _, action := range actions.ActionExecutionDetails {
				if aws.ToString(action.StageName) != "Deploy" {
					t.Fatal("rollback re-executed source")
				}
			}
			for _, tc := range []struct{ stage, id, code string }{{"Missing", v1, "StageNotFoundException"}, {"Deploy", "00000000-0000-0000-0000-000000000000", "PipelineExecutionNotFoundException"}, {"Deploy", rb, "UnableToRollbackStageException"}} {
				_, err := cp.RollbackStage(ctx, &codepipeline.RollbackStageInput{PipelineName: definition.Name, StageName: new(tc.stage), TargetPipelineExecutionId: new(tc.id)})
				assertAPIError(t, err, tc.code)
			}
			foreign := clients.codepipeline("us-west-2", account, "test")
			_, err = foreign.RollbackStage(ctx, &codepipeline.RollbackStageInput{PipelineName: definition.Name, StageName: new("Deploy"), TargetPipelineExecutionId: new(v1)})
			assertAPIError(t, err, "PipelineNotFoundException")
			// Native's API accepts a source-stage rollback despite the guide: its
			// execution lineage stays on v1, but the actual source action reads v2.
			sourceRollback, err := cp.RollbackStage(ctx, &codepipeline.RollbackStageInput{PipelineName: definition.Name, StageName: new("Source"), TargetPipelineExecutionId: new(v1)})
			if err != nil {
				t.Fatal(err)
			}
			sourceID := aws.ToString(sourceRollback.PipelineExecutionId)
			sourceRun := wait(sourceID, cptypes.PipelineExecutionStatusSucceeded)
			sourceActions, err := cp.ListActionExecutions(ctx, &codepipeline.ListActionExecutionsInput{PipelineName: definition.Name, Filter: &cptypes.ActionExecutionFilter{PipelineExecutionId: new(sourceID)}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(sourceRun.ArtifactRevisions[0].RevisionId) != v1Revision || len(sourceActions.ActionExecutionDetails) != 1 || sourceActions.ActionExecutionDetails[0].Output.OutputVariables["VersionId"] != v2Revision {
				t.Fatalf("source rollback revision split: %+v %+v", sourceRun, sourceActions)
			}
			if _, err := cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			_, err = cp.RollbackStage(ctx, &codepipeline.RollbackStageInput{PipelineName: definition.Name, StageName: new("Deploy"), TargetPipelineExecutionId: new(v1)})
			assertAPIError(t, err, "PipelineExecutionOutdatedException")
		})
	}
}
