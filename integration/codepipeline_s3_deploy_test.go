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

func TestCodePipelineS3DeploymentRetainsArtifactAndCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account = "111122223333"
			manual := clock.NewManual(time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: manual})
			cp := clients.codepipeline("us-east-1", account, "test")
			root := clients.iam(account, "test", "")
			objects := func() *s3.Client {
				return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("s3-deploy"), AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("s3-deploy"), PolicyName: new("artifacts"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:*","kms:*"],"Resource":"*"}}`)}); err != nil {
				t.Fatal(err)
			}
			for _, bucket := range []string{"deploy-source", "deploy-artifacts", "deploy-archive", "deploy-website"} {
				if _, err := objects().CreateBucket(ctx, &s3.CreateBucketInput{Bucket: new(bucket)}); err != nil {
					t.Fatal(err)
				}
				if _, err := objects().PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: new(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
					t.Fatal(err)
				}
			}
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			for _, entry := range []struct{ name, body string }{{"index.html", "<h1>retained deployment</h1>"}, {"assets/config.json", `{"revision":1}`}} {
				file, err := writer.Create(entry.name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(file, entry.body); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			putSource := func(body []byte) string {
				t.Helper()
				out, err := objects().PutObject(ctx, &s3.PutObjectInput{Bucket: new("deploy-source"), Key: new("source.zip"), Body: bytes.NewReader(body)})
				if err != nil {
					t.Fatal(err)
				}
				return aws.ToString(out.VersionId)
			}
			revision := putSource(archive.Bytes())
			typeID := func(category cptypes.ActionCategory, provider string) *cptypes.ActionTypeId {
				return &cptypes.ActionTypeId{Category: category, Owner: cptypes.ActionOwnerAws, Provider: new(provider), Version: new("1")}
			}
			definition := &cptypes.PipelineDeclaration{
				Name: new("s3-deploy"), RoleArn: role.Role.Arn, PipelineType: cptypes.PipelineTypeV2, ExecutionMode: cptypes.ExecutionModeQueued,
				ArtifactStore: &cptypes.ArtifactStore{Type: cptypes.ArtifactStoreTypeS3, Location: new("deploy-artifacts")},
				Stages: []cptypes.StageDeclaration{
					{Name: new("Source"), Actions: []cptypes.ActionDeclaration{{Name: new("Source"), ActionTypeId: typeID(cptypes.ActionCategorySource, "S3"), Configuration: map[string]string{"S3Bucket": "deploy-source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("Source")}}}}},
					{Name: new("Approve"), Actions: []cptypes.ActionDeclaration{{Name: new("Review"), ActionTypeId: typeID(cptypes.ActionCategoryApproval, "Manual")}}},
					{Name: new("Deploy"), Actions: []cptypes.ActionDeclaration{
						{Name: new("Archive"), ActionTypeId: typeID(cptypes.ActionCategoryDeploy, "S3"), Configuration: map[string]string{"BucketName": "deploy-archive", "Extract": "false", "ObjectKey": "release.zip"}, InputArtifacts: []cptypes.InputArtifact{{Name: new("Source")}}},
						{Name: new("Website"), ActionTypeId: typeID(cptypes.ActionCategoryDeploy, "S3"), Configuration: map[string]string{"BucketName": "deploy-website", "Extract": "true", "CacheControl": "public, max-age=60", "CannedACL": "bucket-owner-full-control"}, InputArtifacts: []cptypes.InputArtifact{{Name: new("Source")}}},
					}},
				},
			}
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
			waitApproval := func() (string, string) {
				t.Helper()
				for range 30 {
					drain()
					state, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: definition.Name})
					if err != nil {
						t.Fatal(err)
					}
					if action := state.StageStates[1].ActionStates[0].LatestExecution; action != nil && aws.ToString(action.Token) != "" {
						return aws.ToString(state.StageStates[1].LatestExecution.PipelineExecutionId), aws.ToString(action.Token)
					}
				}
				t.Fatal("source never reached approval")
				return "", ""
			}
			executionID, token := waitApproval()
			putSource([]byte("replacement must not reach the admitted deployment"))
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			root = clients.iam(account, "test", "")
			if _, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("s3-deploy"), PolicyName: new("deny-deploy"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:PutObject","Resource":"arn:aws:s3:::deploy-website/*"}}`)}); err != nil {
				t.Fatal(err)
			}
			if _, err := cp.PutApprovalResult(ctx, &codepipeline.PutApprovalResultInput{PipelineName: definition.Name, StageName: new("Approve"), ActionName: new("Review"), Token: new(token), Result: &cptypes.ApprovalResult{Status: cptypes.ApprovalStatusApproved, Summary: new("Deploy retained artifact")}}); err != nil {
				t.Fatal(err)
			}
			waitStatus := func(want cptypes.PipelineExecutionStatus) {
				t.Helper()
				for range 30 {
					drain()
					out, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: definition.Name, PipelineExecutionId: new(executionID)})
					if err != nil {
						t.Fatal(err)
					}
					if out.PipelineExecution.Status == want {
						if len(out.PipelineExecution.ArtifactRevisions) != 1 || aws.ToString(out.PipelineExecution.ArtifactRevisions[0].RevisionId) != revision {
							t.Fatalf("deployment source changed: %+v", out.PipelineExecution)
						}
						return
					}
				}
				t.Fatalf("execution %s did not reach %s", executionID, want)
			}
			waitStatus(cptypes.PipelineExecutionStatusFailed)
			_, err = objects().GetObject(ctx, &s3.GetObjectInput{Bucket: new("deploy-website"), Key: new("index.html")})
			assertAPIError(t, err, "NoSuchKey")
			assertObject := func(bucket, key string, expected []byte, cache string) {
				t.Helper()
				out, err := objects().GetObject(ctx, &s3.GetObjectInput{Bucket: new(bucket), Key: new(key)})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(out.Body)
				out.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(body, expected) || aws.ToString(out.CacheControl) != cache {
					t.Fatalf("deployed %s/%s body=%q cache=%q", bucket, key, body, aws.ToString(out.CacheControl))
				}
			}
			assertObject("deploy-archive", "release.zip", archive.Bytes(), "")
			if _, err := root.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: new("s3-deploy"), PolicyName: new("deny-deploy")}); err != nil {
				t.Fatal(err)
			}
			if _, err := cp.RetryStageExecution(ctx, &codepipeline.RetryStageExecutionInput{PipelineName: definition.Name, StageName: new("Deploy"), PipelineExecutionId: new(executionID), RetryMode: cptypes.StageRetryModeFailedActions}); err != nil {
				t.Fatal(err)
			}
			waitStatus(cptypes.PipelineExecutionStatusSucceeded)
			clients = reopen()
			assertObject("deploy-website", "index.html", []byte("<h1>retained deployment</h1>"), "public, max-age=60")
			assertObject("deploy-website", "assets/config.json", []byte(`{"revision":1}`), "public, max-age=60")
			cp = clients.codepipeline("us-east-1", account, "test")
			var partial bytes.Buffer
			writer = zip.NewWriter(&partial)
			for _, entry := range []struct{ name, body string }{{"/leading.txt", "committed before invalid member"}, {"nested/../relative.txt", "must not deploy"}} {
				file, err := writer.Create(entry.name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(file, entry.body); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			revision = putSource(partial.Bytes())
			started, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: definition.Name})
			if err != nil {
				t.Fatal(err)
			}
			executionID, token = waitApproval()
			if executionID != aws.ToString(started.PipelineExecutionId) {
				t.Fatal("approval bound to wrong execution")
			}
			if _, err := cp.PutApprovalResult(ctx, &codepipeline.PutApprovalResultInput{PipelineName: definition.Name, StageName: new("Approve"), ActionName: new("Review"), Token: new(token), Result: &cptypes.ApprovalResult{Status: cptypes.ApprovalStatusApproved, Summary: new("Check partial deployment")}}); err != nil {
				t.Fatal(err)
			}
			waitStatus(cptypes.PipelineExecutionStatusFailed)
			assertObject("deploy-website", "/leading.txt", []byte("committed before invalid member"), "public, max-age=60")
			_, err = objects().GetObject(ctx, &s3.GetObjectInput{Bucket: new("deploy-website"), Key: new("nested/../relative.txt")})
			assertAPIError(t, err, "NoSuchKey")
			state, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: definition.Name})
			if err != nil {
				t.Fatal(err)
			}
			failed := state.StageStates[2].ActionStates[1].LatestExecution
			if failed == nil || failed.ErrorDetails == nil || aws.ToString(failed.ErrorDetails.Code) != "ConfigurationError" {
				t.Fatalf("invalid archive member lost modeled action failure: %+v", failed)
			}
		})
	}
}
