package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	cptypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

const pipelineLambdaHandler = `import boto3,io,json,os,zipfile
from botocore.config import Config
from botocore.exceptions import ClientError

def handler(event,context):
    job=event['CodePipeline.job']
    data=job['data']
    endpoint=os.environ['AWS_ENDPOINT_URL']
    config=Config(retries={'total_max_attempts':1},s3={'addressing_style':'path'})
    if not data.get('continuationToken'):
        queue=boto3.client('sqs',endpoint_url=endpoint,config=config)
        queue.send_message(QueueUrl=os.environ['QUEUE'],MessageBody=json.dumps({'jobId':job['id'],'artifact':data['inputArtifacts'][0]['location']['s3Location']}))
        return {'ordinary_return_does_not_complete_job':True}
    credential=data['artifactCredentials']
    objects=boto3.client('s3',endpoint_url=endpoint,config=config,aws_access_key_id=credential['accessKeyId'],aws_secret_access_key=credential['secretAccessKey'],aws_session_token=credential['sessionToken'])
    location=data['inputArtifacts'][0]['location']['s3Location']
    with objects.get_object(Bucket=location['bucketName'],Key=location['objectKey'])['Body'] as stream:
        source=stream.read()
    try:
        unrelated=objects.get_object(Bucket=location['bucketName'],Key='unrelated.txt')
        unrelated['Body'].close()
        raise AssertionError('artifact credential escaped its input/output scope')
    except ClientError as error:
        assert error.response['Error']['Code']=='AccessDenied',error.response
    with zipfile.ZipFile(io.BytesIO(source)) as archive:
        document=json.loads(archive.read('config.json'))
    document['value']+=1
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w') as archive:
        archive.writestr('config.json',json.dumps(document))
    location=data['outputArtifacts'][0]['location']['s3Location']
    request={'Bucket':location['bucketName'],'Key':location['objectKey'],'Body':output.getvalue()}
    if data.get('encryptionKey'):
        request.update(ServerSideEncryption='aws:kms',SSEKMSKeyId=data['encryptionKey']['id'])
    objects.put_object(**request)
    pipeline=boto3.client('codepipeline',endpoint_url=endpoint,config=config)
    pipeline.put_job_success_result(jobId=job['id'],outputVariables={'Prefix':'published'},executionDetails={'externalExecutionId':'not-the-function-name','summary':'not-a-native-Lambda-summary'})
`

func TestCodePipelineLambdaDockerRetainsCallbacksAndArtifacts(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise real Lambda containers")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account = "111122223333"
			manual := clock.NewManual(time.Now().UTC())
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: manual}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return newLambdaDockerStack(t, config, nil)
			})
			root := clients.iam(account, "test", "")
			cp := clients.codepipeline("us-east-1", account, "test")
			objects := func() *s3.Client {
				return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			queues := func() *sqs.Client {
				return sqs.New(sqs.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			queue, err := queues().CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: new("pipeline-lambda-jobs")})
			if err != nil {
				t.Fatal(err)
			}
			role := func(name, principal, policy string) string {
				t.Helper()
				out, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new(name), AssumeRolePolicyDocument: new(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":%q},"Action":"sts:AssumeRole"}}`, principal))})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new(name), PolicyName: new("execution"), PolicyDocument: new(policy)}); err != nil {
					t.Fatal(err)
				}
				return aws.ToString(out.Role.Arn)
			}
			pipelineRole := role("pipeline-lambda", "codepipeline.amazonaws.com", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:*","kms:*","lambda:InvokeFunction"],"Resource":"*"}}`)
			functionRole := role("pipeline-function", "lambda.amazonaws.com", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["sqs:SendMessage","codepipeline:PutJobSuccessResult","codepipeline:PutJobFailureResult"],"Resource":"*"}}`)
			for _, bucket := range []string{"invoke-source", "invoke-artifacts", "invoke-deployment"} {
				if _, err := objects().CreateBucket(ctx, &s3.CreateBucketInput{Bucket: new(bucket)}); err != nil {
					t.Fatal(err)
				}
				if _, err := objects().PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: new(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := objects().PutObject(ctx, &s3.PutObjectInput{Bucket: new("invoke-artifacts"), Key: new("unrelated.txt"), Body: strings.NewReader("outside artifact credential scope")}); err != nil {
				t.Fatal(err)
			}
			var source bytes.Buffer
			archive := zip.NewWriter(&source)
			member, err := archive.Create("config.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(member, `{"value":17}`); err != nil {
				t.Fatal(err)
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := objects().PutObject(ctx, &s3.PutObjectInput{Bucket: new("invoke-source"), Key: new("source.zip"), Body: bytes.NewReader(source.Bytes())}); err != nil {
				t.Fatal(err)
			}
			function := lambda.New(lambda.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			if _, err := function.CreateFunction(ctx, &lambda.CreateFunctionInput{FunctionName: new("pipeline-transform"), Role: new(functionRole), Runtime: lambdatypes.RuntimePython312, Handler: new("handler.handler"), Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"handler.py": pipelineLambdaHandler})}, Timeout: new(int32(30)), Environment: &lambdatypes.Environment{Variables: map[string]string{"QUEUE": strings.Replace(aws.ToString(queue.QueueUrl), "127.0.0.1", "host.docker.internal", 1)}}}); err != nil {
				t.Fatal(err)
			}
			if err := lambda.NewFunctionActiveWaiter(function, fastLambdaActiveWaiter).Wait(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: new("pipeline-transform")}, time.Minute); err != nil {
				t.Fatal(err)
			}
			actionType := func(category cptypes.ActionCategory, provider string) *cptypes.ActionTypeId {
				return &cptypes.ActionTypeId{Category: category, Owner: cptypes.ActionOwnerAws, Provider: new(provider), Version: new("1")}
			}
			definition := &cptypes.PipelineDeclaration{Name: new("invoke"), RoleArn: new(pipelineRole), PipelineType: cptypes.PipelineTypeV2, ExecutionMode: cptypes.ExecutionModeQueued, ArtifactStore: &cptypes.ArtifactStore{Type: cptypes.ArtifactStoreTypeS3, Location: new("invoke-artifacts")}, Stages: []cptypes.StageDeclaration{
				{Name: new("Source"), Actions: []cptypes.ActionDeclaration{{Name: new("Source"), ActionTypeId: actionType(cptypes.ActionCategorySource, "S3"), Configuration: map[string]string{"S3Bucket": "invoke-source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("Source")}}}}},
				{Name: new("Invoke"), Actions: []cptypes.ActionDeclaration{{Name: new("Transform"), ActionTypeId: actionType(cptypes.ActionCategoryInvoke, "Lambda"), Configuration: map[string]string{"FunctionName": "pipeline-transform"}, Namespace: new("LambdaResult"), InputArtifacts: []cptypes.InputArtifact{{Name: new("Source")}}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("Produced")}}}}},
				{Name: new("Deploy"), Actions: []cptypes.ActionDeclaration{{Name: new("Deploy"), ActionTypeId: actionType(cptypes.ActionCategoryDeploy, "S3"), Configuration: map[string]string{"BucketName": "invoke-deployment", "Extract": "true", "ObjectKey": "#{LambdaResult.Prefix}"}, InputArtifacts: []cptypes.InputArtifact{{Name: new("Produced")}}}}},
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
			var job struct {
				JobID    string `json:"jobId"`
				Artifact struct {
					BucketName string `json:"bucketName"`
					ObjectKey  string `json:"objectKey"`
				} `json:"artifact"`
			}
			for range 120 {
				drain()
				messages, err := queues().ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
				if err != nil {
					t.Fatal(err)
				}
				if len(messages.Messages) == 0 {
					// Long polling also uses manual service time; advance it
					// between requests while the real runtime runs independently.
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if err := json.Unmarshal([]byte(aws.ToString(messages.Messages[0].Body)), &job); err != nil {
					t.Fatal(err)
				}
				break
			}
			if job.JobID == "" {
				t.Fatal("real function did not receive the pipeline job")
			}
			state, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: definition.Name})
			if err != nil {
				t.Fatal(err)
			}
			executionID := state.StageStates[1].LatestExecution.PipelineExecutionId
			if state.StageStates[1].ActionStates[0].LatestExecution.Status != cptypes.ActionExecutionStatusInProgress {
				t.Fatal("normal Lambda return completed a job without callback")
			}
			if _, err := objects().PutObject(ctx, &s3.PutObjectInput{Bucket: new("invoke-source"), Key: new("source.zip"), Body: strings.NewReader("replacement source must not reach continuation")}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			if _, err := cp.PutJobSuccessResult(ctx, &codepipeline.PutJobSuccessResultInput{JobId: new(job.JobID), ContinuationToken: new("continue-after-restart")}); err != nil {
				t.Fatal(err)
			}
			succeeded := false
			for range 60 {
				drain()
				out, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: definition.Name, PipelineExecutionId: executionID})
				if err != nil {
					t.Fatal(err)
				}
				if out.PipelineExecution.Status == cptypes.PipelineExecutionStatusFailed {
					t.Fatalf("real Lambda pipeline failed: %+v", out.PipelineExecution)
				}
				if out.PipelineExecution.Status == cptypes.PipelineExecutionStatusSucceeded {
					succeeded = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !succeeded {
				t.Fatal("Lambda callback did not complete pipeline deployment")
			}
			deployed, err := objects().GetObject(ctx, &s3.GetObjectInput{Bucket: new("invoke-deployment"), Key: new("published/config.json")})
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Value int `json:"value"`
			}
			decodeErr := json.NewDecoder(deployed.Body).Decode(&result)
			deployed.Body.Close()
			if decodeErr != nil || result.Value != 18 {
				t.Fatalf("Lambda-produced deployment = %+v, %v", result, decodeErr)
			}
			_, err = cp.PutJobSuccessResult(ctx, &codepipeline.PutJobSuccessResultInput{JobId: new(job.JobID)})
			assertAPIError(t, err, "InvalidJobStateException")
			history, err := cp.ListActionExecutions(ctx, &codepipeline.ListActionExecutionsInput{PipelineName: definition.Name, Filter: &cptypes.ActionExecutionFilter{PipelineExecutionId: executionID}})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, action := range history.ActionExecutionDetails {
				if aws.ToString(action.ActionName) != "Transform" {
					continue
				}
				found = true
				if action.Status != cptypes.ActionExecutionStatusSucceeded || aws.ToString(action.Output.ExecutionResult.ExternalExecutionId) != "pipeline-transform" || aws.ToString(action.Output.ExecutionResult.ExternalExecutionSummary) != "" || action.Output.OutputVariables["Prefix"] != "published" {
					t.Fatalf("Lambda callback history = %+v", action)
				}
			}
			if !found {
				t.Fatal("Lambda action missing from retained history")
			}
		})
	}
}
