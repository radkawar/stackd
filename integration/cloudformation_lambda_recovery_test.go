package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd"
	"stackd/clock"
)

// Exact absent-owner recovery must join the current read transaction for IAM.
// Separate service repositories miss the shared SQLite lock boundary exercised
// by the ordinary public controller here.
func TestCloudFormationRejectedLambdaRecoveryWithSharedIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			role, err := c.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName:                 aws.String("rejected-lambda-role"),
				AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{"Resources": map[string]any{
				"Function": map[string]any{"Type": "AWS::Lambda::Function", "Properties": map[string]any{
					"FunctionName": "rejected-lambda", "Runtime": "python3.12", "Handler": "index.handler", "Role": aws.ToString(role.Role.Arn),
					"Code":        map[string]any{"ZipFile": "def handler(event, context): return event"},
					"Environment": map[string]any{"Variables": map[string]any{"AWS_REGION": "reserved"}},
				}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			client := cloudFormationClient(c, "us-east-1", "test", "test")
			created, err := client.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("rejected-lambda-stack"), TemplateBody: aws.String(string(body))})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, client, aws.ToString(created.StackId), cfntypes.StackStatusRollbackComplete)
			events, err := client.DescribeStackEvents(t.Context(), &cloudformation.DescribeStackEventsInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			failed := false
			for _, event := range events.StackEvents {
				if aws.ToString(event.LogicalResourceId) == "Function" && event.ResourceStatus == cfntypes.ResourceStatusCreateFailed {
					failed = true
				}
				if aws.ToString(event.LogicalResourceId) == "Function" && event.ResourceStatus == cfntypes.ResourceStatusDeleteComplete {
					t.Fatal("rejected creation fabricated a physical deletion")
				}
			}
			if !failed {
				t.Fatalf("rejected function lost its failure event: %+v", events.StackEvents)
			}
			lambda := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			_, err = lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String("rejected-lambda")})
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}
