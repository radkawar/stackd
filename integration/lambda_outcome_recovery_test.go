package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/storage"
	lambdastorage "stackd/storage/lambda"
)

// Pause only outcome scheduling so real customer execution can commit its result
// before the stack stops. Reopening uses the ordinary repository and workers.
type lambdaOutcomePausedRepository struct{ lambdastorage.Repository }
type lambdaOutcomePausedReader struct{ lambdastorage.Reader }

func (r lambdaOutcomePausedRepository) View(ctx context.Context, read func(lambdastorage.Reader) error) error {
	return r.Repository.View(ctx, func(reader lambdastorage.Reader) error {
		return read(lambdaOutcomePausedReader{reader})
	})
}

func (lambdaOutcomePausedReader) NextOutcomeDelivery() (lambdastorage.InvocationJob, bool, error) {
	return lambdastorage.InvocationJob{}, false, nil
}

func TestLambdaOutcomeCompletedRecovery(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[lambdaEventsFixture](t, "event_invocation")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 14, 15, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "lambda-outcomes.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			repository := backends.Lambda
			backends.Lambda = lambdaOutcomePausedRepository{repository}
			c := lambdaEventsConnect(t, backends, source)
			lambdaEventsProvision(t, c, fixture)
			legacy, err := c.queues.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("retained-lambda-dead-letter")})
			if err != nil {
				t.Fatal(err)
			}
			var arns []string
			for _, url := range []*string{c.outputURL, c.dlqURL, legacy.QueueUrl} {
				attributes, err := c.queues.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: url, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
				if err != nil {
					t.Fatal(err)
				}
				arns = append(arns, attributes.Attributes["QueueArn"])
			}
			resources, err := json.Marshal(arns)
			if err != nil {
				t.Fatal(err)
			}
			role := lambdaEventsInput[iam.CreateRoleInput](t, fixture, "create_execution_role")
			_, err = (cloudClients{c.server}).iam("test", "test", "").PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role.RoleName, PolicyName: aws.String("outcome-recovery"), PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":%s}]}`, resources))})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.lambda.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: c.functionName, DeadLetterConfig: &lambdatypes.DeadLetterConfig{TargetArn: aws.String(arns[2])}})
			if err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: c.functionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			_, err = c.lambda.PutFunctionEventInvokeConfig(ctx, &awslambda.PutFunctionEventInvokeConfigInput{FunctionName: c.functionName, MaximumRetryAttempts: aws.Int32(0), DestinationConfig: &lambdatypes.DestinationConfig{OnFailure: &lambdatypes.OnFailure{Destination: aws.String(arns[1])}}})
			if err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 2*time.Minute)
			requestID, payload := lambdaEventsInvoke(t, c, fixture, "async_function_error_default_retry")
			lambdaEventsRecord(t, c.functionARN, lambdaEventsReceive(t, c, c.outputURL, 1)[0], requestID, payload)
			deadline := time.Now().Add(time.Minute)
			for {
				var completed bool
				if err := repository.View(ctx, func(reader lambdastorage.Reader) error {
					var err error
					_, completed, err = reader.NextOutcomeDelivery()
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if completed {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("real runtime did not commit its terminal delivery work")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if _, err := c.lambda.DeleteFunction(ctx, &awslambda.DeleteFunctionInput{FunctionName: c.functionName}); err != nil {
				t.Fatal(err)
			}
			if err := c.cloud.Close(); err != nil {
				t.Fatal(err)
			}
			c.server.Close()
			if backend == "sqlite" {
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
			} else {
				backends.Lambda = repository
			}
			previous := c
			c = lambdaEventsConnect(t, backends, source)
			c.functionName, c.functionARN = previous.functionName, previous.functionARN
			_, err = c.lambda.GetFunctionConfiguration(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: c.functionName})
			assertAPIError(t, err, "ResourceNotFoundException")
			destination := lambdaEventsReceive(t, c, previous.dlqURL, 1)[0]
			var record struct {
				RequestContext struct {
					RequestID   string `json:"requestId"`
					FunctionARN string `json:"functionArn"`
					Condition   string `json:"condition"`
					Count       int    `json:"approximateInvokeCount"`
				} `json:"requestContext"`
				RequestPayload  map[string]any `json:"requestPayload"`
				ResponseContext struct {
					StatusCode    int    `json:"statusCode"`
					FunctionError string `json:"functionError"`
				} `json:"responseContext"`
			}
			if err := json.Unmarshal([]byte(aws.ToString(destination.Body)), &record); err != nil {
				t.Fatal(err)
			}
			if record.RequestContext.RequestID != requestID || record.RequestContext.FunctionARN != c.functionARN+":$LATEST" || record.RequestContext.Condition != "RetriesExhausted" || record.RequestContext.Count != 1 || !reflect.DeepEqual(record.RequestPayload, payload) || record.ResponseContext.StatusCode != 200 || record.ResponseContext.FunctionError != "Unhandled" {
				t.Fatalf("retained destination lost its completed invocation: %s", aws.ToString(destination.Body))
			}
			deadLetter := lambdaEventsReceive(t, c, legacy.QueueUrl, 1)[0]
			var nativeInput struct{ Payload string }
			if err := json.Unmarshal(fixture.observation(t, "async_function_error_default_retry").Input, &nativeInput); err != nil {
				t.Fatal(err)
			}
			if aws.ToString(deadLetter.Body) != nativeInput.Payload || aws.ToString(deadLetter.MessageAttributes["RequestID"].StringValue) != requestID || aws.ToString(deadLetter.MessageAttributes["ErrorCode"].StringValue) != "200" {
				t.Fatalf("retained legacy delivery lost its original bytes or invocation: %+v", deadLetter)
			}
			lambdaEventsQuiet(t, c, previous.outputURL, previous.dlqURL, legacy.QueueUrl)
		})
	}
}
