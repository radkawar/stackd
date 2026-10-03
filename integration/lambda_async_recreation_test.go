package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/storage"
)

// Native async_deletion_analysis.json records the same accepted request running
// replacement $LATEST and reaching the old route before a new-route control.
// This regression checks that ordering, not an unmeasured permanent route freeze.
func TestLambdaAsyncSameNameRecreationNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "async-recreation.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			r := lambdaConcurrencyProvision(t, backends, source)
			r.command(t, "reserve_one")
			published, err := r.c.lambda.PublishVersion(ctx, &awslambda.PublishVersionInput{FunctionName: r.name})
			if err != nil {
				t.Fatal(err)
			}
			queueARN := func(url *string) *string {
				t.Helper()
				out, err := r.c.queues.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: url,
					AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
				if err != nil {
					t.Fatal(err)
				}
				return aws.String(out.Attributes["QueueArn"])
			}
			oldARN, newARN := queueARN(r.destination), queueARN(r.dlq)
			configure := func(destination *string) {
				t.Helper()
				_, err := r.c.lambda.PutFunctionEventInvokeConfig(ctx, &awslambda.PutFunctionEventInvokeConfigInput{
					FunctionName: r.name, MaximumRetryAttempts: aws.Int32(1), MaximumEventAgeInSeconds: aws.Int32(180),
					DestinationConfig: &lambdatypes.DestinationConfig{OnSuccess: &lambdatypes.OnSuccess{Destination: destination}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			configure(oldARN)
			advanceClock(t, source, 2*time.Minute)
			invoke := func(label string) string {
				t.Helper()
				payload, err := json.Marshal(map[string]any{"label": label})
				if err != nil {
					t.Fatal(err)
				}
				out, err := r.c.lambda.Invoke(ctx, &awslambda.InvokeInput{FunctionName: r.name,
					InvocationType: lambdatypes.InvocationTypeEvent, Payload: payload})
				if err != nil || out.StatusCode != 202 {
					t.Fatalf("accepted event: %+v %v", out, err)
				}
				id, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
				if !ok || id == "" {
					t.Fatal("accepted request ID absent")
				}
				return id
			}
			oldControl := invoke("old-route-control")
			lambdaEventsReceive(t, r.c, r.audit, 2)
			control := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.destination, 1)[0].Body)
			if control["requestContext"].(map[string]any)["requestId"] != oldControl {
				t.Fatal("old route was not positively established")
			}
			finished := make(chan lambdaConcurrencyResult, 1)
			go func() {
				out, err := r.c.lambda.Invoke(ctx, r.input(t, "held-runtime"))
				finished <- lambdaConcurrencyResult{out: out, err: err}
			}()
			r.auditRecord(t, "held-runtime", "entered")
			r.invoke(t, "rejected-at-one")
			acceptedID := invoke("accepted-before-delete")
			lambdaEventsAwaitRetry(t, r.c, source.Now().Add(time.Second), acceptedID)
			if _, err := r.c.lambda.DeleteFunction(ctx, &awslambda.DeleteFunctionInput{FunctionName: r.name}); err != nil {
				t.Fatal(err)
			}
			_, err = r.c.lambda.GetFunction(ctx, &awslambda.GetFunctionInput{FunctionName: r.name})
			assertAPIError(t, err, "ResourceNotFoundException")
			input := *r.functions[aws.ToString(r.name)]
			input.Publish = true
			input.Code = &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"handler.py": `import boto3,json,os
sqs=boto3.client("sqs")
def handler(event,context):
    marker={"event":event,"deployment":"replacement","runtime_request_id":context.aws_request_id,"invoked_function_arn":context.invoked_function_arn,"function_version":context.function_version}
    sqs.send_message(QueueUrl=os.environ["AUDIT_QUEUE_URL"],MessageBody=json.dumps(marker))
    return marker
`})}
			replacement, err := r.c.lambda.CreateFunction(ctx, &input)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(replacement.Version) == aws.ToString(published.Version) {
				t.Fatal("same-name recreation reused the deleted publication")
			}
			if err := awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(ctx,
				&awslambda.GetFunctionConfigurationInput{FunctionName: r.name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			configure(newARN)
			r.releaseHeld(t)
			select {
			case result := <-finished:
				if result.err != nil || result.out.FunctionError != nil {
					t.Fatalf("old real runtime release: %+v", result)
				}
			case <-time.After(time.Minute):
				t.Fatal("old real runtime did not release")
			}
			r.auditRecord(t, "held-runtime", "exiting")
			if backend == "sqlite" {
				previous := r.c
				if err := previous.cloud.Close(); err != nil {
					t.Fatal(err)
				}
				previous.server.Close()
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
				r.c = lambdaEventsConnect(t, backends, source)
				// Real runtime endpoint variables must follow the reopened listener.
				variables := input.Environment.Variables
				for key, value := range variables {
					variables[key] = strings.ReplaceAll(value, strings.Replace(previous.server.URL, "127.0.0.1", "host.docker.internal", 1), strings.Replace(r.c.server.URL, "127.0.0.1", "host.docker.internal", 1))
				}
				if _, err := r.c.lambda.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: r.name,
					Environment: &lambdatypes.Environment{Variables: variables}}); err != nil {
					t.Fatal(err)
				}
				if err := awslambda.NewFunctionUpdatedWaiter(r.c.lambda, fastLambdaUpdatedWaiter).Wait(ctx,
					&awslambda.GetFunctionConfigurationInput{FunctionName: r.name}, time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			advanceClock(t, source, time.Second)
			marker := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.audit, 1)[0].Body)
			if marker["runtime_request_id"] != acceptedID || marker["deployment"] != "replacement" || marker["function_version"] != "$LATEST" {
				t.Fatalf("accepted payload did not enter replacement runtime: %#v", marker)
			}
			old := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.destination, 1)[0].Body)
			if old["requestContext"].(map[string]any)["requestId"] != acceptedID || old["requestContext"].(map[string]any)["condition"] != "Success" {
				t.Fatalf("old destination lost accepted identity: %#v", old)
			}
			_, err = r.c.lambda.GetFunction(ctx, &awslambda.GetFunctionInput{FunctionName: r.name, Qualifier: published.Version})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = r.c.lambda.Invoke(ctx, &awslambda.InvokeInput{FunctionName: r.name, Qualifier: published.Version,
				Payload: []byte(`{"label":"deleted-publication-must-not-enter-replacement"}`)})
			assertAPIError(t, err, "ResourceNotFoundException")
			advanceClock(t, source, 2*time.Minute)
			newID := invoke("new-route-control")
			lambdaEventsReceive(t, r.c, r.audit, 1)
			newRecord := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.dlq, 1)[0].Body)
			if newRecord["requestContext"].(map[string]any)["requestId"] != newID {
				t.Fatalf("replacement route did not own newly accepted work: %#v", newRecord)
			}
			lambdaEventsQuiet(t, r.c, r.audit, r.destination, r.dlq)
		})
	}
}
