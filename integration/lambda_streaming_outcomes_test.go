package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

// Ordinary Event invocation of streamifyResponse is not InvokeWithResponseStream:
// even the two handler exceptions produce native OnSuccess destination records.
func TestLambdaStreamingDockerAsyncOutcomes(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise real Docker Lambda streaming outcomes")
	}
	fixture := lambdaFixture[struct {
		lambdaStreamingFixture
		StartedAt    time.Time `json:"started_at"`
		Destinations []struct {
			Route    string
			Envelope json.RawMessage
		} `json:"destination_messages"`
	}](t, "streaming_async")
	if len(fixture.Destinations) == 0 {
		t.Fatal("fixture has no consumed destination records")
	}
	customer := lambdaFixture[lambdaStreamingFixture](t, "streaming")
	code := lambdaStreamingCode(t, &customer, "x86_64")
	source := clock.NewManual(fixture.StartedAt)
	c := lambdaEventsConnect(t, storage.NewMemory(), source)
	clients := cloudClients{c.server}
	root, logs := clients.iam("test", "test", ""), logsClient(clients, "test")
	ctx := t.Context()
	const name = "streaming-async-replay"
	normalize := strings.NewReplacer(fixture.Prefix, name, fixture.Account, "000000000000")
	queues := make(map[string]*string)
	for _, row := range fixture.Observations {
		if row.Result.Code != "Success" {
			continue
		}
		switch row.Operation {
		case "create_queue":
			input := lambdaStreamingInput[sqs.CreateQueueInput](t, row.Input, normalize)
			out, err := c.queues.CreateQueue(ctx, &input)
			if err != nil {
				t.Fatal(err)
			}
			queues[strings.TrimPrefix(aws.ToString(input.QueueName), name+"-")] = out.QueueUrl
		case "create_log_group":
			input := lambdaStreamingInput[cloudwatchlogs.CreateLogGroupInput](t, row.Input, normalize)
			if _, err := logs.CreateLogGroup(ctx, &input); err != nil {
				t.Fatal(err)
			}
		case "create_role":
			input := lambdaStreamingInput[iam.CreateRoleInput](t, row.Input, normalize)
			if _, err := root.CreateRole(ctx, &input); err != nil {
				t.Fatal(err)
			}
		case "put_role_policy":
			input := lambdaStreamingInput[iam.PutRolePolicyInput](t, row.Input, normalize)
			if _, err := root.PutRolePolicy(ctx, &input); err != nil {
				t.Fatal(err)
			}
		case "create_function":
			input := lambdaStreamingInput[awslambda.CreateFunctionInput](t, row.Input, normalize)
			input.Code = &lambdatypes.FunctionCode{ZipFile: code}
			if _, err := c.lambda.CreateFunction(ctx, &input); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
		case "put_function_event_invoke_config":
			input := lambdaStreamingInput[awslambda.PutFunctionEventInvokeConfigInput](t, row.Input, normalize)
			if _, err := c.lambda.PutFunctionEventInvokeConfig(ctx, &input); err != nil {
				t.Fatal(err)
			}
			// API-visible configuration is not immediate delivery authority.
			advanceClock(t, source, 2*time.Minute)
			if _, err := c.cloud.RunDueJobs(ctx, 100); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, row := range fixture.Observations {
		if row.Operation != "invoke" {
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			input := lambdaStreamingInput[awslambda.InvokeInput](t, row.Input, normalize)
			event := lambdaQueueObject(t, string(input.Payload))
			var want map[string]any
			var route string
			for _, destination := range fixture.Destinations {
				envelope := lambdaQueueObject(t, normalize.Replace(string(destination.Envelope)))
				if envelope["requestPayload"].(map[string]any)["token"] == event["token"] {
					want, route = envelope, destination.Route
					break
				}
			}
			if want == nil || queues[route] == nil {
				t.Fatalf("native destination missing for invocation token %v", event["token"])
			}
			out, err := c.lambda.Invoke(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			if out.StatusCode != row.Result.Output.StatusCode || out.FunctionError != nil || len(out.Payload) != 0 {
				t.Fatalf("ordinary asynchronous acceptance = %+v; native status = %d", out, row.Result.Output.StatusCode)
			}
			requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
			if !ok || requestID == "" {
				t.Fatal("asynchronous acceptance lacks its correlation request ID")
			}
			// Require a consumed record on the native route. A temporarily empty
			// failure queue would not establish successful routing or completion.
			message := lambdaEventsReceive(t, c, queues[route], 1)[0]
			got := lambdaQueueObject(t, aws.ToString(message.Body))
			if !reflect.DeepEqual(got["requestPayload"], event) {
				t.Fatalf("destination lost invocation token/payload: %s", aws.ToString(message.Body))
			}
			request, ok := got["requestContext"].(map[string]any)
			if !ok || request["requestId"] != requestID {
				t.Fatalf("destination lost accepted request identity: %s", aws.ToString(message.Body))
			}
			timestamp, _ := got["timestamp"].(string)
			if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
				t.Fatalf("destination timestamp %q: %v", timestamp, err)
			}
			request["requestId"] = want["requestContext"].(map[string]any)["requestId"]
			got["timestamp"] = want["timestamp"]
			// Compare malformed-response status/code and field presence, not the
			// service's diagnostic wording. Empty output has no deliveryError.
			for _, envelope := range []map[string]any{got, want} {
				if delivery, ok := envelope["deliveryError"].(map[string]any); ok {
					delete(delivery, "errorMessage")
				}
			}
			// Whole-envelope equality also defends count one and the absence of
			// functionError and responsePayload (including fabricated JSON null).
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s destination = %#v; native = %#v", route, got, want)
			}
		})
	}
}
