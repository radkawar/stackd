package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd/clock"
	"stackd/storage"
)

// Native Lambda appends its own lineage to the incoming header. This checks the
// producer-owned components only; EventBridge must not invent Lambda segments.
func TestEventBridgeTraceDockerLambda(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			backends := storage.NewMemory()
			if kind == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "trace-lambda.sqlite"))
			}
			cloud := lambdaEventsConnect(t, backends, clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)))
			lambdaEventsProvision(t, cloud, lambdaFixture[lambdaEventsFixture](t, "event_invocation"))
			code := lambdaZIP(t, map[string]string{"handler.py": `import os,json,boto3

def handler(event, context):
    boto3.client("sqs").send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps({"event":event,"trace":os.environ.get("_X_AMZN_TRACE_ID")}))
`})
			if _, err := cloud.lambda.UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: cloud.functionName, ZipFile: code}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(cloud.lambda).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: cloud.functionName}, time.Minute, fastLambdaUpdatedWaiter); err != nil {
				t.Fatal(err)
			}
			bus, err := cloud.events.CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: aws.String("trace")})
			if err != nil {
				t.Fatal(err)
			}
			rule, err := cloud.events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("trace"), EventBusName: bus.EventBusArn, EventPattern: aws.String(`{"source":["stackd.trace"]}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cloud.lambda.AddPermission(t.Context(), &awslambda.AddPermissionInput{FunctionName: cloud.functionName, StatementId: aws.String("trace"), Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("events.amazonaws.com"), SourceArn: rule.RuleArn}); err != nil {
				t.Fatal(err)
			}
			targets, err := cloud.events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("trace"), EventBusName: bus.EventBusArn,
				Targets: []eventtypes.Target{{Id: aws.String("lambda"), Arn: aws.String(cloud.functionARN)}}})
			if err != nil || targets.FailedEntryCount != 0 {
				t.Fatal(targets, err)
			}
			for _, trace := range []string{
				"Root=1-6ab2832c-0123456789abcdef01234567;Parent=0123456789abcdef;Sampled=0",
				"Root=1-6ab2832c-0123456789abcdef01234568;Parent=fedcba9876543210;Sampled=0",
			} {
				accepted, err := cloud.events.PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{EventBusName: bus.EventBusArn,
					Source: aws.String("stackd.trace"), DetailType: aws.String("trace"), Detail: aws.String(`{"private":"unchanged"}`), TraceHeader: aws.String(trace)}}})
				if err != nil || accepted.FailedEntryCount != 0 {
					t.Fatal(accepted, err)
				}
				messages := lambdaEventsReceive(t, cloud, cloud.outputURL, 1)
				var result struct {
					Event map[string]json.RawMessage
					Trace string
				}
				if err := json.Unmarshal([]byte(aws.ToString(messages[0].Body)), &result); err != nil {
					t.Fatal(err)
				}
				parts := make(map[string]string)
				for part := range strings.SplitSeq(result.Trace, ";") {
					key, value, ok := strings.Cut(part, "=")
					if ok {
						parts[key] = value
					}
				}
				for part := range strings.SplitSeq(trace, ";") {
					key, value, _ := strings.Cut(part, "=")
					if parts[key] != value {
						t.Fatalf("runtime lost or reused producer trace: %q want %q", result.Trace, trace)
					}
				}
				var detail map[string]string
				if err := json.Unmarshal(result.Event["detail"], &detail); err != nil {
					t.Fatal(err)
				}
				if len(result.Event) != 9 || len(detail) != 1 || detail["private"] != "unchanged" || string(result.Event["id"]) != `"`+aws.ToString(accepted.Entries[0].EventId)+`"` {
					t.Fatalf("runtime trace contaminated customer JSON: %+v", result.Event)
				}
			}
		})
	}
}
