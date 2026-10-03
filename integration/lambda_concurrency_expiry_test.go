package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd/clock"
	"stackd/storage"
	lambdastorage "stackd/storage/lambda"
)

// Keep the native never-executed event and receipts, but use the separately
// captured release-controlled handler instead of sleeping 110 wall seconds.
// Service time crosses the captured age boundary only after a real cap rejection.
func TestLambdaConcurrencyThrottledExpiryNativeOutcome(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaConcurrencyLocal(t, lambdaFixture[struct {
		Capture struct {
			Observations []lambdaConcurrencyObservation
			Deliveries   []lambdaQueueDelivery
		} `json:"never_executed_capture"`
	}](t, "outcomes_expiry"))
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "expiry.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC))
			r := lambdaConcurrencyProvision(t, backends, source)
			r.command(t, "reserve_one")
			r.command(t, "both_routes")
			r.command(t, "both_routes_dlq")
			var age int32
			var payload []byte
			for _, row := range fixture.Capture.Observations {
				switch row.Label {
				case "config_unexecuted":
					age = *lambdaAdmissionInput[awslambda.PutFunctionEventInvokeConfigInput](t, row.Input).MaximumEventAgeInSeconds
				case "never-executed":
					var input struct{ PayloadBase64 string }
					if err := json.Unmarshal(row.Input, &input); err != nil {
						t.Fatal(err)
					}
					var err error
					payload, err = base64.StdEncoding.DecodeString(input.PayloadBase64)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if age == 0 || len(payload) == 0 {
				t.Fatal("native expiry setup is missing")
			}
			if _, err := r.c.lambda.UpdateFunctionEventInvokeConfig(t.Context(), &awslambda.UpdateFunctionEventInvokeConfigInput{FunctionName: r.name, MaximumEventAgeInSeconds: &age}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 2*time.Minute)
			done := r.hold(t)
			entered := r.auditRecord(t, "held-runtime", "entered")
			accepted, err := r.c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: r.name, InvocationType: lambdatypes.InvocationTypeEvent, Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			id, _ := awsmiddleware.GetRequestIDMetadata(accepted.ResultMetadata)
			// Synchronize with the existing retained retry, never a wall-time assumption
			// that the scheduler has probably tried admission already.
			deadline := time.Now().Add(time.Minute)
			for {
				if _, err := r.c.cloud.RunDueJobs(t.Context(), 100); err != nil {
					t.Fatal(err)
				}
				throttled := false
				if err := r.c.repository.View(t.Context(), func(reader lambdastorage.Reader) error {
					next, ok, err := reader.NextInvocation()
					if err != nil || !ok {
						return err
					}
					record, err := reader.Invocation(next.Key)
					if err != nil {
						return err
					}
					throttled = record.RequestID == id && record.ResponseStatus == 429 && record.Due.After(source.Now())
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if throttled {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("accepted event did not reach real capacity rejection")
				}
				time.Sleep(20 * time.Millisecond)
			}
			advanceClock(t, source, time.Duration(age)*time.Second)
			destination := lambdaEventsReceive(t, r.c, r.destination, 1)[0]
			legacy := lambdaEventsReceive(t, r.c, r.dlq, 1)[0]
			for _, native := range fixture.Capture.Deliveries {
				switch native.QueueKind {
				case "destination":
					got, want := lambdaQueueObject(t, aws.ToString(destination.Body)), lambdaQueueObject(t, aws.ToString(native.Message.Body))
					context := got["requestContext"].(map[string]any)
					if context["requestId"] != id || context["functionArn"] != entered["invoked_function_arn"].(string)+":$LATEST" {
						t.Fatal("expired admission lost function/request identity")
					}
					nativeContext := want["requestContext"].(map[string]any)
					context["requestId"], context["functionArn"] = nativeContext["requestId"], nativeContext["functionArn"]
					got["timestamp"] = want["timestamp"]
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("pre-execution expiry=%#v; native=%#v", got, want)
					}
				case "dlq":
					r.compareReceipt(t, "never-executed", legacy, native.Message, id, payload)
				}
			}
			r.finishHeld(t, done, entered)
			advanceClock(t, source, time.Hour)
			lambdaEventsQuiet(t, r.c, r.audit, r.destination, r.dlq)
		})
	}
}
