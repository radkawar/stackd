package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd/clock"
	"stackd/storage"
)

type lambdaConcurrencyExecutionFixture struct {
	lambdaConcurrencyFixture
	Receipts []lambdaQueueDelivery `json:"consumer_receipts"`
	Metrics  struct {
		Rounds []struct{ Values map[string]lambdaQueueMetric }
	}
}

type lambdaConcurrencyRuntime struct {
	*lambdaQueueReplay
	fixture                          lambdaConcurrencyExecutionFixture
	name                             *string
	audit, release, destination, dlq *string
}

func lambdaConcurrencyProvision(t *testing.T, backends *storage.Backends, source *clock.Manual) *lambdaConcurrencyRuntime {
	t.Helper()
	f := lambdaConcurrencyLocal(t, lambdaFixture[lambdaConcurrencyExecutionFixture](t, "concurrency_execution"))
	c := lambdaEventsConnect(t, backends, source)
	r := &lambdaQueueReplay{c: c, source: source, account: "test", endpoint: strings.Replace(c.server.URL, "127.0.0.1", "host.docker.internal", 1), root: (cloudClients{c.server}).iam("test", "test", ""), urls: map[string]*string{}, functions: map[string]*awslambda.CreateFunctionInput{}, settings: map[string]*awslambda.PutFunctionEventInvokeConfigInput{}, metrics: map[string]map[string]lambdaQueueMetric{}}
	runtime := &lambdaConcurrencyRuntime{lambdaQueueReplay: r, fixture: f}
	for _, row := range f.Observations {
		if row.Operation == "create-function" && row.Result.Code == "Success" {
			runtime.name = lambdaAdmissionInput[awslambda.CreateFunctionInput](t, row.Input).FunctionName
		}
		switch row.Operation {
		case "create-queue", "create-role", "put-role-policy", "create-function":
			if row.Result.Code == "Success" {
				runtime.command(t, row.Label)
			}
		}
		if runtime.name != nil {
			break
		}
	}
	for _, binding := range []struct {
		label  string
		target **string
	}{{"create_audit", &runtime.audit}, {"create_release", &runtime.release}, {"create_destination", &runtime.destination}, {"create_dlq", &runtime.dlq}} {
		native := lambdaAdmissionInput[sqs.CreateQueueOutput](t, f.row(t, binding.label).Result.Output)
		*binding.target = r.urls[aws.ToString(native.QueueUrl)]
	}
	return runtime
}

func (r *lambdaConcurrencyRuntime) command(t *testing.T, label string) {
	t.Helper()
	row := r.fixture.row(t, label)
	switch row.Operation {
	case "put-function-concurrency":
		_, err := r.c.lambda.PutFunctionConcurrency(t.Context(), lambdaAdmissionInput[awslambda.PutFunctionConcurrencyInput](t, row.Input))
		if err != nil {
			t.Fatal(err)
		}
	case "delete-function-concurrency":
		_, err := r.c.lambda.DeleteFunctionConcurrency(t.Context(), lambdaAdmissionInput[awslambda.DeleteFunctionConcurrencyInput](t, row.Input))
		if err != nil {
			t.Fatal(err)
		}
	default:
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		r.lambdaQueueReplay.command(t, *lambdaAdmissionInput[lambdaQueueObservation](t, data))
	}
}

func (r *lambdaConcurrencyRuntime) input(t *testing.T, label string) *awslambda.InvokeInput {
	t.Helper()
	row := r.fixture.row(t, label)
	var input struct {
		FunctionName   *string
		InvocationType lambdatypes.InvocationType
		PayloadBase64  string
	}
	if err := json.Unmarshal(row.Input, &input); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(input.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	return &awslambda.InvokeInput{FunctionName: input.FunctionName, InvocationType: input.InvocationType, Payload: payload}
}

func (r *lambdaConcurrencyRuntime) invoke(t *testing.T, label string) *awslambda.InvokeOutput {
	t.Helper()
	want := r.fixture.row(t, label)
	out, err := r.c.lambda.Invoke(t.Context(), r.input(t, label))
	if want.Result.Code != "Success" {
		assertAPIError(t, err, want.Result.Code)
		var throttle *lambdatypes.TooManyRequestsException
		var response *smithyhttp.ResponseError
		if !errors.As(err, &throttle) || string(throttle.Reason) != want.Result.Body["Reason"] || aws.ToString(throttle.Type) != want.Result.Body["Type"] || aws.ToString(throttle.RetryAfterSeconds) != want.Result.Headers["Retry-After"] {
			t.Fatalf("throttle projection differs: %v", err)
		}
		if !errors.As(err, &response) || response.HTTPStatusCode() != want.Result.HTTPStatus {
			t.Fatalf("throttle HTTP status differs: %v", err)
		}
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	r.compareInvoke(t, label, out)
	return out
}

func (r *lambdaConcurrencyRuntime) compareInvoke(t *testing.T, label string, out *awslambda.InvokeOutput) {
	t.Helper()
	row := r.fixture.row(t, label)
	if int(out.StatusCode) != row.Result.HTTPStatus || out.FunctionError != nil {
		t.Fatalf("%s invocation: %+v", label, out)
	}
	native, err := base64.StdEncoding.DecodeString(row.Result.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	if len(native) == 0 {
		if len(out.Payload) != 0 {
			t.Fatalf("%s unexpectedly executed: %s", label, out.Payload)
		}
	} else if !reflect.DeepEqual(lambdaQueueObject(t, string(out.Payload)), lambdaQueueObject(t, string(native))) {
		t.Fatalf("%s output=%s; native=%s", label, out.Payload, native)
	}
}

func (r *lambdaConcurrencyRuntime) auditRecord(t *testing.T, label, phase string) map[string]any {
	t.Helper()
	message := lambdaEventsReceive(t, r.c, r.audit, 1)[0]
	got := lambdaQueueObject(t, aws.ToString(message.Body))
	for _, receipt := range r.fixture.Receipts {
		if receipt.QueueKind != "audit" {
			continue
		}
		want := lambdaQueueObject(t, aws.ToString(receipt.Message.Body))
		if want["event"].(map[string]any)["label"] != label || want["phase"] != phase {
			continue
		}
		for _, key := range []string{"phase", "event", "invoked_function_arn", "function_version", "released"} {
			if !reflect.DeepEqual(got[key], want[key]) {
				t.Fatalf("runtime audit %s/%s %s=%#v; native=%#v", label, phase, key, got[key], want[key])
			}
		}
		return got
	}
	t.Fatalf("missing native audit %s/%s", label, phase)
	return nil
}

func (r *lambdaConcurrencyRuntime) releaseHeld(t *testing.T) {
	t.Helper()
	row := r.fixture.row(t, "release_held")
	input := lambdaAdmissionInput[sqs.SendMessageInput](t, row.Input)
	input.QueueUrl = r.release
	if _, err := r.c.queues.SendMessage(t.Context(), input); err != nil {
		t.Fatal(err)
	}
}

type lambdaConcurrencyResult struct {
	out *awslambda.InvokeOutput
	err error
}

func (r *lambdaConcurrencyRuntime) hold(t *testing.T) <-chan lambdaConcurrencyResult {
	t.Helper()
	input := r.input(t, "held-runtime")
	done := make(chan lambdaConcurrencyResult, 1)
	go func() { out, err := r.c.lambda.Invoke(t.Context(), input); done <- lambdaConcurrencyResult{out, err} }()
	return done
}
func (r *lambdaConcurrencyRuntime) finishHeld(t *testing.T, done <-chan lambdaConcurrencyResult, entered map[string]any) {
	t.Helper()
	r.releaseHeld(t)
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		r.compareInvoke(t, "held-runtime", result.out)
		id, _ := awsmiddleware.GetRequestIDMetadata(result.out.ResultMetadata)
		exiting := r.auditRecord(t, "held-runtime", "exiting")
		if entered["runtime_request_id"] != id || exiting["runtime_request_id"] != id {
			t.Fatalf("reservation mutation replaced active invocation: entered=%v exiting=%v SDK=%s", entered, exiting, id)
		}
	case <-time.After(time.Minute):
		t.Fatal("released real runtime did not finish")
	}
}

func (r *lambdaConcurrencyRuntime) discard(t *testing.T, labels []string, destination, legacy bool) {
	t.Helper()
	ids := map[string]string{}
	for _, label := range labels {
		out := r.invoke(t, label)
		ids[label], _ = awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	}
	for _, route := range []struct {
		kind    string
		url     *string
		enabled bool
	}{{"destination", r.destination, destination}, {"dlq", r.dlq, legacy}} {
		if !route.enabled {
			continue
		}
		seen := map[string]bool{}
		for _, actual := range lambdaEventsReceive(t, r.c, route.url, len(labels)) {
			got := lambdaQueueObject(t, aws.ToString(actual.Body))
			payload := got
			if route.kind == "destination" {
				payload = got["requestPayload"].(map[string]any)
			}
			label := payload["label"].(string)
			id := ids[label]
			if id == "" || seen[label] {
				t.Fatalf("missing/duplicated discarded event: %s", aws.ToString(actual.Body))
			}
			seen[label] = true
			matched := false
			for _, receipt := range r.fixture.Receipts {
				if receipt.QueueKind != route.kind {
					continue
				}
				want := lambdaQueueObject(t, aws.ToString(receipt.Message.Body))
				event := want
				if route.kind == "destination" {
					event = want["requestPayload"].(map[string]any)
				}
				if event["label"] != label {
					continue
				}
				matched = true
				if route.kind == "dlq" {
					r.compareReceipt(t, label, actual, receipt.Message, id, r.input(t, label).Payload)
				} else {
					context := got["requestContext"].(map[string]any)
					if context["requestId"] != id {
						t.Fatal("discard lost accepted request identity")
					}
					context["requestId"] = want["requestContext"].(map[string]any)["requestId"]
					got["timestamp"] = want["timestamp"]
					// Whole-record comparison protects the absence of fabricated runtime
					// responseContext/responsePayload as well as count zero and condition.
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("discard=%#v; native=%#v", got, want)
					}
				}
				break
			}
			if !matched {
				t.Fatalf("native fixture lacks %s receipt for %s", route.kind, label)
			}
		}
	}
	lambdaEventsQuiet(t, r.c, r.audit, r.destination, r.dlq)
}

func TestLambdaConcurrencyExecutionDockerNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "execution.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC))
			r := lambdaConcurrencyProvision(t, backends, source)
			r.command(t, "reserve_one")
			r.invoke(t, "permission-success-control")
			// Both records may already be visible when a synchronous request returns.
			records := lambdaEventsReceive(t, r.c, r.audit, 2)
			for _, record := range records {
				if lambdaQueueObject(t, aws.ToString(record.Body))["event"].(map[string]any)["label"] != "permission-success-control" {
					t.Fatal("wrong permission-control runtime event")
				}
			}
			done := r.hold(t)
			entered := r.auditRecord(t, "held-runtime", "entered")
			r.invoke(t, "rejected-at-one")
			r.invoke(t, "dryrun-at-one")
			r.command(t, "zero_while_active")
			r.invoke(t, "rejected-at-zero-active")
			r.invoke(t, "dryrun-at-zero-active")
			r.command(t, "delete_reservation_while_active")
			r.command(t, "restore_one_while_active")
			r.finishHeld(t, done, entered)
			r.command(t, "zero_settled")
			for _, step := range []struct {
				config              string
				labels              []string
				destination, legacy bool
			}{
				{"both_routes", []string{"zero-both-a", "zero-both-b"}, true, true},
				{"dlq_only", []string{"zero-dlq-only"}, false, true},
				{"destination_only", []string{"zero-destination-only"}, true, false},
			} {
				r.command(t, step.config)
				r.command(t, step.config+"_dlq")
				if step.config == "both_routes" {
					r.invoke(t, "dryrun-zero-settled")
					r.invoke(t, "sync-zero-settled")
				}
				r.discard(t, step.labels, step.destination, step.legacy)
			}
			r.command(t, "restore_capacity")
			r.invoke(t, "recovery-sync")
			lambdaEventsReceive(t, r.c, r.audit, 2)
			r.invoke(t, "recovery-async")
			lambdaEventsReceive(t, r.c, r.audit, 2)
			advanceClock(t, source, 2*time.Hour)
			lambdaEventsQuiet(t, r.c, r.audit, r.destination, r.dlq)
			// Native missing datapoints are not interpreted as zero. Positive observed
			// samples defend no invocations for throttles/discards and DryRun purity.
			r.metrics[aws.ToString(r.name)] = map[string]lambdaQueueMetric{}
			for name, metric := range r.fixture.Metrics.Rounds[len(r.fixture.Metrics.Rounds)-1].Values {
				if metric.Samples != 0 {
					r.metrics[aws.ToString(r.name)][name] = metric
				}
			}
			r.checkMetrics(t)
		})
	}
}

// Both captured handlers must enter before either release exists. Admission must
// reject a third call while both are running, then retain both completions.
func TestLambdaConcurrencyOverlappingDockerEnvironments(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "overlap.sqlite"))
			}
			r := lambdaConcurrencyProvision(t, backends, clock.NewManual(time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC)))
			if _, err := r.c.lambda.PutFunctionConcurrency(t.Context(), &awslambda.PutFunctionConcurrencyInput{FunctionName: r.name, ReservedConcurrentExecutions: aws.Int32(2)}); err != nil {
				t.Fatal(err)
			}
			accept := func() string {
				t.Helper()
				input := r.input(t, "held-runtime")
				input.InvocationType = lambdatypes.InvocationTypeEvent
				out, err := r.c.lambda.Invoke(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				r.compareInvoke(t, "recovery-async", out)
				id, _ := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
				return id
			}
			first := accept()
			enteredFirst := r.auditRecord(t, "held-runtime", "entered")
			second := accept()
			enteredSecond := r.auditRecord(t, "held-runtime", "entered")
			if enteredFirst["runtime_request_id"] != first || enteredSecond["runtime_request_id"] != second || first == second {
				t.Fatal("overlapping requests lost accepted runtime identities")
			}
			r.invoke(t, "rejected-at-one")
			// Identical native labels allow either environment to consume each release.
			r.releaseHeld(t)
			r.releaseHeld(t)
			ids := map[string]bool{first: true, second: true}
			for len(ids) != 0 {
				for _, message := range lambdaEventsReceive(t, r.c, r.audit, 1) {
					record := lambdaQueueObject(t, aws.ToString(message.Body))
					id := record["runtime_request_id"]
					if record["phase"] != "exiting" || record["released"] != true || (id != first && id != second) {
						t.Fatalf("wrong overlapping completion: %#v", record)
					}
					delete(ids, id.(string))
				}
			}
			lambdaEventsQuiet(t, r.c, r.audit)
		})
	}
}
