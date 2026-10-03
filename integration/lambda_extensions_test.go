package stackd_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type lambdaExtensionLifecycleRow struct {
	lambdaQualifiedRow
	FunctionPayload map[string]any `json:"function_payload"`
}

type lambdaExtensionLifecycleFixture struct {
	Observations []lambdaExtensionLifecycleRow
	Deliveries   []struct{ Body map[string]any }
}

type lambdaExtensionLifecycleReplay struct {
	r         *lambdaQualifiedReplay
	fixture   lambdaExtensionLifecycleFixture
	queue     *string
	bodies    []map[string]any
	layerARNs map[string]string
}

func newLambdaExtensionLifecycleReplay(t *testing.T, backend, fixtureName string) *lambdaExtensionLifecycleReplay {
	t.Helper()
	p := &lambdaExtensionLifecycleReplay{r: newLambdaQualifiedReplay(t, backend), fixture: lambdaFixture[lambdaExtensionLifecycleFixture](t, fixtureName), layerARNs: make(map[string]string)}
	// The SDK transport recorder is deliberately not used for concurrent invokes.
	options := p.r.c.lambda.Options()
	options.HTTPClient = p.r.c.server.Client()
	p.r.c.lambda = awslambda.New(options)
	for _, row := range p.fixture.Observations {
		if row.Operation == "invoke" {
			break
		}
		if row.Service == "iam" || row.Operation == "create-queue" || (row.Service == "lambda" && row.Operation != "wait") {
			p.apply(t, row.Label)
		}
	}
	if p.queue == nil {
		t.Fatal("native extension capture omitted collector queue")
	}
	return p
}

func (p *lambdaExtensionLifecycleReplay) row(t *testing.T, label string) lambdaExtensionLifecycleRow {
	t.Helper()
	for _, row := range p.fixture.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("native extension capture omitted %s", label)
	return lambdaExtensionLifecycleRow{}
}

func (p *lambdaExtensionLifecycleReplay) local(t *testing.T, row lambdaExtensionLifecycleRow) lambdaQualifiedRow {
	t.Helper()
	// Normalize a replay copy through the existing account conversion. Native
	// ZIPs, base64 payloads and collector evidence remain untouched.
	return lambdaConcurrencyLocal(t, row.lambdaQualifiedRow)
}

func (p *lambdaExtensionLifecycleReplay) apply(t *testing.T, label string) map[string]any {
	t.Helper()
	row := p.local(t, p.row(t, label))
	if p.r.setup(t, row) {
		if row.Operation == "create-queue" {
			p.queue = aws.String(p.r.queues[row.Result.Output["QueueUrl"].(string)])
		}
		return nil
	}
	input := lambdaNativeBlobInput(p.r.input(t, row)).(map[string]any)
	if layers, ok := input["Layers"].([]any); ok {
		for i, layer := range layers {
			if local, found := p.layerARNs[layer.(string)]; found {
				layers[i] = local
			}
		}
	}
	operation := lambdaLayerOperations(p.r.c.lambda)[row.Operation]
	if operation == nil {
		t.Fatalf("unbound native extension operation %s", row.Operation)
	}
	out, err := operation(t.Context(), input)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if row.Operation == "publish-layer-version" {
		p.layerARNs[row.Result.Output["LayerVersionArn"].(string)] = out["LayerVersionArn"].(string)
	}
	if row.Operation == "create-function" || row.Operation == "update-function-configuration" {
		p.r.ready(t, input["FunctionName"].(string))
	}
	return out
}

func (p *lambdaExtensionLifecycleReplay) invoke(t *testing.T, label string) (*awslambda.InvokeOutput, map[string]any) {
	t.Helper()
	native := p.row(t, label)
	input := lambdaAdmissionInput[awslambda.InvokeInput](t, lambdaQualifiedJSON(t, lambdaNativeBlobInput(p.r.input(t, p.local(t, native)))))
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	out, err := p.r.c.lambda.Invoke(ctx, input)
	if native.Result.Code != "Success" {
		assertAPIError(t, err, native.Result.Code)
		return nil, nil
	}
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if float64(out.StatusCode) != native.Result.Output["StatusCode"] || aws.ToString(out.FunctionError) != stringValue(native.Result.Output["FunctionError"]) {
		tail, _ := base64.StdEncoding.DecodeString(aws.ToString(out.LogResult))
		t.Fatalf("%s response differs from native: status=%d error=%q, want status=%v error=%q; payload=%s; tail=%s", label, out.StatusCode, aws.ToString(out.FunctionError), native.Result.Output["StatusCode"], stringValue(native.Result.Output["FunctionError"]), out.Payload, tail)
	}
	var payload map[string]any
	if len(out.Payload) != 0 {
		if err := json.Unmarshal(out.Payload, &payload); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"counter", "version", "marker_present", "errorType"} {
		if want, captured := native.FunctionPayload[key]; captured && !reflect.DeepEqual(payload[key], want) {
			t.Fatalf("%s payload %s=%v, native %v", label, key, payload[key], want)
		}
	}
	return out, payload
}

func (p *lambdaExtensionLifecycleReplay) collect(t *testing.T) {
	t.Helper()
	out, err := p.r.c.queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: p.queue, MaxNumberOfMessages: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range out.Messages {
		p.bodies = append(p.bodies, lambdaQualifiedBody(t, message.Body))
		if _, err := p.r.c.queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: p.queue, ReceiptHandle: message.ReceiptHandle}); err != nil {
			t.Fatal(err)
		}
	}
}

func (p *lambdaExtensionLifecycleReplay) wait(t *testing.T, description string, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		if _, err := p.r.c.cloud.RunDueJobs(t.Context(), 1000); err != nil {
			t.Fatal(err)
		}
		p.collect(t)
		if predicate() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s; received %d collector messages", description, len(p.bodies))
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func stringValue(v any) string { s, _ := v.(string); return s }

func lambdaExtensionEvent(body map[string]any) map[string]any {
	response, _ := body["response"].(map[string]any)
	var event map[string]any
	_ = json.Unmarshal([]byte(stringValue(response["body"])), &event)
	return event
}

func (p *lambdaExtensionLifecycleReplay) next(requestID string) map[string]any {
	for _, body := range p.bodies {
		if body["kind"] == "next" && lambdaExtensionEvent(body)["requestId"] == requestID {
			return body
		}
	}
	return nil
}

func (p *lambdaExtensionLifecycleReplay) metric(t *testing.T, metric string) float64 {
	t.Helper()
	if _, err := p.r.c.cloud.RunDueJobs(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
	name := p.row(t, "create-function").Input["FunctionName"].(string)
	end := p.r.clock.Now().Add(time.Minute)
	out, err := metricsClient(cloudClients{p.r.c.server}, "test").GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
		Namespace: aws.String("AWS/Lambda"), MetricName: aws.String(metric), Dimensions: []cwtypes.Dimension{{Name: aws.String("FunctionName"), Value: aws.String(name)}},
		StartTime: aws.Time(end.Add(-24 * time.Hour)), EndTime: &end, Period: aws.Int32(60), Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
	})
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, point := range out.Datapoints {
		sum += aws.ToFloat64(point.Sum)
	}
	return sum
}

func (p *lambdaExtensionLifecycleReplay) completed(t *testing.T, invocations, failures float64) {
	t.Helper()
	var gotInvocations, gotFailures float64
	defer func() {
		if t.Failed() {
			t.Logf("last completed invocation metrics: Invocations=%g Errors=%g", gotInvocations, gotFailures)
		}
	}()
	// Metric publications become due at the end of their service-clock minute.
	// Runtime and extension deadlines continue to use real elapsed time.
	if err := p.r.clock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	p.wait(t, fmt.Sprintf("completed invocations=%g errors=%g", invocations, failures), func() bool {
		gotInvocations, gotFailures = p.metric(t, "Invocations"), p.metric(t, "Errors")
		return gotInvocations == invocations && gotFailures == failures
	})
}

func lambdaExtensionBootPair(t *testing.T, before, after map[string]any, key string, same bool) {
	t.Helper()
	a, b := stringValue(before[key]), stringValue(after[key])
	if a == "" || b == "" || (a == b) != same {
		t.Fatalf("%s reuse=%t: before=%v after=%v", key, same, before, after)
	}
	if before["request_id"] == after["request_id"] {
		t.Fatal("distinct invocations reused request ID")
	}
}

func TestLambdaExtensionsLifecycleNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	// Admission and async outcome persistence take different repository paths.
	// Process-failure variants below need only one real runtime, not a full matrix.
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			p := newLambdaExtensionLifecycleReplay(t, backend, "extensions_lifecycle")
			_, first := p.invoke(t, "slow-extension-first")
			// This rejected SDK call proves the ordinary response did not release
			// reserved concurrency while its external extension was still running.
			p.invoke(t, "while-extension-busy")
			p.completed(t, 1, 0)
			_, warm := p.invoke(t, "slow-extension-warm")
			lambdaExtensionBootPair(t, first, warm, "boot", true)
			p.completed(t, 2, 0)
			tail, third := p.invoke(t, "explicit-tail-control")
			lambdaExtensionBootPair(t, warm, third, "boot", true)
			logs, err := base64.StdEncoding.DecodeString(aws.ToString(tail.LogResult))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(logs), "REPORT RequestId: "+stringValue(third["request_id"])) {
				t.Fatalf("Tail returned before final report: %s", logs)
			}
			p.completed(t, 3, 0)
			p.wait(t, "warm extension collector events", func() bool {
				return p.next(stringValue(first["request_id"])) != nil && p.next(stringValue(warm["request_id"])) != nil && p.next(stringValue(third["request_id"])) != nil
			})
			firstNext, warmNext := p.next(stringValue(first["request_id"])), p.next(stringValue(warm["request_id"]))
			if firstNext["extension_boot"] != warmNext["extension_boot"] || firstNext["sequence"].(float64) >= warmNext["sequence"].(float64) {
				t.Fatal("warm invocation did not reuse the ordered extension process")
			}
			p.checkEnvironment(t, stringValue(firstNext["extension_boot"]))

			p.apply(t, "post-response-timeout-config")
			_, timeoutFirst := p.invoke(t, "post-response-timeout-first")
			p.completed(t, 4, 1)
			_, timeoutNext := p.invoke(t, "post-response-timeout-next")
			lambdaExtensionBootPair(t, timeoutFirst, timeoutNext, "boot", false)
			p.completed(t, 5, 2)
			p.wait(t, "reset extension registration", func() bool {
				return p.next(stringValue(timeoutFirst["request_id"])) != nil && p.next(stringValue(timeoutNext["request_id"])) != nil
			})
			p.checkResetIDs(t, stringValue(timeoutFirst["request_id"]), stringValue(timeoutNext["request_id"]))

			p.invoke(t, "async-post-response-timeout")
			if _, err := p.r.c.cloud.RunDueJobs(t.Context(), 1000); err != nil {
				t.Fatal(err)
			}
			var outcome map[string]any
			p.wait(t, "early successful async outcome", func() bool {
				for _, body := range p.bodies {
					if request, ok := body["requestPayload"].(map[string]any); ok && request["probe"] == "async-post-response-timeout" {
						outcome = body
						return true
					}
				}
				return false
			})
			var nativeOutcome map[string]any
			for _, delivery := range p.fixture.Deliveries {
				if request, ok := delivery.Body["requestPayload"].(map[string]any); ok && request["probe"] == "async-post-response-timeout" {
					nativeOutcome = delivery.Body
					break
				}
			}
			if nativeOutcome == nil {
				t.Fatal("native capture omitted async destination outcome")
			}
			gotContext, wantContext := outcome["requestContext"].(map[string]any), nativeOutcome["requestContext"].(map[string]any)
			for _, key := range []string{"condition", "approximateInvokeCount"} {
				if !reflect.DeepEqual(gotContext[key], wantContext[key]) {
					t.Fatalf("async %s=%v, native %v", key, gotContext[key], wantContext[key])
				}
			}
			if !reflect.DeepEqual(outcome["responseContext"], nativeOutcome["responseContext"]) {
				t.Fatalf("async response context=%v, native=%v", outcome["responseContext"], nativeOutcome["responseContext"])
			}
			gotPayload, wantPayload := outcome["responsePayload"].(map[string]any), nativeOutcome["responsePayload"].(map[string]any)
			for _, key := range []string{"counter", "version"} {
				if !reflect.DeepEqual(gotPayload[key], wantPayload[key]) {
					t.Fatalf("async response payload %s=%v, native=%v", key, gotPayload[key], wantPayload[key])
				}
			}
			if gotContext["requestId"] == "" || gotPayload["request_id"] != gotContext["requestId"] {
				t.Fatalf("async response lost invocation correlation: %v", outcome)
			}
			if err := p.r.clock.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			if p.metric(t, "Errors") != 2 {
				t.Fatal("successful async destination was withheld until extension timeout")
			}
			p.completed(t, 6, 3)
			// Native config explicitly disables retries. Advance beyond its event
			// age and retry opportunities, then inspect SDK-visible outcomes.
			if err := p.r.clock.Advance(5 * time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := p.r.c.cloud.RunDueJobs(t.Context(), 1000); err != nil {
				t.Fatal(err)
			}
			p.collect(t)
			outcomes := 0
			for _, body := range p.bodies {
				if request, ok := body["requestPayload"].(map[string]any); ok && request["probe"] == "async-post-response-timeout" {
					outcomes++
				}
			}
			if outcomes != 1 || p.metric(t, "Invocations") != 6 {
				t.Fatalf("async phase failure retried or duplicated outcome: outcomes=%d", outcomes)
			}

			p.apply(t, "runtime-timeout-config")
			p.invoke(t, "runtime-timeout")
			p.completed(t, 7, 4)
			p.invoke(t, "runtime-timeout-recovery")
			p.completed(t, 8, 4)
			p.checkNativePhaseMetrics(t)
		})
	}
}

func (p *lambdaExtensionLifecycleReplay) checkEnvironment(t *testing.T, boot string) {
	t.Helper()
	var want map[string]any
	for _, delivery := range p.fixture.Deliveries {
		if delivery.Body["kind"] == "register" {
			want, _ = delivery.Body["runtime_environment_presence"].(map[string]any)
			if want != nil {
				break
			}
		}
	}
	if want == nil {
		t.Fatal("native collector omitted runtime-only environment observations")
	}
	p.wait(t, "external environment exclusions", func() bool {
		for _, body := range p.bodies {
			if body["kind"] == "register" && body["extension_boot"] == boot {
				if !reflect.DeepEqual(body["runtime_environment_presence"], want) {
					t.Fatalf("external environment=%v, native=%v", body["runtime_environment_presence"], want)
				}
				return true
			}
		}
		return false
	})
}

func (p *lambdaExtensionLifecycleReplay) checkResetIDs(t *testing.T, first, second string) {
	t.Helper()
	a, b := p.next(first), p.next(second)
	if a["extension_boot"] == b["extension_boot"] {
		t.Fatal("failed phase reused extension process")
	}
	p.wait(t, "fresh extension registration identifiers", func() bool {
		identifiers := map[string]string{}
		for _, body := range p.bodies {
			if body["kind"] != "register" {
				continue
			}
			response, _ := body["response"].(map[string]any)
			headers, _ := response["headers"].(map[string]any)
			for key, value := range headers {
				if strings.EqualFold(key, "Lambda-Extension-Identifier") {
					identifiers[stringValue(body["extension_boot"])] = stringValue(value)
				}
			}
		}
		firstID, secondID := identifiers[stringValue(a["extension_boot"])], identifiers[stringValue(b["extension_boot"])]
		if firstID == "" || secondID == "" {
			return false
		}
		if firstID == secondID {
			t.Fatalf("reset reused registration ID: %v", identifiers)
		}
		return true
	})
}

func (p *lambdaExtensionLifecycleReplay) checkNativePhaseMetrics(t *testing.T) {
	t.Helper()
	fixture := lambdaFixture[struct {
		Output struct {
			MetricDataResults []struct {
				Label  string
				Values []float64
			}
		}
	}](t, "extensions_phase_metrics")
	for _, series := range fixture.Output.MetricDataResults {
		metric, stat, _ := strings.Cut(series.Label, "/")
		if stat != "Sum" || (metric != "Invocations" && metric != "Errors" && metric != "Throttles" && metric != "AsyncEventsReceived" && metric != "AsyncEventsDropped" && metric != "DestinationDeliveryFailures") {
			continue
		}
		var want float64
		for _, value := range series.Values {
			want += value
		}
		p.wait(t, "native phase metric "+metric, func() bool { return p.metric(t, metric) == want })
	}
}

func TestLambdaExtensionsFailuresNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	p := newLambdaExtensionLifecycleReplay(t, "memory", "extensions_failures")
	// Pre-registration exit and explicit init/error cover different failure
	// boundaries; repeating exit codes adds no different consumer contract.
	for _, mode := range []string{"before_register_exit_17", "init_error"} {
		p.apply(t, mode+"-configure")
		p.invoke(t, mode)
		actual := p.apply(t, mode+"-control-plane")
		native := p.row(t, mode+"-control-plane").Result.Output
		for _, key := range []string{"State", "LastUpdateStatus"} {
			if actual[key] != native[key] {
				t.Fatalf("init failure changed %s=%v, native=%v", key, actual[key], native[key])
			}
		}
		nativeBoots := map[string]bool{}
		for _, delivery := range p.fixture.Deliveries {
			if delivery.Body["kind"] == "extension_start" && delivery.Body["mode"] == mode {
				nativeBoots[stringValue(delivery.Body["boot"])] = true
			}
		}
		if len(nativeBoots) < 2 {
			t.Fatalf("native capture does not evidence an init retry for %s", mode)
		}
		p.wait(t, "fresh init retry processes for "+mode, func() bool {
			boots := map[string]bool{}
			for _, body := range p.bodies {
				if body["kind"] == "extension_start" && body["mode"] == mode {
					boots[stringValue(body["boot"])] = true
				}
			}
			return len(boots) == len(nativeBoots)
		})
	}
	p.apply(t, "recovery_control-configure")
	p.invoke(t, "init-failure-recovery-control")
	p.completed(t, 3, 2)
	p.apply(t, "post_response_exit-configure")
	_, first := p.invoke(t, "post_response_exit-first")
	p.completed(t, 4, 3)
	_, recovered := p.invoke(t, "post_response_exit-recovery")
	lambdaExtensionBootPair(t, first, recovered, "runtime_boot", false)
	p.completed(t, 5, 3)
	p.wait(t, "extension crash reset with retained marker", func() bool {
		starts := map[bool]string{}
		for _, body := range p.bodies {
			if body["kind"] == "extension_start" && body["mode"] == "post_response_exit" {
				marker, ok := body["marker_present"].(bool)
				if ok {
					starts[marker] = stringValue(body["boot"])
				}
			}
		}
		if len(starts) < 2 {
			return false
		}
		if starts[false] == "" || starts[true] == "" || starts[false] == starts[true] {
			t.Fatalf("crash reset lost /tmp or reused process: %v", starts)
		}
		return true
	})
}
