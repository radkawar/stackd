package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/storage"
)

type lambdaQueueObservation struct {
	Label, Operation string
	Input            json.RawMessage
	Started          int64 `json:"request_started_ms"`
	Result           struct {
		Code   string
		Output json.RawMessage
	}
}

type lambdaQueueInvocation struct {
	Label, Function string
	Payload         json.RawMessage
	PayloadBase64   string `json:"payload_base64"`
}

type lambdaQueueDelivery struct {
	Queue       string `json:"queue_label"`
	QueueKind   string `json:"queue_kind"`
	SourceID    string `json:"source_id"`
	SourceLabel string `json:"source_label"`
	Message     sqstypes.Message
}

type lambdaQueueMetric struct {
	Sum     float64
	Samples float64 `json:"sample_count"`
}

type lambdaQueueCapture struct {
	Account, Region, Prefix string
	Observations            []lambdaQueueObservation
	Invocations             []lambdaQueueInvocation
	Deliveries              []lambdaQueueDelivery
	MetricSnapshots         []struct{ Totals map[string]lambdaQueueMetric } `json:"metric_snapshots"`
}

type lambdaQueueReplay struct {
	c                         *lambdaEventsCloud
	source                    *clock.Manual
	account, prefix, endpoint string
	root                      *iam.Client
	topics                    *sns.Client
	urls                      map[string]*string
	functions                 map[string]*awslambda.CreateFunctionInput
	settings                  map[string]*awslambda.PutFunctionEventInvokeConfigInput
	requests                  map[string]bool
	subscriptions             []*string
	topicARNs                 []*string
	receipts                  []lambdaQueueDelivery
	metrics                   map[string]map[string]lambdaQueueMetric
}

// These captures overlap in wall time: supplemental ASCII and truncation calls
// were consumed by the original delivery process. Merge requests by native time,
// but keep their original ZIPs, payload bytes and consumer receipts intact.
func TestLambdaOutcomeQueuesDockerNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[struct{ Captures map[string]lambdaQueueCapture }](t, "outcomes_queues")
	expiry := lambdaFixture[struct {
		Capture  lambdaQueueCapture
		Retained struct {
			Rounds []struct {
				Aggregates map[string]map[string]struct {
					Datapoints []struct{ Sum, SampleCount float64 }
				}
			}
		} `json:"retained_metrics"`
	}](t, "outcomes_expiry")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, name := range []string{"delivery", "source_context", "expiry"} {
			t.Run(backend+"/"+name, func(t *testing.T) {
				capture := fixture.Captures[name]
				if name == "expiry" {
					capture = expiry.Capture
				}
				if name == "delivery" {
					for _, supplement := range []string{"ascii_controls", "truncation"} {
						extra := fixture.Captures[supplement]
						capture.Observations = append(capture.Observations, extra.Observations...)
						capture.Invocations = append(capture.Invocations, extra.Invocations...)
					}
				}
				// Sorting merged captures must not mutate the fixture reused by
				// the next backend, duplicating supplemental invocations.
				capture.Observations = slices.Clone(capture.Observations)
				sort.SliceStable(capture.Observations, func(i, j int) bool { return capture.Observations[i].Started < capture.Observations[j].Started })
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "lambda-outcome-queues.sqlite"))
				}
				source := clock.NewManual(time.UnixMilli(capture.Observations[0].Started).UTC())
				c := lambdaEventsConnect(t, backends, source)
				clients := cloudClients{c.server}
				c.queues = clients.sqs(capture.Account, "test", "")
				options := c.lambda.Options()
				options.Credentials = credentials.NewStaticCredentialsProvider(capture.Account, "test", "")
				c.lambda = awslambda.New(options)
				r := &lambdaQueueReplay{c: c, source: source, account: capture.Account, prefix: capture.Prefix,
					endpoint: strings.Replace(c.server.URL, "127.0.0.1", "host.docker.internal", 1),
					root:     clients.iam(capture.Account, "test", ""), topics: admissionSNSClient(clients, capture.Account, capture.Region),
					urls: map[string]*string{}, functions: map[string]*awslambda.CreateFunctionInput{}, settings: map[string]*awslambda.PutFunctionEventInvokeConfigInput{}, requests: map[string]bool{}, receipts: capture.Deliveries, metrics: map[string]map[string]lambdaQueueMetric{}}
				invocations := map[string]lambdaQueueInvocation{}
				for _, invocation := range capture.Invocations {
					invocations[invocation.Label] = invocation
				}
				previousNative := source.Now()
				for _, row := range capture.Observations {
					// Admission patch semantics have their own native replay. Only source-key
					// preflight probes belong here, alongside the runtime authority controls.
					selected := false
					switch row.Operation {
					case "create-queue", "set-queue-attributes", "create-topic", "subscribe", "create-role", "put-role-policy", "create-function":
						selected = row.Result.Code == "Success"
					case "put-function-event-invoke-config":
						selected = strings.HasPrefix(row.Label, "config-") || strings.HasPrefix(row.Label, "config_") || strings.HasPrefix(row.Label, "admission-destination-")
					case "update-function-configuration":
						selected = strings.HasPrefix(row.Label, "admission-dlq-")
					case "delete-role-policy":
						selected = row.Label == "repair-role-policy"
					case "invoke":
						selected = true
					}
					if !selected {
						continue
					}
					at := time.UnixMilli(row.Started).UTC()
					if err := source.Advance(at.Sub(previousNative)); err != nil {
						t.Fatal(err)
					}
					previousNative = at
					if row.Operation == "invoke" {
						label := strings.TrimPrefix(row.Label, "invoke-")
						invocation, ok := invocations[label]
						if !ok {
							t.Fatalf("native invocation missing %s", label)
						}
						r.invoke(t, invocation)
					} else {
						r.command(t, row)
					}
				}
				// Native retained metrics include the successful zero Errors samples and
				// two Unicode SNS DLQ failures aggregated into one minute sample.
				if name == "delivery" {
					snapshots := fixture.Captures["retained_metrics"].MetricSnapshots
					for key, want := range snapshots[len(snapshots)-1].Totals {
						function, metric, _ := strings.Cut(key, ":")
						r.metrics[capture.Prefix+"-"+function][metric] = want
					}
				}
				if name == "expiry" {
					rounds := expiry.Retained.Rounds
					for function, metrics := range rounds[len(rounds)-1].Aggregates {
						for metric, native := range metrics {
							if metric == "Throttles" {
								continue
							} // Not a concurrency probe.
							var want lambdaQueueMetric
							for _, point := range native.Datapoints {
								want.Sum += point.Sum
								want.Samples += point.SampleCount
							}
							r.metrics[function][metric] = want
						}
					}
				}
				r.checkMetrics(t)
				// Delete via consumer APIs, then re-query retained samples, rather than
				// inspecting either backend's private metric or outcome records.
				for function := range r.functions {
					if _, err := c.lambda.DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: aws.String(function)}); err != nil {
						t.Fatal(err)
					}
				}
				for _, arn := range r.subscriptions {
					if _, err := r.topics.Unsubscribe(t.Context(), &sns.UnsubscribeInput{SubscriptionArn: arn}); err != nil {
						t.Fatal(err)
					}
				}
				for _, arn := range r.topicARNs {
					if _, err := r.topics.DeleteTopic(t.Context(), &sns.DeleteTopicInput{TopicArn: arn}); err != nil {
						t.Fatal(err)
					}
				}
				for _, url := range r.urls {
					if _, err := c.queues.DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: url}); err != nil {
						t.Fatal(err)
					}
				}
				r.checkMetrics(t)
			})
		}
	}
}

func lambdaQueueInput[T any](t *testing.T, row lambdaQueueObservation) *T {
	t.Helper()
	var input T
	if err := json.Unmarshal(row.Input, &input); err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	return &input
}

func (r *lambdaQueueReplay) localURL(native string) string {
	if url := r.urls[native]; url != nil {
		return strings.Replace(aws.ToString(url), "127.0.0.1", "host.docker.internal", 1)
	}
	return native
}

func (r *lambdaQueueReplay) command(t *testing.T, row lambdaQueueObservation) {
	t.Helper()
	var err error
	switch row.Operation {
	case "create-queue":
		input := lambdaQueueInput[sqs.CreateQueueInput](t, row)
		var out *sqs.CreateQueueOutput
		out, err = r.c.queues.CreateQueue(t.Context(), input)
		if err == nil {
			var native sqs.CreateQueueOutput
			if err := json.Unmarshal(row.Result.Output, &native); err != nil {
				t.Fatal(err)
			}
			r.urls[aws.ToString(native.QueueUrl)] = out.QueueUrl
		}
	case "set-queue-attributes":
		input := lambdaQueueInput[sqs.SetQueueAttributesInput](t, row)
		input.QueueUrl = r.urls[aws.ToString(input.QueueUrl)]
		_, err = r.c.queues.SetQueueAttributes(t.Context(), input)
	case "create-topic":
		var out *sns.CreateTopicOutput
		out, err = r.topics.CreateTopic(t.Context(), lambdaQueueInput[sns.CreateTopicInput](t, row))
		if err == nil {
			r.topicARNs = append(r.topicARNs, out.TopicArn)
		}
	case "subscribe":
		var out *sns.SubscribeOutput
		out, err = r.topics.Subscribe(t.Context(), lambdaQueueInput[sns.SubscribeInput](t, row))
		if err == nil {
			r.subscriptions = append(r.subscriptions, out.SubscriptionArn)
		}
	case "create-role":
		_, err = r.root.CreateRole(t.Context(), lambdaQueueInput[iam.CreateRoleInput](t, row))
	case "put-role-policy":
		_, err = r.root.PutRolePolicy(t.Context(), lambdaQueueInput[iam.PutRolePolicyInput](t, row))
	case "delete-role-policy":
		_, err = r.root.DeleteRolePolicy(t.Context(), lambdaQueueInput[iam.DeleteRolePolicyInput](t, row))
	case "create-function":
		input := lambdaQueueInput[awslambda.CreateFunctionInput](t, row)
		for key, value := range input.Environment.Variables {
			input.Environment.Variables[key] = r.localURL(value)
		}
		input.Environment.Variables["AWS_ENDPOINT_URL"] = r.endpoint
		_, err = r.c.lambda.CreateFunction(t.Context(), input)
		if err == nil {
			r.functions[aws.ToString(input.FunctionName)] = input
			err = awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute)
		}
	case "put-function-event-invoke-config":
		input := lambdaQueueInput[awslambda.PutFunctionEventInvokeConfigInput](t, row)
		_, err = r.c.lambda.PutFunctionEventInvokeConfig(t.Context(), input)
		if err == nil {
			r.settings[aws.ToString(input.FunctionName)] = input
		}
	case "update-function-configuration":
		input := lambdaQueueInput[awslambda.UpdateFunctionConfigurationInput](t, row)
		_, err = r.c.lambda.UpdateFunctionConfiguration(t.Context(), input)
		if err == nil {
			err = awslambda.NewFunctionUpdatedWaiter(r.c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute)
		}
	}
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	// Wait the ordinary deterministic configuration propagation delay without
	// changing native invocation spacing or minute aggregation boundaries.
	if row.Operation == "put-function-event-invoke-config" {
		if err := r.source.Advance(2 * time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.c.cloud.RunDueJobs(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
}

func lambdaQueueObject(t *testing.T, body string) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal([]byte(body), &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func lambdaQueueKind(t *testing.T, message sqstypes.Message) string {
	t.Helper()
	object := lambdaQueueObject(t, aws.ToString(message.Body))
	if kind, ok := object["kind"].(string); ok {
		return kind
	}
	if object["Type"] == "Notification" {
		object = lambdaQueueObject(t, object["Message"].(string))
	}
	if object["requestContext"] != nil {
		return "destination"
	}
	return "dlq"
}

func (r *lambdaQueueReplay) invoke(t *testing.T, invocation lambdaQueueInvocation) {
	t.Helper()
	var event map[string]any
	var payload []byte
	var err error
	if invocation.PayloadBase64 != "" {
		payload, err = base64.StdEncoding.DecodeString(invocation.PayloadBase64)
		if err != nil {
			t.Fatal(err)
		}
		event = lambdaQueueObject(t, string(payload))
	} else {
		event = lambdaQueueObject(t, string(invocation.Payload))
		payload = invocation.Payload
	}
	sourceID, _ := event["source_id"].(string)
	native := map[string][]sqstypes.Message{}
	for _, delivery := range r.receipts {
		if (sourceID != "" && delivery.SourceID == sourceID) || delivery.SourceLabel == invocation.Label {
			queue := delivery.Queue
			if queue == "" {
				queue = delivery.QueueKind
			}
			native[queue] = append(native[queue], delivery.Message)
			// The actual legacy receipt is authoritative for request bytes: JSON
			// re-marshalling would erase the captured spaces and literal UTF-8.
			if invocation.PayloadBase64 == "" && lambdaQueueKind(t, delivery.Message) == "dlq" {
				body := aws.ToString(delivery.Message.Body)
				object := lambdaQueueObject(t, body)
				if object["Type"] == "Notification" {
					body = object["Message"].(string)
				}
				payload = []byte(body)
			}
		}
	}
	if probe, ok := event["probe_queue"].(string); ok {
		// A stack-specific path is the only change to this customer request.
		payload = []byte(strings.ReplaceAll(string(payload), probe, r.localURL(probe)))
	}
	out, err := r.c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: aws.String(invocation.Function), InvocationType: lambdatypes.InvocationTypeEvent, Payload: payload})
	if err != nil || out.StatusCode != 202 || len(out.Payload) != 0 || out.FunctionError != nil {
		t.Fatalf("%s acceptance: %+v, %v", invocation.Label, out, err)
	}
	queueURL := func(kind string) *string {
		for native, url := range r.urls {
			if strings.HasSuffix(native, "/"+r.prefix+"-"+kind) {
				return url
			}
		}
		t.Fatalf("missing native %s queue", kind)
		return nil
	}
	auditMessage := lambdaEventsReceive(t, r.c, queueURL("audit"), 1)[0]
	audit := lambdaQueueObject(t, aws.ToString(auditMessage.Body))
	nativeAudit := native["audit"]
	if len(nativeAudit) != 1 {
		t.Fatalf("%s native audit count %d", invocation.Label, len(nativeAudit))
	}
	wantedAudit := lambdaQueueObject(t, aws.ToString(nativeAudit[0].Body))
	requestField := "aws_request_id"
	if audit["kind"] == "runtime_attempt" {
		requestField = "runtime_request_id"
	}
	requestID, _ := audit[requestField].(string)
	if requestID == "" || r.requests[requestID] {
		t.Fatal("actual runtime omitted or reused another event's request identity")
	}
	r.requests[requestID] = true
	if !reflect.DeepEqual(audit["event"], lambdaQueueObject(t, string(payload))) {
		t.Fatalf("runtime changed original event: %+v", audit)
	}
	for _, field := range []string{"kind", "invoked_function_arn", "function_version", "intended_error"} {
		if !reflect.DeepEqual(audit[field], wantedAudit[field]) {
			t.Fatalf("%s runtime %s: got %v want %v", invocation.Label, field, audit[field], wantedAudit[field])
		}
	}
	probeAllowed := false
	if probe, ok := audit["authority_probe"].(map[string]any); ok {
		probeAllowed = probe["code"] == "Success"
		expected := wantedAudit["authority_probe"].(map[string]any)
		// Native warm credentials briefly retained old policy during the global
		// deny experiment. Source-key cases are the settled authority evidence.
		if !strings.HasSuffix(invocation.Label, "-denied") && probeAllowed != (expected["code"] == "Success") {
			t.Fatalf("%s runtime source-key authority: %+v", invocation.Label, probe)
		}
		if !probeAllowed {
			failure, _ := probe["error"].(map[string]any)
			if failure["Code"] != "AccessDenied" {
				t.Fatalf("unexpected runtime authority failure: %+v", probe)
			}
		}
	}
	delete(native, "audit")
	failed := event["fail"] == true || audit["kind"] == "runtime_attempt"
	if r.metrics[invocation.Function] == nil {
		r.metrics[invocation.Function] = map[string]lambdaQueueMetric{}
	}
	for _, metric := range []string{"Invocations", "Errors", "AsyncEventsReceived", "AsyncEventsDropped", "DestinationDeliveryFailures", "DeadLetterErrors"} {
		value := r.metrics[invocation.Function][metric]
		if metric == "Invocations" || metric == "AsyncEventsReceived" {
			value.Sum++
			value.Samples++
		}
		if metric == "Errors" {
			value.Samples++
			if failed {
				value.Sum++
			}
		}
		if metric == "AsyncEventsDropped" {
			value.Samples++
			if failed {
				value.Sum++
			}
		}
		r.metrics[invocation.Function][metric] = value
	}
	for queue, messages := range native {
		expected := make([]sqstypes.Message, 0, len(messages))
		for _, message := range messages {
			if lambdaQueueKind(t, message) == "authority-positive-probe" && !probeAllowed {
				continue
			}
			expected = append(expected, message)
		}
		if len(expected) == 0 {
			continue
		}
		actual := lambdaEventsReceive(t, r.c, queueURL(queue), len(expected))
		sort.Slice(actual, func(i, j int) bool { return lambdaQueueKind(t, actual[i]) < lambdaQueueKind(t, actual[j]) })
		sort.Slice(expected, func(i, j int) bool { return lambdaQueueKind(t, expected[i]) < lambdaQueueKind(t, expected[j]) })
		for i, message := range actual {
			r.compareReceipt(t, invocation.Label, message, expected[i], requestID, payload)
		}
	}
	// Missing routes are observable too: Unicode SNS DLQ rejection cannot erase
	// a successful SQS destination, and neither denied route may retry later.
	var urls []*string
	for _, url := range r.urls {
		urls = append(urls, url)
	}
	// The runtime audit precedes handler completion. Finish delivery before
	// asserting absence or replaying the next IAM policy change.
	lambdaTargetsIdle(t, r.c)
	t.Logf("checking absent outcomes: invocation=%q function=%q request_id=%q source_id=%q", invocation.Label, invocation.Function, requestID, sourceID)
	lambdaEventsQuiet(t, r.c, urls...)
	// Failure samples have no synthetic zeros. Count only native absent platform
	// effects, never the runtime's supplementary positive-probe messages.
	config := r.settings[invocation.Function]
	function := r.functions[invocation.Function]
	hasDestination, hasDLQ := false, false
	for _, messages := range native {
		for _, message := range messages {
			switch lambdaQueueKind(t, message) {
			case "destination":
				hasDestination = true
			case "dlq":
				hasDLQ = true
			}
		}
	}
	destination := ""
	if config.DestinationConfig != nil {
		if failed && config.DestinationConfig.OnFailure != nil {
			destination = aws.ToString(config.DestinationConfig.OnFailure.Destination)
		}
		if !failed && config.DestinationConfig.OnSuccess != nil {
			destination = aws.ToString(config.DestinationConfig.OnSuccess.Destination)
		}
	}
	for metric, missing := range map[string]bool{"DestinationDeliveryFailures": destination != "" && !hasDestination, "DeadLetterErrors": failed && function.DeadLetterConfig != nil && aws.ToString(function.DeadLetterConfig.TargetArn) != "" && !hasDLQ} {
		if missing {
			value := r.metrics[invocation.Function][metric]
			value.Sum++
			value.Samples = 1
			r.metrics[invocation.Function][metric] = value
		}
	}
}

func (r *lambdaQueueReplay) compareReceipt(t *testing.T, label string, actual, native sqstypes.Message, requestID string, payload []byte) {
	t.Helper()
	kind := lambdaQueueKind(t, native)
	got, want := lambdaQueueObject(t, aws.ToString(actual.Body)), lambdaQueueObject(t, aws.ToString(native.Body))
	actualBody := aws.ToString(actual.Body)
	if want["Type"] == "Notification" {
		if got["Type"] != "Notification" || got["TopicArn"] != want["TopicArn"] {
			t.Fatalf("%s SNS envelope: %+v", label, got)
		}
		snsVerifySignature(t, got, r.endpoint, r.c.server.URL)
		actualBody = got["Message"].(string)
		if kind == "dlq" {
			actualAttributes, _ := got["MessageAttributes"].(map[string]any)
			wantedAttributes, _ := want["MessageAttributes"].(map[string]any)
			request := actualAttributes["RequestID"].(map[string]any)
			if request["Value"] != requestID {
				t.Fatalf("%s SNS DLQ lost runtime request ID", label)
			}
			request["Value"] = wantedAttributes["RequestID"].(map[string]any)["Value"]
			if !reflect.DeepEqual(actualAttributes, wantedAttributes) {
				t.Fatalf("%s SNS DLQ attributes differ: got %#v want %#v", label, actualAttributes, wantedAttributes)
			}
		}
		got, want = lambdaQueueObject(t, actualBody), lambdaQueueObject(t, want["Message"].(string))
	}
	switch kind {
	case "authority-positive-probe":
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s runtime probe: %+v", label, got)
		}
	case "dlq":
		if actualBody != string(payload) {
			t.Fatalf("%s DLQ changed original bytes:\ngot %q\nwant %q", label, actualBody, payload)
		}
		if len(native.MessageAttributes) != 0 {
			if aws.ToString(actual.MessageAttributes["RequestID"].StringValue) != requestID {
				t.Fatalf("%s DLQ lost runtime request ID", label)
			}
			attributes := actual.MessageAttributes
			request := attributes["RequestID"]
			request.StringValue = native.MessageAttributes["RequestID"].StringValue
			attributes["RequestID"] = request
			if !reflect.DeepEqual(attributes, native.MessageAttributes) {
				t.Fatalf("%s DLQ attributes differ: got %#v want %#v", label, attributes, native.MessageAttributes)
			}
			message := aws.ToString(attributes["ErrorMessage"].StringValue)
			if !utf8.ValidString(message) {
				t.Fatalf("%s DLQ error is invalid UTF-8", label)
			}
		}
	case "destination":
		context, ok := got["requestContext"].(map[string]any)
		if !ok || context["requestId"] != requestID {
			t.Fatalf("%s destination lost source runtime ID: %+v", label, got)
		}
		nativeContext := want["requestContext"].(map[string]any)
		context["requestId"] = nativeContext["requestId"]
		if stamp, ok := got["timestamp"].(string); !ok {
			t.Fatal("destination timestamp missing")
		} else if _, err := time.Parse("2006-01-02T15:04:05.000Z", stamp); err != nil {
			t.Fatal(err)
		}
		got["timestamp"] = want["timestamp"]
		if !reflect.DeepEqual(got["requestPayload"], lambdaQueueObject(t, string(payload))) {
			t.Fatalf("%s destination request changed", label)
		}
		// Local queue paths are normalized only after comparing the actual customer
		// event; everything in the final runtime response, including stackTrace and
		// the untruncated error, remains compared against the native receipt.
		got["requestPayload"] = want["requestPayload"]
		response := got["responsePayload"].(map[string]any)
		nativeResponse := want["responsePayload"].(map[string]any)
		for _, field := range []string{"requestId", "runtime_request_id"} {
			if value, exists := response[field]; exists {
				if value != requestID {
					t.Fatalf("%s response lost source request ID", label)
				}
				response[field] = nativeResponse[field]
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s destination differs:\ngot %#v\nnative %#v", label, got, want)
		}
	default:
		t.Fatalf("unrecognized native receipt %s", kind)
	}
}

func (r *lambdaQueueReplay) checkMetrics(t *testing.T) {
	t.Helper()
	if err := r.source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	client := metricsClient(cloudClients{r.c.server}, r.account)
	deadline := time.Now().Add(time.Minute)
	end := r.source.Now().UTC().Truncate(time.Minute)
	for {
		if _, err := r.c.cloud.RunDueJobs(t.Context(), 1000); err != nil {
			t.Fatal(err)
		}
		mismatch := ""
		for function, metrics := range r.metrics {
			for metric, want := range metrics {
				out, err := client.GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
					Namespace: aws.String("AWS/Lambda"), MetricName: aws.String(metric), Dimensions: []cwtypes.Dimension{{Name: aws.String("FunctionName"), Value: aws.String(function)}},
					StartTime: aws.Time(end.Add(-24 * time.Hour)), EndTime: &end, Period: aws.Int32(60), Statistics: []cwtypes.Statistic{cwtypes.StatisticSum, cwtypes.StatisticSampleCount},
				})
				if err != nil {
					t.Fatal(err)
				}
				var got lambdaQueueMetric
				for _, point := range out.Datapoints {
					got.Sum += aws.ToFloat64(point.Sum)
					got.Samples += aws.ToFloat64(point.SampleCount)
				}
				if got != want || (want.Samples == 0 && len(out.Datapoints) != 0) {
					mismatch = fmt.Sprintf("%s/%s: got %+v (%d datapoints), native %+v", function, metric, got, len(out.Datapoints), want)
				}
			}
		}
		if mismatch == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(mismatch)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
