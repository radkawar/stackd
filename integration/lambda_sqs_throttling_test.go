package stackd_test

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"stackd/clock"
	"stackd/storage"
)

type lambdaSQSThrottleFixture struct {
	Runs            []lambdaSQSControlRun
	MetricFollowups []struct {
		Observations []lambdaSQSControlRow
	} `json:"metric_followups"`
	Scenarios []lambdaSQSThrottleScenario `json:"scenario_summary"`
}

type lambdaSQSThrottleScenario struct {
	Name        string
	RunIndex    int `json:"run_index"`
	Function    string
	MappingUUID string `json:"mapping_uuid"`
	Visibility  int    `json:"visibility_seconds"`
	Records     []struct {
		ReceiveCount string `json:"receive_count"`
	} `json:"runtime_records"`
	Metrics map[string]struct{ Sum float64 } `json:"metrics"`
}

type lambdaSQSThrottleRecord struct {
	MessageID  string            `json:"messageId"`
	Body       string            `json:"body"`
	Receipt    string            `json:"receiptHandle"`
	Attributes map[string]string `json:"attributes"`
}

type lambdaSQSThrottleLog struct {
	Kind       string                                      `json:"kind"`
	RequestID  string                                      `json:"requestId"`
	Event      struct{ Records []lambdaSQSThrottleRecord } `json:"event"`
	MessageID  string                                      `json:"messageId"`
	MessageIDs []string                                    `json:"messageIds"`
}

type lambdaSQSThrottleReplay struct {
	*lambdaSQSDeliveryReplay
	native  lambdaSQSThrottleScenario
	queries map[string]cloudwatch.GetMetricStatisticsInput
	bodies  map[string]string
}

func (f lambdaSQSThrottleFixture) scenario(t *testing.T, name string) lambdaSQSThrottleScenario {
	t.Helper()
	for _, scenario := range f.Scenarios {
		if scenario.Name == name {
			return scenario
		}
	}
	t.Fatalf("missing native throttling scenario %s", name)
	return lambdaSQSThrottleScenario{}
}

func lambdaSQSThrottleSetup(t *testing.T, backend string, f lambdaSQSThrottleFixture, name string, saturated bool) *lambdaSQSThrottleReplay {
	t.Helper()
	native := f.scenario(t, name)
	run := f.Runs[native.RunIndex]
	control := newLambdaSQSControlReplay(run)
	// Start near a publication boundary, so observing failed-attempt metrics
	// does not consume a visibility lease. Docker readiness uses wall time.
	control.clock = clock.NewManual(run.StartedAt.Truncate(time.Minute).Add(50 * time.Second))
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sqs-throttling.sqlite"))
	}
	c := lambdaEventsConnect(t, backends, control.clock)
	r := &lambdaSQSThrottleReplay{
		lambdaSQSDeliveryReplay: &lambdaSQSDeliveryReplay{c: c, clock: control.clock, visibility: time.Duration(native.Visibility) * time.Second},
		native:                  native, queries: map[string]cloudwatch.GetMetricStatisticsInput{}, bodies: map[string]string{},
	}
	r.caseData.scenario.Label = name
	row := func(operation, label string) lambdaSQSControlRow {
		for _, observation := range run.Observations {
			if observation.Operation == operation && observation.Result.Code == "Success" && strings.HasPrefix(observation.Label, label) {
				return observation
			}
		}
		t.Fatalf("missing native %s %s", operation, label)
		return lambdaSQSControlRow{}
	}
	root := cloudClients{c.server}
	role := lambdaSQSNativeInput[iam.CreateRoleInput](t, row("create_role", "role_create").Input, control.normalize())
	if _, err := root.iam("test", "test", "").CreateRole(t.Context(), &role); err != nil {
		t.Fatal(err)
	}
	policy := lambdaSQSNativeInput[iam.PutRolePolicyInput](t, row("put_role_policy", "role_policy").Input, control.normalize())
	if _, err := root.iam("test", "test", "").PutRolePolicy(t.Context(), &policy); err != nil {
		t.Fatal(err)
	}
	logs := lambdaSQSNativeInput[cloudwatchlogs.CreateLogGroupInput](t, row("create_log_group", name+"_logs_create").Input, control.normalize())
	if _, err := logsClient(root, "test").CreateLogGroup(t.Context(), &logs); err != nil {
		t.Fatal(err)
	}
	function := lambdaSQSNativeInput[awslambda.CreateFunctionInput](t, row("create_function", name+"_function_create_").Input, control.normalize())
	created, err := c.lambda.CreateFunction(t.Context(), &function)
	if err != nil {
		t.Fatal(err)
	}
	c.functionName, c.functionARN = function.FunctionName, aws.ToString(created.FunctionArn)
	if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: c.functionName}, time.Minute); err != nil {
		t.Fatal(err)
	}
	queue := lambdaSQSNativeInput[sqs.CreateQueueInput](t, row("create_queue", name+"_queue_create").Input, control.normalize())
	if saturated {
		queue.Attributes["VisibilityTimeout"] = "120"
		r.visibility = 120 * time.Second
	}
	queued, err := c.queues.CreateQueue(t.Context(), &queue)
	if err != nil {
		t.Fatal(err)
	}
	r.queueURL = queued.QueueUrl
	control.replacements = append(control.replacements, row("create_queue", name+"_queue_create").Result.Output["QueueUrl"].(string), aws.ToString(r.queueURL))
	// Closing actual function admission is deterministic; the native fast case
	// occupied its reserved slot with a direct hold instead. Neither runs the
	// SQS handler on a rejected attempt. We do not reproduce AWS retry timing.
	capacity := int32(0)
	if name == "code_failure" {
		capacity = 1
	}
	r.reserve(t, capacity)
	mapping := lambdaSQSNativeInput[awslambda.CreateEventSourceMappingInput](t, row("create_event_source_mapping", name+"_mapping_create").Input, control.normalize())
	mapping.Enabled = aws.Bool(false)
	mapping.ScalingConfig = &lambdatypes.ScalingConfig{MaximumConcurrency: aws.Int32(2)}
	r.mapping, err = c.lambda.CreateEventSourceMapping(t.Context(), &mapping)
	if err != nil {
		t.Fatal(err)
	}
	r.state(t, "Disabled")
	control.replacements = append(control.replacements, native.MappingUUID, aws.ToString(r.mapping.UUID))
	// Preserve the native metric descriptors, including UUID-only ESM identity.
	// Earlier two-dimension empty queries are not evidence of zero activity.
	observations := append([]lambdaSQSControlRow(nil), run.Observations...)
	for _, followup := range f.MetricFollowups {
		observations = append(observations, followup.Observations...)
	}
	for _, observation := range observations {
		if observation.Operation != "get_metric_statistics" || observation.Result.Code != "Success" || !strings.HasPrefix(observation.Label, name+"_") {
			continue
		}
		query := lambdaSQSNativeInput[cloudwatch.GetMetricStatisticsInput](t, observation.Input, control.normalize())
		if len(query.Dimensions) != 1 || len(query.Statistics) != 1 || query.Statistics[0] != "Sum" {
			continue
		}
		// A similarly named scenario from another run must not supply dimensions.
		identity := aws.ToString(query.Dimensions[0].Value)
		if identity != aws.ToString(r.mapping.UUID) && identity != native.Function && identity != aws.ToString(queue.QueueName) {
			continue
		}
		query.StartTime = aws.Time(r.clock.Now().Add(-time.Minute))
		r.queries[aws.ToString(query.MetricName)] = query
	}
	r.enabled(t, true)
	send := lambdaSQSNativeInput[sqs.SendMessageInput](t, row("send_message", name+"_send").Input, control.normalize())
	messages := 1
	if saturated {
		messages = 2
	}
	for range messages {
		out, err := c.queues.SendMessage(t.Context(), &send)
		if err != nil {
			t.Fatal(err)
		}
		id := aws.ToString(out.MessageId)
		if _, duplicate := r.bodies[id]; id == "" || duplicate {
			t.Fatalf("source send reused message ID %q", id)
		}
		r.bodies[id] = aws.ToString(send.MessageBody)
	}
	return r
}

func (r *lambdaSQSThrottleReplay) reserve(t *testing.T, capacity int32) {
	t.Helper()
	if _, err := r.c.lambda.PutFunctionConcurrency(t.Context(), &awslambda.PutFunctionConcurrencyInput{FunctionName: r.c.functionName, ReservedConcurrentExecutions: &capacity}); err != nil {
		t.Fatal(err)
	}
}

func (r *lambdaSQSThrottleReplay) mappingAbsentResult(t *testing.T) {
	t.Helper()
	out, err := r.c.lambda.GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: r.mapping.UUID})
	if err != nil {
		t.Fatal(err)
	}
	if out.LastProcessingResult != nil {
		t.Fatalf("SQS Get invented LastProcessingResult=%q", *out.LastProcessingResult)
	}
	listed, err := r.c.lambda.ListEventSourceMappings(t.Context(), &awslambda.ListEventSourceMappingsInput{FunctionName: r.c.functionName})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.EventSourceMappings) != 1 || aws.ToString(listed.EventSourceMappings[0].UUID) != aws.ToString(r.mapping.UUID) {
		t.Fatalf("list lost the source mapping: %+v", listed.EventSourceMappings)
	}
	if listed.EventSourceMappings[0].LastProcessingResult != nil {
		t.Fatalf("SQS List invented LastProcessingResult=%q", *listed.EventSourceMappings[0].LastProcessingResult)
	}
}

func (r *lambdaSQSThrottleReplay) metric(t *testing.T, name string) float64 {
	t.Helper()
	query, ok := r.queries[name]
	if !ok {
		t.Fatalf("no native query for %s", name)
	}
	query.EndTime = aws.Time(r.clock.Now().Add(time.Minute))
	out, err := metricsClient(cloudClients{r.c.server}, "test").GetMetricStatistics(t.Context(), &query)
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, point := range out.Datapoints {
		total += aws.ToFloat64(point.Sum)
	}
	return total
}

func (r *lambdaSQSThrottleReplay) logs(t *testing.T) []lambdaSQSThrottleLog {
	t.Helper()
	query := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + aws.ToString(r.c.functionName)), FilterPattern: aws.String(`"SQSTHR"`)}
	client := logsClient(cloudClients{r.c.server}, "test")
	var records []lambdaSQSThrottleLog
	for {
		out, err := client.FilterLogEvents(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			message := aws.ToString(event.Message)
			at := strings.Index(message, "SQSTHR ")
			if at < 0 {
				continue
			}
			var record lambdaSQSThrottleLog
			if err := json.Unmarshal([]byte(strings.TrimSpace(message[at+len("SQSTHR "):])), &record); err != nil {
				t.Fatal(err)
			}
			records = append(records, record)
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(query.NextToken) {
			return records
		}
		query.NextToken = out.NextToken
	}
}

func (r *lambdaSQSThrottleReplay) awaitThrottled(t *testing.T) {
	t.Helper()
	r.wait(t, 3*time.Second, func() bool {
		visible, hidden := r.counts(t)
		return visible == 0 && hidden == len(r.bodies)
	})
	// At most the next minute boundary, never a full lease. Keep both live
	// batches parked in real throttled admission before restoring capacity.
	publish := r.clock.Now().Truncate(time.Minute).Add(time.Minute + time.Second)
	r.wait(t, publish.Sub(r.clock.Now()), func() bool {
		return r.metric(t, "FailedInvokeEventCount") >= float64(len(r.bodies))
	})
	visible, hidden := r.counts(t)
	if visible != 0 || hidden != len(r.bodies) || len(r.logs(t)) != 0 || r.metric(t, "Invocations") != 0 || r.metric(t, "DeletedEventCount") != 0 {
		t.Fatalf("throttled admission ran or lost source records: visible=%d hidden=%d", visible, hidden)
	}
	r.mappingAbsentResult(t)
}

func (r *lambdaSQSThrottleReplay) finishThrottle(t *testing.T) {
	t.Helper()
	if len(r.native.Records) == 0 {
		t.Fatal("native scenario has no runtime records")
	}
	lastReceive, err := strconv.Atoi(r.native.Records[len(r.native.Records)-1].ReceiveCount)
	if err != nil || lastReceive < 1 {
		t.Fatal("native scenario has no valid final receive count")
	}
	// Only the lease relationship is replayed: count1 means a retained
	// receive; larger native counts require fresh delivery, not that exact count.
	fresh := lastReceive > 1
	codeFailure := r.native.Metrics["Errors"].Sum > 0
	// Bounded service movement lets retries/polls wake; the remaining wall
	// minute is exclusively for the official Node container and log ingestion.
	r.wait(t, 10*time.Second, func() bool {
		visible, hidden := r.counts(t)
		return visible == 0 && hidden == 0
	})
	r.mappingAbsentResult(t)
	r.enabled(t, false)
	r.wait(t, 0, func() bool {
		successes := 0
		for _, entry := range r.logs(t) {
			if entry.Kind == "success" {
				successes++
			}
		}
		return successes == len(r.bodies)
	})
	starts := map[string]lambdaSQSThrottleRecord{}
	outcomes := map[string]lambdaSQSThrottleLog{}
	for _, entry := range r.logs(t) {
		if entry.RequestID == "" {
			t.Fatal("runtime omitted request ID")
		}
		switch entry.Kind {
		case "start":
			if _, duplicate := starts[entry.RequestID]; duplicate || len(entry.Event.Records) != 1 {
				t.Fatalf("unexpected source invocation: %+v", entry)
			}
			starts[entry.RequestID] = entry.Event.Records[0]
		case "throw", "success":
			if _, duplicate := outcomes[entry.RequestID]; duplicate {
				t.Fatalf("runtime completed request twice: %s", entry.RequestID)
			}
			outcomes[entry.RequestID] = entry
		default:
			t.Fatalf("unexpected direct invocation in isolated replay: %+v", entry)
		}
	}
	seen := map[string]int{}
	receives := map[string]int{}
	var errors, successes int
	var failedReceipt, successfulReceipt string
	for request, record := range starts {
		body, expected := r.bodies[record.MessageID]
		if !expected || body != record.Body || record.Receipt == "" {
			t.Fatalf("runtime lost exact source identity/body/receipt: %+v", record)
		}
		count, err := strconv.Atoi(record.Attributes["ApproximateReceiveCount"])
		if err != nil || count < 1 {
			t.Fatalf("invalid runtime receive count: %+v", record)
		}
		outcome, ok := outcomes[request]
		if !ok {
			t.Fatalf("source request %s has no handler completion", request)
		}
		if outcome.Kind == "throw" {
			if !codeFailure || count != 1 || outcome.MessageID != record.MessageID {
				t.Fatalf("unexpected failed delivery: %+v %+v", record, outcome)
			}
			errors++
			failedReceipt = record.Receipt
		} else {
			if len(outcome.MessageIDs) != 1 || outcome.MessageIDs[0] != record.MessageID {
				t.Fatalf("success did not identify its source record: %+v", outcome)
			}
			if (fresh || codeFailure) && count < 2 {
				t.Fatalf("expired/failed lease invoked original receive instead of fresh SQS delivery: %+v", record)
			}
			if !fresh && !codeFailure && count != 1 {
				t.Fatalf("retained throttled batch performed another receive: %+v", record)
			}
			successes++
			seen[record.MessageID]++
			successfulReceipt = record.Receipt
		}
		receives[record.MessageID] = max(receives[record.MessageID], count)
	}
	for id := range r.bodies {
		if seen[id] != 1 {
			t.Fatalf("source %s succeeded %d times", id, seen[id])
		}
	}
	if len(outcomes) != len(starts) || codeFailure && (errors != 1 || failedReceipt == successfulReceipt) {
		t.Fatal("function failure did not redeliver under a fresh receipt with one error")
	}
	advanceClock(t, r.clock, time.Minute)
	trailNativeDrain(t, r.c.cloud)
	metrics := map[string]float64{}
	for name := range r.queries {
		metrics[name] = r.metric(t, name)
	}
	var polled int
	for _, count := range receives {
		polled += count
	}
	// Counts compare source records, attempts, real executions and completions.
	// The native warm/direct calls are deliberately absent locally; neither
	// their Invocations total nor their retry counts are a scheduler contract.
	if metrics["NumberOfMessagesSent"] != float64(len(r.bodies)) || metrics["PolledEventCount"] != float64(polled) || metrics["NumberOfMessagesReceived"] != metrics["PolledEventCount"] || metrics["DeletedEventCount"] != float64(successes) || metrics["NumberOfMessagesDeleted"] != metrics["DeletedEventCount"] {
		t.Fatalf("source receive/delete counters disagree with exact runtime records: %v", metrics)
	}
	if metrics["Invocations"] != float64(len(starts)) || metrics["Errors"] != float64(errors) || metrics["InvokedEventCount"] != metrics["FailedInvokeEventCount"]+float64(successes) || metrics["FailedInvokeEventCount"] != metrics["Throttles"]+float64(errors) {
		t.Fatalf("attempt counters confused throttling with actual execution: %v", metrics)
	}
	if codeFailure {
		if metrics["Throttles"] != 0 || metrics["InvokedEventCount"] != metrics["PolledEventCount"] {
			t.Fatalf("ordinary function error retried a retained batch: %v", metrics)
		}
	} else if metrics["Throttles"] <= 0 || !fresh && metrics["InvokedEventCount"] <= metrics["PolledEventCount"] {
		t.Fatalf("missing retained throttled attempts: %v", metrics)
	}
	r.mappingAbsentResult(t)
}

func TestLambdaSQSMappingDockerNativeThrottleLeases(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[lambdaSQSThrottleFixture](t, "sqs_mapping_throttling")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, name := range []string{"before_expiry_fast", "after_expiry", "code_failure"} {
			t.Run(backend+"/"+name, func(t *testing.T) {
				r := lambdaSQSThrottleSetup(t, backend, fixture, name, false)
				if r.native.Metrics["Errors"].Sum > 0 {
					r.wait(t, 3*time.Second, func() bool {
						for _, entry := range r.logs(t) {
							if entry.Kind == "throw" {
								return true
							}
						}
						return false
					})
					publish := r.clock.Now().Truncate(time.Minute).Add(time.Minute + time.Second)
					r.wait(t, publish.Sub(r.clock.Now()), func() bool { return r.metric(t, "Errors") > 0 })
					if visible, hidden := r.counts(t); visible != 0 || hidden != 1 || r.metric(t, "DeletedEventCount") != 0 {
						t.Fatalf("function-code error deleted/released its source lease: visible=%d hidden=%d", visible, hidden)
					}
					r.mappingAbsentResult(t)
					advanceClock(t, r.clock, r.visibility+time.Second)
					r.finishThrottle(t)
					return
				}
				r.awaitThrottled(t)
				fresh := r.native.Records[len(r.native.Records)-1].ReceiveCount != "1"
				if fresh {
					// Capacity remains closed over expiry; a later successful
					// handler must observe a new receive of the original ID.
					advanceClock(t, r.clock, r.visibility+time.Second)
				}
				r.reserve(t, 2)
				r.finishThrottle(t)
			})
		}
	}
}

func TestLambdaSQSMappingDockerThrottleClockJump(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[lambdaSQSThrottleFixture](t, "sqs_mapping_throttling")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := lambdaSQSThrottleSetup(t, backend, fixture, "after_expiry", true)
			r.awaitThrottled(t)
			// Both BatchSize=1 slots are occupied by 120s source leases, with
			// actual failed attempts observed. There is no spare poller to
			// race a new receive against the old sleeping batch on this jump.
			r.reserve(t, 2)
			advanceClock(t, r.clock, 121*time.Second)
			r.finishThrottle(t)
		})
	}
}
