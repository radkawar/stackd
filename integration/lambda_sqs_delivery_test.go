package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd/clock"
	"stackd/storage"
)

type lambdaSQSDeliveryObservation struct {
	lambdaURLRow
	Slice string `json:"capture_slice"`
}

type lambdaSQSRuntimeEvidence struct {
	Kind      string          `json:"kind"`
	RequestID string          `json:"requestId"`
	Event     map[string]any  `json:"event"`
	Response  json.RawMessage `json:"response"`
}

type lambdaSQSDeliveryScenario struct {
	Label, Token string
	Slice        string `json:"capture_slice"`
	InputLabel   string `json:"input_observation_label"`
	Inputs       []json.RawMessage
	MessageIDs   []string `json:"message_ids"`
	BatchSize    int32    `json:"batch_size"`
	Window       int32    `json:"batch_window_seconds"`
	Partial      bool     `json:"partial_batch_enabled"`
	SendResult   struct {
		Successful []sqstypes.SendMessageBatchResultEntry
	} `json:"send_result"`
}

type lambdaSQSDeliveryFixture struct {
	Account, Prefix string
	StartedAt       time.Time `json:"started_at"`
	Artifact        struct {
		ZIP string `json:"zip_base64"`
	}
	Observations []lambdaSQSDeliveryObservation
	Runtime      []lambdaSQSRuntimeEvidence `json:"runtime_evidence"`
	Scenarios    []lambdaSQSDeliveryScenario
	Isolated     []lambdaSQSDeliveryScenario `json:"isolated_scenarios"`
}

func (f lambdaSQSDeliveryFixture) row(t *testing.T, slice, label string) lambdaSQSDeliveryObservation {
	t.Helper()
	for _, row := range f.Observations {
		if row.Slice == slice && row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native %s/%s", slice, label)
	return lambdaSQSDeliveryObservation{}
}

// Native binary captures retain bytes with explicit metadata. The SDK consumes
// base64 JSON strings; no request value other than that representation changes.
func lambdaSQSNativeInput[T any](t *testing.T, input json.RawMessage, replacements *strings.Replacer) T {
	t.Helper()
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	var binary func(any) any
	binary = func(v any) any {
		switch v := v.(type) {
		case map[string]any:
			if encoded, ok := v["base64"].(string); ok {
				return encoded
			}
			for key, child := range v {
				v[key] = binary(child)
			}
		case []any:
			for i, child := range v {
				v[i] = binary(child)
			}
		}
		return v
	}
	return lambdaStreamingInput[T](t, lambdaQualifiedJSON(t, binary(value)), replacements)
}

type lambdaSQSDeliveryCaseData struct {
	fixture        lambdaSQSDeliveryFixture
	scenario       lambdaSQSDeliveryScenario
	queue, mapping lambdaSQSDeliveryObservation
	send           sqs.SendMessageBatchInput
	nativeIDs      map[string]string           // send entry ID -> native message ID
	native         map[string][]map[string]any // exact native ID -> records, in receive order
}

func lambdaSQSDeliveryCase(t *testing.T, f lambdaSQSDeliveryFixture, label string) lambdaSQSDeliveryCaseData {
	t.Helper()
	var scenario lambdaSQSDeliveryScenario
	for _, s := range append(append([]lambdaSQSDeliveryScenario{}, f.Scenarios...), f.Isolated...) {
		if s.Label == label {
			scenario = s
			break
		}
	}
	if scenario.Label == "" {
		t.Fatalf("missing native scenario %s", label)
	}
	c := lambdaSQSDeliveryCaseData{fixture: f, scenario: scenario, nativeIDs: map[string]string{}, native: map[string][]map[string]any{}}
	if scenario.Slice == "" {
		suffix := "False"
		if label == "fifo_groups_order" {
			suffix = "True"
		}
		c.queue, c.mapping = f.row(t, "primary", "queue_create_"+suffix), f.row(t, "primary", "mapping_create_"+suffix)
		for _, input := range scenario.Inputs {
			c.send.Entries = append(c.send.Entries, lambdaSQSNativeInput[sqstypes.SendMessageBatchRequestEntry](t, input, strings.NewReplacer()))
		}
		for _, entry := range scenario.SendResult.Successful {
			c.nativeIDs[aws.ToString(entry.Id)] = aws.ToString(entry.MessageId)
		}
	} else {
		c.queue = f.row(t, scenario.Slice, "queue_create")
		for _, row := range f.Observations {
			if row.Slice == scenario.Slice && row.Operation == "create_event_source_mapping" && row.Result.Code == "Success" {
				c.mapping = row
				break
			}
		}
		send := f.row(t, scenario.Slice, scenario.InputLabel)
		c.send = lambdaSQSNativeInput[sqs.SendMessageBatchInput](t, send.Input, strings.NewReplacer())
		result := lambdaSQSNativeInput[sqs.SendMessageBatchOutput](t, lambdaQualifiedJSON(t, send.Result.Output), strings.NewReplacer())
		for _, entry := range result.Successful {
			c.nativeIDs[aws.ToString(entry.Id)] = aws.ToString(entry.MessageId)
		}
	}
	owned := map[string]bool{}
	for _, id := range scenario.MessageIDs {
		owned[id] = true
	}
	for _, invocation := range f.Runtime {
		if invocation.Kind != "ESM_EVENT" {
			continue
		}
		for _, value := range invocation.Event["Records"].([]any) {
			record := value.(map[string]any)
			id := record["messageId"].(string)
			if owned[id] {
				c.native[id] = append(c.native[id], record)
			}
		}
	}
	if len(c.nativeIDs) != len(c.send.Entries) || len(c.native) == 0 {
		t.Fatalf("incomplete native source/runtime joins for %s", label)
	}
	return c
}

type lambdaSQSDeliveryReplay struct {
	c                *lambdaEventsCloud
	backends         *storage.Backends
	clock            *clock.Manual
	mapping          *awslambda.CreateEventSourceMappingOutput
	queueURL         *string
	queueARN, sender string
	ids              map[string]string // native ID -> SDK-created local ID
	sequences        map[string]string
	caseData         lambdaSQSDeliveryCaseData
	sentAt           time.Time
	visibility       time.Duration
	path             string
	closeDatabase    func()
}

func lambdaSQSDeliverySetup(t *testing.T, backend string, data lambdaSQSDeliveryCaseData) *lambdaSQSDeliveryReplay {
	t.Helper()
	r := &lambdaSQSDeliveryReplay{caseData: data, clock: clock.NewManual(data.fixture.StartedAt), backends: storage.NewMemory(), ids: map[string]string{}, sequences: map[string]string{}}
	if backend == "sqlite" {
		r.path = filepath.Join(t.TempDir(), "lambda-sqs.sqlite")
		r.backends, r.closeDatabase = openSQLiteBackends(t, r.path)
	}
	r.c = lambdaEventsConnect(t, r.backends, r.clock)
	f := data.fixture
	root := cloudClients{r.c.server}
	identity, err := root.sts("test", "test", "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	r.sender = aws.ToString(identity.UserId)
	replace := strings.NewReplacer(f.Account, aws.ToString(identity.Account))
	roleInput := lambdaSQSNativeInput[iam.CreateRoleInput](t, f.row(t, "primary", "role_create").Input, replace)
	role, err := root.iam("test", "test", "").CreateRole(t.Context(), &roleInput)
	if err != nil {
		t.Fatal(err)
	}
	policy := lambdaSQSNativeInput[iam.PutRolePolicyInput](t, f.row(t, "primary", "role_policy").Input, replace)
	if _, err := root.iam("test", "test", "").PutRolePolicy(t.Context(), &policy); err != nil {
		t.Fatal(err)
	}
	logInput := lambdaSQSNativeInput[cloudwatchlogs.CreateLogGroupInput](t, f.row(t, "primary", "logs_create").Input, replace)
	if _, err := logsClient(root, "test").CreateLogGroup(t.Context(), &logInput); err != nil {
		t.Fatal(err)
	}
	function := lambdaSQSNativeInput[awslambda.CreateFunctionInput](t, f.row(t, "primary", "function_create_3").Input, replace)
	function.Role = role.Role.Arn
	created, err := r.c.lambda.CreateFunction(t.Context(), &function)
	if err != nil {
		t.Fatal(err)
	}
	r.c.functionName, r.c.functionARN = function.FunctionName, aws.ToString(created.FunctionArn)
	if err := awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: function.FunctionName}, time.Minute); err != nil {
		t.Fatal(err)
	}
	queue := lambdaSQSNativeInput[sqs.CreateQueueInput](t, data.queue.Input, replace)
	out, err := r.c.queues.CreateQueue(t.Context(), &queue)
	if err != nil {
		t.Fatal(err)
	}
	r.queueURL = out.QueueUrl
	seconds, err := strconv.Atoi(queue.Attributes["VisibilityTimeout"])
	if err != nil {
		t.Fatal(err)
	}
	r.visibility = time.Duration(seconds) * time.Second
	attributes, err := r.c.queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: r.queueURL, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
	if err != nil {
		t.Fatal(err)
	}
	r.queueARN = attributes.Attributes["QueueArn"]
	mapping := lambdaSQSNativeInput[awslambda.CreateEventSourceMappingInput](t, data.mapping.Input, replace)
	mapping.EventSourceArn, mapping.FunctionName, mapping.Enabled = &r.queueARN, r.c.functionName, aws.Bool(false)
	if data.scenario.Slice == "" {
		mapping.BatchSize, mapping.MaximumBatchingWindowInSeconds = &data.scenario.BatchSize, &data.scenario.Window
		if data.scenario.Partial {
			mapping.FunctionResponseTypes = []lambdatypes.FunctionResponseType{lambdatypes.FunctionResponseTypeReportBatchItemFailures}
		}
	}
	r.mapping, err = r.c.lambda.CreateEventSourceMapping(t.Context(), &mapping)
	if err != nil {
		t.Fatal(err)
	}
	r.state(t, "Disabled")
	return r
}

// Clock-driven bounded SDK waiter. A separate wall deadline bounds a stuck real
// Docker executor; service time never races ahead through a visibility lease.
func (r *lambdaSQSDeliveryReplay) wait(t *testing.T, advance time.Duration, predicate func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	until := r.clock.Now().Add(advance)
	for {
		if _, err := r.c.cloud.RunDueJobs(ctx, 100); err != nil {
			t.Fatal(err)
		}
		if predicate() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("SQS %s did not settle: %v", r.caseData.scenario.Label, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
		if r.clock.Now().Before(until) {
			advanceClock(t, r.clock, min(100*time.Millisecond, until.Sub(r.clock.Now())))
		}
	}
}

func (r *lambdaSQSDeliveryReplay) state(t *testing.T, state string) {
	t.Helper()
	r.wait(t, 2*time.Second, func() bool {
		out, err := r.c.lambda.GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: r.mapping.UUID})
		if err != nil {
			t.Fatal(err)
		}
		return aws.ToString(out.State) == state
	})
}

func (r *lambdaSQSDeliveryReplay) enabled(t *testing.T, enabled bool) {
	t.Helper()
	if _, err := r.c.lambda.UpdateEventSourceMapping(t.Context(), &awslambda.UpdateEventSourceMappingInput{UUID: r.mapping.UUID, Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	state := "Disabled"
	if enabled {
		state = "Enabled"
	}
	r.state(t, state)
}

func (r *lambdaSQSDeliveryReplay) counts(t *testing.T) (visible, hidden int) {
	t.Helper()
	out, err := r.c.queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: r.queueURL, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameApproximateNumberOfMessages, sqstypes.QueueAttributeNameApproximateNumberOfMessagesNotVisible}})
	if err != nil {
		t.Fatal(err)
	}
	visible, err = strconv.Atoi(out.Attributes["ApproximateNumberOfMessages"])
	if err != nil {
		t.Fatal(err)
	}
	hidden, err = strconv.Atoi(out.Attributes["ApproximateNumberOfMessagesNotVisible"])
	if err != nil {
		t.Fatal(err)
	}
	return
}

func (r *lambdaSQSDeliveryReplay) seed(t *testing.T) {
	t.Helper()
	input := r.caseData.send
	input.QueueUrl = r.queueURL
	r.sentAt = r.clock.Now()
	out, err := r.c.queues.SendMessageBatch(t.Context(), &input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Failed) != 0 || len(out.Successful) != len(input.Entries) {
		t.Fatalf("source send failed: %+v", out)
	}
	for _, entry := range out.Successful {
		native := r.caseData.nativeIDs[aws.ToString(entry.Id)]
		if native == "" || aws.ToString(entry.MessageId) == "" {
			t.Fatalf("unjoined send result: %+v", entry)
		}
		r.ids[native] = aws.ToString(entry.MessageId)
		r.sequences[native] = aws.ToString(entry.SequenceNumber)
	}
	// No consumer receive is used here: incrementing ApproximateReceiveCount
	// would silently turn the retained first-attempt error handler into success.
	advanceClock(t, r.clock, 2*time.Second)
	if visible, hidden := r.counts(t); visible != len(input.Entries) || hidden != 0 {
		t.Fatalf("disabled mapping consumed seeded IDs: visible=%d hidden=%d", visible, hidden)
	}
	if evidence := r.runtime(t); len(evidence) != 0 {
		t.Fatalf("disabled mapping invoked customer code: %+v", evidence)
	}
}

func (r *lambdaSQSDeliveryReplay) runtime(t *testing.T) []lambdaSQSRuntimeEvidence {
	t.Helper()
	client := logsClient(cloudClients{r.c.server}, "test")
	query := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + r.caseData.fixture.Prefix), FilterPattern: aws.String(`"ESM_EVENT"`)}
	var result []lambdaSQSRuntimeEvidence
	requests := map[string]bool{}
	for {
		out, err := client.FilterLogEvents(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		for _, log := range out.Events {
			message := aws.ToString(log.Message)
			at := strings.Index(message, "ESM_EVENT ")
			if at < 0 {
				continue
			}
			var evidence lambdaSQSRuntimeEvidence
			if err := json.Unmarshal([]byte(strings.TrimSpace(message[at+len("ESM_EVENT "):])), &evidence); err != nil {
				t.Fatal(err)
			}
			evidence.Kind = "ESM_EVENT"
			if evidence.RequestID == "" || requests[evidence.RequestID] {
				t.Fatalf("missing or duplicate runtime request ID %q", evidence.RequestID)
			}
			requests[evidence.RequestID] = true
			result = append(result, evidence)
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(query.NextToken) {
			break
		}
		query.NextToken = out.NextToken
	}
	// Completion evidence is restricted to exact runtime IDs, never a prefix or
	// all unrelated streams. An ESM_EVENT alone is not proof of handler success.
	for i := range result {
		out, err := client.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: query.LogGroupName, FilterPattern: aws.String(`"` + result[i].RequestID + `"`)})
		if err != nil {
			t.Fatal(err)
		}
		for _, log := range out.Events {
			message := aws.ToString(log.Message)
			for _, kind := range []string{"ESM_RESPONSE", "ESM_THROW"} {
				at := strings.Index(message, kind+" ")
				if at < 0 {
					continue
				}
				var completion lambdaSQSRuntimeEvidence
				if err := json.Unmarshal([]byte(strings.TrimSpace(message[at+len(kind)+1:])), &completion); err != nil {
					t.Fatal(err)
				}
				if completion.RequestID != result[i].RequestID {
					t.Fatalf("completion request ID mismatch")
				}
				result[i].Kind, result[i].Response = kind, completion.Response
			}
		}
	}
	return result
}

func (r *lambdaSQSDeliveryReplay) observed(t *testing.T, evidence []lambdaSQSRuntimeEvidence) map[string][]map[string]any {
	t.Helper()
	local := map[string]string{}
	for native, id := range r.ids {
		local[id] = native
	}
	observed := map[string][]map[string]any{}
	for _, invocation := range evidence {
		records, ok := invocation.Event["Records"].([]any)
		if !ok || len(records) == 0 || len(records) > int(aws.ToInt32(r.mapping.BatchSize)) {
			t.Fatalf("illegal batch count: %v", invocation.Event)
		}
		if len(invocation.Event) != 1 {
			t.Fatalf("native SQS event envelope differs: %v", invocation.Event)
		}
		for _, value := range records {
			record := value.(map[string]any)
			native, ok := local[record["messageId"].(string)]
			if !ok {
				t.Fatalf("runtime message ID not in exact SDK send results: %v", record)
			}
			observed[native] = append(observed[native], record)
		}
	}
	return observed
}

func (r *lambdaSQSDeliveryReplay) awaitAttempt(t *testing.T, attempt int) []lambdaSQSRuntimeEvidence {
	t.Helper()
	var evidence []lambdaSQSRuntimeEvidence
	r.wait(t, time.Duration(aws.ToInt32(r.mapping.MaximumBatchingWindowInSeconds)+1)*time.Second, func() bool {
		evidence = r.runtime(t)
		observed := r.observed(t, evidence)
		for id, records := range observed {
			if len(records) > min(attempt, len(r.caseData.native[id])) {
				t.Fatalf("unexpected delivery/retry for exact native ID %s: %+v", id, records)
			}
		}
		for id, native := range r.caseData.native {
			if len(observed[id]) != min(attempt, len(native)) {
				return false
			}
		}
		for _, invocation := range evidence {
			if invocation.Kind == "ESM_EVENT" {
				return false
			}
		}
		return true
	})
	return evidence
}

func (r *lambdaSQSDeliveryReplay) assertRecords(t *testing.T, evidence []lambdaSQSRuntimeEvidence) {
	t.Helper()
	observed := r.observed(t, evidence)
	for id, native := range r.caseData.native {
		actual := observed[id]
		if len(actual) != len(native) {
			t.Fatalf("exact ID %s attempts=%d native=%d", id, len(actual), len(native))
		}
		for attempt, wantRecord := range native {
			want := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, wantRecord), strings.NewReplacer())
			got := actual[attempt]
			want["messageId"], want["eventSourceARN"] = r.ids[id], r.queueARN
			receipt, ok := got["receiptHandle"].(string)
			if !ok || receipt == "" {
				t.Fatal("runtime omitted source receipt")
			}
			want["receiptHandle"] = receipt
			if attempt > 0 && receipt == actual[attempt-1]["receiptHandle"] {
				t.Fatal("visibility retry reused a receipt")
			}
			attrs := got["attributes"].(map[string]any)
			expected := want["attributes"].(map[string]any)
			expected["SenderId"] = r.sender
			expected["SentTimestamp"] = strconv.FormatInt(r.sentAt.UnixMilli(), 10)
			first, err := strconv.ParseInt(fmt.Sprint(attrs["ApproximateFirstReceiveTimestamp"]), 10, 64)
			if err != nil || first < r.sentAt.UnixMilli() || first > r.clock.Now().UnixMilli() {
				t.Fatalf("invalid first receive timestamp: %v", attrs)
			}
			if attempt > 0 && attrs["ApproximateFirstReceiveTimestamp"] != actual[0]["attributes"].(map[string]any)["ApproximateFirstReceiveTimestamp"] {
				t.Fatal("retry reset first receive timestamp")
			}
			expected["ApproximateFirstReceiveTimestamp"] = strconv.FormatInt(first, 10)
			if _, fifo := expected["SequenceNumber"]; fifo {
				expected["SequenceNumber"] = r.sequences[id]
			}
			// Comparing whole objects preserves absent scalar fields, both empty
			// attribute lists, normalized Number strings and binary base64 bytes.
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("native record %s attempt %d differs:\ngot %s\nwant %s", id, attempt+1, lambdaQualifiedJSON(t, got), lambdaQualifiedJSON(t, want))
			}
		}
	}
	r.assertResponses(t, evidence)
	if r.caseData.scenario.Label == "fifo_groups_order" {
		want, got := map[string][]string{}, map[string][]string{}
		for _, entry := range r.caseData.send.Entries {
			group := aws.ToString(entry.MessageGroupId)
			want[group] = append(want[group], r.ids[r.caseData.nativeIDs[aws.ToString(entry.Id)]])
		}
		for _, invocation := range evidence {
			for _, value := range invocation.Event["Records"].([]any) {
				record := value.(map[string]any)
				group := record["attributes"].(map[string]any)["MessageGroupId"].(string)
				got[group] = append(got[group], record["messageId"].(string))
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("FIFO per-group delivery order got %v want %v", got, want)
		}
	}
}

// Repack only valid native failed-message IDs to the actual legal batch. Invalid
// IDs/types and the missing-member response remain literal native responses.
func (r *lambdaSQSDeliveryReplay) assertResponses(t *testing.T, evidence []lambdaSQSRuntimeEvidence) {
	t.Helper()
	completions := map[string]lambdaSQSRuntimeEvidence{}
	for _, row := range r.caseData.fixture.Runtime {
		if row.Kind == "ESM_RESPONSE" || row.Kind == "ESM_THROW" {
			completions[row.RequestID] = row
		}
	}
	native := map[string]lambdaSQSRuntimeEvidence{}
	for _, row := range r.caseData.fixture.Runtime {
		if row.Kind != "ESM_EVENT" {
			continue
		}
		for _, value := range row.Event["Records"].([]any) {
			record := value.(map[string]any)
			id := record["messageId"].(string)
			if local, ok := r.ids[id]; ok {
				count := record["attributes"].(map[string]any)["ApproximateReceiveCount"].(string)
				native[local+"/"+count] = completions[row.RequestID]
			}
		}
	}
	for _, invocation := range evidence {
		records := invocation.Event["Records"].([]any)
		var expected any
		failed := map[string]bool{}
		repack := true
		for _, value := range records {
			record := value.(map[string]any)
			key := record["messageId"].(string) + "/" + record["attributes"].(map[string]any)["ApproximateReceiveCount"].(string)
			completion, ok := native[key]
			if !ok || completion.Kind != invocation.Kind {
				t.Fatalf("exact source attempt %s completion=%s native=%s", key, invocation.Kind, completion.Kind)
			}
			if completion.Kind == "ESM_THROW" {
				continue
			}
			var response map[string]any
			if err := json.Unmarshal(completion.Response, &response); err != nil {
				t.Fatal(err)
			}
			if expected == nil {
				expected = response
			}
			failures, ok := response["batchItemFailures"].([]any)
			if !ok {
				repack = false
				continue
			}
			for _, value := range failures {
				failure := value.(map[string]any)
				id, ok := failure["itemIdentifier"].(string)
				local, owned := r.ids[id]
				if !ok || !owned {
					repack = false
					continue
				}
				failed[local] = true
			}
		}
		if invocation.Kind == "ESM_THROW" {
			continue
		}
		if repack {
			failures := []any{}
			for _, value := range records {
				id := value.(map[string]any)["messageId"].(string)
				if failed[id] {
					failures = append(failures, map[string]any{"itemIdentifier": id})
				}
			}
			expected = map[string]any{"batchItemFailures": failures}
		}
		var actual any
		if err := json.Unmarshal(invocation.Response, &actual); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("runtime response %s got %s native %s", invocation.RequestID, invocation.Response, lambdaQualifiedJSON(t, expected))
		}
	}
}

func (r *lambdaSQSDeliveryReplay) pending(t *testing.T, count int) {
	t.Helper()
	r.wait(t, 0, func() bool { visible, hidden := r.counts(t); return visible == 0 && hidden == count })
}

func (r *lambdaSQSDeliveryReplay) finish(t *testing.T) []lambdaSQSRuntimeEvidence {
	t.Helper()
	r.awaitAttempt(t, 2)
	r.pending(t, 0)
	r.enabled(t, false)
	advanceClock(t, r.clock, r.visibility+time.Second)
	out, err := r.c.queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: r.queueURL, MaxNumberOfMessages: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 0 {
		t.Fatalf("native acknowledgements/disposal left source IDs after visibility expiry: %+v", out.Messages)
	}
	evidence := r.runtime(t)
	r.assertRecords(t, evidence)
	return evidence
}

func (r *lambdaSQSDeliveryReplay) run(t *testing.T) []lambdaSQSRuntimeEvidence {
	t.Helper()
	r.seed(t)
	r.enabled(t, true) // No further SendMessage call occurs after enable.
	r.awaitAttempt(t, 1)
	retries := 0
	for _, records := range r.caseData.native {
		if len(records) > 1 {
			retries++
		}
	}
	r.pending(t, retries)
	if retries > 0 {
		advanceClock(t, r.clock, r.visibility+time.Second)
	}
	return r.finish(t)
}

func TestLambdaSQSNativeDeliverySDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real SQS Lambda delivery")
	}
	fixture := lambdaFixture[lambdaSQSDeliveryFixture](t, "sqs_mapping_delivery")
	var labels []string
	for _, scenario := range fixture.Scenarios {
		switch scenario.Label {
		case "partial_enabled", "filter_json_and_malformed", "batch_window_zero":
			// In-place native propagation observations are not stable settings.
		default:
			labels = append(labels, scenario.Label)
		}
	}
	for _, scenario := range fixture.Isolated {
		labels = append(labels, scenario.Label)
	}
	sort.Strings(labels)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, label := range labels {
				t.Run(label, func(t *testing.T) {
					lambdaSQSDeliverySetup(t, backend, lambdaSQSDeliveryCase(t, fixture, label)).run(t)
				})
			}
		})
	}
}

func TestLambdaSQSSQLiteVisibilityRecoverySDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real SQS Lambda recovery")
	}
	fixture := lambdaFixture[lambdaSQSDeliveryFixture](t, "sqs_mapping_delivery")
	r := lambdaSQSDeliverySetup(t, "sqlite", lambdaSQSDeliveryCase(t, fixture, "ordinary_error_redelivery"))
	r.seed(t)
	r.enabled(t, true)
	r.awaitAttempt(t, 1)
	r.pending(t, len(r.ids))
	// Shutdown abandons no source state: all messages remain leased in SQS,
	// not in a Lambda receipt ledger or a test-owned reinsertion buffer.
	if err := r.c.cloud.Close(); err != nil {
		t.Fatal(err)
	}
	r.c.server.Close()
	r.closeDatabase()
	r.backends, r.closeDatabase = openSQLiteBackends(t, r.path)
	previous := r.c
	r.c = lambdaEventsConnect(t, r.backends, r.clock)
	r.c.functionName, r.c.functionARN = previous.functionName, previous.functionARN
	if visible, hidden := r.counts(t); visible != 0 || hidden != len(r.ids) {
		t.Fatalf("reopen lost source visibility leases: visible=%d hidden=%d", visible, hidden)
	}
	advanceClock(t, r.clock, r.visibility+time.Second)
	r.finish(t)
}
