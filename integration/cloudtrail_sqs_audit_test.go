package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
)

type sqsAuditAppendFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *sqsAuditAppendFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "sqs.amazonaws.com" && call.EventName == "SendMessageBatch" && call.ErrorCode == "" && f.fail.Swap(false) {
		return errors.New("injected failure after real SQS audit append")
	}
	return nil
}

func TestCloudTrailSQSEncryptedBatchAuditRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sqs-audit.sqlite"))
			}
			failure := &sqsAuditAppendFailure{Storage: backends.Journal}
			backends.Journal = failure
			source := clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC))
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			client := c.sqs(eventDeliveryAccount, "test", "")
			queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("audit-atomic-batch"), Attributes: map[string]string{"KmsMasterKeyId": "alias/aws/sqs"}})
			if err != nil {
				t.Fatal(err)
			}
			input, err := json.Marshal(map[string]any{"QueueUrl": aws.ToString(queue.QueueUrl), "Entries": []map[string]string{{"Id": "first", "MessageBody": "private-first-body"}, {"Id": "second", "MessageBody": "private-second-body"}}})
			if err != nil {
				t.Fatal(err)
			}
			failure.fail.Store(true)
			if _, err := awstest.CallSDK(t.Context(), client, "SendMessageBatch", input); err == nil {
				t.Fatal("batch committed after its audit append failed")
			}
			received, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
			if err != nil || len(received.Messages) != 0 {
				t.Fatalf("failed batch published messages: %+v %v", received, err)
			}
			rows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			failures := 0
			for _, row := range rows {
				if row.SQSMessageAccepted.MessageID != "" {
					t.Fatal("failed batch committed an accepted-message fact")
				}
				if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "SendMessageBatch" {
					if call.ErrorCode != "InternalError" {
						t.Fatalf("failed batch committed success: %+v", call)
					}
					failures++
				}
			}
			if failures != 1 {
				t.Fatalf("expected one final failed batch audit, got %d", failures)
			}
			// The rollback did not poison the KMS retry/cache path. Exactly one
			// command outcome and two message facts survive the successful retry.
			if _, err := awstest.CallSDK(t.Context(), client, "SendMessageBatch", input); err != nil {
				t.Fatal(err)
			}
			rows, err = backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			successes, messages := 0, 0
			for _, row := range rows {
				if row.SQSMessageAccepted.MessageID != "" {
					messages++
				}
				if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "SendMessageBatch" && call.ErrorCode == "" {
					successes++
				}
			}
			if successes != 1 || messages != 2 {
				t.Fatalf("KMS preparation attempts leaked batch outcomes: successes=%d messages=%d", successes, messages)
			}
			if strings.Contains(journalJSON(t, rows), "private-first-body") || strings.Contains(journalJSON(t, rows), "private-second-body") {
				t.Fatal("message bodies leaked into audit history")
			}
			start := source.Now()
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			counts, err := metricsClient(c, eventDeliveryAccount).GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
				Namespace: aws.String("AWS/SQS"), MetricName: aws.String("NumberOfMessagesSent"),
				Dimensions: []cwtypes.Dimension{{Name: aws.String("QueueName"), Value: aws.String("audit-atomic-batch")}},
				StartTime:  &start, EndTime: aws.Time(source.Now()), Period: aws.Int32(60),
				Statistics: []cwtypes.Statistic{"Sum", "SampleCount"},
			})
			if err != nil || len(counts.Datapoints) != 1 || aws.ToFloat64(counts.Datapoints[0].Sum) != 2 || aws.ToFloat64(counts.Datapoints[0].SampleCount) != 1 {
				t.Fatalf("failed batch or KMS preparation leaked queue samples: %+v %v", counts, err)
			}
		})
	}
}

func TestCloudTrailSQSInternalDeliveryKeepsMessageFactAndChildAudit(t *testing.T) {
	backends := storage.NewMemory()
	source := clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC))
	cloud, c, _ := startEventDeliveryCloud(t, backends, source)
	urls := provisionEventDelivery(t, c)
	client := c.sqs(eventDeliveryAccount, "test", "")
	setEventDeliveryPolicy(t, client, urls["target"], "target", nil)
	eventID, requestID := putDeliveryEvent(t, c, map[string]any{"secret": eventDeliverySecret}, source.Now())
	trailNativeDrain(t, cloud)
	rows, err := backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var calls, facts []journal.Event
	for _, row := range rows {
		if row.ParentEventID != eventID {
			continue
		}
		if row.SQSMessageAccepted.MessageID != "" {
			facts = append(facts, row)
		}
		if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "SendMessage" {
			calls = append(calls, row)
		}
	}
	if len(calls) != 1 || len(facts) != 1 {
		t.Fatalf("internal send must keep one message fact and its own audit: calls=%+v facts=%+v", calls, facts)
	}
	call := calls[0]
	if call.ActorService != "events.amazonaws.com" || call.ActorARN != "" || call.RequestID != requestID || call.APICallCompleted.Identity.Type != "AWSService" {
		t.Fatalf("internal send lost its actual child origin: %+v", call)
	}
	var input, output map[string]any
	if err := json.Unmarshal(call.APICallCompleted.RequestParameters, &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(call.APICallCompleted.ResponseElements, &output); err != nil {
		t.Fatal(err)
	}
	if input["queueUrl"] != "https://sqs.us-east-1.amazonaws.com/"+eventDeliveryAccount+"/"+eventDeliveryName+"-target" || input["messageBody"] != "HIDDEN_DUE_TO_SECURITY_REASONS" || output["messageId"] != facts[0].SQSMessageAccepted.MessageID {
		t.Fatalf("internal generated send projection differs from delivered message: input=%+v output=%+v fact=%+v", input, output, facts[0])
	}
	if strings.Contains(journalJSON(t, rows), eventDeliverySecret) {
		t.Fatal("internal send payload leaked into audit history")
	}
}

func TestCloudTrailSQSNativeDataProjections(t *testing.T) {
	fixture := s3NativeLoad(t, "cloudtrail", "service_data_events")
	native := auditNativeRecords(t, "service_data_events")
	backends := storage.NewMemory()
	_, c, _ := startEventDeliveryCloud(t, backends, clock.Real{})
	client := c.sqs(eventDeliveryAccount, "test", "")
	name := strings.TrimPrefix(fixture.Identity["queue_arn"], "arn:aws:sqs:us-east-1:"+eventDeliveryAccount+":")
	queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ label, requestID string }{
		{"correlated-sqs-get-queue-attributes", "45efd2d8-ee21-57af-9a2e-b1f819586ae6"},
		{"correlated-sqs-get-queue-url", "1a4db799-9d88-50ba-923c-d4b96af24dde"},
		{"correlated-sqs-list-queue-tags", "17711d19-7bc6-5150-93f2-7e398cbc067c"},
		{"correlated-sqs-list-dead-letter-source-queues", "68893bb4-b305-5df0-981a-5894447eeada"},
		{"correlated-sqs-send-single", "362b6200-8b38-54f0-9fec-01207c4425d0"},
		{"correlated-sqs-send-batch", "fd8105ec-6374-59d7-b8f6-66cc9409ae7d"},
		{"correlated-sqs-receive-0", "cf72add6-6990-53b1-89b1-cef69eeefb35"},
		{"correlated-sqs-send-batch-mixed-invalid-delay", "fd7900c9-28eb-5513-920a-63e9df6fa5ac"},
		{"correlated-sqs-send-batch-duplicate-ids", "f3954a84-a9df-5a8f-99c8-29a45e5bf116"},
		{"correlated-sqs-change-invalid", "0cafe219-1028-5f92-aab8-8139e7ab0db6"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			var want map[string]any
			for _, record := range native {
				if record["requestID"] == tc.requestID {
					want = record
					break
				}
			}
			if want == nil {
				t.Fatal("missing captured request-ID correlation")
			}
			row := fixture.row(t, tc.label)
			input := json.RawMessage(strings.ReplaceAll(string(row.Input), fixture.Identity["queue_url"], aws.ToString(queue.QueueUrl)))
			before, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			var after int64
			if len(before) != 0 {
				after = before[len(before)-1].Sequence
			}
			_, callErr := awstest.CallSDK(t.Context(), client, want["eventName"].(string), input)
			if (callErr != nil) != (want["errorCode"] != nil) {
				t.Fatalf("SDK outcome differs from native record: %v; native error %v", callErr, want["errorCode"])
			}
			events, err := backends.Journal.Read(t.Context(), after, 1000)
			if err != nil {
				t.Fatal(err)
			}
			var actual []journal.Event
			for _, event := range events {
				if call := event.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" {
					actual = append(actual, event)
				}
			}
			if len(actual) != 1 {
				t.Fatalf("SDK batch/poll must emit exactly one command outcome: %+v", actual)
			}
			document, err := apievents.CloudTrailRecord(actual[0])
			if err != nil {
				t.Fatal(err)
			}
			document = []byte(strings.ReplaceAll(string(document), aws.ToString(queue.QueueUrl), fixture.Identity["queue_url"]))
			var got map[string]any
			if err := json.Unmarshal(document, &got); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"apiVersion", "eventSource", "eventName", "eventCategory", "managementEvent", "readOnly", "resources", "requestParameters", "errorCode"} {
				if !reflect.DeepEqual(got[field], want[field]) {
					t.Fatalf("%s: got %#v; native %#v", field, got[field], want[field])
				}
			}
			// Captured synthetic payloads were normalized, so their MD5s and
			// generated IDs differ. Assert native member names, array presence,
			// entry IDs, sender faults and codes, not random IDs/error wording.
			sqsAuditNormalizeResponse(t, want["responseElements"])
			sqsAuditNormalizeResponse(t, got["responseElements"])
			if !reflect.DeepEqual(got["responseElements"], want["responseElements"]) {
				t.Fatalf("response: got %#v; native %#v", got["responseElements"], want["responseElements"])
			}
			if got["requestID"] == "" || got["eventID"] == "" {
				t.Fatal("audit lost generated request/event identity")
			}
		})
	}
}

func sqsAuditNormalizeResponse(t *testing.T, value any) {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		for field, child := range value {
			switch field {
			case "messageId", "mD5OfMessageBody", "mD5OfMessageAttributes", "mD5OfMessageSystemAttributes", "message":
				if text, ok := child.(string); !ok || text == "" {
					t.Fatalf("missing generated native response field %s: %#v", field, child)
				}
				value[field] = "<generated>"
			default:
				sqsAuditNormalizeResponse(t, child)
			}
		}
	case []any:
		for _, child := range value {
			sqsAuditNormalizeResponse(t, child)
		}
	}
}

func TestCloudTrailSQSNativeManagementProjection(t *testing.T) {
	var native map[string]any
	for _, record := range auditNativeRecords(t, "service_management_events") {
		if record["eventSource"] == "sqs.amazonaws.com" && record["eventName"] == "CreateQueue" {
			native = record
			break
		}
	}
	if native == nil {
		t.Fatal("missing native CreateQueue management record")
	}
	backends := storage.NewMemory()
	_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)))
	account := native["recipientAccountId"].(string)
	input, err := json.Marshal(native["requestParameters"])
	if err != nil {
		t.Fatal(err)
	}
	result, err := awstest.CallSDK(t.Context(), c.sqs(account, "test", ""), "CreateQueue", input)
	if err != nil {
		t.Fatal(err)
	}
	output := result.(*sqs.CreateQueueOutput)
	rows, err := backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var actual []journal.Event
	for _, row := range rows {
		if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "CreateQueue" {
			actual = append(actual, row)
		}
	}
	if len(actual) != 1 {
		t.Fatalf("expected one CreateQueue management event: %+v", actual)
	}
	document, err := apievents.CloudTrailRecord(actual[0])
	if err != nil {
		t.Fatal(err)
	}
	nativeURL := native["responseElements"].(map[string]any)["queueUrl"].(string)
	document = []byte(strings.ReplaceAll(string(document), aws.ToString(output.QueueUrl), nativeURL))
	var got map[string]any
	if err := json.Unmarshal(document, &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"apiVersion", "eventSource", "eventName", "eventCategory", "managementEvent", "readOnly", "resources", "requestParameters", "responseElements"} {
		if !reflect.DeepEqual(got[field], native[field]) {
			t.Fatalf("%s: got %#v; native %#v", field, got[field], native[field])
		}
	}
}

// sqsReceiveDeadlineClock distinguishes the receive's absolute deadline from
// unrelated background scheduler timers in the full stack.
type sqsReceiveDeadlineClock struct {
	*clock.Manual
	deadline   time.Time
	registered chan struct{}
	once       sync.Once
}

func (c *sqsReceiveDeadlineClock) NewTimerAt(at time.Time) clock.Timer {
	timer := c.Manual.NewTimerAt(at)
	if at.Equal(c.deadline) {
		c.once.Do(func() { close(c.registered) })
	}
	return timer
}

func (c *sqsReceiveDeadlineClock) wait(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-c.registered:
	case <-ctx.Done():
		t.Fatal("receive did not register its modeled deadline")
	}
}

func TestCloudTrailSQSReceiveOnlyAuditsFinalEmptyPoll(t *testing.T) {
	backends := storage.NewMemory()
	source := clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC))
	pollClock := &sqsReceiveDeadlineClock{Manual: source, deadline: source.Now().Add(20 * time.Second), registered: make(chan struct{})}
	_, c, _ := startEventDeliveryCloud(t, backends, pollClock)
	client := c.sqs(eventDeliveryAccount, "test", "")
	queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("audit-empty-poll")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		output *sqs.ReceiveMessageOutput
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, WaitTimeSeconds: 20})
		done <- result{output, err}
	}()
	pollClock.wait(t, ctx)
	rows, err := backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "ReceiveMessage" {
			t.Fatal("an intermediate empty poll published a completed API event")
		}
	}
	advanceClock(t, source, 20*time.Second)
	select {
	case result := <-done:
		if result.err != nil || result.output == nil || len(result.output.Messages) != 0 {
			t.Fatalf("final empty receive: %+v %v", result.output, result.err)
		}
	case <-ctx.Done():
		t.Fatal("receive did not finish at its modeled deadline")
	}
	rows, err = backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	receives := 0
	for _, row := range rows {
		if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "ReceiveMessage" {
			receives++
			document, err := apievents.CloudTrailRecord(row)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if err := json.Unmarshal(document, &record); err != nil {
				t.Fatal(err)
			}
			if record["eventCategory"] != "Data" || record["readOnly"] != true || record["responseElements"] != nil || !row.At.Equal(source.Now()) {
				t.Fatalf("final empty receive lost native classification/null response/completion time: %+v", record)
			}
		}
	}
	if receives != 1 {
		t.Fatalf("expected exactly one final empty receive, got %d", receives)
	}
}

func TestCloudTrailSQSCanceledReceiveCommitsFinalAudit(t *testing.T) {
	backends, _ := openSQLiteBackends(t, filepath.Join(t.TempDir(), "sqs-canceled-audit.sqlite"))
	source := clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC))
	pollClock := &sqsReceiveDeadlineClock{Manual: source, deadline: source.Now().Add(20 * time.Second), registered: make(chan struct{})}
	_, c, _ := startEventDeliveryCloud(t, backends, pollClock)
	client := c.sqs(eventDeliveryAccount, "test", "")
	queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("audit-canceled-poll")})
	if err != nil {
		t.Fatal(err)
	}
	wait, stopWaiting := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopWaiting()
	ctx, cancel := context.WithCancel(wait)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, WaitTimeSeconds: 20})
		done <- err
	}()
	pollClock.wait(t, wait)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("receive cancellation: %v", err)
		}
	case <-wait.Done():
		t.Fatal("caller cancellation did not release receive")
	}
	// Cancellation can release the SDK before its server handler finishes.
	// Join that handler before reading the committed journal.
	c.server.Close()
	rows, err := backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	receives := 0
	for _, row := range rows {
		if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "ReceiveMessage" {
			receives++
			if call.ErrorCode != "RequestCanceled" || call.Identity.AccountID != eventDeliveryAccount || call.Identity.Type != "Root" || row.ActorARN != "arn:aws:iam::"+eventDeliveryAccount+":root" || row.RequestID == "" || call.SourceIPAddress == "" || call.UserAgent == "" {
				t.Fatalf("canceled receive lost its outcome or verified caller: %+v %+v", row, call)
			}
		}
	}
	if receives != 1 {
		t.Fatalf("expected one final canceled receive audit, got %d", receives)
	}
}

func TestCloudTrailSQSExactQueueSelectorExcludesListQueues(t *testing.T) {
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	data := s3NativeLoad(t, "cloudtrail", "service_data_events")
	source := clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC))
	cloud, c, _ := startEventDeliveryCloud(t, storage.NewMemory(), source)
	trailNativeProvision(t, c, controls, objects, false)
	client, trails := c.sqs(eventDeliveryAccount, "test", ""), trailNativeClient(c)
	name := strings.TrimPrefix(data.Identity["queue_arn"], "arn:aws:sqs:us-east-1:"+eventDeliveryAccount+":")
	queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name})
	if err != nil {
		t.Fatal(err)
	}
	_, err = trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(controls.Identity["trail_name"]), AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{{
		Name: aws.String("exact-owned-queue"), FieldSelectors: []trailtypes.AdvancedFieldSelector{
			{Field: aws.String("eventCategory"), Equals: []string{"Data"}},
			{Field: aws.String("resources.type"), Equals: []string{"AWS::SQS::Queue"}},
			{Field: aws.String("resources.ARN"), Equals: []string{data.Identity["queue_arn"]}},
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trails.StartLogging(t.Context(), &cloudtrail.StartLoggingInput{Name: aws.String(controls.Identity["trail_name"])}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListQueues(t.Context(), &sqs.ListQueuesInput{QueueNamePrefix: &name}); err != nil {
		t.Fatal(err)
	}
	if _, err := trails.StopLogging(t.Context(), &cloudtrail.StopLoggingInput{Name: aws.String(controls.Identity["trail_name"])}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 6*time.Minute)
	trailNativeDrain(t, cloud)
	records := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(c, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
	if len(records) != 1 || records[0]["eventName"] != "GetQueueAttributes" || records[0]["responseElements"] != nil {
		t.Fatalf("exact queue selector admitted wildcard ListQueues or lost the selected read: %#v", records)
	}
	rows, err := cloud.Events(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	lists := 0
	for _, row := range rows {
		if call := row.APICallCompleted; call != nil && call.EventSource == "sqs.amazonaws.com" && call.EventName == "ListQueues" {
			lists++
			if call.Category != journal.CategoryData || !call.ReadOnly || len(call.EventResources) != 1 || call.EventResources[0].ARN != "arn:aws:sqs:us-east-1:"+eventDeliveryAccount+":*" {
				t.Fatalf("ListQueues must still audit its documented wildcard resource: %+v", call)
			}
		}
	}
	if lists != 1 {
		t.Fatalf("exact selector exclusion must not suppress the API outcome itself: %d", lists)
	}
}
