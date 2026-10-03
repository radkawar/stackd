package stackd_test

import (
	"fmt"
	"maps"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
)

type snsFilterFixture struct {
	snsAdmissionFixture
	Gaps  []string
	Cases []struct {
		Label string
		Cases []struct{ Label string }
	}
	CaseResults []struct {
		Label, Group, Observation string
		PublishLabel              string `json:"publish_label"`
		DeliveryCount             int    `json:"delivery_count"`
	} `json:"case_results"`
	ReceiveWindows []struct {
		Label    string
		Started  int64 `json:"started_ms"`
		Finished int64 `json:"finished_ms"`
	} `json:"receive_windows"`
	ReceiveWindowSeconds float64            `json:"receive_window_seconds"`
	PreviousAttempts     []snsFilterFixture `json:"previous_attempts"`
}

type snsFilterReceipt struct {
	notification snsAdmissionNotification
	attributes   map[string]sqstypes.MessageAttributeValue
}

type snsFilterQueue struct {
	nativeURL, nativeARN string
	url, arn             *string
	receipts             map[string]snsFilterReceipt
}

type snsFilterReplay struct {
	cloud         *stackd.Stack
	topics        *sns.Client
	queues        *sqs.Client
	topicARN      *string
	endpoints     []*snsFilterQueue
	subscriptions map[string]*string
}

func TestSNSNativeFilters(t *testing.T) {
	for _, filename := range []string{"filters", "message_rules", "subject_structure"} {
		data, err := os.ReadFile("../testdata/aws/sns/" + filename + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var fixture snsFilterFixture
		awsDecodeJSON(t, data, &fixture)
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(filename+"/"+backend, func(t *testing.T) {
				snsFilterRun(t, backend, fixture)
				for i, previous := range fixture.PreviousAttempts {
					t.Run(fmt.Sprintf("previous-attempt-%d", i), func(t *testing.T) { snsFilterRun(t, backend, previous) })
				}
			})
		}
	}
}

func snsFilterRun(t *testing.T, backend string, fixture snsFilterFixture) {
	t.Helper()
	for _, limitation := range fixture.Limitations {
		t.Log(limitation)
	}
	for _, gap := range fixture.Gaps {
		t.Log(gap)
	}
	for _, window := range fixture.ReceiveWindows {
		t.Logf("Native %s receive window: %d..%d (%s); absence is bounded evidence, not permanent non-delivery", window.Label, window.Started, window.Finished, time.Duration(window.Finished-window.Started)*time.Millisecond)
	}
	if fixture.ReceiveWindowSeconds != 0 {
		t.Logf("Native receive window: %.3fs", fixture.ReceiveWindowSeconds)
	}
	cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
	replay := snsFilterReplay{cloud: cloud, topics: admissionSNSClient(clients, fixture.Account, fixture.Region), queues: clients.sqs(fixture.Account, "test", ""), subscriptions: map[string]*string{}}
	replay.setup(t, fixture)
	// Original cases and case_results retain native grouping and distinguish a
	// measured non-observation from an admission rejection. No policy evaluator
	// derives expected matches, and no native receive ordering is reproduced.
	caseNames := map[string]string{}
	for _, group := range fixture.Cases {
		for _, item := range group.Cases {
			caseNames[item.Label] = group.Label + "/" + item.Label
		}
	}
	caseRows := map[string]int{}
	for i, result := range fixture.CaseResults {
		caseRows[result.PublishLabel] = i
	}
	for _, row := range fixture.Observations {
		if row.Service != "sns" {
			continue
		}
		switch row.Operation {
		case "subscribe", "unsubscribe", "publish", "publish-batch":
		default:
			continue // Setup/readback/cleanup remain evidence, not new oracles.
		}
		name := row.Label
		if i, ok := caseRows[row.Label]; ok {
			name = caseNames[fixture.CaseResults[i].Label]
		}
		if !t.Run(name, func(t *testing.T) {
			advanceClock(t, source, time.Millisecond)
			if i, ok := caseRows[row.Label]; ok {
				result := fixture.CaseResults[i]
				t.Logf("Native %s: %s, %d observed deliveries", result.Group, result.Observation, result.DeliveryCount)
			}
			delivered := 0
			switch row.Operation {
			case "subscribe":
				replay.subscribe(t, row)
			case "unsubscribe":
				replay.unsubscribe(t, row)
			case "publish":
				delivered = replay.consume(t, replay.publish(t, row))
			case "publish-batch":
				delivered = replay.consume(t, replay.publishBatch(t, row))
			}
			if i, ok := caseRows[row.Label]; ok && delivered != fixture.CaseResults[i].DeliveryCount {
				t.Fatalf("consumed %d notifications, native case_results records %d within its receive window", delivered, fixture.CaseResults[i].DeliveryCount)
			}
		}) {
			t.FailNow()
		}
	}
}

func (r *snsFilterReplay) setup(t *testing.T, fixture snsFilterFixture) {
	t.Helper()
	for _, row := range fixture.Observations {
		if row.Operation == "create-topic" {
			var in sns.CreateTopicInput
			awsDecodeJSON(t, row.Input, &in)
			out, err := r.topics.CreateTopic(t.Context(), &in)
			if err != nil {
				t.Fatal(err)
			}
			r.topicARN = out.TopicArn
		}
		if row.Operation == "create-queue" {
			var in sqs.CreateQueueInput
			var native sqs.CreateQueueOutput
			awsDecodeJSON(t, row.Input, &in)
			awsDecodeJSON(t, row.Result.Output, &native)
			out, err := r.queues.CreateQueue(t.Context(), &in)
			if err != nil {
				t.Fatal(err)
			}
			attrs, err := r.queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: out.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
			if err != nil {
				t.Fatal(err)
			}
			r.endpoints = append(r.endpoints, &snsFilterQueue{nativeURL: aws.ToString(native.QueueUrl), url: out.QueueUrl, arn: aws.String(attrs.Attributes["QueueArn"]), receipts: map[string]snsFilterReceipt{}})
		}
	}
	for _, queue := range r.endpoints {
		policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, aws.ToString(queue.arn), aws.ToString(r.topicARN))
		if _, err := r.queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.url, Attributes: map[string]string{"Policy": policy}}); err != nil {
			t.Fatal(err)
		}
		for _, row := range fixture.Observations {
			if row.Service != "sqs" || row.Result.Code != "Success" {
				continue
			}
			var in struct {
				QueueURL string `json:"QueueUrl"`
			}
			awsDecodeJSON(t, row.Input, &in)
			if in.QueueURL != queue.nativeURL {
				continue
			}
			switch row.Operation {
			case "get-queue-attributes":
				var out sqs.GetQueueAttributesOutput
				awsDecodeJSON(t, row.Result.Output, &out)
				if arn := out.Attributes["QueueArn"]; arn != "" {
					queue.nativeARN = arn
				}
			case "receive-message":
				var out sqs.ReceiveMessageOutput
				awsDecodeJSON(t, row.Result.Output, &out)
				for _, message := range out.Messages {
					var notification snsAdmissionNotification
					awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &notification)
					queue.receipts[notification.MessageId] = snsFilterReceipt{notification, message.MessageAttributes}
				}
			}
		}
	}
}

func (r *snsFilterReplay) subscribe(t *testing.T, row awsNativeObservation) {
	t.Helper()
	var in sns.SubscribeInput
	awsDecodeJSON(t, row.Input, &in)
	in.TopicArn = r.topicARN
	found := false
	for _, queue := range r.endpoints {
		if aws.ToString(in.Endpoint) == queue.nativeARN {
			in.Endpoint, found = queue.arn, true
			break
		}
	}
	if !found {
		t.Fatalf("native subscription endpoint has no captured queue: %s", aws.ToString(in.Endpoint))
	}
	out, err := r.topics.Subscribe(t.Context(), &in)
	awsNativeResult(t, row, err)
	if err == nil {
		var native sns.SubscribeOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		r.subscriptions[aws.ToString(native.SubscriptionArn)] = out.SubscriptionArn
	}
}

func (r *snsFilterReplay) unsubscribe(t *testing.T, row awsNativeObservation) {
	t.Helper()
	var in sns.UnsubscribeInput
	awsDecodeJSON(t, row.Input, &in)
	nativeARN := aws.ToString(in.SubscriptionArn)
	in.SubscriptionArn = r.subscriptions[nativeARN]
	if in.SubscriptionArn == nil {
		t.Fatalf("uncaptured subscription: %s", nativeARN)
	}
	_, err := r.topics.Unsubscribe(t.Context(), &in)
	awsNativeResult(t, row, err)
}

// Publication helpers return local-to-native IDs. A successful admission is
// deliberately not evidence of delivery: only captured SQS receipts supply it.
func (r *snsFilterReplay) publish(t *testing.T, row awsNativeObservation) map[string]string {
	t.Helper()
	var in sns.PublishInput
	awsDecodeJSON(t, row.Input, &in)
	in.TopicArn = r.topicARN
	out, err := r.topics.Publish(t.Context(), &in)
	awsNativeResult(t, row, err)
	if err != nil {
		return nil
	}
	var native sns.PublishOutput
	awsDecodeJSON(t, row.Result.Output, &native)
	return map[string]string{aws.ToString(out.MessageId): aws.ToString(native.MessageId)}
}

func (r *snsFilterReplay) publishBatch(t *testing.T, row awsNativeObservation) map[string]string {
	t.Helper()
	var in sns.PublishBatchInput
	awsDecodeJSON(t, row.Input, &in)
	in.TopicArn = r.topicARN
	out, err := r.topics.PublishBatch(t.Context(), &in)
	awsNativeResult(t, row, err)
	if err != nil {
		return nil
	}
	var native sns.PublishBatchOutput
	awsDecodeJSON(t, row.Result.Output, &native)
	type failure struct {
		Code        string
		SenderFault bool
	}
	gotFailed, wantFailed := map[string]failure{}, map[string]failure{}
	for _, entry := range out.Failed {
		gotFailed[aws.ToString(entry.Id)] = failure{aws.ToString(entry.Code), entry.SenderFault}
	}
	for _, entry := range native.Failed {
		wantFailed[aws.ToString(entry.Id)] = failure{aws.ToString(entry.Code), entry.SenderFault}
	}
	if len(out.Failed) != len(gotFailed) || !maps.Equal(gotFailed, wantFailed) {
		t.Fatalf("batch per-entry failures: got %v, native %v", gotFailed, wantFailed)
	}
	remaining := map[string]string{}
	for _, entry := range native.Successful {
		remaining[aws.ToString(entry.Id)] = aws.ToString(entry.MessageId)
	}
	ids := map[string]string{}
	for _, entry := range out.Successful {
		id := aws.ToString(entry.Id)
		nativeID, ok := remaining[id]
		if !ok {
			t.Fatalf("unexpected successful batch entry %q", id)
		}
		localID := aws.ToString(entry.MessageId)
		if _, exists := ids[localID]; exists {
			t.Fatalf("distinct batch entries share message ID %q", localID)
		}
		ids[localID] = nativeID
		delete(remaining, id)
	}
	if len(remaining) != 0 {
		t.Fatalf("missing successful batch entries: %v", remaining)
	}
	return ids
}

func (r *snsFilterReplay) consume(t *testing.T, ids map[string]string) int {
	t.Helper()
	delivered := 0
	for _, queue := range r.endpoints {
		wanted := map[string]snsFilterReceipt{}
		for localID, nativeID := range ids {
			if receipt, observed := queue.receipts[nativeID]; observed {
				wanted[localID] = receipt
			}
		}
		for _, message := range snsAdmissionReceive(t, r.cloud, r.queues, queue.url) {
			var got snsAdmissionNotification
			awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &got)
			want, ok := wanted[got.MessageId]
			if !ok {
				t.Fatalf("%s: unexpected/duplicate delivery %+v; native absence is bounded by recorded receive windows", queue.nativeURL, got)
			}
			// An explicitly empty selected payload must still be a Message string,
			// not an omitted field mistaken for the decoder's empty-string default.
			var envelope struct{ Message *string }
			awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
			if envelope.Message == nil || got.Type != want.notification.Type || got.Message != want.notification.Message || got.TopicArn != aws.ToString(r.topicARN) || !reflect.DeepEqual(got.Subject, want.notification.Subject) || !maps.Equal(got.MessageAttributes, want.notification.MessageAttributes) || !reflect.DeepEqual(message.MessageAttributes, want.attributes) {
				t.Fatalf("%s: consumed notification differs from native: got %+v (SQS attributes %+v), native %+v (SQS attributes %+v)", queue.nativeURL, got, message.MessageAttributes, want.notification, want.attributes)
			}
			delete(wanted, got.MessageId)
			delivered++
		}
		if len(wanted) != 0 {
			t.Fatalf("%s: native-observed deliveries missing: %v", queue.nativeURL, wanted)
		}
	}
	return delivered
}
