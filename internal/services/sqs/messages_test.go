package sqs

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestMessageAttributesChecksumsAndReceiptLifecycle(t *testing.T) {
	s, c, clock, _ := fixture(t)
	ctx := context.Background()
	url := create(t, c, "messages", map[string]string{"VisibilityTimeout": "5"})
	out, err := c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("hello ✓"), MessageAttributes: map[string]types.MessageAttributeValue{"my_attribute_name_1": {DataType: aws.String("String"), StringValue: aws.String("my_attribute_value_1")}}})
	if err != nil {
		t.Fatal(err)
	}
	// Official AWS SendMessageBatch example fixture; independent of our encoder.
	if aws.ToString(out.MD5OfMessageAttributes) != "8ef4d60dbc8efda9f260e1dfd09d29f3" {
		t.Fatalf("attribute digest=%s", aws.ToString(out.MD5OfMessageAttributes))
	}
	s.mu.Lock()
	for _, q := range s.queues {
		for _, m := range q.messages {
			if bytes.Contains(m.data, []byte("hello")) || !m.encrypted {
				t.Error("SSE-SQS left message payload plaintext")
			}
		}
	}
	s.mu.Unlock()
	first := receive(t, c, url, 1)
	if len(first) != 1 || aws.ToString(first[0].MessageId) != aws.ToString(out.MessageId) || first[0].Attributes["ApproximateReceiveCount"] != "1" {
		t.Fatalf("first receive=%+v", first)
	}
	if len(receive(t, c, url, 1)) != 0 {
		t.Fatal("in-flight message was visible")
	}
	advance(t, clock, 5*time.Second)
	second := receive(t, c, url, 1)
	if len(second) != 1 || aws.ToString(second[0].ReceiptHandle) == aws.ToString(first[0].ReceiptHandle) || second[0].Attributes["ApproximateReceiveCount"] != "2" {
		t.Fatalf("second receive=%+v", second)
	}
	_, err = c.DeleteMessage(ctx, &sdk.DeleteMessageInput{QueueUrl: aws.String(url), ReceiptHandle: first[0].ReceiptHandle})
	if err != nil {
		t.Fatal(err)
	}
	if attributes(t, c, url)["ApproximateNumberOfMessagesNotVisible"] != "1" {
		t.Fatal("stale receipt deleted message")
	}
	_, err = c.ChangeMessageVisibility(ctx, &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(url), ReceiptHandle: first[0].ReceiptHandle, VisibilityTimeout: 0})
	requireCode(t, err, "ReceiptHandleIsInvalid")
	_, err = c.ChangeMessageVisibility(ctx, &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(url), ReceiptHandle: second[0].ReceiptHandle, VisibilityTimeout: 0})
	if err != nil {
		t.Fatal(err)
	}
	third := receive(t, c, url, 1)
	if len(third) != 1 {
		t.Fatal("visibility zero did not release message")
	}
	_, err = c.DeleteMessage(ctx, &sdk.DeleteMessageInput{QueueUrl: aws.String(url), ReceiptHandle: third[0].ReceiptHandle})
	if err != nil {
		t.Fatal(err)
	}
	if len(receive(t, c, url, 1)) != 0 {
		t.Fatal("deleted message visible")
	}
	_, err = c.DeleteMessage(ctx, &sdk.DeleteMessageInput{QueueUrl: aws.String(url), ReceiptHandle: aws.String("fabricated")})
	requireCode(t, err, "ReceiptHandleIsInvalid")
}
func TestDelayRetentionAndPurge(t *testing.T) {
	_, c, clock, _ := fixture(t)
	ctx := context.Background()
	url := create(t, c, "delayed", map[string]string{"DelaySeconds": "10", "MessageRetentionPeriod": "60"})
	send(t, c, url, "later")
	if len(receive(t, c, url, 1)) != 0 || attributes(t, c, url)["ApproximateNumberOfMessagesDelayed"] != "1" {
		t.Fatal("delay was ignored")
	}
	advance(t, clock, 10*time.Second)
	if len(receive(t, c, url, 1)) != 1 {
		t.Fatal("delayed message never became visible")
	}
	advance(t, clock, 50*time.Second)
	if len(receive(t, c, url, 1)) != 0 {
		t.Fatal("retention did not expire message")
	}
	send(t, c, url, "purge")
	_, err := c.PurgeQueue(ctx, &sdk.PurgeQueueInput{QueueUrl: aws.String(url)})
	if err != nil {
		t.Fatal(err)
	}
	if attributes(t, c, url)["ApproximateNumberOfMessagesDelayed"] != "0" {
		t.Fatal("purge retained delayed message")
	}
	_, err = c.PurgeQueue(ctx, &sdk.PurgeQueueInput{QueueUrl: aws.String(url)})
	requireCode(t, err, "AWS.SimpleQueueService.PurgeQueueInProgress")
}
func TestBatchesPartialFailuresAreAtomicPerEntry(t *testing.T) {
	_, c, _, _ := fixture(t)
	ctx := context.Background()
	url := create(t, c, "batch", nil)
	out, err := c.SendMessageBatch(ctx, &sdk.SendMessageBatchInput{QueueUrl: aws.String(url), Entries: []types.SendMessageBatchRequestEntry{{Id: aws.String("good"), MessageBody: aws.String("ok")}, {Id: aws.String("bad"), MessageBody: aws.String("bad\x00")}, {Id: aws.String("also_good"), MessageBody: aws.String("other")}}})
	if err != nil || len(out.Successful) != 2 || len(out.Failed) != 1 || aws.ToString(out.Failed[0].Code) != "InvalidMessageContents" || !out.Failed[0].SenderFault {
		t.Fatalf("send batch=%v %v", out, err)
	}
	_, err = c.SendMessageBatch(ctx, &sdk.SendMessageBatchInput{QueueUrl: aws.String(url), Entries: []types.SendMessageBatchRequestEntry{{Id: aws.String("same"), MessageBody: aws.String("a")}, {Id: aws.String("same"), MessageBody: aws.String("b")}}})
	requireCode(t, err, "AWS.SimpleQueueService.BatchEntryIdsNotDistinct")
	got := receive(t, c, url, 10)
	if len(got) != 2 {
		t.Fatalf("queued=%d", len(got))
	}
	changed, err := c.ChangeMessageVisibilityBatch(ctx, &sdk.ChangeMessageVisibilityBatchInput{QueueUrl: aws.String(url), Entries: []types.ChangeMessageVisibilityBatchRequestEntry{{Id: aws.String("good"), ReceiptHandle: got[0].ReceiptHandle, VisibilityTimeout: 0}, {Id: aws.String("bad"), ReceiptHandle: aws.String("invalid"), VisibilityTimeout: 0}}})
	if err != nil || len(changed.Successful) != 1 || len(changed.Failed) != 1 {
		t.Fatalf("visibility batch=%v %v", changed, err)
	}
	deleted, err := c.DeleteMessageBatch(ctx, &sdk.DeleteMessageBatchInput{QueueUrl: aws.String(url), Entries: []types.DeleteMessageBatchRequestEntry{{Id: aws.String("good"), ReceiptHandle: got[1].ReceiptHandle}, {Id: aws.String("bad"), ReceiptHandle: aws.String("invalid")}}})
	if err != nil || len(deleted.Successful) != 1 || len(deleted.Failed) != 1 {
		t.Fatalf("delete batch=%v %v", deleted, err)
	}
	if len(receive(t, c, url, 10)) != 1 {
		t.Fatal("batch transition produced wrong queue contents")
	}
}
func TestBinaryNumberAttributesAndInvalidContent(t *testing.T) {
	_, c, _, _ := fixture(t)
	ctx := context.Background()
	url := create(t, c, "attrs", nil)
	_, err := c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("binary"), MessageAttributes: map[string]types.MessageAttributeValue{"blob": {DataType: aws.String("Binary.custom"), BinaryValue: []byte{0, 1, 254, 255}}, "number": {DataType: aws.String("Number"), StringValue: aws.String("001.2300e2")}}})
	if err != nil {
		t.Fatal(err)
	}
	got := receive(t, c, url, 1)
	if len(got) != 1 || !bytes.Equal(got[0].MessageAttributes["blob"].BinaryValue, []byte{0, 1, 254, 255}) || aws.ToString(got[0].MessageAttributes["number"].StringValue) != "123" {
		t.Fatalf("attributes=%v", got)
	}
	for _, name := range []string{"AWS.foo", "a..b", ".a", "bad!"} {
		_, err = c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("bad"), MessageAttributes: map[string]types.MessageAttributeValue{name: {DataType: aws.String("String"), StringValue: aws.String("v")}}})
		requireCode(t, err, "InvalidParameterValue")
	}
	_, err = c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String(strings.Repeat("x", 1<<20+1))})
	requireCode(t, err, "InvalidParameterValue")
}
func TestLongPollingWakesOnSendAndShutdown(t *testing.T) {
	s, c, _, _ := fixture(t)
	ctx := context.Background()
	url := create(t, c, "poll", nil)
	result := make(chan *sdk.ReceiveMessageOutput, 1)
	failures := make(chan error, 1)
	go func() {
		out, err := c.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url), WaitTimeSeconds: 20})
		result <- out
		failures <- err
	}()
	send(t, c, url, "wake")
	select {
	case got := <-result:
		if err := <-failures; err != nil || got == nil || len(got.Messages) != 1 {
			t.Fatalf("long poll=%v %v", got, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll did not wake")
	}
	cancelled, cancel := context.WithCancel(ctx)
	go func() {
		_, err := c.ReceiveMessage(cancelled, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url), WaitTimeSeconds: 20})
		failures <- err
	}()
	cancel()
	select {
	case err := <-failures:
		if err == nil {
			t.Fatal("cancelled receive succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt poll")
	}
	go func() {
		_, err := c.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{QueueUrl: aws.String(url), WaitTimeSeconds: 20})
		failures <- err
	}()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failures:
		if err == nil {
			t.Fatal("closed receive succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not interrupt poll")
	}
}
func TestConcurrentReceiversClaimDistinctMessages(t *testing.T) {
	_, c, _, _ := fixture(t)
	url := create(t, c, "concurrent", nil)
	const count = 30
	for i := 0; i < count; i++ {
		send(t, c, url, "work")
	}
	var wg sync.WaitGroup
	results := make(chan string, count)
	failures := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Go(func() {
			out, err := c.ReceiveMessage(context.Background(), &sdk.ReceiveMessageInput{QueueUrl: aws.String(url)})
			if err != nil {
				failures <- err
				return
			}
			for _, m := range out.Messages {
				results <- aws.ToString(m.MessageId)
			}
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	seen := make(map[string]bool)
	for id := range results {
		if seen[id] {
			t.Errorf("duplicate concurrent delivery %s", id)
		}
		seen[id] = true
	}
	if len(seen) != count {
		t.Fatalf("received %d/%d", len(seen), count)
	}
}
