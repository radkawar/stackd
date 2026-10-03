package sqs

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func fifoSend(t *testing.T, c *sdk.Client, url, body, group, dedup string) *sdk.SendMessageOutput {
	t.Helper()
	in := &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String(body), MessageGroupId: aws.String(group)}
	if dedup != "" {
		in.MessageDeduplicationId = aws.String(dedup)
	}
	out, err := c.SendMessage(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestFIFOGroupSerializationDedupAndReceiveRetries(t *testing.T) {
	_, c, clock, _ := fixture(t)
	ctx := context.Background()
	url := create(t, c, "ordered.fifo", map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true"})
	a := fifoSend(t, c, url, "a1", "a", "")
	duplicate := fifoSend(t, c, url, "a1", "a", "")
	if aws.ToString(a.MessageId) != aws.ToString(duplicate.MessageId) || aws.ToString(a.SequenceNumber) != aws.ToString(duplicate.SequenceNumber) {
		t.Fatal("dedup did not reuse original result")
	}
	fifoSend(t, c, url, "a2", "a", "")
	fifoSend(t, c, url, "b1", "b", "")
	in := &sdk.ReceiveMessageInput{QueueUrl: aws.String(url), MaxNumberOfMessages: 1, ReceiveRequestAttemptId: aws.String("attempt-one"), MessageSystemAttributeNames: []types.MessageSystemAttributeName{types.MessageSystemAttributeNameAll}}
	first, err := c.ReceiveMessage(ctx, in)
	if err != nil || len(first.Messages) != 1 || aws.ToString(first.Messages[0].Body) != "a1" {
		t.Fatalf("first=%v %v", first, err)
	}
	retry, err := c.ReceiveMessage(ctx, in)
	if err != nil || len(retry.Messages) != 1 || aws.ToString(retry.Messages[0].ReceiptHandle) != aws.ToString(first.Messages[0].ReceiptHandle) || retry.Messages[0].Attributes["ApproximateReceiveCount"] != "1" {
		t.Fatalf("retry=%v %v", retry, err)
	}
	next := receive(t, c, url, 10)
	if len(next) != 1 || aws.ToString(next[0].Body) != "b1" {
		t.Fatalf("group isolation=%v", next)
	}
	_, err = c.DeleteMessage(ctx, &sdk.DeleteMessageInput{QueueUrl: aws.String(url), ReceiptHandle: first.Messages[0].ReceiptHandle})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ReceiveMessage(ctx, in)
	requireCode(t, err, "InvalidParameterValue")
	next = receive(t, c, url, 10)
	if len(next) != 1 || aws.ToString(next[0].Body) != "a2" {
		t.Fatalf("group did not release=%v", next)
	}
	duplicate = fifoSend(t, c, url, "a1", "a", "")
	if aws.ToString(duplicate.MessageId) != aws.ToString(a.MessageId) {
		t.Fatal("delete discarded dedup window")
	}
	advance(t, clock, 5*time.Minute)
	fresh := fifoSend(t, c, url, "a1", "a", "")
	if aws.ToString(fresh.MessageId) == aws.ToString(a.MessageId) {
		t.Fatal("dedup interval did not expire")
	}
}
func TestFIFOGroupScopedDedupAndDelayUpdate(t *testing.T) {
	_, c, clock, _ := fixture(t)
	ctx := context.Background()
	url := create(t, c, "groups.fifo", map[string]string{"FifoQueue": "true", "DeduplicationScope": "messageGroup", "FifoThroughputLimit": "perMessageGroupId", "DelaySeconds": "10"})
	a := fifoSend(t, c, url, "same", "a", "token")
	b := fifoSend(t, c, url, "same", "b", "token")
	if aws.ToString(a.MessageId) == aws.ToString(b.MessageId) {
		t.Fatal("group-scoped dedup crossed groups")
	}
	if len(receive(t, c, url, 10)) != 0 {
		t.Fatal("FIFO delay ignored")
	}
	_, err := c.SetQueueAttributes(ctx, &sdk.SetQueueAttributesInput{QueueUrl: aws.String(url), Attributes: map[string]string{"DelaySeconds": "20"}})
	if err != nil {
		t.Fatal(err)
	}
	advance(t, clock, 10*time.Second)
	if len(receive(t, c, url, 10)) != 0 {
		t.Fatal("FIFO delay update was not retroactive")
	}
	advance(t, clock, 10*time.Second)
	if got := receive(t, c, url, 10); len(got) != 2 {
		t.Fatalf("delivery=%v", got)
	}
	_, err = c.SendMessage(ctx, &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("bad"), MessageGroupId: aws.String("a"), MessageDeduplicationId: aws.String("x"), DelaySeconds: 1})
	requireCode(t, err, "InvalidParameterValue")
}
