package sqs

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func nativeFIFOMessage(t *testing.T, caseName, body string) types.Message {
	t.Helper()
	for _, observation := range fifoNativeCapture(t) {
		if observation.Case != caseName {
			continue
		}
		for _, m := range observation.Output.Messages {
			if aws.ToString(m.Body) == body {
				return m
			}
		}
	}
	t.Fatalf("missing native message %s in %s", body, caseName)
	return types.Message{}
}

func TestFIFODeadLetterNativeHistoryAndDeduplication(t *testing.T) {
	f := fifoRedriveFixture(t, NewMemoryRepository(nil))
	sent := fifoSend(t, f.c, f.source, "poison", "source-group", "source-poison")
	advance(t, f.clock, time.Second)
	first := receive(t, f.c, f.source, 1)
	if len(first) != 1 {
		t.Fatal("missing source delivery")
	}
	advance(t, f.clock, time.Second)
	if len(receive(t, f.c, f.source, 1)) != 0 {
		t.Fatal("exhausted message remained at source")
	}
	f.reopen(t)
	dead := receive(t, f.c, f.dlq, 1)
	if len(dead) != 1 {
		t.Fatal("missing dead-letter delivery")
	}
	got := dead[0]
	nativeSource := nativeFIFOMessage(t, "source_attempt_poison", "poison")
	nativeDead := nativeFIFOMessage(t, "dead_arrival_poison", "poison")
	if (aws.ToString(got.MessageId) == aws.ToString(sent.MessageId)) != (aws.ToString(nativeDead.MessageId) == aws.ToString(nativeSource.MessageId)) ||
		(got.Attributes["MessageDeduplicationId"] == aws.ToString(sent.MessageId)) != (nativeDead.Attributes["MessageDeduplicationId"] == aws.ToString(nativeSource.MessageId)) {
		t.Fatalf("dead-letter identity differs from native: %v", got)
	}
	for _, key := range []string{"SenderId", "SentTimestamp", "ApproximateFirstReceiveTimestamp"} {
		if (got.Attributes[key] == first[0].Attributes[key]) != (nativeDead.Attributes[key] == nativeSource.Attributes[key]) {
			t.Fatalf("dead-letter %s differs from native: source=%v dead=%v", key, first[0], got)
		}
	}
	for _, key := range []string{"MessageGroupId", "ApproximateReceiveCount"} {
		if got.Attributes[key] != nativeDead.Attributes[key] {
			t.Fatalf("dead-letter %s = %s, native %s", key, got.Attributes[key], nativeDead.Attributes[key])
		}
	}
	if got.Attributes["DeadLetterQueueSourceArn"] != attributes(t, f.c, f.source)["QueueArn"] {
		t.Fatal("dead-letter source ARN was lost")
	}
	deleteFairMessages(t, f.c, f.dlq, dead)
	f.reopen(t)
	duplicate := fifoSend(t, f.c, f.dlq, "duplicate-poison", "source-group", got.Attributes["MessageDeduplicationId"])
	for _, observation := range fifoNativeCapture(t) {
		if observation.Case == "duplicate_dead_arrival" {
			if (aws.ToString(duplicate.MessageId) == aws.ToString(got.MessageId)) != (observation.Output.MessageID == aws.ToString(nativeDead.MessageId)) ||
				(aws.ToString(duplicate.SequenceNumber) == got.Attributes["SequenceNumber"]) != (observation.Output.SequenceNumber == nativeDead.Attributes["SequenceNumber"]) {
				t.Fatalf("dead-letter deduplication differs from native: %v", duplicate)
			}
		}
	}
	if len(receive(t, f.c, f.dlq, 1)) != 0 {
		t.Fatal("duplicate dead-letter message was delivered after deletion and reconstruction")
	}
}

func TestFIFODeadLetterReturnSourceResetsNativeHistory(t *testing.T) {
	f := fifoRedriveFixture(t, NewMemoryRepository(nil))
	fifoSend(t, f.c, f.source, "return", "source-group", "source-return")
	receive(t, f.c, f.source, 1)
	advance(t, f.clock, time.Second)
	receive(t, f.c, f.source, 1)
	dead := receive(t, f.c, f.dlq, 1)
	if len(dead) != 1 {
		t.Fatal("missing dead-letter delivery")
	}
	if _, err := f.c.ChangeMessageVisibility(t.Context(), &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(f.dlq), ReceiptHandle: dead[0].ReceiptHandle, VisibilityTimeout: 0}); err != nil {
		t.Fatal(err)
	}
	f.startFIFO(t, "")
	advance(t, f.clock, time.Second)
	if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	returned := receive(t, f.c, f.source, 1)
	if len(returned) != 1 {
		t.Fatal("redrive did not permit a new source delivery")
	}
	got := returned[0]
	nativeDead := nativeFIFOMessage(t, "dead_arrival_return", "return")
	nativeReturn := nativeFIFOMessage(t, "returned_source", "return")
	if (aws.ToString(got.MessageId) == aws.ToString(dead[0].MessageId)) != (aws.ToString(nativeReturn.MessageId) == aws.ToString(nativeDead.MessageId)) ||
		(got.Attributes["MessageDeduplicationId"] == aws.ToString(dead[0].MessageId)) != (nativeReturn.Attributes["MessageDeduplicationId"] == aws.ToString(nativeDead.MessageId)) {
		t.Fatalf("return identity differs from native: %v", got)
	}
	for _, key := range []string{"MessageGroupId", "ApproximateReceiveCount", "DeadLetterQueueSourceArn"} {
		if got.Attributes[key] != nativeReturn.Attributes[key] {
			t.Fatalf("returned %s = %s, native %s", key, got.Attributes[key], nativeReturn.Attributes[key])
		}
	}
	for _, key := range []string{"SentTimestamp", "ApproximateFirstReceiveTimestamp"} {
		if (got.Attributes[key] == dead[0].Attributes[key]) != (nativeReturn.Attributes[key] == nativeDead.Attributes[key]) {
			t.Fatalf("returned %s did not reset as in AWS", key)
		}
	}
	if len(receive(t, f.c, f.source, 1)) != 0 {
		t.Fatal("second failed delivery did not exhaust source policy")
	}
	deadAgain := receive(t, f.c, f.dlq, 1)
	if len(deadAgain) != 1 || deadAgain[0].Attributes["ApproximateReceiveCount"] != "2" || deadAgain[0].Attributes["MessageDeduplicationId"] != aws.ToString(got.MessageId) {
		t.Fatalf("subsequent dead-letter cycle lost its new identity: %v", deadAgain)
	}
}

func TestDeadLetterRetentionUsesQueueTypeAndSurvivesReconstruction(t *testing.T) {
	for _, fifo := range []bool{false, true} {
		name := "standard"
		if fifo {
			name = "fifo"
		}
		t.Run(name, func(t *testing.T) {
			f := fifoRedriveFixture(t, NewMemoryRepository(nil))
			if !fifo {
				f.source, f.dlq, f.arn = deadLetterFixture(t, f.c)
			}
			if _, err := f.c.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: aws.String(f.dlq), Attributes: map[string]string{"MessageRetentionPeriod": "60"}}); err != nil {
				t.Fatal(err)
			}
			if fifo {
				fifoSend(t, f.c, f.source, "retained", "g", "input")
			} else {
				send(t, f.c, f.source, "retained")
			}
			receive(t, f.c, f.source, 1)
			advance(t, f.clock, 40*time.Second)
			receive(t, f.c, f.source, 1)
			f.reopen(t)
			dead := receive(t, f.c, f.dlq, 1)
			if len(dead) != 1 || dead[0].Attributes["ApproximateReceiveCount"] != "2" {
				t.Fatalf("missing delivery history: %v", dead)
			}
			advance(t, f.clock, 20*time.Second)
			want := "0"
			if fifo {
				want = "1"
			}
			if got := attributes(t, f.c, f.dlq)["ApproximateNumberOfMessagesNotVisible"]; got != want {
				t.Fatalf("in-flight count after original retention = %s, want %s", got, want)
			}
			advance(t, f.clock, 40*time.Second)
			if got := attributes(t, f.c, f.dlq)["ApproximateNumberOfMessagesNotVisible"]; got != "0" {
				t.Fatalf("message outlived dead-letter retention: %s", got)
			}
		})
	}
}

func TestFIFODeadLetterCommitFailurePreservesSourceAndDeduplication(t *testing.T) {
	backend := &failingRepository{Repository: NewMemoryRepository(nil)}
	f := fifoRedriveFixture(t, backend)
	sent := fifoSend(t, f.c, f.source, "atomic", "g", "input")
	receive(t, f.c, f.source, 1)
	backend.fail = true
	_, err := f.c.ReceiveMessage(t.Context(), &sdk.ReceiveMessageInput{QueueUrl: aws.String(f.source)})
	if err == nil {
		t.Fatal("failed dead-letter commit succeeded")
	}
	backend.fail = false
	f.reopen(t)
	if attributes(t, f.c, f.source)["ApproximateNumberOfMessages"] != "1" || attributes(t, f.c, f.dlq)["ApproximateNumberOfMessages"] != "0" {
		t.Fatal("failed dead-letter commit moved the source message")
	}
	receive(t, f.c, f.source, 1)
	dead := receive(t, f.c, f.dlq, 1)
	if len(dead) != 1 || dead[0].Attributes["ApproximateReceiveCount"] != "2" || aws.ToString(dead[0].MessageId) != aws.ToString(sent.MessageId) {
		t.Fatalf("dead-letter retry lost history or was suppressed by failed deduplication: %v", dead)
	}
	duplicate := fifoSend(t, f.c, f.dlq, "duplicate", "g", aws.ToString(sent.MessageId))
	if aws.ToString(duplicate.MessageId) != aws.ToString(dead[0].MessageId) || aws.ToString(duplicate.SequenceNumber) != dead[0].Attributes["SequenceNumber"] {
		t.Fatal("successful dead-letter retry did not publish its deduplication binding")
	}
}
