package sqs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func fifoRedriveFixture(t *testing.T, backend Repository) *redriveFixture {
	t.Helper()
	f := &redriveFixture{backend: backend, clock: newClock()}
	f.s = NewWithConfig(Config{Repository: backend, Clock: f.clock})
	f.c = testClient(testServer(t, f.s), "111111111111", "us-east-1")
	f.dlq = create(t, f.c, "dead.fifo", map[string]string{"FifoQueue": "true", "VisibilityTimeout": "600"})
	f.arn = attributes(t, f.c, f.dlq)["QueueArn"]
	policy, err := json.Marshal(map[string]any{"deadLetterTargetArn": f.arn, "maxReceiveCount": 1})
	if err != nil {
		t.Fatal(err)
	}
	f.source = create(t, f.c, "source.fifo", map[string]string{"FifoQueue": "true", "RedrivePolicy": string(policy), "VisibilityTimeout": "0"})
	f.destination = create(t, f.c, "destination.fifo", map[string]string{"FifoQueue": "true"})
	return f
}

func (f *redriveFixture) startFIFO(t *testing.T, destination string) {
	t.Helper()
	in := &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(f.arn), MaxNumberOfMessagesPerSecond: aws.Int32(10)}
	if destination != "" {
		in.DestinationArn = aws.String(attributes(t, f.c, destination)["QueueArn"])
	}
	out, err := f.c.StartMessageMoveTask(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	f.handle = aws.ToString(out.TaskHandle)
	f.reopen(t)
}

type fifoNativeObservation struct {
	Case   string
	Output struct {
		MessageID      string `json:"MessageId"`
		SequenceNumber string
		Messages       []types.Message
		Results        []types.ListMessageMoveTasksResultEntry
	}
}

func fifoNativeCapture(t *testing.T) []fifoNativeObservation {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/sqs/fifo_redrive.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct{ Observations []fifoNativeObservation }
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	return capture.Observations
}

func checkFIFORedriveIdentity(t *testing.T, body string, sent *sdk.SendMessageOutput, moved types.Message) {
	t.Helper()
	var nativeSource string
	var nativeMoved types.Message
	for _, observation := range fifoNativeCapture(t) {
		if observation.Case == "send_"+body {
			nativeSource = observation.Output.MessageID
		}
		if observation.Case == "held_destination" || observation.Case == "released_destination" {
			for _, m := range observation.Output.Messages {
				if aws.ToString(m.Body) == body {
					nativeMoved = m
				}
			}
		}
	}
	if nativeSource == "" || nativeMoved.MessageId == nil {
		t.Fatalf("missing native delivery for %s", body)
	}
	if (aws.ToString(moved.MessageId) == aws.ToString(sent.MessageId)) != (aws.ToString(nativeMoved.MessageId) == nativeSource) ||
		(moved.Attributes["MessageDeduplicationId"] == aws.ToString(sent.MessageId)) != (nativeMoved.Attributes["MessageDeduplicationId"] == nativeSource) ||
		moved.Attributes["MessageGroupId"] != nativeMoved.Attributes["MessageGroupId"] || moved.Attributes["ApproximateReceiveCount"] != nativeMoved.Attributes["ApproximateReceiveCount"] {
		t.Fatalf("redrive identity for %s differs from native: sent=%v moved=%v native=%v", body, sent, moved, nativeMoved)
	}
}

func TestFIFORedriveBlocksHeldGroupAndRetainsDestinationDeduplication(t *testing.T) {
	f := fifoRedriveFixture(t, NewMemoryRepository(nil))
	a0 := fifoSend(t, f.c, f.dlq, "a0", "a", "manual-a0")
	held := receive(t, f.c, f.dlq, 1)
	if len(held) != 1 {
		t.Fatal("missing held message")
	}
	a1 := fifoSend(t, f.c, f.dlq, "a1", "a", "manual-a1")
	b0 := fifoSend(t, f.c, f.dlq, "b0", "b", "manual-b0")
	f.startFIFO(t, f.destination)
	advance(t, f.clock, time.Second)
	if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	got := receive(t, f.c, f.destination, 10)
	if len(got) != 1 || aws.ToString(got[0].Body) != "b0" {
		t.Fatalf("redrive bypassed a held group: %v", got)
	}
	checkFIFORedriveIdentity(t, "b0", b0, got[0])
	deleteFairMessages(t, f.c, f.destination, got)
	f.reopen(t)
	duplicate := fifoSend(t, f.c, f.destination, "duplicate-b0", "b", got[0].Attributes["MessageDeduplicationId"])
	if aws.ToString(duplicate.MessageId) != aws.ToString(got[0].MessageId) || aws.ToString(duplicate.SequenceNumber) != got[0].Attributes["SequenceNumber"] {
		t.Fatalf("redrive deduplication lost on reconstruction: %v", duplicate)
	}
	if len(receive(t, f.c, f.destination, 10)) != 0 {
		t.Fatal("redrive duplicate was delivered")
	}
	if status := f.status(t); status.ApproximateNumberOfMessagesMoved != 1 || aws.ToString(status.Status) != moveRunning {
		t.Fatalf("held task: %v", status)
	}
	if _, err := f.c.ChangeMessageVisibility(t.Context(), &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(f.dlq), ReceiptHandle: held[0].ReceiptHandle, VisibilityTimeout: 0}); err != nil {
		t.Fatal(err)
	}
	advance(t, f.clock, 2*time.Second)
	if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	got = receive(t, f.c, f.destination, 10)
	if len(got) != 2 || aws.ToString(got[0].Body) != "a0" || aws.ToString(got[1].Body) != "a1" {
		t.Fatalf("released group order: %v", got)
	}
	checkFIFORedriveIdentity(t, "a0", a0, got[0])
	checkFIFORedriveIdentity(t, "a1", a1, got[1])
	if status := f.status(t); status.ApproximateNumberOfMessagesMoved != 3 || aws.ToString(status.Status) != moveCompleted {
		t.Fatalf("released task: %v", status)
	}
}

func TestFIFORedriveUsesDestinationDeduplicationScopeAndOriginalWindow(t *testing.T) {
	for _, scope := range []string{"queue", "messageGroup"} {
		t.Run(scope, func(t *testing.T) {
			f := fifoRedriveFixture(t, NewMemoryRepository(nil))
			if _, err := f.c.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: aws.String(f.destination), Attributes: map[string]string{"DeduplicationScope": scope}}); err != nil {
				t.Fatal(err)
			}
			sent := fifoSend(t, f.c, f.dlq, "collision", "source-group", "input-token")
			seed := fifoSend(t, f.c, f.destination, "existing", "other-group", aws.ToString(sent.MessageId))
			deleteFairMessages(t, f.c, f.destination, receive(t, f.c, f.destination, 1))
			advance(t, f.clock, 4*time.Minute)
			f.startFIFO(t, f.destination)
			advance(t, f.clock, time.Second)
			if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			messages := receive(t, f.c, f.destination, 10)
			if scope == "queue" && len(messages) != 0 {
				t.Fatalf("queue-wide duplicate delivered: %v", messages)
			}
			if scope == "messageGroup" && (len(messages) != 1 || aws.ToString(messages[0].Body) != "collision") {
				t.Fatalf("group-scoped message was suppressed: %v", messages)
			}
			wantMoved := int64(0)
			if scope == "messageGroup" {
				wantMoved = 1
			}
			if got := f.status(t).ApproximateNumberOfMessagesMoved; got != wantMoved {
				t.Fatalf("moved count = %d, want %d", got, wantMoved)
			}
			duplicate := fifoSend(t, f.c, f.destination, "still-duplicate", "other-group", aws.ToString(sent.MessageId))
			if aws.ToString(duplicate.MessageId) != aws.ToString(seed.MessageId) {
				t.Fatal("redrive replaced the existing deduplication binding")
			}
			advance(t, f.clock, 59*time.Second)
			fresh := fifoSend(t, f.c, f.destination, "after-window", "other-group", aws.ToString(sent.MessageId))
			if aws.ToString(fresh.MessageId) == aws.ToString(seed.MessageId) {
				t.Fatal("redrive extended the original deduplication window")
			}
		})
	}
}

func TestFIFORedriveCommitFailureCannotPublishOnlyDeduplication(t *testing.T) {
	backend := &failingRepository{Repository: NewMemoryRepository(nil)}
	f := fifoRedriveFixture(t, backend)
	sent := fifoSend(t, f.c, f.dlq, "atomic", "g", "input")
	f.startFIFO(t, f.destination)
	advance(t, f.clock, time.Second)
	backend.fail = true
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err == nil {
		t.Fatal("failed redrive commit succeeded")
	}
	backend.fail = false
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	got := receive(t, f.c, f.destination, 10)
	if len(got) != 1 || aws.ToString(got[0].Body) != "atomic" {
		t.Fatalf("failed commit suppressed or duplicated retry: %v", got)
	}
	duplicate := fifoSend(t, f.c, f.destination, "duplicate", "g", aws.ToString(sent.MessageId))
	if aws.ToString(duplicate.MessageId) != aws.ToString(got[0].MessageId) {
		t.Fatal("successful retry omitted deduplication")
	}
}

func TestFIFORedriveNativeDuplicateSendBindings(t *testing.T) {
	// Each native duplicate response reuses its redriven identity; exercising
	// the equivalent SDK sends above also checks their response checksums.
	native := fifoNativeCapture(t)
	f := fifoRedriveFixture(t, NewMemoryRepository(nil))
	for _, o := range native {
		if !strings.HasPrefix(o.Case, "send_") || o.Case == "send_collision" {
			continue
		}
		body := strings.TrimPrefix(o.Case, "send_")
		fifoSend(t, f.c, f.dlq, body, string(body[0]), "manual-"+body)
	}
	f.startFIFO(t, f.destination)
	advance(t, f.clock, time.Second)
	if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	for _, m := range receive(t, f.c, f.destination, 10) {
		var nativeID, duplicateID, nativeSequence, duplicateSequence string
		for _, o := range native {
			if o.Case == "duplicate_"+aws.ToString(m.Body) {
				duplicateID, duplicateSequence = o.Output.MessageID, o.Output.SequenceNumber
			}
			if o.Case == "held_destination" || o.Case == "released_destination" {
				for _, n := range o.Output.Messages {
					if aws.ToString(n.Body) == aws.ToString(m.Body) {
						nativeID, nativeSequence = aws.ToString(n.MessageId), n.Attributes["SequenceNumber"]
					}
				}
			}
		}
		got := fifoSend(t, f.c, f.destination, "duplicate-"+aws.ToString(m.Body), m.Attributes["MessageGroupId"], m.Attributes["MessageDeduplicationId"])
		if (aws.ToString(got.MessageId) == aws.ToString(m.MessageId)) != (duplicateID == nativeID) || (aws.ToString(got.SequenceNumber) == m.Attributes["SequenceNumber"]) != (duplicateSequence == nativeSequence) {
			t.Fatal("duplicate response binding differs from AWS")
		}
	}
}

func TestFIFORedriveNativeCollisionCompletion(t *testing.T) {
	f := fifoRedriveFixture(t, NewMemoryRepository(nil))
	sent := fifoSend(t, f.c, f.dlq, "collision", "collision-group", "collision-input")
	fifoSend(t, f.c, f.destination, "existing", "collision-group", aws.ToString(sent.MessageId))
	seed := receive(t, f.c, f.destination, 1)
	if len(seed) != 1 || aws.ToString(seed[0].Body) != "existing" {
		t.Fatal("collision seed was not established")
	}
	deleteFairMessages(t, f.c, f.destination, seed)
	f.startFIFO(t, f.destination)
	advance(t, f.clock, time.Second)
	if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	got := f.status(t)
	var want types.ListMessageMoveTasksResultEntry
	for _, observation := range fifoNativeCapture(t) {
		if observation.Case == "collision_progress" {
			want = observation.Output.Results[0]
		}
	}
	if aws.ToString(want.Status) != moveCompleted {
		t.Fatal("missing native collision completion")
	}
	if got.ApproximateNumberOfMessagesMoved != want.ApproximateNumberOfMessagesMoved ||
		aws.ToInt64(got.ApproximateNumberOfMessagesToMove) != aws.ToInt64(want.ApproximateNumberOfMessagesToMove) || aws.ToString(got.Status) != aws.ToString(want.Status) {
		t.Fatalf("collision completion=%v, native=%v", got, want)
	}
	if len(receive(t, f.c, f.destination, 1)) != 0 || len(receive(t, f.c, f.dlq, 1)) != 0 {
		t.Fatal("completed collision retained or delivered a duplicate")
	}
}
