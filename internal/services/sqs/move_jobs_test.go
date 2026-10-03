package sqs

import (
	"encoding/json"
	"path"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"stackd/clock"
)

type redriveFixture struct {
	s                                     *Service
	c                                     *sdk.Client
	clock                                 *clock.Manual
	backend                               Repository
	source, dlq, destination, arn, handle string
}

// Reopening keeps the automatic worker stopped until explicitly started, so
// tests can also exercise the shared driver's bounded drain deterministically.
func (f *redriveFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s = NewWithConfig(Config{Repository: f.backend, Clock: f.clock})
	server := testServer(t, f.s)
	f.c = testClient(server, "111111111111", "us-east-1")
	for _, target := range []*string{&f.source, &f.dlq, &f.destination} {
		name := path.Base(*target)
		out, err := f.c.GetQueueUrl(t.Context(), &sdk.GetQueueUrlInput{QueueName: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		*target = aws.ToString(out.QueueUrl)
	}
}

func retainedRedrive(t *testing.T, backend Repository, count int, rate int32) *redriveFixture {
	t.Helper()
	f := &redriveFixture{backend: backend, clock: newClock()}
	f.s = NewWithConfig(Config{Repository: backend, Clock: f.clock})
	f.c = testClient(testServer(t, f.s), "111111111111", "us-east-1")
	f.source, f.dlq, f.arn = deadLetterFixture(t, f.c)
	f.destination = create(t, f.c, "destination", nil)
	sendTenant(t, f.c, f.dlq, "", count)
	out, err := f.c.StartMessageMoveTask(t.Context(), &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(f.arn), DestinationArn: aws.String(attributes(t, f.c, f.destination)["QueueArn"]), MaxNumberOfMessagesPerSecond: aws.Int32(rate)})
	if err != nil {
		t.Fatal(err)
	}
	f.handle = aws.ToString(out.TaskHandle)
	f.reopen(t)
	return f
}

func (f *redriveFixture) status(t *testing.T) types.ListMessageMoveTasksResultEntry {
	t.Helper()
	out, err := f.c.ListMessageMoveTasks(t.Context(), &sdk.ListMessageMoveTasksInput{SourceArn: aws.String(f.arn)})
	if err != nil || len(out.Results) != 1 {
		t.Fatalf("task status: %v %v", out, err)
	}
	return out.Results[0]
}

func TestRedriveRetainsRateProgressAcrossBoundedDrainsAndReconstruction(t *testing.T) {
	f := retainedRedrive(t, NewMemoryRepository(nil), 5, 2)
	advance(t, f.clock, 2*time.Second)
	result, err := f.s.jobs.RunDue(t.Context(), 2)
	if err != nil || result.Processed != 2 || !result.More {
		t.Fatalf("bounded drain: %v %v", result, err)
	}
	first := f.status(t)
	if first.ApproximateNumberOfMessagesMoved != 2 || aws.ToInt64(first.ApproximateNumberOfMessagesToMove) != 5 {
		t.Fatalf("partial task: %v", first)
	}
	f.reopen(t)
	result, err = f.s.jobs.RunDue(t.Context(), 10)
	if err != nil || result.Processed != 2 || result.More {
		t.Fatalf("recovered drain: %v %v", result, err)
	}
	if got := f.status(t); got.ApproximateNumberOfMessagesMoved != 4 || got.StartedTimestamp != first.StartedTimestamp {
		t.Fatalf("recovered status: %v", got)
	}
	advance(t, f.clock, time.Second/2)
	f.s.StartWorkers()
	done := awaitMove(t, f.s, f.c, f.arn, "COMPLETED")
	if done.ApproximateNumberOfMessagesMoved != 5 || aws.ToInt64(done.ApproximateNumberOfMessagesToMove) != 5 {
		t.Fatalf("completed count: %v", done)
	}
	if got := receive(t, f.c, f.destination, 10); len(got) != 5 {
		t.Fatalf("destination messages: %v", got)
	}
}

func TestRedriveFailedCommitRetainsMessagesCountersAndDeadline(t *testing.T) {
	backend := &failingRepository{Repository: NewMemoryRepository(nil)}
	f := retainedRedrive(t, backend, 3, 1)
	advance(t, f.clock, time.Second)
	backend.fail = true
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err == nil {
		t.Fatal("failed redrive commit succeeded")
	}
	if err := backend.View(t.Context(), func(r Reader) error {
		tasks, err := r.MoveTasks()
		if err != nil {
			return err
		}
		if len(tasks) != 1 || tasks[0].Status != moveRunning || tasks[0].Moved != 0 || !tasks[0].Due.Equal(tasks[0].Started.Add(time.Second)) {
			t.Fatalf("failed commit changed task: %v", tasks)
		}
		for name, count := range map[string]int{"dead": 3, "destination": 0} {
			q, err := r.Queue(QueueKey{Partition: "aws", Account: "111111111111", Region: "us-east-1", Name: name})
			if err != nil {
				return err
			}
			messages, err := r.Messages(q.ID)
			if err != nil {
				return err
			}
			if len(messages.Messages) != count {
				t.Fatalf("%s has %d messages, want %d", name, len(messages.Messages), count)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	backend.fail = false
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t); got.ApproximateNumberOfMessagesMoved != 1 {
		t.Fatalf("retry status: %v", got)
	}
	if got := receive(t, f.c, f.destination, 10); len(got) != 1 {
		t.Fatalf("retry duplicated or lost message: %v", got)
	}
}

func TestRedriveRechecksDestinationPolicyBeforeMoving(t *testing.T) {
	f := retainedRedrive(t, NewMemoryRepository(nil), 2, 1)
	arn := attributes(t, f.c, f.destination)["QueueArn"]
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":"` + arn + `"}]}`
	if _, err := f.c.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: aws.String(f.destination), Attributes: map[string]string{"Policy": policy}}); err != nil {
		t.Fatal(err)
	}
	advance(t, f.clock, time.Second)
	if _, err := f.s.jobs.RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	got := f.status(t)
	if aws.ToString(got.Status) != moveFailed || got.ApproximateNumberOfMessagesMoved != 0 || got.FailureReason == nil {
		t.Fatalf("policy revocation: %v", got)
	}
	if attributes(t, f.c, f.dlq)["ApproximateNumberOfMessages"] != "2" || len(receive(t, f.c, f.destination, 10)) != 0 {
		t.Fatal("denied redrive moved messages")
	}
}

func TestRedriveEqualDeadlinesUseAcceptanceOrder(t *testing.T) {
	f := retainedRedrive(t, NewMemoryRepository(nil), 1, 1)
	secondDLQ := create(t, f.c, "second-dead", nil)
	secondARN := attributes(t, f.c, secondDLQ)["QueueArn"]
	policy, err := json.Marshal(map[string]any{"deadLetterTargetArn": secondARN, "maxReceiveCount": 1})
	if err != nil {
		t.Fatal(err)
	}
	create(t, f.c, "second-source", map[string]string{"RedrivePolicy": string(policy)})
	send(t, f.c, secondDLQ, "second")
	if _, err := f.c.StartMessageMoveTask(t.Context(), &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(secondARN), DestinationArn: aws.String(attributes(t, f.c, f.destination)["QueueArn"]), MaxNumberOfMessagesPerSecond: aws.Int32(1)}); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	advance(t, f.clock, time.Second)
	for _, body := range []string{"-0", "second"} {
		if _, err := f.s.jobs.RunDue(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		messages := receive(t, f.c, f.destination, 10)
		if len(messages) != 1 || aws.ToString(messages[0].Body) != body {
			t.Fatalf("equal deadline order: %v, want %q", messages, body)
		}
	}
}
