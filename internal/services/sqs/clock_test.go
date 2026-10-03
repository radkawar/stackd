package sqs

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awswire"
)

type advancingClockAuthorizer struct {
	t        *testing.T
	clock    *clock.Manual
	instants []time.Time
}

func (a *advancingClockAuthorizer) Authorize(_ context.Context, request authorization.Request) *awswire.Error {
	if request.EvaluationTime == nil {
		a.t.Error("authorization omitted captured time")
	} else {
		a.instants = append(a.instants, *request.EvaluationTime)
	}
	advance(a.t, a.clock, time.Minute)
	return nil
}

func TestManualClockSharesTimeAcrossAuthorizationActions(t *testing.T) {
	manual := newClock()
	authorizer := &advancingClockAuthorizer{t: t, clock: manual}
	service := NewWithConfig(Config{Clock: manual, Authorizer: authorizer})
	client := testClient(testServer(t, service), "111111111111", "us-east-1")
	instant := manual.Now()
	_, err := client.CreateQueue(t.Context(), &sdk.CreateQueueInput{QueueName: aws.String("authorization-time"), Tags: map[string]string{"team": "test"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(authorizer.instants) != 2 || !authorizer.instants[0].Equal(instant) || !authorizer.instants[1].Equal(instant) {
		t.Fatalf("create/tag authorization instants = %v, want %v", authorizer.instants, instant)
	}
}

type pollResult struct {
	output *sdk.ReceiveMessageOutput
	err    error
}

func startPoll(ctx context.Context, client *sdk.Client, url string) <-chan pollResult {
	result := make(chan pollResult, 1)
	go func() {
		out, err := client.ReceiveMessage(ctx, &sdk.ReceiveMessageInput{
			QueueUrl: aws.String(url), WaitTimeSeconds: 20,
			MessageSystemAttributeNames: []types.MessageSystemAttributeName{types.MessageSystemAttributeNameAll},
		})
		result <- pollResult{out, err}
	}()
	return result
}

func finishPoll(t *testing.T, result <-chan pollResult) pollResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not finish after its modeled deadline or cancellation")
		return pollResult{}
	}
}

func requireMessages(t *testing.T, result <-chan pollResult, count int) *sdk.ReceiveMessageOutput {
	t.Helper()
	got := finishPoll(t, result)
	if got.err != nil || got.output == nil || len(got.output.Messages) != count {
		t.Fatalf("receive=%v %v, want %d messages", got.output, got.err, count)
	}
	return got.output
}

func requirePending(t *testing.T, clock *clock.Manual, count int) {
	t.Helper()
	if got := clock.Pending(); got != count {
		t.Fatalf("pending timers=%d, want %d", got, count)
	}
}

func TestManualClockLongPollExpiresAtExactDeadline(t *testing.T) {
	_, client, clock, _ := fixture(t)
	url := create(t, client, "deadline", nil)
	result := startPoll(t.Context(), client, url)
	waitForTimers(t, clock, 1)
	advance(t, clock, 20*time.Second-time.Nanosecond)
	requirePending(t, clock, 1)
	advance(t, clock, time.Nanosecond)
	requireMessages(t, result, 0)
	requirePending(t, clock, 0)
}

func TestManualClockDefaultAuthorizationUsesModeledTime(t *testing.T) {
	_, client, manual, _ := fixture(t)
	url := create(t, client, "policy-time", nil)
	arn := attributes(t, client, url)["QueueArn"]
	deadline := manual.Now().Add(time.Minute)
	document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":%q,"Condition":{"DateGreaterThanEquals":{"aws:CurrentTime":%q}}}]}`, arn, deadline.Format(time.RFC3339))
	_, err := client.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: aws.String(url), Attributes: map[string]string{"Policy": document}})
	if err != nil {
		t.Fatal(err)
	}
	send(t, client, url, "before expiry")
	advance(t, manual, time.Minute)
	_, err = client.SendMessage(t.Context(), &sdk.SendMessageInput{QueueUrl: aws.String(url), MessageBody: aws.String("at expiry")})
	requireCode(t, err, "AccessDenied")
}

func TestManualClockLongPollWakesAtDelayAndVisibilityBoundaries(t *testing.T) {
	_, client, clock, _ := fixture(t)
	url := create(t, client, "scheduled", map[string]string{"DelaySeconds": "5", "VisibilityTimeout": "7"})
	sent := send(t, client, url, "scheduled message")
	result := startPoll(t.Context(), client, url)
	waitForTimers(t, clock, 1)
	advance(t, clock, 5*time.Second-time.Nanosecond)
	requirePending(t, clock, 1)
	if attributes(t, client, url)["ApproximateNumberOfMessagesDelayed"] != "1" {
		t.Fatal("message became visible before delay elapsed")
	}
	advance(t, clock, time.Nanosecond)
	first := requireMessages(t, result, 1).Messages[0]
	if aws.ToString(first.MessageId) != aws.ToString(sent.MessageId) || first.Attributes["ApproximateReceiveCount"] != "1" {
		t.Fatalf("first delivery=%v", first)
	}
	requirePending(t, clock, 0)

	result = startPoll(t.Context(), client, url)
	waitForTimers(t, clock, 1)
	advance(t, clock, 7*time.Second-time.Nanosecond)
	requirePending(t, clock, 1)
	advance(t, clock, time.Nanosecond)
	second := requireMessages(t, result, 1).Messages[0]
	if aws.ToString(second.MessageId) != aws.ToString(first.MessageId) || aws.ToString(second.ReceiptHandle) == aws.ToString(first.ReceiptHandle) || second.Attributes["ApproximateReceiveCount"] != "2" {
		t.Fatalf("redelivery=%v", second)
	}
	requirePending(t, clock, 0)
}

func TestManualClockRetentionPrunesDuringLongPoll(t *testing.T) {
	_, client, clock, _ := fixture(t)
	url := create(t, client, "retained", map[string]string{"MessageRetentionPeriod": "60", "VisibilityTimeout": "120"})
	send(t, client, url, "expires while invisible")
	if len(receive(t, client, url, 1)) != 1 {
		t.Fatal("initial receive failed")
	}
	advance(t, clock, 50*time.Second)
	result := startPoll(t.Context(), client, url)
	waitForTimers(t, clock, 1)
	advance(t, clock, 10*time.Second)
	// The retention wake prunes the message and registers the remaining wait.
	waitForTimers(t, clock, 1)
	attrs := attributes(t, client, url)
	if attrs["ApproximateNumberOfMessagesNotVisible"] != "0" || attrs["ApproximateNumberOfMessages"] != "0" {
		t.Fatalf("expired message retained: %v", attrs)
	}
	advance(t, clock, 10*time.Second)
	requireMessages(t, result, 0)
	requirePending(t, clock, 0)
}

func TestManualClockLongPollReschedulesWhenVisibilityChanges(t *testing.T) {
	_, client, clock, _ := fixture(t)
	url := create(t, client, "rescheduled", map[string]string{"VisibilityTimeout": "10"})
	send(t, client, url, "released early")
	first := receive(t, client, url, 1)
	result := startPoll(t.Context(), client, url)
	waitForTimers(t, clock, 1)
	_, err := client.ChangeMessageVisibility(t.Context(), &sdk.ChangeMessageVisibilityInput{
		QueueUrl: aws.String(url), ReceiptHandle: first[0].ReceiptHandle, VisibilityTimeout: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	advance(t, clock, 2*time.Second)
	requireMessages(t, result, 1)
	requirePending(t, clock, 0)
}

func TestManualClockLongPollCancellationAndShutdownReleaseTimers(t *testing.T) {
	for _, mode := range []string{"cancel", "close", "delete", "send"} {
		t.Run(mode, func(t *testing.T) {
			s, client, clock, _ := fixture(t)
			url := create(t, client, "waiting", nil)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := startPoll(ctx, client, url)
			waitForTimers(t, clock, 1)
			switch mode {
			case "cancel":
				cancel()
			case "close":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				requirePending(t, clock, 0)
			case "delete":
				if _, err := client.DeleteQueue(t.Context(), &sdk.DeleteQueueInput{QueueUrl: aws.String(url)}); err != nil {
					t.Fatal(err)
				}
			case "send":
				send(t, client, url, "wakes without advancing time")
			}
			got := finishPoll(t, result)
			if mode == "send" {
				if got.err != nil || got.output == nil || len(got.output.Messages) != 1 {
					t.Fatalf("send wake=%v %v", got.output, got.err)
				}
			} else if got.err == nil {
				t.Fatal("canceled receive succeeded")
			}
			if mode == "delete" {
				requireCode(t, got.err, "AWS.SimpleQueueService.NonExistentQueue")
			}
			// HTTP cancellation can complete at the client before the server sees it.
			// Close joins the server handler and gives a deterministic leak check.
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			requirePending(t, clock, 0)
		})
	}
}

// gatedTimerClock holds the first absolute registration outside the clock lock
// to reproduce advances/queue notifications after the state transaction commits.
type gatedTimerClock struct {
	*clock.Manual
	once     sync.Once
	deadline chan time.Time
	release  chan struct{}
}

func (c *gatedTimerClock) NewTimerAt(at time.Time) clock.Timer {
	c.once.Do(func() { c.deadline <- at; <-c.release })
	return c.Manual.NewTimerAt(at)
}

func TestManualClockAdvanceBeforeTimerRegistrationCannotMissDeadline(t *testing.T) {
	for _, before := range []time.Duration{5 * time.Second, 20 * time.Second} {
		t.Run(before.String(), func(t *testing.T) {
			manual := newClock()
			clock := &gatedTimerClock{Manual: manual, deadline: make(chan time.Time, 1), release: make(chan struct{})}
			s := NewWithConfig(Config{Clock: clock})
			server := testServer(t, s)
			released := false
			t.Cleanup(func() {
				if !released {
					close(clock.release)
				}
			})
			client := testClient(server, "111111111111", "us-east-1")
			url := create(t, client, "registration", nil)
			started := manual.Now()
			result := startPoll(t.Context(), client, url)
			select {
			case at := <-clock.deadline:
				if !at.Equal(started.Add(20 * time.Second)) {
					t.Fatalf("deadline=%v", at)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timer was not registered")
			}
			advance(t, manual, before)
			close(clock.release)
			released = true
			if before < 20*time.Second {
				waitForTimers(t, manual, 1)
				advance(t, manual, 20*time.Second-before)
			}
			requireMessages(t, result, 0)
			requirePending(t, manual, 0)
		})
	}
}

func TestManualClockQueueNotificationBeforeTimerRegistrationIsNotLost(t *testing.T) {
	manual := newClock()
	clock := &gatedTimerClock{Manual: manual, deadline: make(chan time.Time, 1), release: make(chan struct{})}
	s := NewWithConfig(Config{Clock: clock})
	server := testServer(t, s)
	released := false
	t.Cleanup(func() {
		if !released {
			close(clock.release)
		}
	})
	client := testClient(server, "111111111111", "us-east-1")
	url := create(t, client, "notify", nil)
	result := startPoll(t.Context(), client, url)
	select {
	case <-clock.deadline:
	case <-time.After(5 * time.Second):
		t.Fatal("timer was not registered")
	}
	send(t, client, url, "arrived during registration")
	close(clock.release)
	released = true
	requireMessages(t, result, 1)
	requirePending(t, manual, 0)
}

type advancingKMS struct {
	testKMS
	clock *clock.Manual
}

func (k *advancingKMS) GenerateDataKey(ctx context.Context, id string, ec map[string]string) ([]byte, []byte, string, *awswire.Error) {
	plaintext, ciphertext, arn, err := k.testKMS.GenerateDataKey(ctx, id, ec)
	if advanceErr := k.clock.Advance(20 * time.Second); advanceErr != nil {
		return nil, nil, "", failure("InvalidState", advanceErr.Error())
	}
	return plaintext, ciphertext, arn, err
}

func TestManualClockMessageTransactionStartsAfterKeyPreparation(t *testing.T) {
	manual := newClock()
	backend := &advancingKMS{clock: manual}
	s := NewWithConfig(Config{Clock: manual, KMS: backend})
	server := testServer(t, s)
	client := testClient(server, "111111111111", "us-east-1")
	url := create(t, client, "atomic-time", map[string]string{"KmsMasterKeyId": "test-key", "DelaySeconds": "10"})
	started := manual.Now()
	out, err := client.SendMessageBatch(t.Context(), &sdk.SendMessageBatchInput{QueueUrl: aws.String(url), Entries: []types.SendMessageBatchRequestEntry{
		{Id: aws.String("first"), MessageBody: aws.String("one")},
		{Id: aws.String("second"), MessageBody: aws.String("two")},
	}})
	if err != nil || len(out.Successful) != 2 {
		t.Fatalf("batch=%v %v", out, err)
	}
	if err := s.repository.View(t.Context(), func(reader Reader) error {
		q, err := reader.Queue(QueueKey{Partition: "aws", Account: "111111111111", Region: "us-east-1", Name: "atomic-time"})
		if err != nil {
			return err
		}
		messages, err := reader.Messages(q.ID)
		if err != nil {
			return err
		}
		if len(messages.Messages) != 2 {
			t.Fatalf("stored messages=%v", messages)
		}
		for _, message := range messages.Messages {
			if !message.Sent.Equal(started.Add(20*time.Second)) || !message.Available.Equal(started.Add(30*time.Second)) {
				t.Fatalf("split transaction timestamps: %v", message)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, client, url, 10); len(got) != 0 {
		t.Fatalf("preparation time consumed the message delay: %v", got)
	}
	advance(t, manual, 10*time.Second)
	if got := receive(t, client, url, 10); len(got) != 2 {
		t.Fatalf("message delay did not release the committed batch: %v", got)
	}
}

func TestManualClockRedriveRateAndShutdown(t *testing.T) {
	s, client, clock, _ := fixture(t)
	source, _, arn := deadLetterFixture(t, client)
	for range 3 {
		send(t, client, source, "retry")
	}
	if len(receive(t, client, source, 10)) != 3 {
		t.Fatal("source delivery failed")
	}
	receive(t, client, source, 10)
	_, err := client.StartMessageMoveTask(t.Context(), &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(arn), MaxNumberOfMessagesPerSecond: aws.Int32(1)})
	if err != nil {
		t.Fatal(err)
	}
	waitForTimers(t, clock, 1)
	advance(t, clock, time.Second-time.Nanosecond)
	out, err := client.ListMessageMoveTasks(t.Context(), &sdk.ListMessageMoveTasksInput{SourceArn: aws.String(arn)})
	if err != nil || len(out.Results) != 1 || out.Results[0].ApproximateNumberOfMessagesMoved != 0 {
		t.Fatalf("early move=%v %v", out, err)
	}
	advance(t, clock, time.Nanosecond)
	waitForTimers(t, clock, 1)
	out, err = client.ListMessageMoveTasks(t.Context(), &sdk.ListMessageMoveTasksInput{SourceArn: aws.String(arn)})
	if err != nil || len(out.Results) != 1 || out.Results[0].ApproximateNumberOfMessagesMoved != 1 {
		t.Fatalf("first move=%v %v", out, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	requirePending(t, clock, 0)
	advance(t, clock, 36*time.Hour)
	if err := s.repository.View(t.Context(), func(reader Reader) error {
		tasks, err := reader.MoveTasks()
		if err != nil {
			return err
		}
		if len(tasks) != 1 || tasks[0].Status != moveRunning || tasks[0].Moved != 1 {
			t.Fatalf("closed task changed: %v", tasks)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
