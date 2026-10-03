package sqs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"stackd/clock"
)

func deadLetterFixture(t *testing.T, c *sdk.Client) (string, string, string) {
	t.Helper()
	dlq := create(t, c, "dead", nil)
	arn := attributes(t, c, dlq)["QueueArn"]
	policy, _ := json.Marshal(map[string]any{"deadLetterTargetArn": arn, "maxReceiveCount": 1})
	source := create(t, c, "source", map[string]string{"RedrivePolicy": string(policy), "VisibilityTimeout": "0"})
	return source, dlq, arn
}
func waitForTimers(t *testing.T, clock *clock.Manual, count int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := clock.WaitForTimers(ctx, count); err != nil {
		t.Fatal(err)
	}
}
func advanceMoves(t *testing.T, clock *clock.Manual, ticks int) {
	t.Helper()
	for range ticks {
		waitForTimers(t, clock, 1)
		advance(t, clock, time.Second)
	}
}
func awaitMove(t *testing.T, s *Service, c *sdk.Client, arn, status string) types.ListMessageMoveTasksResultEntry {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := s.jobs.RunDue(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	out, err := c.ListMessageMoveTasks(t.Context(), &sdk.ListMessageMoveTasksInput{SourceArn: aws.String(arn)})
	if err != nil || len(out.Results) != 1 || aws.ToString(out.Results[0].Status) != status {
		t.Fatalf("move=%v %v, want %s", out, err, status)
	}
	return out.Results[0]
}
func TestDeadLetterRedriveAndOriginalSourceMove(t *testing.T) {
	s, c, clock, _ := fixture(t)
	ctx := context.Background()
	source, dlq, arn := deadLetterFixture(t, c)
	original := send(t, c, source, "poison")
	if len(receive(t, c, source, 1)) != 1 || len(receive(t, c, source, 1)) != 0 {
		t.Fatal("maxReceiveCount did not redrive")
	}
	sources, err := c.ListDeadLetterSourceQueues(ctx, &sdk.ListDeadLetterSourceQueuesInput{QueueUrl: aws.String(dlq), MaxResults: aws.Int32(1)})
	if err != nil || len(sources.QueueUrls) != 1 || sources.QueueUrls[0] != source {
		t.Fatalf("sources=%v %v", sources, err)
	}
	task, err := c.StartMessageMoveTask(ctx, &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(arn)})
	if err != nil || task.TaskHandle == nil {
		t.Fatalf("start=%v %v", task, err)
	}
	advanceMoves(t, clock, 2)
	result := awaitMove(t, s, c, arn, "COMPLETED")
	if result.ApproximateNumberOfMessagesMoved != 1 || result.TaskHandle != nil {
		t.Fatalf("move result=%v", result)
	}
	messages := receive(t, c, source, 1)
	if len(messages) != 1 || aws.ToString(messages[0].Body) != "poison" || aws.ToString(messages[0].MessageId) == aws.ToString(original.MessageId) || messages[0].Attributes["ApproximateReceiveCount"] != "1" {
		t.Fatalf("redriven=%v", messages)
	}
	_, err = c.CancelMessageMoveTask(ctx, &sdk.CancelMessageMoveTaskInput{TaskHandle: task.TaskHandle})
	requireCode(t, err, "AWS.SimpleQueueService.UnsupportedOperation")
}
func TestMoveCancellationAndCustomDestination(t *testing.T) {
	s, c, clock, _ := fixture(t)
	ctx := context.Background()
	source, dlq, arn := deadLetterFixture(t, c)
	for i := 0; i < 3; i++ {
		send(t, c, source, "retry")
	}
	if len(receive(t, c, source, 10)) != 3 {
		t.Fatal("missing source messages")
	}
	receive(t, c, source, 10)
	destination := create(t, c, "destination", nil)
	destinationARN := attributes(t, c, destination)["QueueArn"]
	task, err := c.StartMessageMoveTask(ctx, &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(arn), DestinationArn: aws.String(destinationARN), MaxNumberOfMessagesPerSecond: aws.Int32(1)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.StartMessageMoveTask(ctx, &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(arn)})
	requireCode(t, err, "AWS.SimpleQueueService.UnsupportedOperation")
	cancelled, err := c.CancelMessageMoveTask(ctx, &sdk.CancelMessageMoveTaskInput{TaskHandle: task.TaskHandle})
	if err != nil || cancelled.ApproximateNumberOfMessagesMoved != 0 {
		t.Fatalf("cancel=%v %v", cancelled, err)
	}
	awaitMove(t, s, c, arn, "CANCELLED")
	if attributes(t, c, dlq)["ApproximateNumberOfMessages"] != "3" {
		t.Fatal("cancel moved messages")
	}
	_, err = c.StartMessageMoveTask(ctx, &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(arn), DestinationArn: aws.String(destinationARN)})
	if err != nil {
		t.Fatal(err)
	}
	advanceMoves(t, clock, 4)
	awaitMove(t, s, c, arn, "COMPLETED")
	if len(receive(t, c, destination, 10)) != 3 {
		t.Fatal("custom destination did not receive messages")
	}
}
func TestRedriveAllowPolicyRejectsUnauthorizedSource(t *testing.T) {
	_, c, _, _ := fixture(t)
	ctx := context.Background()
	dlq := create(t, c, "denied", map[string]string{"RedriveAllowPolicy": `{"redrivePermission":"denyAll"}`})
	arn := attributes(t, c, dlq)["QueueArn"]
	policy, _ := json.Marshal(map[string]any{"deadLetterTargetArn": arn, "maxReceiveCount": 1})
	_, err := c.CreateQueue(ctx, &sdk.CreateQueueInput{QueueName: aws.String("source"), Attributes: map[string]string{"RedrivePolicy": string(policy)}})
	requireCode(t, err, "InvalidAttributeValue")
	_, err = c.GetQueueUrl(ctx, &sdk.GetQueueUrlInput{QueueName: aws.String("source")})
	requireCode(t, err, "AWS.SimpleQueueService.NonExistentQueue")
}
