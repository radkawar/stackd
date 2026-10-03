package sqs

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type forwardingCapture struct {
	Conditions   map[string]json.RawMessage `json:"deny_conditions"`
	Observations []struct {
		Case   string
		Error  *struct{ Code string }
		Output struct {
			Results  []types.ListMessageMoveTasksResultEntry
			Messages []types.Message
		}
	}
}

func readForwarding(t *testing.T, name string) forwardingCapture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/sqs/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var capture forwardingCapture
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	return capture
}

func forwardingFixture(t *testing.T) *redriveFixture {
	t.Helper()
	f := &redriveFixture{backend: NewMemoryRepository(nil), clock: newClock()}
	f.s = NewWithConfig(Config{Repository: f.backend, Clock: f.clock})
	f.c = testClient(testServer(t, f.s), "111111111111", "us-east-1")
	f.source, f.dlq, f.arn = deadLetterFixture(t, f.c)
	f.destination = create(t, f.c, "destination", nil)
	send(t, f.c, f.dlq, "redriven")
	return f
}

func restrictForwarding(t *testing.T, f *redriveFixture, condition json.RawMessage, attributesOnly bool) {
	t.Helper()
	for url, actions := range map[string]string{f.dlq: `"sqs:ReceiveMessage","sqs:DeleteMessage"`, f.destination: `"sqs:SendMessage"`} {
		arn := attributes(t, f.c, url)["QueueArn"]
		if attributesOnly {
			actions = `"sqs:GetQueueAttributes"`
		}
		doc := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":[%s],"Resource":%q,"Condition":%s}}`, actions, arn, condition)
		if _, err := f.c.SetQueueAttributes(t.Context(), &sdk.SetQueueAttributesInput{QueueUrl: aws.String(url), Attributes: map[string]string{"Policy": doc}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRedriveNativeAdmissionUsesDirectPermissions(t *testing.T) {
	capture := readForwarding(t, "forwarding_redrive")
	for _, name := range []string{"last", "first", "chain", "via", "attributes"} {
		t.Run(name, func(t *testing.T) {
			f := forwardingFixture(t)
			destination := attributes(t, f.c, f.destination)["QueueArn"]
			condition := capture.Conditions[name]
			if name == "attributes" {
				condition = capture.Conditions["last"]
			}
			restrictForwarding(t, f, condition, name == "attributes")
			_, err := f.c.StartMessageMoveTask(t.Context(), &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(f.arn), DestinationArn: aws.String(destination)})
			found := false
			for _, observation := range capture.Observations {
				if observation.Case == name+"_start" {
					found = true
					if observation.Error == nil {
						t.Fatal("native admission did not deny this policy")
					}
					requireCode(t, err, observation.Error.Code)
				}
			}
			if !found {
				t.Fatal("missing native admission")
			}
			if len(receive(t, f.c, f.destination, 10)) != 0 {
				t.Fatal("denied admission moved a message")
			}
		})
	}
}

func TestRedriveNativeExecutionForwardsCallerAndRetainsRestrictions(t *testing.T) {
	capture := readForwarding(t, "forwarding_execution")
	for _, name := range []string{"last", "first", "chain", "via", "principal"} {
		t.Run(name, func(t *testing.T) {
			f := forwardingFixture(t)
			held, err := f.c.ReceiveMessage(t.Context(), &sdk.ReceiveMessageInput{QueueUrl: aws.String(f.dlq), VisibilityTimeout: 600})
			if err != nil || len(held.Messages) != 1 {
				t.Fatalf("hold=%v %v", held, err)
			}
			started, err := f.c.StartMessageMoveTask(t.Context(), &sdk.StartMessageMoveTaskInput{SourceArn: aws.String(f.arn), DestinationArn: aws.String(attributes(t, f.c, f.destination)["QueueArn"]), MaxNumberOfMessagesPerSecond: aws.Int32(10)})
			if err != nil {
				t.Fatal(err)
			}
			f.handle = aws.ToString(started.TaskHandle)
			f.reopen(t)
			restrictForwarding(t, f, capture.Conditions[name], false)
			_, err = f.c.ReceiveMessage(t.Context(), &sdk.ReceiveMessageInput{QueueUrl: aws.String(f.dlq)})
			requireCode(t, err, "AccessDenied")
			_, err = f.c.SendMessage(t.Context(), &sdk.SendMessageInput{QueueUrl: aws.String(f.destination), MessageBody: aws.String("direct")})
			requireCode(t, err, "AccessDenied")
			advance(t, f.clock, time.Second)
			if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			if aws.ToString(f.status(t).Status) != moveRunning {
				t.Fatal("held message triggered a delivery authorization failure")
			}
			if _, err := f.c.ChangeMessageVisibility(t.Context(), &sdk.ChangeMessageVisibilityInput{QueueUrl: aws.String(f.dlq), ReceiptHandle: held.Messages[0].ReceiptHandle, VisibilityTimeout: 0}); err != nil {
				t.Fatal(err)
			}
			advance(t, f.clock, time.Second)
			if _, err := f.s.jobs.RunDue(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			got := f.status(t)
			messages := receive(t, f.c, f.destination, 10)
			var nativeTask types.ListMessageMoveTasksResultEntry
			var nativeMessages []types.Message
			for _, observation := range capture.Observations {
				if observation.Case == name+"_progress" {
					nativeTask = observation.Output.Results[0]
				}
				if observation.Case == name+"_destination" {
					nativeMessages = observation.Output.Messages
				}
			}
			if nativeTask.Status == nil {
				t.Fatal("missing native task completion")
			}
			if aws.ToString(got.Status) != aws.ToString(nativeTask.Status) || aws.ToString(got.FailureReason) != aws.ToString(nativeTask.FailureReason) {
				t.Fatalf("task=%v, native=%v", got, nativeTask)
			}
			// Native moved counters sometimes lag COMPLETED; compare the actual
			// delivered message, not a transient approximate count.
			if len(messages) != len(nativeMessages) || len(messages) == 1 && aws.ToString(messages[0].Body) != aws.ToString(nativeMessages[0].Body) {
				t.Fatalf("delivery=%v, native=%v", messages, nativeMessages)
			}
		})
	}
}
