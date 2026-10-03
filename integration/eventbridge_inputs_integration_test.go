package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/storage"
)

func TestEventBridgeSQSNativeInputs(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case         string
			TargetInput  json.RawMessage `json:"target_input"`
			TargetAccess string          `json:"target_access"`
			TargetARN    string          `json:"target_arn"`
			Context      struct {
				RuleName      string `json:"rule_name"`
				RuleARN       string `json:"rule_arn"`
				IngestionTime string `json:"ingestion_time"`
			}
			Event struct {
				ID         string
				Source     string
				DetailType string `json:"detail-type"`
				Time       time.Time
				Detail     json.RawMessage
				Resources  []string
			}
			Delivery struct {
				Kind, Body string
				Attributes map[string]sqstypes.MessageAttributeValue
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	const bus = "stackd-event-input-owned"
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "inputs.sqlite"))
			}
			epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
			cloud, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(epoch))
			events, queues := eventDeliveryClient(c, eventDeliveryAccount), c.sqs(eventDeliveryAccount, "test", "")
			if _, err := events.CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: aws.String(bus)}); err != nil {
				t.Fatal(err)
			}
			createQueue := func(name string, allow bool) *string {
				t.Helper()
				out, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				if allow {
					policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:%s:%s"}]}`, eventDeliveryAccount, name)
					if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: out.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
						t.Fatal(err)
					}
				}
				return out.QueueUrl
			}
			dlq := createQueue(bus+"-dlq", true)
			for _, row := range fixture.Observations {
				if row.Delivery.Kind != "target" && row.Delivery.Kind != "dlq" {
					continue // Admission-only and bounded unobserved captures make no delivery claim.
				}
				t.Run(row.Case, func(t *testing.T) {
					name := bus + "-" + row.Context.RuleName
					targetURL := createQueue(name, row.TargetAccess != "denied")
					target := eventtypes.Target{Id: aws.String("target"), Arn: aws.String("arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":" + name),
						DeadLetterConfig: &eventtypes.DeadLetterConfig{Arn: aws.String("arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":" + bus + "-dlq")},
						RetryPolicy:      &eventtypes.RetryPolicy{MaximumRetryAttempts: aws.Int32(0), MaximumEventAgeInSeconds: aws.Int32(60)}}
					if row.TargetAccess == "missing" {
						target.Arn = aws.String(row.TargetARN)
					}
					if err := json.Unmarshal(row.TargetInput, &target); err != nil {
						t.Fatal(err)
					}
					pattern := fmt.Sprintf(`{"detail":{"case":[%q]}}`, row.Case)
					if _, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String(row.Context.RuleName), EventBusName: aws.String(bus), EventPattern: aws.String(pattern)}); err != nil {
						t.Fatal(err)
					}
					out, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(row.Context.RuleName), EventBusName: aws.String(bus), Targets: []eventtypes.Target{target}})
					if err != nil || out.FailedEntryCount != 0 {
						t.Fatal("native admitted target rejected", out, err)
					}
					accepted, err := events.PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{EventBusName: aws.String(bus), Source: aws.String(row.Event.Source), DetailType: aws.String(row.Event.DetailType), Detail: aws.String(string(row.Event.Detail)), Time: &row.Event.Time, Resources: row.Event.Resources}}})
					if err != nil || accepted.FailedEntryCount != 0 {
						t.Fatal("target projection failed event admission", accepted, err)
					}
					if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
						t.Fatal(err)
					}
					for kind, url := range map[string]*string{"target": targetURL, "dlq": dlq} {
						messages, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url, MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
						if err != nil {
							t.Fatal(err)
						}
						if kind != row.Delivery.Kind {
							if len(messages.Messages) != 0 {
								t.Fatalf("unexpected %s delivery: %+v", kind, messages.Messages)
							}
							continue
						}
						if len(messages.Messages) != 1 {
							t.Fatalf("expected one %s message, got %+v", kind, messages.Messages)
						}
						message := messages.Messages[0]
						want := strings.ReplaceAll(row.Delivery.Body, row.Event.ID, aws.ToString(accepted.Entries[0].EventId))
						if row.Context.IngestionTime != "" {
							want = strings.ReplaceAll(want, row.Context.IngestionTime, epoch.Format("2006-01-02T15:04:05.000Z"))
						}
						assertEventInputBody(t, aws.ToString(message.Body), want)
						attributes := make(map[string]string, len(row.Delivery.Attributes))
						for key, value := range row.Delivery.Attributes {
							attributes[key] = aws.ToString(value.StringValue)
						}
						assertEventDeliveryAttributes(t, message.MessageAttributes, attributes)
						if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: message.ReceiptHandle}); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func assertEventInputBody(t *testing.T, got, want string) {
	t.Helper()
	// Object member order is not part of JSON semantics. Preserve exact bytes
	// for text, scalar and invalid outputs, including native retained whitespace.
	if strings.HasPrefix(want, "{") && json.Valid([]byte(want)) {
		var actual, expected any
		if err := json.Unmarshal([]byte(got), &actual); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(want), &expected); err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(actual, expected) {
			return
		}
	} else if got == want {
		return
	}
	t.Errorf("input body differs\ngot:  %s\nwant: %s", got, want)
}
