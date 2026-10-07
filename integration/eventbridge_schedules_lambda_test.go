package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/storage"
	eventstorage "stackd/storage/eventbridge"
	lambdastorage "stackd/storage/lambda"
)

// The scheduled_delivery native capture establishes UTC cron cadence, rate
// reanchoring on enable and cancellation while disabled. event_invocation supplies
// the actual Python ZIP, Lambda execution-role/SQS grant and SourceArn denial
// contract. Logical deadlines below are not an AWS invocation-latency SLA.
//
// https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
// https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutTargets.html
// https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html
// https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html
// https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html
func TestEventBridgeScheduledDockerLambda(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[lambdaEventsFixture](t, "event_invocation")
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "scheduled-lambda.sqlite")
			backends := storage.NewMemory()
			var closeDatabase func()
			if kind == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
			cloud := lambdaEventsConnect(t, backends, source)
			lambdaEventsProvision(t, cloud, fixture)

			type scheduledTarget struct {
				name, expression, arn string
				input                 *string
				payload               map[string]any
			}
			targets := []scheduledTarget{
				{name: "scheduled-lambda-rate", expression: "rate(1 minute)"},
				{name: "scheduled-lambda-cron", expression: "cron(* * * * ? *)"},
				{name: "scheduled-lambda-denied", expression: "rate(1 minute)"},
			}
			for index := range targets {
				target := &targets[index]
				if index < 2 {
					target.input = aws.String(fmt.Sprintf(`{ "schedule": %q, "message": "line\nquote\"", "unicode": "é", "values": [true, null, 7, {"nested":"unchanged"}] }`, target.name))
					if err := json.Unmarshal([]byte(*target.input), &target.payload); err != nil {
						t.Fatal(err)
					}
				}
				created, err := cloud.events.PutRule(t.Context(), &eventbridge.PutRuleInput{
					Name: aws.String(target.name), ScheduleExpression: aws.String(target.expression), State: eventtypes.RuleStateDisabled,
				})
				if err != nil {
					t.Fatal(err)
				}
				target.arn = aws.ToString(created.RuleArn)
				if index < 2 {
					permission := lambdaEventsInput[awslambda.AddPermissionInput](t, fixture, "grant_good_rule")
					permission.FunctionName, permission.StatementId, permission.SourceArn = cloud.functionName, aws.String(target.name), created.RuleArn
					if _, err := cloud.lambda.AddPermission(t.Context(), permission); err != nil {
						t.Fatal(err)
					}
				}
			}

			attributes, err := cloud.queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{
				QueueUrl: cloud.dlqURL, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn},
			})
			if err != nil {
				t.Fatal(err)
			}
			dlqARN := attributes.Attributes["QueueArn"]
			if dlqARN == "" {
				t.Fatal("native SQS DLQ has no ARN")
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, dlqARN, targets[2].arn)
			if _, err := cloud.queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{
				QueueUrl: cloud.dlqURL, Attributes: map[string]string{"Policy": policy},
			}); err != nil {
				t.Fatal(err)
			}
			for index, target := range targets {
				binding := eventtypes.Target{
					Id: aws.String("lambda"), Arn: aws.String(cloud.functionARN), Input: target.input,
					RetryPolicy: &eventtypes.RetryPolicy{MaximumRetryAttempts: aws.Int32(0), MaximumEventAgeInSeconds: aws.Int32(60)},
				}
				if index == 2 {
					binding.DeadLetterConfig = &eventtypes.DeadLetterConfig{Arn: aws.String(dlqARN)}
				}
				out, err := cloud.events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(target.name), Targets: []eventtypes.Target{binding}})
				if err != nil || out.FailedEntryCount != 0 || len(out.FailedEntries) != 0 {
					t.Fatalf("binding scheduled Docker Lambda target %s: %+v, %v", target.name, out, err)
				}
			}

			assertControls := func(state eventtypes.RuleState) {
				t.Helper()
				for _, target := range targets {
					rule, err := cloud.events.DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{Name: aws.String(target.name)})
					if err != nil {
						t.Fatal(err)
					}
					if rule.State != state || aws.ToString(rule.ScheduleExpression) != target.expression || aws.ToString(rule.Arn) != target.arn {
						t.Fatalf("scheduled rule controls changed: %+v", rule)
					}
					listed, err := cloud.events.ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{Rule: aws.String(target.name)})
					if err != nil {
						t.Fatal(err)
					}
					if len(listed.Targets) != 1 || aws.ToString(listed.Targets[0].Arn) != cloud.functionARN || aws.ToString(listed.Targets[0].Input) != aws.ToString(target.input) || listed.Targets[0].RoleArn != nil {
						t.Fatalf("scheduled rule lost its native Lambda/constant Input binding: %+v", listed)
					}
				}
			}
			setEnabled := func(enabled bool, indices ...int) {
				t.Helper()
				for _, index := range indices {
					name := aws.String(targets[index].name)
					if enabled {
						if _, err := cloud.events.EnableRule(t.Context(), &eventbridge.EnableRuleInput{Name: name}); err != nil {
							t.Fatal(err)
						}
					} else if _, err := cloud.events.DisableRule(t.Context(), &eventbridge.DisableRuleInput{Name: name}); err != nil {
						t.Fatal(err)
					}
					state := eventtypes.RuleStateDisabled
					if enabled {
						state = eventtypes.RuleStateEnabled
					}
					out, err := cloud.events.DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{Name: name})
					if err != nil || out.State != state {
						t.Fatalf("schedule state transition %s: %+v, %v", *name, out, err)
					}
				}
			}

			seenRequests := make(map[string]bool)
			assertPhase := func(label string, wantRate, wantCron, wantDenied int) {
				t.Helper()
				ebScheduledLambdaSettled(t, cloud, backends, source)
				messages := ebScheduledLambdaMessages(t, cloud, cloud.outputURL)
				counts := make(map[string]int)
				for _, message := range messages {
					var record struct {
						Event map[string]any `json:"event"`
					}
					if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &record); err != nil {
						t.Fatal(err)
					}
					name, _ := record.Event["schedule"].(string)
					index := -1
					for candidate := range 2 {
						if targets[candidate].name == name {
							index = candidate
						}
					}
					if index < 0 {
						t.Fatalf("%s: unexpected guest event, including denied-source invocation: %s", label, aws.ToString(message.Body))
					}
					// This is the native fixture's customer boto3 effect, including
					// actual Runtime API context, not a forwarded EventBridge copy.
					requestID := lambdaEventsRecord(t, cloud.functionARN, message, "", targets[index].payload)
					if seenRequests[requestID] {
						t.Fatalf("%s: separate scheduled occurrences reused runtime request ID %q", label, requestID)
					}
					seenRequests[requestID] = true
					counts[name]++
				}
				if counts[targets[0].name] != wantRate || counts[targets[1].name] != wantCron {
					t.Fatalf("%s at %s: guest receipts=%v, want rate=%d cron=%d", label, source.Now(), counts, wantRate, wantCron)
				}
				deadLetters := ebScheduledLambdaMessages(t, cloud, cloud.dlqURL)
				if len(deadLetters) != wantDenied {
					t.Fatalf("%s: denied-source DLQ receipts=%d, want %d: %+v", label, len(deadLetters), wantDenied, deadLetters)
				}
				for _, message := range deadLetters {
					for name, want := range map[string]string{"ERROR_CODE": "NO_PERMISSIONS", "RULE_ARN": targets[2].arn, "TARGET_ARN": cloud.functionARN} {
						attribute := message.MessageAttributes[name]
						if aws.ToString(attribute.DataType) != "String" || aws.ToString(attribute.StringValue) != want {
							t.Fatalf("%s: denied-source DLQ %s=%+v, want %q", label, name, attribute, want)
						}
					}
					var event struct {
						Source     string   `json:"source"`
						DetailType string   `json:"detail-type"`
						Resources  []string `json:"resources"`
					}
					if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &event); err != nil {
						t.Fatal(err)
					}
					if event.Source != "aws.events" || event.DetailType != "Scheduled Event" || len(event.Resources) != 1 || event.Resources[0] != targets[2].arn {
						t.Fatalf("%s: denied-source DLQ lost the actual scheduled occurrence: %s", label, aws.ToString(message.Body))
					}
				}
			}
			advance := func(duration time.Duration, label string, rate, cron, denied int) {
				t.Helper()
				if err := source.Advance(duration); err != nil {
					t.Fatal(err)
				}
				assertPhase(label, rate, cron, denied)
			}

			assertControls(eventtypes.RuleStateDisabled)
			advance(4*time.Minute+20*time.Second, "initially disabled", 0, 0, 0)
			setEnabled(true, 0, 1)
			assertPhase("rate enable anchor", 1, 0, 0)
			advance(35*time.Second, "first UTC cron minute", 0, 1, 0)
			advance(25*time.Second, "next rate occurrence", 1, 0, 0)
			advance(35*time.Second, "next cron occurrence", 0, 1, 0)
			setEnabled(false, 0, 1)
			advance(5*time.Minute+20*time.Second, "disabled after real guest completion", 0, 0, 0)

			if kind == "sqlite" {
				if err := cloud.cloud.Close(); err != nil {
					t.Fatal(err)
				}
				cloud.server.Close()
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
				previous := cloud
				cloud = lambdaEventsConnect(t, backends, source)
				cloud.functionName, cloud.functionARN = previous.functionName, previous.functionARN
				// These remain owner-issued retained URLs. Endpoint injection
				// redirects customer boto3 without rewriting durable configuration.
				cloud.outputURL, cloud.dlqURL = previous.outputURL, previous.dlqURL
				assertControls(eventtypes.RuleStateDisabled)
				assertPhase("retained disabled controls", 0, 0, 0)
			}
			advance(3*time.Minute+5*time.Second, "disabled across further missed intervals", 0, 0, 0)
			setEnabled(true, 0, 1)
			// Exact counts reject replay of every disabled interval. A rate gets
			// a fresh logical anchor; cron waits for the next UTC calendar minute.
			assertPhase("resume without disabled backlog", 1, 0, 0)
			advance(35*time.Second, "resumed cron future occurrence", 0, 1, 0)
			advance(25*time.Second, "resumed rate future occurrence", 1, 0, 0)
			advance(35*time.Second, "resumed cron next occurrence", 0, 1, 0)
			setEnabled(false, 0, 1)

			// Both exact SourceArn grants remain on this same function. The
			// otherwise identical ungranted source must not enter the guest.
			setEnabled(true, 2)
			assertPhase("wrong SourceArn negative control", 0, 0, 1)
			advance(time.Minute, "wrong SourceArn future occurrence", 0, 0, 1)
			setEnabled(false, 2)
			advance(2*time.Minute, "all schedules disabled", 0, 0, 0)
		})
	}
}

// A drain claims asynchronous Lambda work but deliberately does not join customer
// code. Read both service-owned repositories in one shared transaction and wait
// for actual runtime completion before observing SQS or advancing service time.
// No wall-time quiet window, clock-timer count or sleeping establishes absence.
func ebScheduledLambdaSettled(t *testing.T, cloud *lambdaEventsCloud, backends *storage.Backends, source *clock.Manual) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for {
		if _, err := cloud.cloud.RunDueJobs(ctx, 1000); err != nil {
			t.Fatalf("draining scheduled Lambda work at %s: %v", source.Now(), err)
		}
		pending := false
		if err := backends.EventBridge.View(ctx, func(r eventstorage.Reader) error {
			rule, found, err := r.NextScheduledRule()
			if err != nil {
				return err
			}
			pending = found && !rule.NextSchedule.After(source.Now())
			delivery, found, err := r.NextDelivery()
			if err != nil {
				return err
			}
			if found {
				if delivery.Due.After(source.Now()) {
					return fmt.Errorf("scheduled target unexpectedly retained retry: %+v", delivery)
				}
				pending = true
			}
			return cloud.repository.View(r.Context(), func(lambda lambdastorage.Reader) error {
				inFlight, err := lambda.InFlightInvocations()
				if err != nil {
					return err
				}
				pending = pending || len(inFlight) != 0
				job, found, err := lambda.NextInvocation()
				if err != nil {
					return err
				}
				if found {
					if job.Due.After(source.Now()) {
						invocation, err := lambda.Invocation(job.Key)
						if err != nil {
							return err
						}
						return fmt.Errorf("real scheduled Lambda did not complete successfully: %+v", invocation)
					}
					pending = true
				}
				return nil
			})
		}); err != nil {
			t.Fatalf("awaiting scheduled Lambda completion at %s: %v", source.Now(), err)
		}
		if !pending {
			return
		}
		runtime.Gosched()
	}
}

func ebScheduledLambdaMessages(t *testing.T, cloud *lambdaEventsCloud, url *string) []sqstypes.Message {
	t.Helper()
	var messages []sqstypes.Message
	for {
		out, err := cloud.queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{
			QueueUrl: url, MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			return messages
		}
		for _, message := range out.Messages {
			if _, err := cloud.queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
			messages = append(messages, message)
		}
	}
}
