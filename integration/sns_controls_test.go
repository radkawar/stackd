package stackd_test

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/internal/awstest"
)

type snsControlFixture struct {
	snsAdmissionFixture
	EmptyPolicyCapture snsAdmissionFixture `json:"empty_policy_capture"`
	Deliveries         []struct {
		MessageID     string   `json:"sns_message_id"`
		Subscriptions []string `json:"subscription_arn_from_unsubscribe_url"`
	}
}

func snsControlsFixture(t *testing.T, name string) snsControlFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sns/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture snsControlFixture
	awsDecodeJSON(t, data, &fixture)
	for _, limitation := range fixture.Limitations {
		t.Log(limitation)
	}
	return fixture
}

func snsControlRow(t *testing.T, fixture snsAdmissionFixture, label string) awsNativeObservation {
	t.Helper()
	for _, row := range fixture.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native observation %s", label)
	return awsNativeObservation{}
}

func snsControlReplay(t *testing.T, client any, row awsNativeObservation, prepare ...func(any)) any {
	t.Helper()
	operation := ""
	for _, word := range strings.Split(row.Operation, "-") {
		operation += strings.ToUpper(word[:1]) + word[1:]
	}
	out, err := awstest.CallSDK(t.Context(), client, operation, row.Input, prepare...)
	awsNativeResult(t, row, err)
	return out
}

// Queue setup is local test isolation; native observations are never augmented
// with invented receives. All authorization probes use the real SNS/SQS path.
func snsControlQueue(t *testing.T, clients cloudClients, account, name, topicARN string) (*sqs.Client, *string, string) {
	t.Helper()
	queues := clients.sqs(account, "test", "")
	queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name})
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
	if err != nil {
		t.Fatal(err)
	}
	queueARN := attrs.Attributes["QueueArn"]
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, queueARN, topicARN)
	if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
		t.Fatal(err)
	}
	return queues, queue.QueueUrl, queueARN
}

func snsControlSubscribe(t *testing.T, topics *sns.Client, topicARN, queueARN string) string {
	t.Helper()
	out, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: &topicARN, Protocol: aws.String("sqs"), Endpoint: &queueARN, ReturnSubscriptionArn: true})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.SubscriptionArn)
}

func snsControlPolicy(t *testing.T, topics *sns.Client, topicARN, document string) {
	t.Helper()
	if _, err := topics.SetTopicAttributes(t.Context(), &sns.SetTopicAttributesInput{TopicArn: &topicARN, AttributeName: aws.String("Policy"), AttributeValue: &document}); err != nil {
		t.Fatal(err)
	}
}

func snsControlSetCaptured(t *testing.T, topics *sns.Client, topicARN string, row awsNativeObservation) {
	t.Helper()
	snsControlReplay(t, topics, row, func(value any) {
		in := value.(*sns.SetTopicAttributesInput)
		in.AttributeValue = aws.String(strings.ReplaceAll(aws.ToString(in.AttributeValue), aws.ToString(in.TopicArn), topicARN))
		in.TopicArn = &topicARN
	})
}

func snsControlUser(t *testing.T, clients cloudClients, fixture snsAdmissionFixture, name, policy string) *sns.Client {
	t.Helper()
	_, key, secret := clients.user(t, fixture.Account, name)
	if policy != "" {
		putUserPolicy(t, clients.iam(fixture.Account, "test", ""), name, policy)
	}
	return clients.snsRegion(fixture.Region, key, secret, "")
}

func snsControlPublish(t *testing.T, cloud *stackd.Stack, topics *sns.Client, queues *sqs.Client, topicARN string, queueURL *string, message string, allowed bool) {
	t.Helper()
	out, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: &topicARN, Message: &message})
	if allowed {
		if err != nil {
			t.Fatal(err)
		}
	} else {
		assertAPIError(t, err, "AuthorizationError")
	}
	messages := snsAdmissionReceive(t, cloud, queues, queueURL)
	if !allowed {
		if len(messages) != 0 {
			t.Fatalf("denied publication reached consumer: %v", messages)
		}
		return
	}
	if len(messages) != 1 {
		t.Fatalf("publication reached %d consumers, want one", len(messages))
	}
	var envelope snsAdmissionNotification
	awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &envelope)
	if envelope.Message != message || envelope.MessageId != aws.ToString(out.MessageId) || envelope.TopicArn != topicARN {
		t.Fatalf("consumer did not receive this publication intact: %+v", envelope)
	}
}

func TestSNSNativeTopicControls(t *testing.T) {
	fixture := snsControlsFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, _ := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			create := snsControlRow(t, fixture.snsAdmissionFixture, "topic-create-data")
			var first sns.CreateTopicInput
			awsDecodeJSON(t, create.Input, &first)
			out := snsControlReplay(t, topics, create).(*sns.CreateTopicOutput)
			topicARN := aws.ToString(out.TopicArn)
			queues, queueURL, queueARN := snsControlQueue(t, clients, fixture.Account, "topic-controls", topicARN)
			snsControlSubscribe(t, topics, topicARN, queueARN)
			// Resource-tag authorization is a local regression: the native capture
			// observed tag mutation/readback, not this IAM user's publication.
			tagPolicy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sns:Publish","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/stage":"replacement"}}}}`, topicARN)
			tagged := snsControlUser(t, clients, fixture.snsAdmissionFixture, "tagged-publisher", tagPolicy)
			display := ""
			tagAllows := false
			for _, row := range fixture.Observations {
				if row.Label == "topic-create-data" || strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "recovery-") {
					continue
				}
				switch row.Operation {
				case "create-topic", "set-topic-attributes", "tag-resource", "untag-resource":
				default:
					continue // No default-policy literal or field-copy readback assertions.
				}
				if !t.Run(row.Label, func(t *testing.T) {
					result := snsControlReplay(t, topics, row)
					switch row.Operation {
					case "create-topic":
						if row.Result.Code == "Success" && aws.ToString(result.(*sns.CreateTopicOutput).TopicArn) != topicARN {
							t.Fatal("idempotent creation changed topic identity")
						}
						// A conflicting create must preserve both the original route
						// and the state used by the next CreateTopic admission.
						if display != "" {
							_, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: first.Name, Attributes: map[string]string{"DisplayName": display}})
							if err != nil {
								t.Fatalf("failed creation changed existing attributes: %v", err)
							}
						}
						snsControlPublish(t, cloud, topics, queues, topicARN, queueURL, row.Label, true)
					case "set-topic-attributes":
						var in sns.SetTopicAttributesInput
						awsDecodeJSON(t, row.Input, &in)
						if row.Result.Code == "Success" && aws.ToString(in.AttributeName) == "DisplayName" {
							previous := display
							display = aws.ToString(in.AttributeValue)
							_, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: first.Name, Attributes: map[string]string{"DisplayName": display}})
							if err != nil {
								t.Fatalf("updated display not used by create admission: %v", err)
							}
							if previous != "" {
								_, err = topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: first.Name, Attributes: map[string]string{"DisplayName": previous}})
								assertAPIError(t, err, "InvalidParameter")
							}
						}
					case "tag-resource":
						var in sns.TagResourceInput
						awsDecodeJSON(t, row.Input, &in)
						for _, tag := range in.Tags {
							if aws.ToString(tag.Key) == "stage" {
								tagAllows = aws.ToString(tag.Value) == "replacement"
							}
						}
					case "untag-resource":
						tagAllows = false
					}
					if row.Operation == "tag-resource" || row.Operation == "untag-resource" || row.Label == "topic-create-conflicting-tags" {
						t.Run("local_resource_tag_delivery", func(t *testing.T) {
							snsControlPublish(t, cloud, tagged, queues, topicARN, queueURL, row.Label+" tagged", tagAllows)
						})
					}
				}) {
					t.FailNow()
				}
			}
			t.Run("local_cross_account_permission_grants", func(t *testing.T) {
				// Rebind only the captured grantee account, leaving the resource
				// owned by the original account. This is not native cross-account evidence.
				foreignAccount := "222222222222"
				foreign := admissionSNSClient(clients, foreignAccount, fixture.Region)
				snsControlPublish(t, cloud, foreign, queues, topicARN, queueURL, "before grant", false)
				for _, label := range []string{"topic-add-permission", "topic-add-permission-repeat", "topic-remove-permission", "topic-remove-permission-repeat"} {
					row := snsControlRow(t, fixture.snsAdmissionFixture, label)
					if !t.Run(label, func(t *testing.T) {
						snsControlReplay(t, topics, row, func(value any) {
							if in, ok := value.(*sns.AddPermissionInput); ok {
								in.AWSAccountId = []string{foreignAccount}
							}
						})
						snsControlPublish(t, cloud, foreign, queues, topicARN, queueURL, label, row.Operation == "add-permission")
					}) {
						t.FailNow()
					}
				}
			})
		})
	}
}

func TestSNSNativePolicyActions(t *testing.T) {
	fixture := snsControlsFixture(t, "policy_actions")
	controls := snsControlsFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, _ := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			out, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("policy-actions")})
			if err != nil {
				t.Fatal(err)
			}
			topicARN := aws.ToString(out.TopicArn)
			queues, queueURL, queueARN := snsControlQueue(t, clients, fixture.Account, "policy-actions", topicARN)
			snsControlSubscribe(t, topics, topicARN, queueARN)
			publisher := snsControlUser(t, clients, fixture.snsAdmissionFixture, "policy-publisher", allow(`"sns:Publish"`, topicARN))
			// A deny baseline makes failed policy replacement observable. Root
			// identity fallback must not conceal an accidentally cleared policy.
			snsControlPolicy(t, topics, topicARN, fmt.Sprintf(`{"Statement":[{"Sid":"DenyPublish","Effect":"Deny","Principal":"*","Action":"sns:Publish","Resource":%q}]}`, topicARN))
			snsControlPublish(t, cloud, publisher, queues, topicARN, queueURL, "deny baseline", false)
			rows := []awsNativeObservation{snsControlRow(t, controls.snsAdmissionFixture, "topic-invalid-policy")}
			for _, row := range fixture.Observations {
				if row.Operation == "set-topic-attributes" {
					rows = append(rows, row)
				}
			}
			for _, row := range rows {
				if !t.Run(row.Label, func(t *testing.T) {
					snsControlSetCaptured(t, topics, topicARN, row)
					snsControlPublish(t, cloud, publisher, queues, topicARN, queueURL, row.Label, row.Result.Code == "Success")
				}) {
					t.FailNow()
				}
			}
			t.Run("local_cross_account_numeric_principal_and_empty_policy", func(t *testing.T) {
				empty := fixture.EmptyPolicyCapture
				foreignAccount := "222222222222"
				foreign := admissionSNSClient(clients, foreignAccount, fixture.Region)
				snsControlPublish(t, cloud, foreign, queues, topicARN, queueURL, "before numeric grant", false)
				row := snsControlRow(t, empty, "set-single-policy")
				snsControlReplay(t, topics, row, func(value any) {
					in := value.(*sns.SetTopicAttributesInput)
					// Preserve numeric-account syntax; rebind its grantee independently
					// of the resource account so its grant actually controls delivery.
					document := strings.ReplaceAll(aws.ToString(in.AttributeValue), aws.ToString(in.TopicArn), topicARN)
					document = strings.ReplaceAll(document, `"AWS": "`+fixture.Account+`"`, `"AWS": "`+foreignAccount+`"`)
					in.TopicArn, in.AttributeValue = &topicARN, &document
				})
				snsControlPublish(t, cloud, foreign, queues, topicARN, queueURL, row.Label, true)
				for _, label := range []string{"set-explicit-empty-policy", "remove-last-statement", "add-after-removal"} {
					row := snsControlRow(t, empty, label)
					if !t.Run(label, func(t *testing.T) {
						var target struct{ TopicArn string }
						awsDecodeJSON(t, row.Input, &target)
						row.Input = []byte(strings.ReplaceAll(string(row.Input), target.TopicArn, topicARN))
						snsControlReplay(t, topics, row)
						snsControlPublish(t, cloud, foreign, queues, topicARN, queueURL, label, true)
					}) {
						t.FailNow()
					}
				}
			})
		})
	}
}

func TestSNSNativePolicySourceOwner(t *testing.T) {
	fixture := snsControlsFixture(t, "policy_context")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			out, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("source-owner")})
			if err != nil {
				t.Fatal(err)
			}
			topicARN := aws.ToString(out.TopicArn)
			queues, queueURL, queueARN := snsControlQueue(t, clients, fixture.Account, "source-owner", topicARN)
			snsControlSubscribe(t, topics, topicARN, queueARN)
			publisher := snsControlUser(t, clients, fixture.snsAdmissionFixture, "Delegated", allow(`"sns:Publish"`, topicARN))
			t.Run("ordinary_iam", func(t *testing.T) {
				for _, suffix := range []string{"absent", "actual", "wrong"} {
					if !t.Run(suffix, func(t *testing.T) {
						snsControlSetCaptured(t, topics, topicARN, snsControlRow(t, fixture.snsAdmissionFixture, "set-owner-"+suffix))
						row := snsControlRow(t, fixture.snsAdmissionFixture, "publish-owner-"+suffix)
						var in sns.PublishInput
						awsDecodeJSON(t, row.Input, &in)
						result := snsControlReplay(t, publisher, row, func(value any) { value.(*sns.PublishInput).TopicArn = &topicARN })
						messages := snsAdmissionReceive(t, cloud, queues, queueURL)
						if row.Result.Code != "Success" {
							if len(messages) != 0 {
								t.Fatal("explicitly denied IAM message reached SQS")
							}
							return
						}
						out := result.(*sns.PublishOutput)
						if len(messages) != 1 {
							t.Fatalf("accepted IAM publication delivered %d messages", len(messages))
						}
						var body snsAdmissionNotification
						awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &body)
						if body.MessageId != aws.ToString(out.MessageId) || body.Message != aws.ToString(in.Message) {
							t.Fatalf("wrong IAM publication delivered: %+v", body)
						}
					}) {
						t.FailNow()
					}
				}
			})
			t.Run("actual_cloudwatch_producer", func(t *testing.T) {
				// Use a fresh default-policy topic for the captured positive control.
				created, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("source-owner-cloudwatch")})
				if err != nil {
					t.Fatal(err)
				}
				alarmTopic := aws.ToString(created.TopicArn)
				alarmQueues, alarmURL, alarmQueueARN := snsControlQueue(t, clients, fixture.Account, "source-owner-cloudwatch", alarmTopic)
				snsControlSubscribe(t, topics, alarmTopic, alarmQueueARN)
				metrics := metricsClient(clients, fixture.Account)
				row := snsControlRow(t, fixture.snsAdmissionFixture, "create-default-policy-alarm")
				var alarm cloudwatch.PutMetricAlarmInput
				awsDecodeJSON(t, row.Input, &alarm)
				snsControlReplay(t, metrics, row, func(value any) { value.(*cloudwatch.PutMetricAlarmInput).AlarmActions = []string{alarmTopic} })
				trigger := func(t *testing.T, delivered bool) {
					t.Helper()
					for _, label := range []string{"baseline-alarm", "activate-alarm"} {
						advanceClock(t, source, time.Millisecond)
						row := snsControlRow(t, fixture.snsAdmissionFixture, label)
						snsControlReplay(t, metrics, row, func(value any) { value.(*cloudwatch.SetAlarmStateInput).AlarmName = alarm.AlarmName })
					}
					messages := snsAdmissionReceive(t, cloud, alarmQueues, alarmURL)
					if !delivered {
						if len(messages) != 0 {
							t.Fatal("SourceOwner explicit deny did not block actual CloudWatch producer")
						}
						return
					}
					if len(messages) != 1 {
						t.Fatalf("authorized CloudWatch producer delivered %d messages", len(messages))
					}
					var envelope snsAdmissionNotification
					awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &envelope)
					var notification struct{ AlarmName string }
					awsDecodeJSON(t, []byte(envelope.Message), &notification)
					if envelope.TopicArn != alarmTopic || notification.AlarmName != aws.ToString(alarm.AlarmName) {
						t.Fatalf("wrong producer reached consumer: %+v", envelope)
					}
				}
				trigger(t, true)
				// This condition matrix is a local regression, not a manufactured
				// native CloudWatch capture. The same captured deny conditions that
				// matched absent IAM context must distinguish an actual producer.
				for _, suffix := range []string{"absent", "actual", "wrong"} {
					if !t.Run("local_condition_"+suffix, func(t *testing.T) {
						snsControlSetCaptured(t, topics, alarmTopic, snsControlRow(t, fixture.snsAdmissionFixture, "set-owner-"+suffix))
						trigger(t, suffix != "actual")
					}) {
						t.FailNow()
					}
				}
				if _, err := metrics.DeleteAlarms(t.Context(), &cloudwatch.DeleteAlarmsInput{AlarmNames: []string{aws.ToString(alarm.AlarmName)}}); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestSNSNativeRetainedSubscriptionIncarnations(t *testing.T) {
	fixture := snsControlsFixture(t, "deletion")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			queues := clients.sqs(fixture.Account, "test", "")
			var topicARN string
			var queueURL *string
			subscriptions := map[string]string{}
			identities := map[string]string{}
			for _, row := range fixture.Observations {
				if strings.HasPrefix(row.Label, "cleanup-") {
					break
				}
				// Replay measured elapsed intervals only. This deliberately stops
				// short of the uncalibrated local five-minute cleanup deadline.
				if delta := time.UnixMilli(row.Started).Sub(source.Now()); delta > 0 {
					advanceClock(t, source, delta)
				}
				if row.Service != "sns" && row.Operation != "create-queue" && row.Operation != "set-queue-attributes" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					for native, local := range identities {
						row.Input = []byte(strings.ReplaceAll(string(row.Input), native, local))
					}
					var client any = topics
					if row.Service == "sqs" {
						client = queues
					}
					result := snsControlReplay(t, client, row)
					if row.Result.Code != "Success" {
						return
					}
					switch row.Operation {
					case "create-topic":
						out := result.(*sns.CreateTopicOutput)
						if topicARN != "" && topicARN != aws.ToString(out.TopicArn) {
							t.Fatal("same-name recreation changed ARN")
						}
						topicARN = aws.ToString(out.TopicArn)
					case "create-queue":
						out := result.(*sqs.CreateQueueOutput)
						var native sqs.CreateQueueOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						identities[aws.ToString(native.QueueUrl)] = aws.ToString(out.QueueUrl)
						queueURL = out.QueueUrl
					case "subscribe":
						out := result.(*sns.SubscribeOutput)
						var native sns.SubscribeOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						for _, previous := range subscriptions {
							if previous == aws.ToString(out.SubscriptionArn) {
								t.Fatal("new incarnation reused retained subscription identity")
							}
						}
						subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(out.SubscriptionArn)
						identities[aws.ToString(native.SubscriptionArn)] = aws.ToString(out.SubscriptionArn)
					case "list-subscriptions-by-topic":
						out := result.(*sns.ListSubscriptionsByTopicOutput)
						var native sns.ListSubscriptionsByTopicOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						want, got := map[string]bool{}, map[string]bool{}
						for _, subscription := range native.Subscriptions {
							want[subscriptions[aws.ToString(subscription.SubscriptionArn)]] = true
						}
						for _, subscription := range out.Subscriptions {
							got[aws.ToString(subscription.SubscriptionArn)] = true
						}
						if !reflect.DeepEqual(got, want) || out.NextToken != nil {
							t.Fatalf("current membership includes wrong incarnation: got %v, want %v", got, want)
						}
					case "publish":
						var in sns.PublishInput
						awsDecodeJSON(t, row.Input, &in)
						out := result.(*sns.PublishOutput)
						var native sns.PublishOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						want, got := map[string]int{}, map[string]int{}
						for _, delivery := range fixture.Deliveries {
							if delivery.MessageID == aws.ToString(native.MessageId) {
								for _, subscription := range delivery.Subscriptions {
									want[subscriptions[subscription]]++
								}
							}
						}
						for _, message := range snsAdmissionReceive(t, cloud, queues, queueURL) {
							var envelope struct {
								snsAdmissionNotification
								UnsubscribeURL string
							}
							awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
							if envelope.MessageId != aws.ToString(out.MessageId) || envelope.Message != aws.ToString(in.Message) || envelope.TopicArn != topicARN {
								t.Fatalf("delivery belongs to another publication: %+v", envelope)
							}
							unsubscribe, err := url.Parse(envelope.UnsubscribeURL)
							if err != nil {
								t.Fatal(err)
							}
							got[unsubscribe.Query().Get("SubscriptionArn")]++
						}
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("publication routes: got %v, native %v", got, want)
						}
					}
				}) {
					t.FailNow()
				}
			}
			// Local regression after the captured final unsubscribe: no route may
			// remain merely because two incarnations shared the same topic ARN.
			out, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: &topicARN, Message: aws.String("after both unsubscribed")})
			if err != nil {
				t.Fatal(err)
			}
			if messages := snsAdmissionReceive(t, cloud, queues, queueURL); len(messages) != 0 {
				t.Fatalf("removed incarnations delivered new publication %s: %v", aws.ToString(out.MessageId), messages)
			}
		})
	}
}
