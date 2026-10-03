package stackd_test

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type snsCrossObservation struct {
	awsNativeObservation
	Caller string `json:"caller_account"`
	Actor  string `json:"actor_arn"`
}

func snsCrossTopics(t *testing.T, clients cloudClients, owner, subscriber, region string) map[string]*sns.Client {
	t.Helper()
	topics := map[string]*sns.Client{
		owner:       snsControlUser(t, clients, snsAdmissionFixture{Account: owner, Region: region}, "Delegated", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`),
		"anonymous": snsHTTPAnonymous(clients, region),
	}
	roles := clients.iam(subscriber, "test", "")
	role, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("OrganizationAccountAccessRole"), AssumeRolePolicyDocument: aws.String(fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}}`, subscriber))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("probe"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)}); err != nil {
		t.Fatal(err)
	}
	session, err := clients.sts(subscriber, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("cross-account-replay"), DurationSeconds: aws.Int32(3600)})
	if err != nil {
		t.Fatal(err)
	}
	credential := session.Credentials
	topics[subscriber] = clients.snsRegion(region, aws.ToString(credential.AccessKeyId), aws.ToString(credential.SecretAccessKey), aws.ToString(credential.SessionToken))
	return topics
}

// snsCrossReceipt consumes one captured SNS envelope from real SQS delivery.
// Native polling boundaries need not coincide with local scheduling boundaries.
func snsCrossReceipt(t *testing.T, pending []sqstypes.Message, expected sqstypes.Message, endpoint string) ([]sqstypes.Message, map[string]any) {
	t.Helper()
	var want map[string]any
	awsDecodeJSON(t, []byte(aws.ToString(expected.Body)), &want)
	index := slices.IndexFunc(pending, func(message sqstypes.Message) bool {
		var got map[string]any
		awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &got)
		return got["Type"] == want["Type"] && got["TopicArn"] == want["TopicArn"] && (want["Type"] != "Notification" || got["Message"] == want["Message"])
	})
	if index < 0 {
		t.Fatalf("missing native %s delivery %q", want["Type"], want["Message"])
	}
	message := pending[index]
	pending = slices.Delete(pending, index, index+1)
	var got map[string]any
	awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &got)
	token, _ := want["Token"].(string)
	if token != "" {
		snsVerifySignature(t, got, endpoint, endpoint)
	} else if got["MessageId"] != want["MessageId"] {
		t.Fatalf("notification not correlated to accepted publication: %v", got)
	}
	for _, field := range []string{"MessageGroupId", "MessageDeduplicationId"} {
		value := expected.Attributes[field]
		if field == "MessageDeduplicationId" && token != "" && value == want["MessageId"] {
			value = got["MessageId"].(string)
		}
		if message.Attributes[field] != value {
			t.Fatalf("native %s=%q, got %q", field, value, message.Attributes[field])
		}
	}
	return pending, got
}

func TestSNSNativeCrossAccountConfirmation(t *testing.T) {
	for _, fixtureName := range []string{"cross_account_confirmation.json", "deleted_rejoin.json", "confirmation_lifetime.json", "confirmation_lifetime_supplement.json", "confirmation_lifetime_scope.json"} {
		t.Run(fixtureName, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/sns/" + fixtureName)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Region                string
				Observations, Cleanup []snsCrossObservation
				Sessions              []struct {
					Actor string `json:"actor_arn"`
					Input sts.AssumeRoleInput
				}
			}
			awsDecodeJSON(t, data, &fixture)
			// Resource teardown separates the two native runs. The false-confirmation
			// cleanup also captures upgrading protection and rejecting its second token.
			rows := slices.Clone(fixture.Observations)
			for _, row := range fixture.Cleanup {
				if row.Result.Code == "Success" && (row.Operation == "delete-topic" || row.Operation == "delete-queue") || row.Operation == "confirm-subscription" && strings.HasPrefix(row.Label, "owner-false-cleanup-confirm-") {
					rows = append(rows, row)
				}
			}
			slices.SortStableFunc(rows, func(a, b snsCrossObservation) int { return int(a.Started - b.Started) })
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					const owner, subscriber = "000000000000", "917546008205"
					cloud, clients, source := admissionFixtureCloud(t, backend, snsAdmissionFixture{Observations: []awsNativeObservation{rows[0].awsNativeObservation}})
					topics := snsCrossTopics(t, clients, owner, subscriber, fixture.Region)
					sessions := make(map[string]*sns.Client, len(fixture.Sessions))
					for _, native := range fixture.Sessions {
						session, err := clients.sts(subscriber, "test", "").AssumeRole(t.Context(), &native.Input)
						if err != nil {
							t.Fatal(err)
						}
						credential := session.Credentials
						sessions[native.Actor] = clients.snsRegion(fixture.Region, aws.ToString(credential.AccessKeyId), aws.ToString(credential.SecretAccessKey), aws.ToString(credential.SessionToken))
					}
					queues := clients.sqs(subscriber, "test", "")
					var replacements []string
					mapped := map[string]string{}
					bind := func(native, local string) {
						t.Helper()
						if previous, ok := mapped[native]; ok {
							if previous != local {
								t.Fatalf("native identity %s changed from %s to %s", native, previous, local)
							}
							return
						}
						mapped[native] = local
						replacements = append(replacements, native, local)
					}
					normalize := func(data []byte) []byte { return []byte(strings.NewReplacer(replacements...).Replace(string(data))) }
					pending := map[string][]sqstypes.Message{}
					received := map[string]bool{}
					var listingTopic string
					for _, capture := range rows {
						if capture.Service != "sns" && capture.Service != "sqs" || capture.Operation == "delete-message" {
							continue
						}
						if !t.Run(capture.Label, func(t *testing.T) {
							if delta := time.UnixMilli(capture.Started).Sub(source.Now()); delta > 0 {
								advanceClock(t, source, delta)
							}
							row := capture.awsNativeObservation
							row.Input = normalize(row.Input)
							if row.Operation == "receive-message" {
								var input sqs.ReceiveMessageInput
								var native sqs.ReceiveMessageOutput
								awsDecodeJSON(t, row.Input, &input)
								awsDecodeJSON(t, row.Result.Output, &native)
								queue := aws.ToString(input.QueueUrl)
								pending[queue] = append(pending[queue], snsAdmissionReceive(t, cloud, queues, input.QueueUrl)...)
								for _, expected := range native.Messages {
									expected.Body = aws.String(string(normalize([]byte(aws.ToString(expected.Body)))))
									var got map[string]any
									pending[queue], got = snsCrossReceipt(t, pending[queue], expected, clients.server.URL)
									var want map[string]any
									awsDecodeJSON(t, []byte(aws.ToString(expected.Body)), &want)
									if token, _ := want["Token"].(string); token != "" {
										bind(token, got["Token"].(string))
									}
									received[got["MessageId"].(string)] = true
								}
								// AWS's bounded negative receive is not a latency guarantee. It
								// does establish that a pending endpoint must not get its probe.
								if before, _, ok := strings.Cut(row.Label, "-pending-receive-"); ok {
									for _, publish := range rows {
										if publish.Label != before+"-pending-publish" {
											continue
										}
										var input sns.PublishInput
										awsDecodeJSON(t, publish.Input, &input)
										for _, message := range pending[queue] {
											var envelope map[string]string
											awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
											if envelope["Type"] == "Notification" && envelope["Message"] == aws.ToString(input.Message) {
												t.Fatal("pending endpoint received publication")
											}
										}
									}
								}
								return
							}
							var client any = topics[capture.Caller]
							if session, ok := sessions[capture.Actor]; ok {
								client = session
							}
							if row.Service == "sqs" {
								client = queues
							}
							result := snsControlReplay(t, client, row)
							if row.Result.Code != "Success" {
								return
							}
							switch out := result.(type) {
							case *sns.CreateTopicOutput:
								listingTopic = aws.ToString(out.TopicArn)
							case *sqs.CreateQueueOutput:
								var want sqs.CreateQueueOutput
								awsDecodeJSON(t, row.Result.Output, &want)
								bind(aws.ToString(want.QueueUrl), aws.ToString(out.QueueUrl))
							case *sns.SubscribeOutput:
								var want sns.SubscribeOutput
								awsDecodeJSON(t, row.Result.Output, &want)
								if aws.ToString(want.SubscriptionArn) == "pending confirmation" {
									if aws.ToString(out.SubscriptionArn) != "pending confirmation" {
										t.Fatal("pending subscription was auto-confirmed")
									}
								} else {
									bind(aws.ToString(want.SubscriptionArn), aws.ToString(out.SubscriptionArn))
								}
							case *sns.ConfirmSubscriptionOutput:
								var want sns.ConfirmSubscriptionOutput
								awsDecodeJSON(t, normalize(row.Result.Output), &want)
								if aws.ToString(out.SubscriptionArn) != aws.ToString(want.SubscriptionArn) {
									t.Fatal("confirmation changed subscription identity")
								}
							case *sns.PublishOutput:
								var want sns.PublishOutput
								awsDecodeJSON(t, row.Result.Output, &want)
								bind(aws.ToString(want.MessageId), aws.ToString(out.MessageId))
							}
							snsCrossResult(t, result, normalize(row.Result.Output), func(topic string) bool { return topic == listingTopic })
						}) {
							t.FailNow()
						}
					}
					for _, messages := range pending {
						for _, message := range messages {
							var envelope map[string]string
							awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
							if envelope["Type"] == "Notification" && !received[envelope["MessageId"]] {
								t.Fatalf("local publication absent from native consumer capture: %v", envelope)
							}
						}
					}
				})
			}
		})
	}
}

// Compare ownership and listing state after normalizing only dynamic identities.
// The predicate bounds account-wide native lists to resources owned by the probe.
func snsCrossResult(t *testing.T, result any, native []byte, includesTopic func(string) bool) {
	t.Helper()
	switch out := result.(type) {
	case *sns.GetSubscriptionAttributesOutput:
		var want sns.GetSubscriptionAttributesOutput
		awsDecodeJSON(t, native, &want)
		if !maps.Equal(out.Attributes, want.Attributes) {
			t.Fatalf("subscription attributes: got %v want %v", out.Attributes, want.Attributes)
		}
	case *sns.ListSubscriptionsOutput:
		var want sns.ListSubscriptionsOutput
		awsDecodeJSON(t, native, &want)
		out.Subscriptions = slices.DeleteFunc(out.Subscriptions, func(sub snstypes.Subscription) bool { return !includesTopic(aws.ToString(sub.TopicArn)) })
		want.Subscriptions = slices.DeleteFunc(want.Subscriptions, func(sub snstypes.Subscription) bool { return !includesTopic(aws.ToString(sub.TopicArn)) })
		snsCrossSubscriptions(t, out.Subscriptions, want.Subscriptions)
	case *sns.ListSubscriptionsByTopicOutput:
		var want sns.ListSubscriptionsByTopicOutput
		awsDecodeJSON(t, native, &want)
		snsCrossSubscriptions(t, out.Subscriptions, want.Subscriptions)
	}
}

func snsCrossSubscriptions(t *testing.T, got, want []snstypes.Subscription) {
	t.Helper()
	byEndpoint := func(rows []snstypes.Subscription) map[[3]string][2]string {
		out := make(map[[3]string][2]string, len(rows))
		for _, row := range rows {
			out[[3]string{aws.ToString(row.TopicArn), aws.ToString(row.Protocol), aws.ToString(row.Endpoint)}] = [2]string{aws.ToString(row.Owner), aws.ToString(row.SubscriptionArn)}
		}
		return out
	}
	if got, want := byEndpoint(got), byEndpoint(want); !maps.Equal(got, want) {
		t.Fatalf("subscription ownership/state: got %v want %v", got, want)
	}
}
