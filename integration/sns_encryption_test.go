package stackd_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/clock"
	"stackd/internal/awstest"
	snsstore "stackd/storage/sns"
)

func snsEncryptionFixture(t *testing.T) snsAdmissionFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sns/encryption.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture snsAdmissionFixture
	awsDecodeJSON(t, data, &fixture)
	// Capture timestamps observe responses, not exact native admission instants.
	fixture.Observations[0].Started = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	return fixture
}

func TestSNSNativeEncryptedRetainedHTTP(t *testing.T) {
	type attempt struct {
		Record struct {
			ReceivedAt time.Time `json:"received_at"`
			Message    struct {
				Type, Message string
				Timestamp     time.Time
			}
			Response struct{ StatusCode int }
		}
	}
	type cryptoEvent struct {
		EventTime            time.Time
		EventName, ErrorCode string
		UserIdentity         struct{ UserName string }
	}
	for _, name := range []string{"encryption_live_retry", "encryption_live_authority"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/sns/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				snsAdmissionFixture
				Attempts  []attempt     `json:"actual_notification_attempt_receipts"`
				Receiver  []attempt     `json:"actual_receiver_receipts"`
				Audit     []cryptoEvent `json:"owned_source_key_crypto_audit_events"`
				Authority struct {
					Audit []cryptoEvent `json:"publisher_sns_decrypt_events"`
				} `json:"authority_evidence"`
			}
			awsDecodeJSON(t, data, &fixture)
			for _, received := range fixture.Receiver {
				if received.Record.Message.Type == "Notification" {
					fixture.Attempts = append(fixture.Attempts, received)
				}
			}
			fixture.Audit = append(fixture.Audit, fixture.Authority.Audit...)
			fixture.Observations[0].Started = fixture.Attempts[0].Record.Message.Timestamp.UnixMilli()
			controls := map[string]awsNativeObservation{}
			for _, row := range fixture.Observations {
				operation := row.Service + ":" + row.Operation
				if _, exists := controls[operation]; !exists {
					controls[operation] = row
				}
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
					topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
					keys := clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
					publisherName := fixture.Audit[0].UserIdentity.UserName
					publisher := snsControlUser(t, clients, fixture.snsAdmissionFixture, publisherName, `{"Statement":{"Effect":"Allow","Action":["sns:Publish","kms:GenerateDataKey","kms:Decrypt"],"Resource":"*"}}`)
					receipts := make(chan snsHTTPReceipt, 32)
					receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						if err != nil {
							w.WriteHeader(400)
							return
						}
						receipts <- snsHTTPReceipt{Header: r.Header.Clone(), Body: string(body)}
						if r.Header.Get("X-Amz-Sns-Message-Type") == "SubscriptionConfirmation" {
							w.WriteHeader(200)
						} else {
							w.WriteHeader(fixture.Attempts[0].Record.Response.StatusCode)
						}
					}))
					defer receiver.Close()
					topic := snsControlReplay(t, topics, controls["sns:create-topic"]).(*sns.CreateTopicOutput)
					key := snsControlReplay(t, keys, controls["kms:create-key"]).(*kms.CreateKeyOutput)
					snsEncryptionSet(t, topics, aws.ToString(topic.TopicArn), aws.ToString(key.KeyMetadata.KeyId))
					var nativeSubscription sns.SubscribeInput
					awsDecodeJSON(t, controls["sns:subscribe"].Input, &nativeSubscription)
					if _, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("http"), Endpoint: aws.String(receiver.URL), Attributes: map[string]string{"DeliveryPolicy": nativeSubscription.Attributes["DeliveryPolicy"]}}); err != nil {
						t.Fatal(err)
					}
					snsHTTPDrain(t, cloud)
					confirmation := snsHTTPEnvelope(t, snsHTTPNext(t, receipts))
					if _, err := topics.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: aws.String(confirmation["Token"].(string))}); err != nil {
						t.Fatal(err)
					}
					published := snsControlReplay(t, publisher, controls["sns:publish"]).(*sns.PublishOutput)
					for i, attempt := range fixture.Attempts {
						if i > 0 {
							advanceClock(t, source, attempt.Record.ReceivedAt.Sub(source.Now()))
						}
						snsHTTPDrain(t, cloud)
						got := snsHTTPEnvelope(t, snsHTTPNext(t, receipts))
						if got["MessageId"] != aws.ToString(published.MessageId) || got["Message"] != attempt.Record.Message.Message {
							t.Fatalf("retained notification changed at %s: %v", attempt.Record.ReceivedAt, got)
						}
						if i == 0 {
							if len(fixture.Authority.Audit) != 0 {
								putUserPolicy(t, clients.iam(fixture.Account, "test", ""), publisherName, `{"Statement":[{"Effect":"Allow","Action":["sns:Publish","kms:GenerateDataKey","kms:Decrypt"],"Resource":"*"},{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}]}`)
							} else if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
								t.Fatal(err)
							}
						}
					}
					// A real native failed Decrypt establishes the cold boundary;
					// no recovery or terminal outcome is invented for either capture.
					for _, event := range fixture.Audit {
						if event.EventName != "Decrypt" || event.ErrorCode == "" {
							continue
						}
						advanceClock(t, source, event.EventTime.Sub(source.Now()))
						snsHTTPDrain(t, cloud)
						select {
						case receipt := <-receipts:
							t.Fatalf("cold unauthorized source reached endpoint: %s", receipt.Body)
						default:
						}
						audit := auditLatestRecord(t, organizationTrailClient(clients, fixture.Account, fixture.Region), "Decrypt")
						identity := audit["userIdentity"].(map[string]any)
						if audit["errorCode"] != event.ErrorCode || identity["type"] != "IAMUser" || identity["userName"] != publisherName || identity["invokedBy"] != "sns.amazonaws.com" {
							t.Fatalf("cold decrypt lost its native caller/error identity: %v", audit)
						}
						if audit["sourceIPAddress"] != "sns.amazonaws.com" || audit["userAgent"] != "sns.amazonaws.com" {
							t.Fatalf("cold decrypt lost its forwarding service: %v", audit)
						}
						if event.ErrorCode == "AccessDenied" && (audit["requestParameters"] != nil || audit["resources"] != nil) {
							t.Fatalf("native denied decrypt omits request parameters and resources: %v", audit)
						}
					}
				})
			}
		})
	}
}

func snsEncryptionQueue(t *testing.T, clients cloudClients, account, name, topicARN string, fifo bool) (*sqs.Client, *string, string) {
	t.Helper()
	if !fifo {
		return snsControlQueue(t, clients, account, name, topicARN)
	}
	name += ".fifo"
	queues := clients.sqs(account, "test", "")
	queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &name, Attributes: map[string]string{"FifoQueue": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:sqs:us-east-1:" + account + ":" + name
	policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}}`, arn, topicARN)
	if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
		t.Fatal(err)
	}
	return queues, queue.QueueUrl, arn
}

func snsEncryptionSet(t *testing.T, topics *sns.Client, arn, key string) {
	t.Helper()
	_, err := topics.SetTopicAttributes(t.Context(), &sns.SetTopicAttributesInput{TopicArn: &arn, AttributeName: aws.String("KmsMasterKeyId"), AttributeValue: &key})
	if err != nil {
		t.Fatal(err)
	}
	out, err := topics.GetTopicAttributes(t.Context(), &sns.GetTopicAttributesInput{TopicArn: &arn})
	if err != nil {
		t.Fatal(err)
	}
	got, present := out.Attributes["KmsMasterKeyId"]
	if got != key || present != (key != "") {
		t.Fatalf("key readback = %q present=%v, want %q", got, present, key)
	}
}

func TestSNSNativeEncryption(t *testing.T) {
	fixture := snsEncryptionFixture(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source := admissionFixtureCloud(t, backend, fixture)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			keys := clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
			key, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			alias := "alias/sns-encryption"
			if _, err := keys.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: key.KeyMetadata.KeyId}); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"standard", "fifo"} {
				t.Run(mode, func(t *testing.T) {
					name := "encrypted-" + mode
					attrs := map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn)}
					if mode == "fifo" {
						name += ".fifo"
						attrs["FifoTopic"] = "true"
						attrs["ContentBasedDeduplication"] = "true"
					}
					topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: &name, Attributes: attrs})
					if err != nil {
						t.Fatal(err)
					}
					arn := aws.ToString(topic.TopicArn)
					queues, url, qarn := snsEncryptionQueue(t, clients, fixture.Account, "encrypted-"+mode, arn, mode == "fifo")
					snsControlSubscribe(t, topics, arn, qarn)
					rawQueues, rawURL, rawARN := snsEncryptionQueue(t, clients, fixture.Account, "encrypted-raw-"+mode, arn, mode == "fifo")
					if _, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: &arn, Protocol: aws.String("sqs"), Endpoint: &rawARN, Attributes: map[string]string{"RawMessageDelivery": "true"}}); err != nil {
						t.Fatal(err)
					}
					row := snsControlRow(t, fixture, mode+"-payload")
					var input sns.PublishInput
					awsDecodeJSON(t, row.Input, &input)
					input.TopicArn = &arn
					published, err := topics.Publish(t.Context(), &input)
					awsNativeResult(t, row, err)
					messages := snsAdmissionReceive(t, cloud, queues, url)
					if len(messages) != 1 {
						t.Fatalf("wrapped deliveries=%d", len(messages))
					}
					var envelope map[string]json.RawMessage
					awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &envelope)
					var body, id string
					awsDecodeJSON(t, envelope["Message"], &body)
					awsDecodeJSON(t, envelope["MessageId"], &id)
					if body != aws.ToString(input.Message) || id != aws.ToString(published.MessageId) {
						t.Fatalf("wrapped payload lost original body/identity: %s", aws.ToString(messages[0].Body))
					}
					_, signed := envelope["Signature"]
					if signed != (mode == "standard") {
						t.Fatalf("native signing distinction lost: %s", aws.ToString(messages[0].Body))
					}
					if signed {
						var notification map[string]any
						awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &notification)
						snsVerifySignature(t, notification, clients.server.URL, clients.server.URL)
					}
					raw := snsAdmissionReceive(t, cloud, rawQueues, rawURL)
					if len(raw) != 1 || aws.ToString(raw[0].Body) != body || aws.ToString(raw[0].MessageAttributes["tag"].StringValue) != "visible metadata" {
						t.Fatalf("raw encryption delivery: %v", raw)
					}
					batchRow := snsControlRow(t, fixture, mode+"-batch")
					var batch sns.PublishBatchInput
					awsDecodeJSON(t, batchRow.Input, &batch)
					batch.TopicArn = &arn
					out, err := topics.PublishBatch(t.Context(), &batch)
					awsNativeResult(t, batchRow, err)
					if len(out.Successful) != 2 || len(out.Failed) != 0 {
						t.Fatalf("encrypted batch: %+v", out)
					}
					if got := snsAdmissionReceive(t, cloud, queues, url); len(got) != 2 {
						t.Fatalf("batch deliveries=%d", len(got))
					}
					if got := snsAdmissionReceive(t, cloud, rawQueues, rawURL); len(got) != 2 {
						t.Fatalf("raw batch deliveries=%d", len(got))
					}
					if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
						t.Fatal(err)
					}
					input.Message = aws.String("warm disabled " + mode)
					_, err = topics.Publish(t.Context(), &input)
					awsNativeResult(t, snsControlRow(t, fixture, mode+"-disabled-warm"), err)
					if got := snsAdmissionReceive(t, cloud, queues, url); len(got) != 1 {
						t.Fatalf("warm disabled delivery=%v", got)
					}
					advanceClock(t, source, 5*time.Minute)
					input.Message = aws.String("cold disabled")
					_, err = topics.Publish(t.Context(), &input)
					coldLabel := "disabled-cold"
					if mode == "fifo" {
						coldLabel = "fifo-disabled-cold"
					}
					awsNativeResult(t, snsControlRow(t, fixture, coldLabel), err)
					_, err = topics.PublishBatch(t.Context(), &batch)
					awsNativeResult(t, snsControlRow(t, fixture, coldLabel+"-batch"), err)
					if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
						t.Fatal(err)
					}
					for _, identifier := range []string{aws.ToString(key.KeyMetadata.KeyId), alias, "arn:aws:kms:" + fixture.Region + ":" + fixture.Account + ":" + alias, ""} {
						snsEncryptionSet(t, topics, arn, identifier)
						input.Message = aws.String("identifier " + identifier)
						if _, err := topics.Publish(t.Context(), &input); err != nil {
							t.Fatal(err)
						}
					}
					snsEncryptionSet(t, topics, arn, "nonsense")
					_, err = topics.Publish(t.Context(), &input)
					awsNativeResult(t, snsControlRow(t, fixture, "publish-key-0"), err)
				})
			}
		})
	}
}

func TestSNSNativeEncryptionAuthorization(t *testing.T) {
	fixture := snsEncryptionFixture(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cloud, clients, source := admissionFixtureCloud(t, backend, fixture)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			keys := clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
			key, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("authority"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn)}})
			if err != nil {
				t.Fatal(err)
			}
			arn := aws.ToString(topic.TopicArn)
			queues, url, qarn := snsControlQueue(t, clients, fixture.Account, "authority", arn)
			snsControlSubscribe(t, topics, arn, qarn)
			for _, tc := range []struct{ name, actions, label string }{{"none", "", "iam-none"}, {"generate", `,"kms:GenerateDataKey"`, "iam-generate"}, {"both", `,"kms:GenerateDataKey","kms:Decrypt"`, "iam-both-settled"}} {
				policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["sns:Publish"%s],"Resource":"*"}}`, tc.actions)
				publisher := snsControlUser(t, clients, fixture, "publisher-"+tc.name, policy)
				_, err := publisher.Publish(t.Context(), &sns.PublishInput{TopicArn: &arn, Message: aws.String(tc.name)})
				awsNativeResult(t, snsControlRow(t, fixture, tc.label), err)
				got := snsAdmissionReceive(t, cloud, queues, url)
				want := 0
				if tc.name == "both" {
					want = 1
				}
				if len(got) != want {
					t.Fatalf("%s delivered %d, want %d", tc.name, len(got), want)
				}
			}
			var policyInput kms.PutKeyPolicyInput
			awsDecodeJSON(t, snsControlRow(t, fixture, "context-key-policy").Input, &policyInput)
			var document map[string]any
			awsDecodeJSON(t, []byte(aws.ToString(policyInput.Policy)), &document)
			statements := document["Statement"].([]any)
			statements[1].(map[string]any)["Condition"] = map[string]any{"StringNotEquals": map[string]string{"kms:EncryptionContext:aws:sns:topicArn": arn}}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			policyInput.KeyId, policyInput.Policy = key.KeyMetadata.KeyId, aws.String(string(encoded))
			if _, err := keys.PutKeyPolicy(t.Context(), &policyInput); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 5*time.Minute)
			_, err = topics.Publish(t.Context(), &sns.PublishInput{TopicArn: &arn, Message: aws.String("context match")})
			awsNativeResult(t, snsControlRow(t, fixture, "context-publish"), err)
			wrong, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("wrong-context"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn)}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = topics.Publish(t.Context(), &sns.PublishInput{TopicArn: wrong.TopicArn, Message: aws.String("wrong context")})
			awsNativeResult(t, snsControlRow(t, fixture, "wrong-context-publish"), err)
		})
	}
}

func TestSNSNativeEncryptionPublisherCache(t *testing.T) {
	for _, name := range []string{"encryption_role_cache", "encryption_equivalent_sessions", "encryption_alias_retarget"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/sns/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Account, Region  string
				EnableKeyStarted int64 `json:"enable_B_started_ms"`
				Observations     []struct {
					awsNativeObservation
					Observed        time.Time
					CallerAccessKey string `json:"caller_access_key"`
				}
				Receipts []struct {
					Label   string
					Message sqstypes.Message
				}
			}
			awsDecodeJSON(t, data, &fixture)
			expected := map[string][]string{}
			for _, receipt := range fixture.Receipts {
				expected[receipt.Label] = append(expected[receipt.Label], aws.ToString(receipt.Message.Body))
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					base := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
					setup := snsAdmissionFixture{Account: fixture.Account, Region: fixture.Region, Observations: []awsNativeObservation{{Started: base.UnixMilli()}}}
					cloud, clients, source := admissionFixtureCloud(t, backend, setup)
					topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
					keys := clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
					users := clients.iam(fixture.Account, "test", "")
					tokens := clients.sts(fixture.Account, "test", "")
					queues := clients.sqs(fixture.Account, "test", "")
					controls := map[string]any{"sns": topics, "kms": keys, "iam": users, "sts": tokens, "sqs": queues}
					sessions := map[string]*sns.Client{}
					var replacements []string
					var queueURL *string
					for _, row := range fixture.Observations {
						// Collector calls are represented by the actual receipt comparisons.
						if row.Service == "cloudtrail" || row.Service == "sqs" && (row.Operation == "receive-message" || row.Operation == "delete-message") {
							continue
						}
						// Replay the confirmed repair, not this capture's transient
						// post-EnableKey failure: local key changes are immediate.
						if fixture.EnableKeyStarted != 0 && row.Started >= fixture.EnableKeyStarted && row.Service == "sns" && row.Result.Code == "KMSDisabled" {
							continue
						}
						elapsed := row.Observed.Sub(fixture.Observations[0].Observed)
						if row.Started != 0 {
							elapsed = time.Duration(row.Started-fixture.Observations[0].Started) * time.Millisecond
						}
						at := base.Add(elapsed)
						if at.After(source.Now()) {
							advanceClock(t, source, at.Sub(source.Now()))
						}
						if row.Service == "sts" && row.Operation == "get-caller-identity" {
							var native sts.GetCallerIdentityOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							replacements = append(replacements, aws.ToString(native.Arn), "arn:aws:iam::"+fixture.Account+":root")
							continue
						}
						// Native role propagation failures issued no publishing session.
						if row.Service == "sts" && row.Operation == "assume-role" && row.Result.Code != "Success" {
							continue
						}
						observation := row.awsNativeObservation
						observation.Input = []byte(strings.NewReplacer(replacements...).Replace(string(row.Input)))
						client := controls[row.Service]
						publish := row.Service == "sns" && row.Operation == "publish"
						if publish && row.CallerAccessKey != "" {
							publisher := sessions[row.CallerAccessKey]
							if publisher == nil {
								t.Fatalf("%s: missing captured publishing session %s", row.Label, row.CallerAccessKey)
							}
							client = publisher
						}
						switch out := snsControlReplay(t, client, observation).(type) {
						case *kms.CreateKeyOutput:
							var native kms.CreateKeyOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							replacements = append(replacements, aws.ToString(native.KeyMetadata.KeyId), aws.ToString(out.KeyMetadata.KeyId))
						case *sqs.CreateQueueOutput:
							var native sqs.CreateQueueOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							queueURL = out.QueueUrl
							replacements = append(replacements, aws.ToString(native.QueueUrl), aws.ToString(queueURL))
						case *sts.AssumeRoleOutput:
							var native sts.AssumeRoleOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							credential := out.Credentials
							sessions[aws.ToString(native.Credentials.AccessKeyId)] = clients.snsRegion(fixture.Region, aws.ToString(credential.AccessKeyId), aws.ToString(credential.SecretAccessKey), aws.ToString(credential.SessionToken))
						}
						if publish {
							var bodies []string
							for _, message := range snsAdmissionReceive(t, cloud, queues, queueURL) {
								bodies = append(bodies, aws.ToString(message.Body))
							}
							if !slices.Equal(bodies, expected[row.Label]) {
								t.Fatalf("%s: delivered bodies=%v, native=%v", row.Label, bodies, expected[row.Label])
							}
						}
					}
				})
			}
		})
	}
}

func TestSQLiteSNSEncryptedWorkRecovery(t *testing.T) {
	fixture := snsEncryptionFixture(t)
	path := filepath.Join(t.TempDir(), "sns-encryption.sqlite")
	backends, closeDatabase := openSQLiteBackends(t, path)
	backends.SNS = snsFIFOStoppedWorker{backends.SNS}
	source := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	_, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
	keys := clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
	key, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("retained.fifo"), Attributes: map[string]string{"FifoTopic": "true", "ContentBasedDeduplication": "true", "KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn)}})
	if err != nil {
		t.Fatal(err)
	}
	arn := aws.ToString(topic.TopicArn)
	_, _, qarn := snsEncryptionQueue(t, clients, fixture.Account, "retained", arn, true)
	snsControlSubscribe(t, topics, arn, qarn)
	publisher := snsControlUser(t, clients, fixture, "retained-publisher", `{"Statement":{"Effect":"Allow","Action":["sns:Publish","kms:GenerateDataKey","kms:Decrypt"],"Resource":"*"}}`)
	body := "secret encrypted retained body"
	published, err := publisher.Publish(t.Context(), &sns.PublishInput{TopicArn: &arn, Message: &body, MessageGroupId: aws.String("g")})
	if err != nil {
		t.Fatal(err)
	}
	// Customer configuration changes must not reinterpret already admitted work.
	replacement, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	snsEncryptionSet(t, topics, arn, aws.ToString(replacement.KeyMetadata.Arn))
	if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: &arn, Message: aws.String("replacement key"), MessageGroupId: aws.String("g")}); err != nil {
		t.Fatal(err)
	}
	snsEncryptionSet(t, topics, arn, "")
	if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: &arn, Message: aws.String("plaintext after reset"), MessageGroupId: aws.String("g")}); err != nil {
		t.Fatal(err)
	}
	putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "retained-publisher", `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`)
	if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
		t.Fatal(err)
	}
	if err := backends.SNS.View(t.Context(), func(r snsstore.Reader) error {
		message, err := r.Message(snsstore.MessageKey{ID: aws.ToString(published.MessageId)})
		if err != nil {
			return err
		}
		if message.Body != "" || bytes.Contains(message.EncryptedBody, []byte(body)) || len(message.WrappedDataKey) == 0 || message.KMSKeyARN != aws.ToString(key.KeyMetadata.Arn) {
			return fmt.Errorf("retained message is plaintext or lost original key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	closeCloud()
	// These topic-only ciphertexts predate retained per-message KMS context.
	historicalPath := filepath.Join(t.TempDir(), "sns-version145.sqlite")
	historical := awstest.HistoricalSQLite(t, historicalPath, "../storage/sqlite/schema", 145, path, nil)
	closeDatabase()
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	path = historicalPath
	backends, _ = openSQLiteBackends(t, path)
	cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
	queues := clients.sqs(fixture.Account, "test", "")
	queue, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("retained.fifo")})
	if err != nil {
		t.Fatal(err)
	}
	if got := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl); len(got) != 0 {
		t.Fatalf("unavailable old key bypassed FIFO predecessor: %v", got)
	}
	keys = clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
	if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 20*time.Second)
	if got := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl); len(got) != 0 {
		t.Fatalf("restored key bypassed revoked publisher authority: %v", got)
	}
	// Accepted work needs its original decrypt permission, not a new Publish grant.
	putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "retained-publisher", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":%q},{"Effect":"Deny","Action":"sns:Publish","Resource":"*"}]}`, aws.ToString(key.KeyMetadata.Arn)))
	advanceClock(t, source, 20*time.Second)
	messages := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl)
	if len(messages) != 3 {
		t.Fatalf("restart deliveries=%d", len(messages))
	}
	for i, want := range []string{body, "replacement key", "plaintext after reset"} {
		var envelope snsAdmissionNotification
		awsDecodeJSON(t, []byte(aws.ToString(messages[i].Body)), &envelope)
		if envelope.Message != want || i == 0 && envelope.MessageId != aws.ToString(published.MessageId) {
			t.Fatalf("recovered encrypted work changed: %+v", envelope)
		}
	}
	topics = admissionSNSClient(clients, fixture.Account, fixture.Region)
	duplicate, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: &arn, Message: &body, MessageGroupId: aws.String("g")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(duplicate.MessageId) != aws.ToString(published.MessageId) {
		t.Fatal("encryption reset/restart lost FIFO identity")
	}
	if got := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl); len(got) != 0 {
		t.Fatalf("duplicate created delivery: %v", got)
	}
}

func TestSNSNativeEncryptedSourceConditions(t *testing.T) {
	for _, name := range []string{"service_sources", "event_source_cache"} {
		t.Run(name, func(t *testing.T) {
			var fixture struct {
				snsAdmissionFixture
				OrganizationID string `json:"organization_id"`
				Owned          struct {
					Queues map[string]struct{ URL string }
				} `json:"owned_resources"`
				Receipts []struct {
					Case, Phase, Queue string
					Message            sqstypes.Message
				}
				CloudTrail struct {
					Events []struct{ Event map[string]any }
				}
			}
			data, err := os.ReadFile("../testdata/aws/sns/encryption_" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			awsDecodeJSON(t, data, &fixture)
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
					queues := clients.sqs(fixture.Account, "test", "")
					trails := organizationTrailClient(clients, fixture.Account, fixture.Region)
					var bindings []string
					if fixture.OrganizationID != "" {
						org, err := clients.organizations(fixture.Account, "test").CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
						if err != nil {
							t.Fatal(err)
						}
						bindings = append(bindings, fixture.OrganizationID, aws.ToString(org.Organization.Id))
					}
					controls := map[string]any{
						"sns":    admissionSNSClient(clients, fixture.Account, fixture.Region),
						"kms":    clients.kmsRegion(fixture.Region, fixture.Account, "test", ""),
						"events": eventDeliveryClient(clients, fixture.Account), "sqs": queues,
					}
					for _, row := range fixture.Observations {
						if row.Service == "sts" || row.Service == "organizations" || row.Service == "cloudtrail" ||
							row.Service == "sqs" && (row.Operation == "receive-message" || row.Operation == "delete-message") {
							continue
						}
						if at := time.UnixMilli(row.Started); at.After(source.Now()) {
							advanceClock(t, source, at.Sub(source.Now()))
						}
						row.Input = []byte(strings.NewReplacer(bindings...).Replace(string(row.Input)))
						out := snsControlReplay(t, controls[row.Service], row)
						switch result := out.(type) {
						case *kms.CreateKeyOutput:
							var native kms.CreateKeyOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							bindings = append(bindings, aws.ToString(native.KeyMetadata.KeyId), aws.ToString(result.KeyMetadata.KeyId))
						case *sqs.CreateQueueOutput:
							var native sqs.CreateQueueOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							bindings = append(bindings, aws.ToString(native.QueueUrl), aws.ToString(result.QueueUrl))
						case *eventbridge.PutEventsOutput:
							if result.FailedEntryCount != 0 {
								t.Fatalf("%s: %+v", row.Label, result)
							}
							var native eventbridge.PutEventsOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							bindings = append(bindings, aws.ToString(native.Entries[0].EventId), aws.ToString(result.Entries[0].EventId))
							var in eventbridge.PutEventsInput
							awsDecodeJSON(t, row.Input, &in)
							var detail struct{ Case, Phase string }
							awsDecodeJSON(t, []byte(aws.ToString(in.Entries[0].Detail)), &detail)
							for _, receipt := range fixture.Receipts {
								if receipt.Case != detail.Case || receipt.Phase != detail.Phase {
									continue
								}
								normalize := strings.NewReplacer(bindings...)
								for _, lane := range []string{"collector", "dlq"} {
									url := normalize.Replace(fixture.Owned.Queues[lane].URL)
									messages := snsAdmissionReceive(t, cloud, queues, &url)
									if lane != receipt.Queue {
										if len(messages) != 0 {
											t.Errorf("%s: unexpected %s delivery: %+v", row.Label, lane, messages)
										}
										continue
									}
									if len(messages) != 1 {
										t.Fatalf("%s: %s receipts=%d", row.Label, lane, len(messages))
									}
									var got, want map[string]any
									awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &got)
									awsDecodeJSON(t, []byte(normalize.Replace(aws.ToString(receipt.Message.Body))), &want)
									// Ingestion time is provider-generated; event identity remains correlated.
									want["time"] = got["time"]
									if !reflect.DeepEqual(got, want) {
										t.Errorf("%s: body=%v, native=%v", row.Label, got, want)
									}
									for _, name := range []string{"ERROR_CODE", "RULE_ARN", "TARGET_ARN"} {
										got, want := messages[0].MessageAttributes[name], receipt.Message.MessageAttributes[name]
										if !reflect.DeepEqual(got, want) {
											t.Errorf("%s: %s=%s:%q, native=%s:%q", row.Label, name, aws.ToString(got.DataType), aws.ToString(got.StringValue), aws.ToString(want.DataType), aws.ToString(want.StringValue))
										}
									}
								}
							}
						}
					}
					for _, captured := range fixture.CloudTrail.Events {
						native := captured.Event
						name, _ := native["eventName"].(string)
						identity, _ := native["userIdentity"].(map[string]any)
						if (name == "GenerateDataKey" || name == "Decrypt") && identity["type"] == "AWSService" {
							snsSourceCryptoAudit(t, trails, native, bindings...)
						}
					}
				})
			}
		})
	}
}

func snsSourceCryptoAudit(t *testing.T, trails *cloudtrail.Client, native map[string]any, bindings ...string) {
	t.Helper()
	name := native["eventName"].(string)
	page, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{
		MaxResults:       aws.Int32(50),
		LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: &name}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := json.Marshal(native["resources"])
	if err != nil {
		t.Fatal(err)
	}
	var expected any
	awsDecodeJSON(t, []byte(strings.NewReplacer(bindings...).Replace(string(resources))), &expected)
	request, _ := native["requestParameters"].(map[string]any)
	want, _ := request["encryptionContext"].(map[string]any)
	var actual map[string]any
	for _, event := range page.Events {
		awsDecodeJSON(t, []byte(aws.ToString(event.CloudTrailEvent)), &actual)
		request, _ := actual["requestParameters"].(map[string]any)
		context, _ := request["encryptionContext"].(map[string]any)
		if reflect.DeepEqual(actual["resources"], expected) && actual["errorCode"] == native["errorCode"] && context["aws:sns:sourceArn"] == want["aws:sns:sourceArn"] {
			break
		}
		actual = nil
	}
	if actual == nil {
		t.Fatalf("%s: missing KMS record for %v", name, expected)
	}
	for _, field := range []string{"userIdentity", "sourceIPAddress", "userAgent"} {
		if !reflect.DeepEqual(actual[field], native[field]) {
			t.Errorf("%s: %s=%v, native=%v", name, field, actual[field], native[field])
		}
	}
	request, _ = actual["requestParameters"].(map[string]any)
	if got, _ := request["encryptionContext"].(map[string]any); !reflect.DeepEqual(got, want) {
		t.Errorf("%s: context=%v, native=%v", name, got, want)
	}
}

func TestSNSNativeEncryptedServiceSources(t *testing.T) {
	for _, name := range []string{"cloudwatch_source", "cloudtrail_source", "s3_source", "cloudtrail_notification"} {
		t.Run(name, func(t *testing.T) {
			var fixture struct {
				snsAdmissionFixture
				Receipts   []struct{ Message sqstypes.Message }
				CloudTrail struct {
					Events []struct{ Event map[string]any }
				}
				Object struct {
					Body string `json:"body_utf8"`
				}
				Findings json.RawMessage
			}
			data, err := os.ReadFile("../testdata/aws/sns/encryption_" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			awsDecodeJSON(t, data, &fixture)
			var findings struct {
				Correlations []struct {
					Observation string `json:"trigger_observation"`
					RequestID   string `json:"api_response_request_id"`
					Bucket      string
				} `json:"owned_write_notification_correlations"`
			}
			if name == "cloudtrail_notification" {
				awsDecodeJSON(t, fixture.Findings, &findings)
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					cloud, clients, source := admissionFixtureCloud(t, backend, fixture.snsAdmissionFixture)
					trails := organizationTrailClient(clients, fixture.Account, fixture.Region)
					queues := clients.sqs(fixture.Account, "test", "")
					objects := s3NativeClient(clients, fixture.Account, "test")
					controls := map[string]any{
						"sns": admissionSNSClient(clients, fixture.Account, fixture.Region),
						"kms": clients.kmsRegion(fixture.Region, fixture.Account, "test", ""),
						"sqs": queues, "cloudwatch": metricsClient(clients, fixture.Account),
						"cloudtrail": trails, "s3api": objects,
					}
					var bindings []string
					var queueURL *string
					var messages []sqstypes.Message
					for _, row := range fixture.Observations {
						if name == "s3_source" || name == "cloudtrail_notification" {
							if elapsed := time.UnixMilli(row.Started).Sub(source.Now()); elapsed > 0 {
								advanceClock(t, source, elapsed)
								trailNativeDrain(t, cloud)
							}
						}
						if row.Service == "sts" || row.Service == "sqs" && row.Operation == "delete-message" ||
							row.Service == "s3api" && row.Operation == "get-object" {
							continue
						}
						if row.Service == "sqs" && row.Operation == "receive-message" {
							messages = append(messages, snsAdmissionReceive(t, cloud, queues, queueURL)...)
							continue
						}
						row.Input = []byte(strings.NewReplacer(bindings...).Replace(string(row.Input)))
						if row.Service == "s3api" && row.Operation == "put-object" {
							native := s3NativeObservation{Label: row.Label, Operation: "PutObject", Input: row.Input}
							native.Result.HTTPStatus = row.Result.HTTPStatus
							_, _, err := s3NativeInvoke(t, controls[row.Service], native, []byte(fixture.Object.Body))
							awsNativeResult(t, row, err)
							continue
						}
						out := snsControlReplay(t, controls[row.Service], row)
						for _, correlation := range findings.Correlations {
							if row.Label == correlation.Observation {
								bindings = append(bindings, correlation.RequestID, nativeAuditRequestID(t, out, nil))
							}
						}
						switch out := out.(type) {
						case *kms.CreateKeyOutput:
							var native kms.CreateKeyOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							bindings = append(bindings, aws.ToString(native.KeyMetadata.KeyId), aws.ToString(out.KeyMetadata.KeyId))
						case *sqs.CreateQueueOutput:
							var native sqs.CreateQueueOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							queueURL = out.QueueUrl
							bindings = append(bindings, aws.ToString(native.QueueUrl), aws.ToString(out.QueueUrl))
						case *sns.SubscribeOutput:
							var native sns.SubscribeOutput
							awsDecodeJSON(t, row.Result.Output, &native)
							bindings = append(bindings, aws.ToString(native.SubscriptionArn), aws.ToString(out.SubscriptionArn))
						}
					}
					messages = append(messages, snsAdmissionReceive(t, cloud, queues, queueURL)...)
					if name == "cloudtrail_notification" {
						if !slices.ContainsFunc(messages, func(message sqstypes.Message) bool {
							return aws.ToString(message.Body) == aws.ToString(fixture.Receipts[0].Message.Body)
						}) {
							t.Fatal("missing native trail validation publication")
						}
						for _, correlation := range findings.Correlations {
							id := strings.NewReplacer(bindings...).Replace(correlation.RequestID)
							want := trailSNSNotification{Bucket: correlation.Bucket, Records: []map[string]any{{"requestID": id}}}
							if !slices.ContainsFunc(messages, func(message sqstypes.Message) bool {
								return trailSNSLogNotification(t, objects, want, aws.ToString(message.Body))
							}) {
								t.Fatalf("missing notified S3 log for %s", correlation.Observation)
							}
						}
					} else {
						if len(messages) != len(fixture.Receipts) {
							t.Fatalf("receipts=%d, native=%d", len(messages), len(fixture.Receipts))
						}
						for i, receipt := range fixture.Receipts {
							actual, native := aws.ToString(messages[i].Body), aws.ToString(receipt.Message.Body)
							if name == "cloudtrail_source" {
								if actual != native {
									t.Errorf("body=%s, native=%s", actual, native)
								}
								continue
							}
							var got, want map[string]any
							awsDecodeJSON(t, []byte(actual), &got)
							awsDecodeJSON(t, []byte(native), &want)
							if name == "s3_source" {
								// Transport/provider identities have separate S3 replay coverage.
								for _, field := range []string{"Time", "RequestId", "HostId"} {
									delete(want, field)
								}
								if records, ok := want["Records"].([]any); ok {
									for _, value := range records {
										record := value.(map[string]any)
										for _, field := range []string{"eventTime", "eventVersion", "userIdentity", "requestParameters", "responseElements"} {
											delete(record, field)
										}
										object := record["s3"].(map[string]any)
										delete(object["bucket"].(map[string]any), "ownerIdentity")
										delete(object["object"].(map[string]any), "sequencer")
									}
								}
								s3NativeProjection(t, "encrypted S3 notification", want, got)
								continue
							}
							for _, field := range []string{"AlarmConfigurationUpdatedTimestamp", "StateChangeTime"} {
								want[field] = got[field]
							}
							if !reflect.DeepEqual(got, want) {
								t.Errorf("body=%v, native=%v", got, want)
							}
						}
					}
					for _, captured := range fixture.CloudTrail.Events {
						if name := captured.Event["eventName"]; name == "GenerateDataKey" || name == "Decrypt" {
							snsSourceCryptoAudit(t, trails, captured.Event, bindings...)
						}
					}
				})
			}
		})
	}
}
