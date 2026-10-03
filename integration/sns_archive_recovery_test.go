package stackd_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd/clock"
	"stackd/internal/scheduler"
	"stackd/storage"
	snsstore "stackd/storage/sns"
)

// Only discovery is held. Admission, archive selection, delivery creation,
// authorization, encryption and endpoint effects use the real implementations.
type snsRecoveryDiscovery struct {
	snsstore.Repository
	replay, delivery, expiration atomic.Bool
}

type snsRecoveryReader struct {
	snsstore.Reader
	hold *snsRecoveryDiscovery
}

func (r *snsRecoveryDiscovery) View(ctx context.Context, fn func(snsstore.Reader) error) error {
	return r.Repository.View(ctx, func(reader snsstore.Reader) error {
		return fn(snsRecoveryReader{Reader: reader, hold: r})
	})
}

func (r snsRecoveryReader) NextReplay() (snsstore.SubscriptionRecord, bool, error) {
	if r.hold.replay.Load() {
		return snsstore.SubscriptionRecord{}, false, nil
	}
	return r.Reader.NextReplay()
}

func (r snsRecoveryReader) NextDelivery() (scheduler.Job, bool, error) {
	if r.hold.delivery.Load() {
		return scheduler.Job{}, false, nil
	}
	return r.Reader.NextDelivery()
}

func (r snsRecoveryReader) NextArchiveExpiration() (snsstore.ArchiveEntry, bool, error) {
	if r.hold.expiration.Load() {
		return snsstore.ArchiveEntry{}, false, nil
	}
	return r.Reader.NextArchiveExpiration()
}

func snsRecoveryTopic(t *testing.T, topics *sns.Client, name string, days int) string {
	t.Helper()
	out, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: &name, Attributes: map[string]string{
		"FifoTopic": "true", "ArchivePolicy": fmt.Sprintf(`{"MessageRetentionPeriod":%d}`, days),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.TopicArn)
}

func snsRecoveryPublish(t *testing.T, topics *sns.Client, arn, body string) *sns.PublishOutput {
	t.Helper()
	out, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: &arn, Message: &body, MessageGroupId: aws.String("ordered"), MessageDeduplicationId: aws.String(strings.ReplaceAll(body, " ", "-"))})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func snsRecoveryReplay(t *testing.T, topics *sns.Client, subscription string, start time.Time) {
	t.Helper()
	policy := fmt.Sprintf(`{"PointType":"Timestamp","StartingPoint":%q}`, start.Format(time.RFC3339Nano))
	snsRecoverySetReplay(t, topics, subscription, policy)
}

func snsRecoverySetReplay(t *testing.T, topics *sns.Client, subscription, policy string) {
	t.Helper()
	if _, err := topics.SetSubscriptionAttributes(t.Context(), &sns.SetSubscriptionAttributesInput{SubscriptionArn: &subscription, AttributeName: aws.String("ReplayPolicy"), AttributeValue: &policy}); err != nil {
		t.Fatal(err)
	}
}

func snsRecoveryStatus(t *testing.T, topics *sns.Client, subscription, want string) {
	t.Helper()
	out, err := topics.GetSubscriptionAttributes(t.Context(), &sns.GetSubscriptionAttributesInput{SubscriptionArn: &subscription})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Attributes["ReplayStatus"]; got != want {
		t.Fatalf("replay status = %q, want %q", got, want)
	}
	if want == "" {
		if _, present := out.Attributes["ReplayPolicy"]; present {
			t.Fatal("cancelled replay still exposes policy")
		}
	}
}

func snsRecoveryArchive(t *testing.T, topics *sns.Client, arn, policy string) {
	t.Helper()
	if _, err := topics.SetTopicAttributes(t.Context(), &sns.SetTopicAttributesInput{TopicArn: &arn, AttributeName: aws.String("ArchivePolicy"), AttributeValue: &policy}); err != nil {
		t.Fatal(err)
	}
}

func snsRecoveryQueueURL(t *testing.T, queues *sqs.Client, name string) *string {
	t.Helper()
	out, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: &name})
	if err != nil {
		t.Fatal(err)
	}
	return out.QueueUrl
}

func snsRecoveryMessages(t *testing.T, messages []sqstypes.Message, replayed bool, publications ...*sns.PublishOutput) {
	t.Helper()
	if len(messages) != len(publications) {
		t.Fatalf("received %d messages, want %d: %+v", len(messages), len(publications), messages)
	}
	for i, message := range messages {
		var envelope map[string]any
		awsDecodeJSON(t, []byte(aws.ToString(message.Body)), &envelope)
		if envelope["MessageId"] != aws.ToString(publications[i].MessageId) || envelope["SequenceNumber"] != aws.ToString(publications[i].SequenceNumber) {
			t.Fatalf("message %d lost publication identity/order: %+v", i, envelope)
		}
		marker, present := envelope["Replayed"]
		if replayed && marker != "true" || !replayed && present {
			t.Fatalf("unexpected replay marker: %+v", envelope)
		}
	}
}

func TestSQLiteSNSArchiveAndAcceptedReplayRecovery(t *testing.T) {
	fixture := snsControlsFixture(t, "archive_transitions").snsAdmissionFixture
	path := filepath.Join(t.TempDir(), "archive.sqlite")
	backends, closeDB := openSQLiteBackends(t, path)
	source := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	start := source.Now()
	_, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
	arn := snsRecoveryTopic(t, topics, "recovery.fifo", 1)
	first := snsRecoveryPublish(t, topics, arn, "archived without any subscription")
	second := snsRecoveryPublish(t, topics, arn, "second archived publication")
	closeCloud()
	closeDB()

	backends, closeDB = openSQLiteBackends(t, path)
	hold := &snsRecoveryDiscovery{Repository: backends.SNS}
	hold.replay.Store(true)
	backends.SNS = hold
	_, clients, closeCloud = startEventDeliveryCloud(t, backends, source)
	topics = admissionSNSClient(clients, fixture.Account, fixture.Region)
	_, _, queueARN := snsControlQueue(t, clients, fixture.Account, "recovery", arn)
	subscription := snsControlSubscribe(t, topics, arn, queueARN)
	snsRecoveryReplay(t, topics, subscription, start)
	snsRecoveryStatus(t, topics, subscription, "Pending")
	closeCloud()
	closeDB()

	// Recover the pending cursor and let it create real endpoint work, but stop
	// before dispatch. A second restart must recover those accepted deliveries.
	backends, closeDB = openSQLiteBackends(t, path)
	hold = &snsRecoveryDiscovery{Repository: backends.SNS}
	hold.delivery.Store(true)
	backends.SNS = hold
	cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	topics = admissionSNSClient(clients, fixture.Account, fixture.Region)
	trailNativeDrain(t, cloud)
	snsRecoveryStatus(t, topics, subscription, "Completed")
	closeCloud()
	closeDB()

	backends, _ = openSQLiteBackends(t, path)
	cloud, clients, _ = startEventDeliveryCloud(t, backends, source)
	topics, queues := admissionSNSClient(clients, fixture.Account, fixture.Region), clients.sqs(fixture.Account, "test", "")
	queueURL := snsRecoveryQueueURL(t, queues, "recovery")
	messages := snsAdmissionReceive(t, cloud, queues, queueURL)
	snsRecoveryMessages(t, messages, true, first, second)
	for i, body := range []string{"archived without any subscription", "second archived publication"} {
		var envelope struct{ Message, Timestamp string }
		awsDecodeJSON(t, []byte(aws.ToString(messages[i].Body)), &envelope)
		publishedAt, err := time.Parse(time.RFC3339Nano, envelope.Timestamp)
		if err != nil || !publishedAt.Equal(start) || envelope.Message != body {
			t.Fatalf("restart changed original body/timestamp: %+v, %v", envelope, err)
		}
	}
	// The last delivery and then the last subscription may disappear without
	// collecting the archive's only remaining references to the message bodies.
	if _, err := topics.Unsubscribe(t.Context(), &sns.UnsubscribeInput{SubscriptionArn: &subscription}); err != nil {
		t.Fatal(err)
	}
	subscription = snsControlSubscribe(t, topics, arn, queueARN)
	snsRecoveryReplay(t, topics, subscription, start)
	snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), true, first, second)
}

func TestSQLiteSNSArchiveReplayCancellationPreservesLiveWork(t *testing.T) {
	for _, state := range []struct{ admitted, replacement bool }{{false, false}, {false, true}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("admitted=%v/replacement=%v", state.admitted, state.replacement), func(t *testing.T) {
			fixture := snsControlsFixture(t, "archive_transitions").snsAdmissionFixture
			path := filepath.Join(t.TempDir(), "cancel.sqlite")
			backends, closeDB := openSQLiteBackends(t, path)
			hold := &snsRecoveryDiscovery{Repository: backends.SNS}
			hold.delivery.Store(true)
			hold.replay.Store(!state.admitted)
			backends.SNS = hold
			source := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
			start := source.Now()
			cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			arn := snsRecoveryTopic(t, topics, "cancel.fifo", 1)
			archived := snsRecoveryPublish(t, topics, arn, "archive only")
			_, _, queueARN := snsControlQueue(t, clients, fixture.Account, "cancel", arn)
			subscription := snsControlSubscribe(t, topics, arn, queueARN)
			snsRecoveryReplay(t, topics, subscription, start)
			trailNativeDrain(t, cloud)
			advanceClock(t, source, time.Second)
			live := snsRecoveryPublish(t, topics, arn, "live work must survive")
			if state.replacement {
				snsRecoveryReplay(t, topics, subscription, source.Now())
				hold.replay.Store(false)
				trailNativeDrain(t, cloud)
			} else {
				snsRecoverySetReplay(t, topics, subscription, "{}")
				snsRecoveryStatus(t, topics, subscription, "")
			}
			closeCloud()
			closeDB()
			backends, _ = openSQLiteBackends(t, path)
			cloud, clients, _ = startEventDeliveryCloud(t, backends, source)
			topics, queues := admissionSNSClient(clients, fixture.Account, fixture.Region), clients.sqs(fixture.Account, "test", "")
			queueURL := snsRecoveryQueueURL(t, queues, "cancel")
			messages := snsAdmissionReceive(t, cloud, queues, queueURL)
			count := 1
			if state.admitted {
				count++
			}
			if state.replacement {
				count++
			}
			if len(messages) != count {
				t.Fatalf("cancellation/replacement changed admitted live or replay work: %+v", messages)
			}
			if state.admitted {
				snsRecoveryMessages(t, messages[:1], true, archived)
				messages = messages[1:]
			}
			snsRecoveryMessages(t, messages[:1], false, live)
			if state.replacement {
				snsRecoveryMessages(t, messages[1:], true, live)
			}
			snsRecoveryReplay(t, topics, subscription, start)
			snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), true, archived, live)
		})
	}
}

func TestSNSArchiveRetentionAndIncarnationBoundaries(t *testing.T) {
	fixture := snsControlsFixture(t, "archive_transitions").snsAdmissionFixture
	fixture.Observations[0].Started = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "retention.sqlite"))
			}
			hold := &snsRecoveryDiscovery{Repository: backends.SNS}
			hold.expiration.Store(true)
			backends.SNS = hold
			source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started))
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			arn := snsRecoveryTopic(t, topics, "retention.fifo", 2)
			snsRecoveryPublish(t, topics, arn, "expires after retention reduction")
			advanceClock(t, source, 25*time.Hour)
			recent := snsRecoveryPublish(t, topics, arn, "retained after reduction")
			queues, queueURL, queueARN := snsControlQueue(t, clients, fixture.Account, "retention", arn)
			subscription := snsControlSubscribe(t, topics, arn, queueARN)
			snsRecoveryArchive(t, topics, arn, `{"MessageRetentionPeriod":1}`)
			// A delayed expiration worker must not let a retention increase
			// resurrect publications expired by the preceding reduction.
			snsRecoveryArchive(t, topics, arn, `{"MessageRetentionPeriod":2}`)
			hold.expiration.Store(false)
			replayAvailable := func(want ...*sns.PublishOutput) {
				t.Helper()
				attrs, err := topics.GetTopicAttributes(t.Context(), &sns.GetTopicAttributesInput{TopicArn: &arn})
				if err != nil {
					t.Fatal(err)
				}
				beginning, err := time.Parse(time.RFC3339Nano, attrs.Attributes["BeginningArchiveTime"])
				if err != nil {
					t.Fatal(err)
				}
				snsRecoveryReplay(t, topics, subscription, beginning)
				snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), true, want...)
			}
			replayAvailable(recent)
			advanceClock(t, source, 49*time.Hour)
			replayAvailable()
			// Same-instant publications make these incarnation checks independent
			// of StartingPoint validation: leaked old entries would be selected.
			old := snsRecoveryPublish(t, topics, arn, "old archive incarnation")
			snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), false, old)
			snsRecoveryArchive(t, topics, arn, "{}")
			snsRecoveryArchive(t, topics, arn, `{"MessageRetentionPeriod":1}`)
			replayAvailable()
			deleted := snsRecoveryPublish(t, topics, arn, "deleted topic incarnation")
			snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), false, deleted)
			snsRecoveryArchive(t, topics, arn, "{}")
			if _, err := topics.DeleteTopic(t.Context(), &sns.DeleteTopicInput{TopicArn: &arn}); err != nil {
				t.Fatal(err)
			}
			arn = snsRecoveryTopic(t, topics, "retention.fifo", 1)
			fresh := snsRecoveryPublish(t, topics, arn, "new topic incarnation")
			// Native retained subscriptions still route this ordinary publication;
			// consume it before comparing the new incarnation's archive replay.
			snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), false, fresh)
			subscription = snsControlSubscribe(t, topics, arn, queueARN)
			replayAvailable(fresh)
		})
	}
}

func TestSQLiteSNSEncryptedArchiveSourceKeyRecovery(t *testing.T) {
	fixture := snsControlsFixture(t, "archive_transitions").snsAdmissionFixture
	path := filepath.Join(t.TempDir(), "encrypted-archive.sqlite")
	backends, closeDB := openSQLiteBackends(t, path)
	source := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	start := source.Now()
	_, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
	topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
	keys := clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
	oldKey, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	arn := snsRecoveryTopic(t, topics, "encrypted-archive.fifo", 1)
	snsEncryptionSet(t, topics, arn, aws.ToString(oldKey.KeyMetadata.Arn))
	secret := "encrypted archive body surviving without live references"
	original := snsRecoveryPublish(t, topics, arn, secret)
	snsEncryptionSet(t, topics, arn, aws.ToString(newKey.KeyMetadata.Arn))
	newer := snsRecoveryPublish(t, topics, arn, "new key archive body")
	// This is the established encrypted-at-rest boundary; recovery below proves
	// the source key through actual KMS decryption rather than copied key fields.
	if err := backends.SNS.View(t.Context(), func(r snsstore.Reader) error {
		message, err := r.Message(snsstore.MessageKey{ID: aws.ToString(original.MessageId)})
		if err != nil {
			return err
		}
		if message.Body != "" || bytes.Contains(message.EncryptedBody, []byte(secret)) || len(message.EncryptedBody) == 0 || len(message.WrappedDataKey) == 0 {
			return fmt.Errorf("archive retained plaintext or lost encrypted payload")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: oldKey.KeyMetadata.KeyId}); err != nil {
		t.Fatal(err)
	}
	closeCloud()
	closeDB()
	backends, _ = openSQLiteBackends(t, path)
	cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
	topics = admissionSNSClient(clients, fixture.Account, fixture.Region)
	queues, queueURL, queueARN := snsControlQueue(t, clients, fixture.Account, "encrypted-archive", arn)
	subscription := snsControlSubscribe(t, topics, arn, queueARN)
	snsRecoveryReplay(t, topics, subscription, start)
	snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), true)
	snsRecoveryStatus(t, topics, subscription, "Completed")
	keys = clients.kmsRegion(fixture.Region, fixture.Account, "test", "")
	if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: oldKey.KeyMetadata.KeyId}); err != nil {
		t.Fatal(err)
	}
	snsRecoveryReplay(t, topics, subscription, start)
	snsRecoveryMessages(t, snsAdmissionReceive(t, cloud, queues, queueURL), true)
	snsRecoveryStatus(t, topics, subscription, "Completed")
	// Enabling the original key does not supply the archive service's missing
	// authority. Grant Decrypt for this source, independently of its publisher.
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:aws:sns:topicArn":%q}}}]}`, fixture.Account, arn)
	for _, id := range []*string{oldKey.KeyMetadata.KeyId, newKey.KeyMetadata.KeyId} {
		if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: id, PolicyName: aws.String("default"), Policy: &policy}); err != nil {
			t.Fatal(err)
		}
	}
	snsRecoveryReplay(t, topics, subscription, start)
	messages := snsAdmissionReceive(t, cloud, queues, queueURL)
	snsRecoveryMessages(t, messages, true, original, newer)
	var envelope snsAdmissionNotification
	awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &envelope)
	if envelope.Message != secret {
		t.Fatalf("archive decrypted to %q", envelope.Message)
	}
	t.Log("Local cold-start recovery only: native encrypted replay captures do not establish a cold KMS cache deadline.")
}

func TestSNSNativeArchiveEndpointTransitions(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/sns/archive_transitions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		snsAdmissionFixture
		DeniedStatus       map[string]string `json:"denied_status"`
		AfterDisableStatus map[string]string `json:"after_disable_status"`
	}
	awsDecodeJSON(t, data, &fixture)
	var nativeArchive struct{ Attributes map[string]string }
	awsDecodeJSON(t, snsControlRow(t, fixture.snsAdmissionFixture, "archive-attributes").Result.Output, &nativeArchive)
	beginning, err := time.Parse(time.RFC3339Nano, nativeArchive.Attributes["BeginningArchiveTime"])
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "transitions.sqlite"))
			}
			hold := &snsRecoveryDiscovery{Repository: backends.SNS}
			backends.SNS = hold
			cloud, clients, _ := startEventDeliveryCloud(t, backends, clock.NewManual(beginning))
			topics, queues := admissionSNSClient(clients, fixture.Account, fixture.Region), clients.sqs(fixture.Account, "test", "")
			row := func(label string) awsNativeObservation {
				return snsControlRow(t, fixture.snsAdmissionFixture, label)
			}
			topic := snsControlReplay(t, topics, row("create-topic")).(*sns.CreateTopicOutput)
			queue := snsControlReplay(t, queues, row("create-queue")).(*sqs.CreateQueueOutput)
			setQueue := func(label string) {
				snsControlReplay(t, queues, row(label), func(value any) { value.(*sqs.SetQueueAttributesInput).QueueUrl = queue.QueueUrl })
			}
			setQueue("allow-endpoint")
			subscription := snsControlReplay(t, topics, row("subscribe")).(*sns.SubscribeOutput)
			setReplay := func(label string) {
				snsControlReplay(t, topics, row(label), func(value any) {
					value.(*sns.SetSubscriptionAttributesInput).SubscriptionArn = subscription.SubscriptionArn
				})
			}
			checkReceive := func(label string, published *sns.PublishOutput) {
				t.Helper()
				var native sqs.ReceiveMessageOutput
				awsDecodeJSON(t, row(label).Result.Output, &native)
				messages := snsAdmissionReceive(t, cloud, queues, queue.QueueUrl)
				if len(native.Messages) == 0 {
					snsRecoveryMessages(t, messages, true)
					return
				}
				var expected map[string]any
				awsDecodeJSON(t, []byte(aws.ToString(native.Messages[0].Body)), &expected)
				snsRecoveryMessages(t, messages, expected["Replayed"] == "true", published)
				var envelope map[string]any
				awsDecodeJSON(t, []byte(aws.ToString(messages[0].Body)), &envelope)
				if envelope["Message"] != expected["Message"] {
					t.Fatalf("%s: payload = %v, want %v", label, envelope["Message"], expected["Message"])
				}
			}
			original := snsControlReplay(t, topics, row("publish-original")).(*sns.PublishOutput)
			checkReceive("baseline-receive", original)
			setQueue("deny-endpoint")
			setReplay("denied-replay")
			checkReceive("denied-receive", original)
			snsRecoveryStatus(t, topics, aws.ToString(subscription.SubscriptionArn), fixture.DeniedStatus["ReplayStatus"])
			setQueue("restore-endpoint")
			setReplay("repaired-replay")
			checkReceive("repaired-receive", original)
			hold.replay.Store(true)
			setReplay("pending-before-disable")
			var pending struct{ Attributes map[string]string }
			awsDecodeJSON(t, row("pending-status-before-disable").Result.Output, &pending)
			snsRecoveryStatus(t, topics, aws.ToString(subscription.SubscriptionArn), pending.Attributes["ReplayStatus"])
			snsControlReplay(t, topics, row("disable-with-attached-replay"))
			hold.replay.Store(false)
			trailNativeDrain(t, cloud)
			snsRecoveryStatus(t, topics, aws.ToString(subscription.SubscriptionArn), fixture.AfterDisableStatus["ReplayStatus"])
			live := snsControlReplay(t, topics, row("publish-after-disable")).(*sns.PublishOutput)
			checkReceive("after-disable-receive", live)
			setReplay("cancel-after-disable")
			var cancelled struct{ Attributes map[string]string }
			awsDecodeJSON(t, row("after-cancel-status").Result.Output, &cancelled)
			snsRecoveryStatus(t, topics, aws.ToString(subscription.SubscriptionArn), cancelled.Attributes["ReplayStatus"])
			// An unrelated tenant cannot expose or replace this subscription's
			// archive selection even when it knows the complete resource ARN.
			foreign := admissionSNSClient(clients, "222222222222", fixture.Region)
			_, err := foreign.SetSubscriptionAttributes(t.Context(), &sns.SetSubscriptionAttributesInput{SubscriptionArn: subscription.SubscriptionArn, AttributeName: aws.String("ReplayPolicy"), AttributeValue: aws.String("{}")})
			assertAPIError(t, err, "AuthorizationError")
			_, err = foreign.GetTopicAttributes(t.Context(), &sns.GetTopicAttributesInput{TopicArn: topic.TopicArn})
			assertAPIError(t, err, "AuthorizationError")
		})
	}
}
