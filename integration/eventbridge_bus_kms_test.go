package stackd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	service "stackd/internal/services/eventbridge"
	"stackd/storage"
	domain "stackd/storage/eventbridge"
)

// Hold only job selection, not resource transactions or KMS calls. This makes
// accepted-but-unprocessed restart/key transitions deterministic.
type busKMSRepository struct {
	domain.Repository
	paused atomic.Bool
}
type busKMSReader struct {
	domain.Reader
	owner *busKMSRepository
}

func (r busKMSReader) NextDelivery() (domain.DeliveryRecord, bool, error) {
	if r.owner.paused.Load() {
		return domain.DeliveryRecord{}, false, nil
	}
	return r.Reader.NextDelivery()
}
func (r *busKMSRepository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return r.Repository.View(ctx, func(reader domain.Reader) error { return fn(busKMSReader{reader, r}) })
}

func busKMSKey(t *testing.T, clients cloudClients) *string {
	t.Helper()
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*","Condition":{"StringLike":{"aws:SourceArn":"arn:aws:events:us-east-1:%s:event-bus/*","kms:EncryptionContext:aws:events:event-bus:arn":"arn:aws:events:us-east-1:%s:event-bus/*"}}}]}`, eventDeliveryAccount, eventDeliveryAccount, eventDeliveryAccount)
	out, err := clients.kms(eventDeliveryAccount, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	return out.KeyMetadata.Arn
}

func busKMSPut(t *testing.T, clients cloudClients, bus, marker, trace string) *eventbridge.PutEventsOutput {
	t.Helper()
	out, err := eventDeliveryClient(clients, eventDeliveryAccount).PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{EventBusName: &bus, Source: aws.String(eventDeliveryName), DetailType: aws.String("encryption"), Detail: aws.String(fmt.Sprintf(`{"private":%q,"number":1.2300}`, marker)), TraceHeader: &trace}}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEventBridgeBusKMSRetainedSDK(t *testing.T) {
	fixtureData, err := os.ReadFile("../testdata/aws/eventbridge/bus_kms_envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Attributes map[string]struct{ StringValue, DataType string }
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatal(err)
	}
	controlData, err := os.ReadFile("../testdata/aws/eventbridge/bus_kms_control.json")
	if err != nil {
		t.Fatal(err)
	}
	var control struct {
		Cold          struct{ ErrorCode string } `json:"cold_entry_error"`
		Configuration struct{ Code string }      `json:"configuration_read_error"`
	}
	if err := json.Unmarshal(controlData, &control); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bus-kms.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if kind == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			gate := &busKMSRepository{Repository: backends.EventBridge}
			gate.paused.Store(true)
			backends.EventBridge = gate
			source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
			_, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
			urls := provisionEventDelivery(t, clients)
			setEventDeliveryPolicy(t, clients.sqs(eventDeliveryAccount, "test", ""), urls["target"], "target", nil)
			setEventDeliveryPolicy(t, clients.sqs(eventDeliveryAccount, "test", ""), urls["dlq"], "dlq", nil)
			first, second := busKMSKey(t, clients), busKMSKey(t, clients)
			keys := clients.kms(eventDeliveryAccount, "test", "")
			alias := "alias/bus-retention"
			if _, err := keys.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: first}); err != nil {
				t.Fatal(err)
			}
			events := eventDeliveryClient(clients, eventDeliveryAccount)
			updated, err := events.UpdateEventBus(t.Context(), &eventbridge.UpdateEventBusInput{Name: aws.String(eventDeliveryName), KmsKeyIdentifier: &alias, DeadLetterConfig: &eventtypes.DeadLetterConfig{Arn: aws.String(eventDeliveryQueueARN("dlq"))}})
			if err != nil || aws.ToString(updated.KmsKeyIdentifier) != "arn:aws:kms:us-east-1:"+eventDeliveryAccount+":"+alias {
				t.Fatal(updated, err)
			}
			projection, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{EventBusName: aws.String(eventDeliveryName), Rule: aws.String(eventDeliveryName), Targets: []eventtypes.Target{{Id: aws.String("projection"), Arn: aws.String(eventDeliveryQueueARN("target")), InputPath: aws.String("$.detail")}}})
			if err != nil || projection.FailedEntryCount != 0 {
				t.Fatal(projection, err)
			}
			trace := "Root=1-6ab2832c-0123456789abcdef01234567;Parent=0123456789abcdef;Sampled=0"
			marker := "bus-customer-plaintext-must-not-be-retained"
			accepted := busKMSPut(t, clients, eventDeliveryName, marker, trace)
			if accepted.FailedEntryCount != 0 {
				t.Fatal(accepted)
			}
			id := aws.ToString(accepted.Entries[0].EventId)
			if err := gate.Repository.View(t.Context(), func(r domain.Reader) error {
				event, err := r.Event(id)
				if err != nil {
					return err
				}
				if event.Detail != "" || event.KeyARN != aws.ToString(first) || bytes.Contains(event.Payload.Content, []byte(marker)) || len(event.Payload.Content) < 3 || !bytes.Equal(event.Payload.Content[:3], []byte{2, 4, 0x78}) {
					t.Fatalf("retained customer plaintext or wrong key: %+v", event)
				}
				deliveries, err := r.EventDeliveries(id)
				if err != nil {
					return err
				}
				for _, delivery := range deliveries {
					if delivery.TargetID == "projection" && (delivery.Input != "" || len(delivery.TargetConfiguration) == 0 || bytes.Contains(delivery.TargetConfiguration, []byte("$.detail"))) {
						t.Fatalf("retained projected plaintext: %+v", delivery)
					}
				}
				rule, err := r.Rule(domain.RuleKey{Bus: event.Bus, Name: eventDeliveryName})
				if err != nil {
					return err
				}
				if rule.Pattern != "" || len(rule.EncryptedPattern) == 0 {
					t.Fatalf("rule pattern retained without encryption: %+v", rule)
				}
				targets, err := r.Targets(rule.Key)
				if err != nil {
					return err
				}
				for _, target := range targets {
					if target.Input.Input != nil || target.Input.InputPath != nil || target.Input.Transformer != nil || len(target.EncryptedConfiguration) == 0 {
						t.Fatalf("target configuration retained without encryption: %+v", target)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Pending work stays bound to first, even when the current bus key is
			// replaced and disabled before reopening the entire cloud.
			if _, err := events.UpdateEventBus(t.Context(), &eventbridge.UpdateEventBusInput{Name: aws.String(eventDeliveryName), KmsKeyIdentifier: second}); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: second}); err != nil {
				t.Fatal(err)
			}
			closeCloud()
			if kind == "sqlite" {
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
			} else {
				backends.EventBridge = gate.Repository
			}
			gate = &busKMSRepository{Repository: backends.EventBridge}
			backends.EventBridge = gate
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			queues := clients.sqs(eventDeliveryAccount, "test", "")
			for _, name := range []string{"target", "dlq"} {
				out, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(eventDeliveryName + "-" + name)})
				if err != nil {
					t.Fatal(err)
				}
				urls[name] = out.QueueUrl
			}
			messages := eventTraceReceive(t, cloud, clients, urls["target"])
			if len(messages) != 2 {
				t.Fatalf("old-key delivery after reopen: %+v", messages)
			}
			for _, message := range messages {
				if message.Attributes["AWSTraceHeader"] != trace || !bytes.Contains([]byte(aws.ToString(message.Body)), []byte(marker)) || !bytes.Contains([]byte(aws.ToString(message.Body)), []byte("1.2300")) {
					t.Fatalf("payload or trace changed: %+v", message)
				}
			}
			cold := busKMSPut(t, clients, eventDeliveryName, "cold-disabled", trace)
			if cold.FailedEntryCount != 1 || aws.ToString(cold.Entries[0].ErrorCode) != control.Cold.ErrorCode {
				t.Fatal(cold)
			}
			events = eventDeliveryClient(clients, eventDeliveryAccount)
			_, readErr := events.DescribeRule(t.Context(), &eventbridge.DescribeRuleInput{Name: aws.String(eventDeliveryName), EventBusName: aws.String(eventDeliveryName)})
			assertAPIError(t, readErr, control.Configuration.Code)
			keys = clients.kms(eventDeliveryAccount, "test", "")
			if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: second}); err != nil {
				t.Fatal(err)
			}
			warm := busKMSPut(t, clients, eventDeliveryName, "warm-before-disable", trace)
			if warm.FailedEntryCount != 0 {
				t.Fatal(warm)
			}
			if messages := eventTraceReceive(t, cloud, clients, urls["target"]); len(messages) != 2 {
				t.Fatalf("warm delivery: %+v", messages)
			}
			gate.paused.Store(true)
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: second}); err != nil {
				t.Fatal(err)
			}
			pending := busKMSPut(t, clients, eventDeliveryName, "warm-accepted-after-disable", trace)
			if pending.FailedEntryCount != 0 {
				t.Fatal(pending)
			}
			gate.paused.Store(false)
			dead := eventTraceReceive(t, cloud, clients, urls["dlq"])
			if len(dead) != 1 {
				t.Fatalf("expected one bus DLQ for fanout: %+v", dead)
			}
			if len(dead[0].MessageAttributes) != len(fixture.Attributes) {
				t.Fatal(dead[0].MessageAttributes)
			}
			for name, expected := range fixture.Attributes {
				got := dead[0].MessageAttributes[name]
				if aws.ToString(got.StringValue) != expected.StringValue || aws.ToString(got.DataType) != expected.DataType {
					t.Fatalf("native DLQ attribute %s: %+v", name, got)
				}
			}
			var encrypted struct {
				Source     string
				DetailType string `json:"detail-type"`
				Detail     map[string]string
			}
			if err := json.Unmarshal([]byte(aws.ToString(dead[0].Body)), &encrypted); err != nil {
				t.Fatal(err)
			}
			ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Detail["encrypted-payload"])
			if err != nil || len(ciphertext) < 3 || !bytes.Equal(ciphertext[:3], []byte{2, 4, 0x78}) || encrypted.Source != "aws.events" || encrypted.DetailType != "Encrypted Events" || encrypted.Detail["kms-key-arn"] != aws.ToString(second) || encrypted.Detail["event-bus-arn"] != eventDeliveryBusARN {
				t.Fatalf("native bus DLQ envelope: %+v %v", encrypted, err)
			}
			if dead[0].Attributes["AWSTraceHeader"] != trace {
				t.Fatal("bus DLQ lost transport trace")
			}
			if messages := eventTraceReceive(t, cloud, clients, urls["target"]); len(messages) != 0 {
				t.Fatalf("denied event reached targets: %+v", messages)
			}
			if err := source.Advance(30 * time.Second); err != nil {
				t.Fatal(err)
			}
			expired := busKMSPut(t, clients, eventDeliveryName, "expired-disabled", trace)
			if expired.FailedEntryCount != 1 || aws.ToString(expired.Entries[0].ErrorCode) != control.Cold.ErrorCode {
				t.Fatal(expired)
			}
			if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: second}); err != nil {
				t.Fatal(err)
			}
			recovered := busKMSPut(t, clients, eventDeliveryName, "recovered", trace)
			if recovered.FailedEntryCount != 0 {
				t.Fatal(recovered)
			}
			if messages := eventTraceReceive(t, cloud, clients, urls["target"]); len(messages) != 2 {
				t.Fatalf("key recovery: %+v", messages)
			}
			// A trusted first-party producer still joins its original transaction:
			// customer CMK failure must not roll back this unrelated source event.
			events = eventDeliveryClient(clients, eventDeliveryAccount)
			if _, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String(eventDeliveryName), EventBusName: aws.String(eventDeliveryName), EventPattern: aws.String(`{"source":["aws.s3"]}`)}); err != nil {
				t.Fatal(err)
			}
			publisher := service.ServicePublisher{Repository: backends.EventBridge, Events: backends.Journal, Clock: source}
			publish := func(id string) {
				t.Helper()
				if err := backends.EventBridge.Update(t.Context(), func(tx domain.Transaction) error {
					return publisher.PublishEvent(tx.Context(), service.EventRecord{ID: id, Bus: service.BusKey{Scope: service.Scope{Partition: "aws", Account: eventDeliveryAccount, Region: "us-east-1"}, Name: eventDeliveryName}, Source: "aws.s3", DetailType: "Object Created", Detail: `{"service":"independent"}`, Account: eventDeliveryAccount, Time: source.Now()})
				}); err != nil {
					t.Fatal(err)
				}
			}
			publish("service-owned-enabled")
			if messages := eventTraceReceive(t, cloud, clients, urls["target"]); len(messages) != 2 {
				t.Fatalf("AWS service event did not reach target: %+v", messages)
			}
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: second}); err != nil {
				t.Fatal(err)
			}
			publish("service-owned-disabled")
			if messages := eventTraceReceive(t, cloud, clients, urls["target"]); len(messages) != 0 {
				t.Fatalf("encrypted rule matched with denied key: %+v", messages)
			}
			if err := backends.EventBridge.View(t.Context(), func(r domain.Reader) error {
				event, err := r.Event("service-owned-disabled")
				if err != nil {
					return err
				}
				if event.Detail != `{"service":"independent"}` || len(event.Payload.DataKey) != 0 {
					t.Fatalf("service event used customer payload key: %+v", event)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEventBridgeBusKMSForwardReplaySDK(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			backends := storage.NewMemory()
			if kind == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "forward-kms.sqlite"))
			}
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			urls := provisionEventDelivery(t, clients)
			for _, sink := range []string{"target", "dlq"} {
				setEventDeliveryPolicy(t, clients.sqs(eventDeliveryAccount, "test", ""), urls[sink], sink, nil)
			}
			events := eventDeliveryClient(clients, eventDeliveryAccount)
			originKey, receiverKey := busKMSKey(t, clients), busKMSKey(t, clients)
			if _, err := events.UpdateEventBus(t.Context(), &eventbridge.UpdateEventBusInput{Name: aws.String(eventDeliveryName), KmsKeyIdentifier: originKey}); err != nil {
				t.Fatal(err)
			}
			destination := "kms-receiver"
			bus, err := events.CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: &destination, KmsKeyIdentifier: receiverKey})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: &destination, EventBusName: &destination, EventPattern: aws.String(fmt.Sprintf(`{"source":[%q]}`, eventDeliveryName))}); err != nil {
				t.Fatal(err)
			}
			targets, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: &destination, EventBusName: &destination, Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: aws.String(eventDeliveryQueueARN("target"))}}})
			if err != nil || targets.FailedEntryCount != 0 {
				t.Fatal(targets, err)
			}
			identities := clients.iam(eventDeliveryAccount, "test", "")
			role, err := identities.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("encrypted-forward"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identities.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("receiver"), PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"events:PutEvents","Resource":%q}]}`, aws.ToString(bus.EventBusArn)))}); err != nil {
				t.Fatal(err)
			}
			targets, err = events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(eventDeliveryName), EventBusName: aws.String(eventDeliveryName), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: bus.EventBusArn, RoleArn: role.Role.Arn, DeadLetterConfig: &eventtypes.DeadLetterConfig{Arn: aws.String(eventDeliveryQueueARN("dlq"))}}}})
			if err != nil || targets.FailedEntryCount != 0 {
				t.Fatal(targets, err)
			}
			archive, err := events.CreateArchive(t.Context(), &eventbridge.CreateArchiveInput{ArchiveName: aws.String("receiver-archive"), EventSourceArn: bus.EventBusArn})
			if err != nil {
				t.Fatal(err)
			}
			trace := "Root=1-6ab2832c-0123456789abcdef01234567;Parent=0123456789abcdef;Sampled=0"
			accepted := busKMSPut(t, clients, eventDeliveryName, "forward-encrypted", trace)
			if accepted.FailedEntryCount != 0 {
				t.Fatal(accepted)
			}
			messages := eventTraceReceive(t, cloud, clients, urls["target"])
			if len(messages) != 1 || messages[0].Attributes["AWSTraceHeader"] != trace || !bytes.Contains([]byte(aws.ToString(messages[0].Body)), []byte("forward-encrypted")) {
				t.Fatalf("encrypted forward: %+v", messages)
			}
			replay, err := events.StartReplay(t.Context(), &eventbridge.StartReplayInput{ReplayName: aws.String("encrypted-replay"), EventSourceArn: archive.ArchiveArn, EventStartTime: aws.Time(source.Now().Add(-time.Second)), EventEndTime: aws.Time(source.Now().Add(time.Second)), Destination: &eventtypes.ReplayDestination{Arn: bus.EventBusArn}})
			if err != nil || replay.State != "STARTING" {
				t.Fatal(replay, err)
			}
			if err := source.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			messages = eventTraceReceive(t, cloud, clients, urls["target"])
			if len(messages) != 1 || messages[0].Attributes["AWSTraceHeader"] != "" || !bytes.Contains([]byte(aws.ToString(messages[0].Body)), []byte(`"replay-name":"encrypted-replay"`)) || !bytes.Contains([]byte(aws.ToString(messages[0].Body)), []byte("forward-encrypted")) {
				t.Fatalf("encrypted replay: %+v", messages)
			}
			keys := clients.kms(eventDeliveryAccount, "test", "")
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: receiverKey}); err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(30 * time.Second); err != nil {
				t.Fatal(err)
			}
			denied := busKMSPut(t, clients, eventDeliveryName, "receiver-denied", trace)
			if denied.FailedEntryCount != 0 {
				t.Fatal(denied)
			}
			if messages := eventTraceReceive(t, cloud, clients, urls["dlq"]); len(messages) != 1 || !bytes.Contains([]byte(aws.ToString(messages[0].Body)), []byte("receiver-denied")) {
				t.Fatalf("forward failure DLQ: %+v", messages)
			}
			if messages := eventTraceReceive(t, cloud, clients, urls["target"]); len(messages) != 0 {
				t.Fatalf("disabled receiver delivered: %+v", messages)
			}
			if _, err := events.UpdateEventBus(t.Context(), &eventbridge.UpdateEventBusInput{Name: &destination, KmsKeyIdentifier: aws.String("")}); err == nil {
				t.Fatal("reset ignored disabled old key")
			}
			if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: receiverKey}); err != nil {
				t.Fatal(err)
			}
			reset, err := events.UpdateEventBus(t.Context(), &eventbridge.UpdateEventBusInput{Name: &destination, KmsKeyIdentifier: aws.String("")})
			if err != nil || aws.ToString(reset.KmsKeyIdentifier) != "" {
				t.Fatal(reset, err)
			}
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: receiverKey}); err != nil {
				t.Fatal(err)
			}
			plain := busKMSPut(t, clients, eventDeliveryName, "receiver-reset", trace)
			if plain.FailedEntryCount != 0 {
				t.Fatal(plain)
			}
			if messages := eventTraceReceive(t, cloud, clients, urls["target"]); len(messages) != 1 || !bytes.Contains([]byte(aws.ToString(messages[0].Body)), []byte("receiver-reset")) {
				t.Fatalf("reset forward: %+v", messages)
			}
		})
	}
}
