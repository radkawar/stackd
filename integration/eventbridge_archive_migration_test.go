package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

// Replay the measured key controls through SDK clients, with local service time
// replacing AWS propagation delays. Retained delivery, rather than configuration
// echo, proves that rewrapping completed before an old key becomes unavailable.
func TestEventBridgeArchiveKeyMigration(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/archive_key_transitions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Source       struct{ Account string }
		Observations []struct {
			Label  string
			Input  json.RawMessage
			Output struct{ State string }
		}
	}
	ebTargetRoleDecode(t, data, &fixture)
	var keyInput kms.CreateKeyInput
	states := map[string]string{}
	for _, row := range fixture.Observations {
		if row.Label == "key-0" {
			ebTargetRoleDecode(t, row.Input, &keyInput)
		}
		states[row.Label] = row.Output.State
	}
	if keyInput.Policy == nil || states["update-replace"] == "" || states["update-reset"] == "" {
		t.Fatal("missing native archive transition controls")
	}
	denialData, err := os.ReadFile("../testdata/aws/eventbridge/archive_key_transition_denials.json")
	if err != nil {
		t.Fatal(err)
	}
	var denial struct {
		Observations []struct {
			Label  string
			Output struct{ State string }
		}
	}
	ebTargetRoleDecode(t, denialData, &denial)
	failureStates := map[string]eventtypes.ArchiveState{}
	for _, row := range denial.Observations {
		if row.Output.State == "UPDATE_FAILED" {
			failureStates[row.Label] = eventtypes.ArchiveState(row.Output.State)
		}
	}
	if failureStates["poll-replace"] == "" || failureStates["poll-reset"] == "" {
		t.Fatal("missing native failed migration controls")
	}
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "archive-migration.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if kind == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			epoch := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
			source := clock.NewManual(epoch)
			cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
			events := eventDeliveryClient(clients, fixture.Source.Account)
			keys := clients.kms(fixture.Source.Account, "test", "")
			queues := clients.sqs(fixture.Source.Account, "test", "")
			var keyARNs []string
			for range 3 {
				key, err := keys.CreateKey(t.Context(), &keyInput)
				if err != nil {
					t.Fatal(err)
				}
				keyARNs = append(keyARNs, aws.ToString(key.KeyMetadata.Arn))
			}
			bus, err := events.CreateEventBus(t.Context(), &eventbridge.CreateEventBusInput{Name: aws.String("migration"), KmsKeyIdentifier: &keyARNs[2]})
			if err != nil {
				t.Fatal(err)
			}
			q, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("migration")})
			if err != nil {
				t.Fatal(err)
			}
			queueARN := "arn:aws:sqs:us-east-1:" + fixture.Source.Account + ":migration"
			queuePolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q}]}`, queueARN)
			if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: q.QueueUrl, Attributes: map[string]string{"Policy": queuePolicy}}); err != nil {
				t.Fatal(err)
			}
			pattern := `{"source":["stackd.archive.migration"]}`
			if _, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("collector"), EventBusName: aws.String("migration"), EventPattern: &pattern}); err != nil {
				t.Fatal(err)
			}
			if out, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("collector"), EventBusName: aws.String("migration"), Targets: []eventtypes.Target{{Id: aws.String("q"), Arn: &queueARN}}}); err != nil || out.FailedEntryCount != 0 {
				t.Fatal(out, err)
			}
			archive, err := events.CreateArchive(t.Context(), &eventbridge.CreateArchiveInput{ArchiveName: aws.String("migration"), EventSourceArn: bus.EventBusArn, KmsKeyIdentifier: &keyARNs[0], EventPattern: &pattern})
			if err != nil {
				t.Fatal(err)
			}
			put := func(phase string) {
				t.Helper()
				// An older customer timestamp must not evade migration selection.
				out, err := events.PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{EventBusName: aws.String("migration"), Source: aws.String("stackd.archive.migration"), DetailType: aws.String("migration"), Detail: aws.String(fmt.Sprintf(`{"phase":%q}`, phase)), Time: aws.Time(epoch.Add(-time.Minute))}}})
				if err != nil || out.FailedEntryCount != 0 {
					t.Fatal(out, err)
				}
			}
			setPolicy := func(arn string, deny bool) {
				t.Helper()
				var policy map[string]any
				ebTargetRoleDecode(t, []byte(aws.ToString(keyInput.Policy)), &policy)
				if deny {
					policy["Statement"] = append(policy["Statement"].([]any), map[string]any{"Effect": "Deny", "Principal": map[string]string{"Service": "events.amazonaws.com"}, "Action": "kms:ReEncryptFrom", "Resource": "*"})
				}
				body, err := json.Marshal(policy)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: &arn, PolicyName: aws.String("default"), Policy: aws.String(string(body))}); err != nil {
					t.Fatal(err)
				}
			}
			put("before")
			trailNativeDrain(t, cloud)
			_ = snsAdmissionReceive(t, cloud, queues, q.QueueUrl)
			wantPhases := map[string]bool{"before": true}
			for i, change := range []struct{ name, destination string }{{"replace", keyARNs[1]}, {"reset", ""}} {
				setPolicy(keyARNs[i], true)
				updated, err := events.UpdateArchive(t.Context(), &eventbridge.UpdateArchiveInput{ArchiveName: aws.String("migration"), KmsKeyIdentifier: &change.destination})
				if err != nil || string(updated.State) != states["update-"+change.name] {
					t.Fatal("native migration admission", updated, err)
				}
				put(change.name)
				wantPhases[change.name] = true
				advanceClock(t, source, time.Second)
				trailNativeDrain(t, cloud)
				_ = snsAdmissionReceive(t, cloud, queues, q.QueueUrl)
				pending, err := events.DescribeArchive(t.Context(), &eventbridge.DescribeArchiveInput{ArchiveName: aws.String("migration")})
				if err != nil || pending.State != failureStates["poll-"+change.name] || aws.ToString(pending.KmsKeyIdentifier) != keyARNs[i] || pending.EventCount != int64(len(wantPhases)) {
					t.Fatal("denied rewrap lost retained work", pending, err)
				}
				if (pending.EventPattern == nil) != (change.name == "replace") {
					t.Fatal("failed update pattern visibility differs from native", pending)
				}
				closeCloud()
				closeDB()
				if kind == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
				cloud, clients, closeCloud = startEventDeliveryCloud(t, backends, source)
				events, keys = eventDeliveryClient(clients, fixture.Source.Account), clients.kms(fixture.Source.Account, "test", "")
				setPolicy(keyARNs[i], false)
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, cloud)
				failed, err := events.DescribeArchive(t.Context(), &eventbridge.DescribeArchiveInput{ArchiveName: aws.String("migration")})
				if err != nil || failed.State != eventtypes.ArchiveStateUpdateFailed {
					t.Fatal("failed migration changed without a retry", failed, err)
				}
				retry, err := events.UpdateArchive(t.Context(), &eventbridge.UpdateArchiveInput{ArchiveName: aws.String("migration"), KmsKeyIdentifier: &change.destination, EventPattern: &pattern})
				if err != nil || retry.State != eventtypes.ArchiveStateUpdating {
					t.Fatal("explicit key migration retry", retry, err)
				}
				// Reopen again with successful work pending, not just a terminal
				// failure, to prove that the scheduler owns durable progress.
				closeCloud()
				closeDB()
				if kind == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
				cloud, clients, closeCloud = startEventDeliveryCloud(t, backends, source)
				events, keys, queues = eventDeliveryClient(clients, fixture.Source.Account), clients.kms(fixture.Source.Account, "test", ""), clients.sqs(fixture.Source.Account, "test", "")
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, cloud)
				settled, err := events.DescribeArchive(t.Context(), &eventbridge.DescribeArchiveInput{ArchiveName: aws.String("migration")})
				if err != nil || settled.State != eventtypes.ArchiveStateEnabled || aws.ToString(settled.KmsKeyIdentifier) != change.destination {
					t.Fatal("migration did not recover after reopening", settled, err)
				}
				if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: &keyARNs[i]}); err != nil {
					t.Fatal(err)
				}
				name := "after-" + change.name
				if _, err := events.StartReplay(t.Context(), &eventbridge.StartReplayInput{ReplayName: &name, EventSourceArn: archive.ArchiveArn, EventStartTime: aws.Time(epoch.Add(-2 * time.Minute)), EventEndTime: aws.Time(epoch), Destination: &eventtypes.ReplayDestination{Arn: bus.EventBusArn}}); err != nil {
					t.Fatal(err)
				}
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, cloud)
				progress, err := events.DescribeReplay(t.Context(), &eventbridge.DescribeReplayInput{ReplayName: &name})
				if err != nil || progress.State != eventtypes.ReplayStateCompleted {
					t.Fatal("retained replay still depends on old key", progress, err)
				}
				got := map[string]bool{}
				for _, message := range snsAdmissionReceive(t, cloud, queues, q.QueueUrl) {
					var body struct {
						Replay string `json:"replay-name"`
						Detail struct{ Phase string }
					}
					ebTargetRoleDecode(t, []byte(aws.ToString(message.Body)), &body)
					if body.Replay != name || got[body.Detail.Phase] {
						t.Fatal("wrong or duplicate migrated replay", body)
					}
					got[body.Detail.Phase] = true
				}
				if !reflect.DeepEqual(got, wantPhases) {
					t.Fatalf("retained replay got %v, want %v", got, wantPhases)
				}
				busState, err := events.DescribeEventBus(t.Context(), &eventbridge.DescribeEventBusInput{Name: aws.String("migration")})
				if err != nil || aws.ToString(busState.KmsKeyIdentifier) != keyARNs[2] {
					t.Fatal("archive transition changed bus encryption", busState, err)
				}
			}
			// Delete a pending migration, then recreate the same public ARN.
			// Neither its retained work nor its accepted replay may cross the
			// archive incarnation boundary.
			if _, err := events.UpdateArchive(t.Context(), &eventbridge.UpdateArchiveInput{ArchiveName: aws.String("migration"), KmsKeyIdentifier: &keyARNs[2]}); err != nil {
				t.Fatal(err)
			}
			if _, err := events.StartReplay(t.Context(), &eventbridge.StartReplayInput{ReplayName: aws.String("deleted-source"), EventSourceArn: archive.ArchiveArn, EventStartTime: aws.Time(epoch.Add(-2 * time.Minute)), EventEndTime: aws.Time(epoch), Destination: &eventtypes.ReplayDestination{Arn: bus.EventBusArn}}); err != nil {
				t.Fatal(err)
			}
			if _, err := events.DeleteArchive(t.Context(), &eventbridge.DeleteArchiveInput{ArchiveName: aws.String("migration")}); err != nil {
				t.Fatal(err)
			}
			if _, err := events.CreateArchive(t.Context(), &eventbridge.CreateArchiveInput{ArchiveName: aws.String("migration"), EventSourceArn: bus.EventBusArn, EventPattern: &pattern}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			deleted, err := events.DescribeReplay(t.Context(), &eventbridge.DescribeReplayInput{ReplayName: aws.String("deleted-source")})
			if err != nil || deleted.State != eventtypes.ReplayStateFailed {
				t.Fatal("accepted replay crossed archive incarnations", deleted, err)
			}
			fresh, err := events.DescribeArchive(t.Context(), &eventbridge.DescribeArchiveInput{ArchiveName: aws.String("migration")})
			if err != nil || fresh.EventCount != 0 || fresh.KmsKeyIdentifier != nil {
				t.Fatal("pending migration crossed archive incarnations", fresh, err)
			}
			if messages := snsAdmissionReceive(t, cloud, queues, q.QueueUrl); len(messages) != 0 {
				t.Fatal("deleted archive delivered retained events", messages)
			}
		})
	}
}
