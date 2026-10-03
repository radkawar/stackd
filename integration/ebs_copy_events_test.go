package stackd_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	ebsdomain "stackd/internal/services/ebs"
)

// Native EBS notifications are not CloudTrail API events. No trail is configured:
// matching destination-account/regional rules must route the original envelopes
// through durable EventBridge target work to real SQS queues after reconstruction.
func TestEBSCopySnapshotNativeNotifications(t *testing.T) {
	var native struct {
		ebsCopyFixture
		EventBridge struct {
			Events []struct{ Event json.RawMessage }
		}
	}
	awsReadFixture(t, "ebs/copy_controls.json", &native)
	rows := map[string]ebsNativeCall{}
	for _, row := range native.Calls {
		rows[row.Label] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var cloud *stackd.Stack
			r := newEBSCopyReplay(t, native.ebsCopyFixture, backend, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			type destination struct {
				account, region, name, pattern string
				count                          int
			}
			pattern := `{"source":["aws.ec2"],"detail-type":["EBS Snapshot Notification"],"detail":{"event":["copySnapshot"]}}`
			destinations := []destination{
				{"111111111111", "us-east-1", "copy-owner", pattern, 3},
				{"222222222222", "us-east-1", "copy-recipient", pattern, 2},
				{"111111111111", "us-west-2", "copy-owner-other-region", pattern, 0},
				{"222222222222", "us-west-2", "copy-recipient-other-region", pattern, 0},
				{"222222222222", "us-east-1", "copy-unmatched", `{"source":["aws.ec2"],"detail":{"event":["createSnapshot"]}}`, 0},
			}
			queueClient := func(destination destination) *sqs.Client {
				return sqs.New(sqs.Options{Region: destination.region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(destination.account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
			}
			for _, destination := range destinations {
				queues := queueClient(destination)
				queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(destination.name)})
				if err != nil {
					t.Fatal(err)
				}
				rules := eventbridge.New(eventbridge.Options{Region: destination.region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(destination.account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
				rule, err := rules.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String(destination.name), EventPattern: aws.String(destination.pattern)})
				if err != nil {
					t.Fatal(err)
				}
				arn := "arn:aws:sqs:" + destination.region + ":" + destination.account + ":" + destination.name
				policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, arn, aws.ToString(rule.RuleArn))
				if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
					t.Fatal(err)
				}
				accepted, err := rules.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(destination.name), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: aws.String(arn)}}})
				if err != nil || accepted.FailedEntryCount != 0 {
					t.Fatalf("register copy notification target: %+v %v", accepted, err)
				}
			}
			copied := map[string]bool{}
			for _, label := range []string{
				"source", "pending-source-actual", "source-complete", "source-state-1", "source-readiness-12",
				"completed-default-description", "completion-duration-normal", "member-private-source-actual",
				"share-source", "member-shared-source-actual",
				"initial-pending-source-actual", "initial-completed-default-description", "initial-completion-duration-normal",
				"initial-member-private-source-actual", "initial-member-shared-source-actual",
			} {
				row, ok := rows[label]
				if !ok {
					t.Fatalf("missing native copy notification setup %q", label)
				}
				if !t.Run(label, func(t *testing.T) { r.call(t, row) }) {
					return
				}
				if row.Operation == "ModifySnapshotAttribute" {
					r.clock.Advance(ebsdomain.SharingDelay)
				}
				if row.Operation == "CopySnapshot" {
					var output struct{ SnapshotID string }
					awsDecodeJSON(t, row.Output, &output)
					copied[output.SnapshotID] = true
				}
			}
			wanted := map[string]map[string]any{}
			for _, captured := range native.EventBridge.Events {
				var document map[string]any
				awsDecodeJSON(t, captured.Event, &document)
				detail, ok := document["detail"].(map[string]any)
				if !ok {
					continue
				}
				arn, _ := detail["snapshot_id"].(string)
				id := arn[strings.LastIndex(arn, "/")+1:]
				if copied[id] {
					wanted[r.bindings[id]] = document
				}
			}
			if len(wanted) != len(copied) {
				t.Fatalf("native notification evidence covers %d of %d selected copies", len(wanted), len(copied))
			}
			// Neither lifecycle publication nor accepted target work may depend on
			// process-local callbacks. Delivery starts only after this reconstruction.
			r.clients = r.reopen()
			trailNativeDrain(t, cloud)
			seen := map[string]struct{ eventID, body string }{}
			receive := func(destination destination, initial bool) {
				t.Helper()
				queues := queueClient(destination)
				queue, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(destination.name)})
				if err != nil {
					t.Fatal(err)
				}
				delivered := map[string]bool{}
				for range 100 {
					messages, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
					if err != nil {
						t.Fatal(err)
					}
					if len(messages.Messages) == 0 {
						if initial && len(delivered) != destination.count {
							t.Fatalf("notification route %s/%s received %d distinct copies, want %d", destination.account, destination.region, len(delivered), destination.count)
						}
						return
					}
					for _, message := range messages.Messages {
						body := aws.ToString(message.Body)
						var actual map[string]any
						awsDecodeJSON(t, []byte(body), &actual)
						detail, ok := actual["detail"].(map[string]any)
						if !ok {
							t.Fatalf("notification lacks native detail: %#v", actual)
						}
						arn, _ := detail["snapshot_id"].(string)
						id := arn[strings.LastIndex(arn, "/")+1:]
						expected := wanted[id]
						if expected == nil || destination.count == 0 || actual["account"] != destination.account || actual["region"] != destination.region {
							t.Fatalf("unexpected notification or destination scope: %#v", actual)
						}
						eventID, _ := actual["id"].(string)
						if previous, exists := seen[id]; exists {
							// EventBridge/SQS delivery is at least once across reopen
							// and acknowledgement boundaries. The native publication
							// identity and body, not its number of receipts, are stable.
							if previous.eventID != eventID || previous.body != body {
								t.Fatalf("snapshot republished a different notification: old %+v, new %s", previous, body)
							}
						} else {
							if !initial {
								t.Fatalf("reconstruction published a new snapshot event: %s", body)
							}
							ebsCopyNormalizeEvent(t, r, expected, actual)
							ec2NetworkCompare(t, "notification["+id+"]", expected, actual, r.bindings)
							seen[id] = struct{ eventID, body string }{eventID, body}
						}
						delivered[id] = true
						if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queue.QueueUrl, ReceiptHandle: message.ReceiptHandle}); err != nil {
							t.Fatal(err)
						}
					}
				}
				t.Fatalf("notification route %s/%s did not quiesce", destination.account, destination.region)
			}
			for _, destination := range destinations {
				receive(destination, true)
			}
			if len(seen) != len(wanted) {
				t.Fatalf("missing native notifications: delivered %d of %d", len(seen), len(wanted))
			}
			r.clients = r.reopen()
			r.clock.Advance(time.Minute)
			trailNativeDrain(t, cloud)
			for _, destination := range destinations {
				receive(destination, false)
			}
		})
	}
}

func ebsCopyNormalizeEvent(t *testing.T, r *ebsSnapshotReplay, expected, actual map[string]any) {
	t.Helper()
	before := expected["detail"].(map[string]any)
	after := actual["detail"].(map[string]any)
	arn := before["snapshot_id"].(string)
	state := r.snapshots[arn[strings.LastIndex(arn, "/")+1:]]
	if state == nil {
		t.Fatal("native notification has no replayed snapshot")
	}
	for _, part := range []struct {
		before, after map[string]any
		key           string
		at            time.Time
	}{
		{expected, actual, "time", state.sealed.Add(ebsdomain.CompletionDelay).Truncate(time.Second)},
		{before, after, "startTime", state.created},
		{before, after, "endTime", state.sealed.Add(ebsdomain.CompletionDelay)},
		{before, after, "completionDurationStartTime", state.created},
	} {
		if _, present := part.before[part.key]; !present {
			continue
		}
		value, ok := part.after[part.key].(string)
		stamp, err := time.Parse(time.RFC3339Nano, value)
		if !ok || err != nil || stamp.Sub(part.at).Abs() > time.Millisecond {
			t.Fatalf("notification %s lost its lifecycle time: %v, want %v", part.key, part.after[part.key], part.at)
		}
		part.before[part.key] = value
	}
	id, ok := actual["id"].(string)
	if !ok || id == "" {
		t.Fatalf("invalid notification identity: %#v", actual)
	}
	r.bind(t, expected["id"].(string), id)
}
