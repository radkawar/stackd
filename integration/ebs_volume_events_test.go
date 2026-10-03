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
	"stackd/journal"
	"stackd/storage"
)

type ebsVolumeConformanceFixture struct {
	ebsCopyFixture
	EventBridge struct {
		Events []struct{ Event json.RawMessage }
	}
	CloudTrail struct {
		Events []struct {
			Label string `json:"call_label"`
			Event map[string]any
		}
	}
}

func ebsVolumeCallRows(t *testing.T, v *ebsVolumeReplay, backends **storage.Backends, row ebsNativeCall) []journal.Event {
	t.Helper()
	before, err := (*backends).Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var sequence int64
	if len(before) != 0 {
		sequence = before[len(before)-1].Sequence
	}
	v.call(t, row)
	if row.Operation == "CreateVolume" && row.Code == "Success" {
		// Native KMS work is asynchronous. Observe the admitted volume's
		// service work before comparing its complete grant/decrypt audit.
		v.clock.Advance(ebsdomain.VolumeCreationDelay)
		trailNativeDrain(t, v.clients.server.Config.Handler.(*stackd.Stack))
	}
	observed, err := (*backends).Journal.Read(t.Context(), sequence, 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range observed {
		call := event.APICallCompleted
		if call == nil || call.EventName != row.Operation || call.EventSource != row.Service+".amazonaws.com" || event.AccountID != v.account(row) {
			continue
		}
		if found {
			t.Fatalf("duplicate caller outcome for %s", row.Label)
		}
		found = true
		v.bind(t, row.RequestID, event.RequestID)
	}
	if !found {
		t.Fatalf("missing durable caller outcome for %s", row.Label)
	}
	return observed
}

// Compare actual native envelopes after durable EventBridge -> SQS delivery,
// including the separate delete notification caused by a failed creation.
func TestEBSVolumeNativeNotifications(t *testing.T) {
	var native ebsVolumeConformanceFixture
	awsReadFixture(t, "ebs/volume_data.json", &native)
	var modification ebsVolumeConformanceFixture
	awsReadFixture(t, "ebs/volume_controls_events.json", &modification)
	native.Calls = append(native.Calls, modification.Calls...)
	native.EventBridge.Events = append(native.EventBridge.Events, modification.EventBridge.Events...)
	rows := map[string]ebsNativeCall{}
	for _, row := range native.Calls {
		rows[row.Label] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var cloud *stackd.Stack
			var backends *storage.Backends
			v := newEBSVolumeReplay(t, native.ebsCopyFixture, backend, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				backends = config.Storage
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			invoke := func(label string) {
				t.Helper()
				row, ok := rows[label]
				if !ok {
					t.Fatalf("missing native volume notification call %q", label)
				}
				ebsVolumeCallRows(t, v, &backends, row)
				if row.Operation == "ModifySnapshotAttribute" {
					v.clock.Advance(ebsdomain.SharingDelay)
				}
			}
			for _, label := range []string{"owner-target-key", "disabled-target-key", "disable-target-key", "plain-source", "plain-source-put", "plain-source-complete", "plain-source-snapshot-state-1", "plain-share"} {
				invoke(label)
			}
			invoke("events-source")
			var modified struct{ VolumeID string }
			awsDecodeJSON(t, rows["events-source"].Output, &modified)
			invoke("available-" + modified.VolumeID + "-1")
			trailNativeDrain(t, cloud)
			type route struct{ account, region, name, pattern string }
			pattern := `{"source":["aws.ec2"],"detail-type":["EBS Volume Notification","EBS Snapshot Notification"],"detail":{"event":["createVolume","deleteVolume","createSnapshot","modifyVolume"]}}`
			routes := []route{
				{"111111111111", "us-east-1", "volume-owner", pattern},
				{"222222222222", "us-east-1", "volume-member", pattern},
				{"111111111111", "us-west-2", "volume-other-region", pattern},
				{"222222222222", "us-east-1", "volume-unmatched", `{"source":["aws.ec2"],"detail":{"event":["copySnapshot"]}}`},
			}
			queues := func(route route) *sqs.Client {
				return sqs.New(sqs.Options{Region: route.region, BaseEndpoint: aws.String(v.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(route.account, "test", ""), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
			}
			for _, route := range routes {
				client := queues(route)
				queue, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(route.name)})
				if err != nil {
					t.Fatal(err)
				}
				rules := eventbridge.New(eventbridge.Options{Region: route.region, BaseEndpoint: aws.String(v.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(route.account, "test", ""), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
				rule, err := rules.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String(route.name), EventPattern: aws.String(route.pattern)})
				if err != nil {
					t.Fatal(err)
				}
				arn := "arn:aws:sqs:" + route.region + ":" + route.account + ":" + route.name
				policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, arn, aws.ToString(rule.RuleArn))
				if _, err := client.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
					t.Fatal(err)
				}
				out, err := rules.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(route.name), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: aws.String(arn)}}})
				if err != nil || out.FailedEntryCount != 0 {
					t.Fatalf("volume notification target: %+v %v", out, err)
				}
			}
			selected := map[string]bool{}
			for _, label := range []string{"plain-default", "member-plain", "plain-custom-encrypted", "invalid-key", "disabled-key"} {
				invoke(label)
				var out struct{ VolumeID string }
				awsDecodeJSON(t, rows[label].Output, &out)
				selected[out.VolumeID] = true
				invoke(label + "-volume-state-0")
			}
			invoke("plain-default-snapshot")
			var snapshot struct{ SnapshotID string }
			awsDecodeJSON(t, rows["plain-default-snapshot"].Output, &snapshot)
			selected[snapshot.SnapshotID] = true
			v.clock.Advance(ebsdomain.CompletionDelay)
			for _, label := range []string{"plain-default", "member-plain", "plain-custom-encrypted"} {
				var volume struct{ VolumeID string }
				awsDecodeJSON(t, rows[label].Output, &volume)
				invoke("cleanup-delete-" + volume.VolumeID)
			}
			v.clock.Advance(ebsdomain.VolumeDeletionDelay)
			selected[modified.VolumeID] = true
			invoke("events-modify-grow")
			invoke("events-modify-initial-state")
			invoke("events-modify-final-state")
			wanted := map[string]map[string]any{}
			for _, row := range native.EventBridge.Events {
				var event map[string]any
				awsDecodeJSON(t, row.Event, &event)
				id, action := ebsVolumeEventIdentity(t, event)
				if selected[id] && (action == "createVolume" || action == "deleteVolume" || action == "createSnapshot" || action == "modifyVolume") {
					wanted[action+"/"+event["detail"].(map[string]any)["result"].(string)+"/"+v.bindings[id]] = event
				}
			}
			// Five creates, two automatic deletes, three explicit deletes,
			// one snapshot and two modification phases are native positives.
			if len(wanted) != 13 {
				t.Fatalf("native volume event selection = %d, want 13", len(wanted))
			}
			seen := map[string]string{}
			receive := func(repeated bool) {
				t.Helper()
				v.clients = v.reopen()
				trailNativeDrain(t, cloud)
				for _, route := range routes {
					client := queues(route)
					queue, err := client.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(route.name)})
					if err != nil {
						t.Fatal(err)
					}
					for range 100 {
						messages, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
						if err != nil {
							t.Fatal(err)
						}
						if len(messages.Messages) == 0 {
							break
						}
						for _, message := range messages.Messages {
							body := aws.ToString(message.Body)
							var actual map[string]any
							awsDecodeJSON(t, []byte(body), &actual)
							id, action := ebsVolumeEventIdentity(t, actual)
							key := action + "/" + actual["detail"].(map[string]any)["result"].(string) + "/" + id
							expected := wanted[key]
							if expected == nil || route.name == "volume-unmatched" || actual["account"] != route.account || actual["region"] != route.region {
								t.Fatalf("unexpected volume route %s: %s", route.name, body)
							}
							if previous, exists := seen[key]; exists {
								if previous != body {
									t.Fatalf("republished volume event changed identity/body: %s", body)
								}
							} else {
								if repeated {
									t.Fatalf("reopen produced a new volume event: %s", body)
								}
								ebsVolumeNormalizeEvent(t, v, expected, actual)
								ec2NetworkCompare(t, "volume-event["+key+"]", expected, actual, v.bindings)
								seen[key] = body
							}
							if _, err := client.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queue.QueueUrl, ReceiptHandle: message.ReceiptHandle}); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			}
			receive(false)
			if len(seen) != len(wanted) {
				t.Fatalf("delivered %d of %d native volume events", len(seen), len(wanted))
			}
			v.clock.Advance(time.Minute)
			receive(true)
		})
	}
}

func ebsVolumeEventIdentity(t *testing.T, event map[string]any) (string, string) {
	t.Helper()
	resources, ok := event["resources"].([]any)
	if !ok || len(resources) == 0 {
		t.Fatalf("event has no native resource: %#v", event)
	}
	arn, ok := resources[0].(string)
	if !ok {
		t.Fatal("event resource is not an ARN")
	}
	detail, ok := event["detail"].(map[string]any)
	if !ok {
		t.Fatal("event has no detail")
	}
	action, _ := detail["event"].(string)
	return arn[strings.LastIndex(arn, "/")+1:], action
}

func ebsVolumeNormalizeEvent(t *testing.T, v *ebsVolumeReplay, expected, actual map[string]any) {
	t.Helper()
	id, action := ebsVolumeEventIdentity(t, expected)
	if action == "createSnapshot" {
		ebsCopyNormalizeEvent(t, v.ebsSnapshotReplay, expected, actual)
		return
	}
	state := v.volumes[id]
	if state == nil {
		t.Fatalf("notification refers to uncreated volume %s", id)
	}
	when := state.created.Add(ebsdomain.VolumeCreationDelay)
	if action == "deleteVolume" && !state.deleted.IsZero() {
		when = state.deleted.Add(ebsdomain.VolumeDeletionDelay)
	}
	if action == "modifyVolume" {
		when = state.modified.Add(ebsdomain.VolumeModificationOptimizingDelay)
		if actual["detail"].(map[string]any)["result"] == "completed" {
			when = state.modified.Add(ebsdomain.VolumeModificationCompletionDelay)
		}
	}
	value, ok := actual["time"].(string)
	stamp, err := time.Parse(time.RFC3339Nano, value)
	if !ok || err != nil || !stamp.Equal(when.Truncate(time.Second)) {
		t.Fatalf("volume event lost lifecycle time: %v, expected %v", actual["time"], when)
	}
	expected["time"] = value
	eventID, ok := actual["id"].(string)
	if !ok || eventID == "" {
		t.Fatal("volume event lost publication identity")
	}
	v.bind(t, expected["id"].(string), eventID)
}
