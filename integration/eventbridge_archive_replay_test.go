package stackd_test

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"

	"stackd/clock"
	"stackd/storage"
)

type ebArchiveReplayReceipt struct {
	Queue string
	Body  map[string]any
}

type ebArchiveReplayStep struct {
	Name           string
	Call           *ebTargetRoleObservation
	AdvanceSeconds int
	Drain          bool
	Receipts       *[]ebArchiveReplayReceipt
}

type ebArchiveReplayRun struct {
	Name  string
	Start time.Time
	Steps []ebArchiveReplayStep
}

// Captured receipt IDs are symbols, not ignored fields: originals bind to the
// PutEvents response, replay occurrences must be fresh, and fan-out must share
// one ID. Everything else in the public event envelope compares exactly.
func ebArchiveReplayReceipts(t *testing.T, r *ebTargetRoleReplay, expected []ebArchiveReplayReceipt, ids, owners map[string]string) {
	t.Helper()
	queues := r.clients.sqs(r.account, "test", "")
	remaining := slices.Clone(expected)
	for queue, url := range r.queues {
		for _, message := range snsAdmissionReceive(t, r.cloud, queues, url) {
			var got map[string]any
			ebTargetRoleDecode(t, []byte(aws.ToString(message.Body)), &got)
			detail, _ := got["detail"].(map[string]any)
			index := slices.IndexFunc(remaining, func(want ebArchiveReplayReceipt) bool {
				wantDetail, _ := want.Body["detail"].(map[string]any)
				return queue == want.Queue && got["replay-name"] == want.Body["replay-name"] && detail["marker"] == wantDetail["marker"]
			})
			if index < 0 {
				t.Fatalf("unexpected receipt on %s (matched by replay-name + detail.marker): %+v", queue, got)
			}
			want := maps.Clone(remaining[index].Body)
			nativeID, _ := want["id"].(string)
			localID, _ := got["id"].(string)
			if nativeID == "" || localID == "" {
				t.Fatalf("receipt omitted event identity: got=%+v want=%+v", got, want)
			}
			if bound := ids[nativeID]; bound != "" && bound != localID {
				t.Fatalf("one accepted occurrence changed ID across deliveries: %s != %s", bound, localID)
			}
			if owner := owners[localID]; owner != "" && owner != nativeID {
				t.Fatalf("replay reused another accepted occurrence's ID: %s", localID)
			}
			ids[nativeID], owners[localID] = localID, nativeID
			want["id"] = localID
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("queue %s changed native envelope: got=%+v want=%+v", queue, got, want)
			}
			remaining = slices.Delete(remaining, index, index+1)
		}
	}
	if len(remaining) != 0 {
		t.Fatalf("missing native receipts: %+v", remaining)
	}
}

func ebArchiveReplayTimeEqual(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

func ebArchiveReplayOutput(t *testing.T, row ebTargetRoleObservation, output any, ids, owners map[string]string) {
	t.Helper()
	switch got := output.(type) {
	case *eventbridge.PutEventsOutput:
		var want eventbridge.PutEventsOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if len(got.Entries) != len(want.Entries) {
			t.Fatalf("%s: accepted event count=%d want=%d", row.Label, len(got.Entries), len(want.Entries))
		}
		for i, entry := range got.Entries {
			nativeID, localID := aws.ToString(want.Entries[i].EventId), aws.ToString(entry.EventId)
			if nativeID == "" || localID == "" || owners[localID] != "" {
				t.Fatalf("%s: acceptance did not create a distinct event ID", row.Label)
			}
			ids[nativeID], owners[localID] = localID, nativeID
		}
	case *eventbridge.StartReplayOutput:
		var want eventbridge.StartReplayOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if got.State != want.State || aws.ToString(got.ReplayArn) != aws.ToString(want.ReplayArn) || got.ReplayStartTime == nil {
			t.Fatalf("%s: start=%+v want=%+v", row.Label, got, want)
		}
	case *eventbridge.CancelReplayOutput:
		var want eventbridge.CancelReplayOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if got.State != want.State || aws.ToString(got.ReplayArn) != aws.ToString(want.ReplayArn) {
			t.Fatalf("%s: cancellation=%+v want=%+v", row.Label, got, want)
		}
	case *eventbridge.DescribeReplayOutput:
		var want eventbridge.DescribeReplayOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if got.State != want.State || aws.ToString(got.ReplayName) != aws.ToString(want.ReplayName) || aws.ToString(got.EventSourceArn) != aws.ToString(want.EventSourceArn) ||
			!reflect.DeepEqual(got.Destination, want.Destination) || !ebArchiveReplayTimeEqual(got.EventStartTime, want.EventStartTime) ||
			!ebArchiveReplayTimeEqual(got.EventEndTime, want.EventEndTime) || !ebArchiveReplayTimeEqual(got.EventLastReplayedTime, want.EventLastReplayedTime) {
			t.Fatalf("%s: replay state/window/minute progress=%+v want=%+v", row.Label, got, want)
		}
		terminal := got.State == "COMPLETED" || got.State == "CANCELLED" || got.State == "FAILED"
		if got.ReplayStartTime == nil || terminal != (got.ReplayEndTime != nil) || terminal && got.ReplayEndTime.Before(*got.ReplayStartTime) {
			t.Fatalf("%s: inconsistent lifecycle timestamps: %+v", row.Label, got)
		}
	case *eventbridge.DescribeArchiveOutput:
		var want eventbridge.DescribeArchiveOutput
		ebTargetRoleDecode(t, row.Output, &want)
		// Native SizeBytes is preserved as evidence in the fixture, not treated
		// as a specified byte encoding. Retained count defends no rearchival.
		if got.EventCount != want.EventCount || !reflect.DeepEqual(got.RetentionDays, want.RetentionDays) || got.State != want.State {
			t.Fatalf("%s: retained archive state=%+v want=%+v", row.Label, got, want)
		}
	case *eventbridge.ListReplaysOutput:
		var want eventbridge.ListReplaysOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if len(got.Replays) != len(want.Replays) {
			t.Fatalf("%s: replay history=%+v want=%+v", row.Label, got.Replays, want.Replays)
		}
		for _, replay := range want.Replays {
			index := slices.IndexFunc(got.Replays, func(actual eventtypes.Replay) bool {
				return aws.ToString(actual.ReplayName) == aws.ToString(replay.ReplayName)
			})
			if index < 0 || got.Replays[index].State != replay.State || aws.ToString(got.Replays[index].EventSourceArn) != aws.ToString(replay.EventSourceArn) {
				t.Fatalf("%s: terminal history changed after source deletion: got=%+v want=%+v", row.Label, got.Replays, replay)
			}
		}
	}
}

func TestEventBridgeArchiveReplaySDK(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/replays.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Account, Region string
		Runs            []ebArchiveReplayRun
	}
	ebTargetRoleDecode(t, data, &fixture)
	for _, kind := range []string{"memory", "sqlite"} {
		for _, run := range fixture.Runs {
			t.Run(kind+"/"+run.Name, func(t *testing.T) {
				backends := storage.NewMemory()
				if kind == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "replays.sqlite"))
				}
				source := clock.NewManual(run.Start)
				cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
				r := ebTargetRoleNew(cloud, clients, fixture.Account, fixture.Region)
				ids, owners := make(map[string]string), make(map[string]string)
				for _, step := range run.Steps {
					t.Run(step.Name, func(t *testing.T) {
						if step.AdvanceSeconds != 0 {
							if err := source.Advance(time.Duration(step.AdvanceSeconds) * time.Second); err != nil {
								t.Fatal(err)
							}
						}
						if step.Call != nil {
							ebArchiveReplayOutput(t, *step.Call, r.call(t, *step.Call), ids, owners)
						}
						if step.Drain {
							if result, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || result.More {
								t.Fatalf("archive/replay work did not settle: %+v, %v", result, err)
							}
						}
						if step.Receipts != nil {
							ebArchiveReplayReceipts(t, r, *step.Receipts, ids, owners)
						}
					})
					if t.Failed() {
						t.FailNow()
					}
				}
			})
		}
	}
}
