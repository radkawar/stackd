package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

type ebScheduledReceipt struct {
	Queue, Origin string
	Body          json.RawMessage
}

type ebScheduledRun struct {
	Name           string
	Start          time.Time
	AdvanceSeconds int
	DiscardSetup   bool
	Setup          []ebTargetRoleObservation
	Expected       []ebScheduledReceipt
	Control        *struct {
		Call     ebTargetRoleObservation
		Expected []ebScheduledReceipt
	}
}

func ebScheduledRead(t *testing.T, r *ebTargetRoleReplay) map[string][]any {
	t.Helper()
	messages := make(map[string][]any)
	queues := r.clients.sqs(r.account, "test", "")
	for name, url := range r.queues {
		for _, message := range snsAdmissionReceive(t, r.cloud, queues, url) {
			var body any
			ebTargetRoleDecode(t, []byte(aws.ToString(message.Body)), &body)
			messages[name] = append(messages[name], body)
		}
	}
	return messages
}

// One origin's ID must survive bus matching and every input projection. Only
// native-generated IDs change; all other envelope fields compare exactly.
func ebScheduledAssert(t *testing.T, got map[string][]any, expected []ebScheduledReceipt, ids map[string]string) {
	t.Helper()
	for _, messages := range got {
		for _, body := range messages {
			object, ok := body.(map[string]any)
			if !ok {
				continue // InputPath selects the JSON string event ID.
			}
			resources, _ := object["resources"].([]any)
			id, _ := object["id"].(string)
			if len(resources) == 1 && id != "" {
				origin, _ := resources[0].(string)
				if previous, exists := ids[origin]; exists && previous != id {
					t.Fatalf("one scheduled occurrence changed identity across targets: %s: %s != %s", origin, previous, id)
				}
				ids[origin] = id
			}
		}
	}
	for _, row := range expected {
		id := ids[row.Origin]
		if id == "" {
			t.Fatalf("missing scheduled origin %s: %+v", row.Origin, got)
		}
		var want any
		ebTargetRoleDecode(t, []byte(strings.ReplaceAll(string(row.Body), "<event-id>", id)), &want)
		index := slices.IndexFunc(got[row.Queue], func(body any) bool { return reflect.DeepEqual(body, want) })
		if index < 0 {
			t.Fatalf("queue %s omitted native scheduled body: want=%+v got=%+v", row.Queue, want, got[row.Queue])
		}
		got[row.Queue] = slices.Delete(got[row.Queue], index, index+1)
	}
	for queue, remaining := range got {
		if len(remaining) != 0 {
			t.Fatalf("queue %s received extra scheduled work: %+v", queue, remaining)
		}
	}
}

func TestEventBridgeScheduledDeliverySDK(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/eventbridge/scheduled_delivery.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Account, Region string
		Runs            []ebScheduledRun
	}
	ebTargetRoleDecode(t, data, &fixture)
	for _, kind := range []string{"memory", "sqlite"} {
		for _, run := range fixture.Runs {
			t.Run(kind+"/"+run.Name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "scheduled.sqlite")
				backends := storage.NewMemory()
				if kind == "sqlite" {
					backends, _ = openSQLiteBackends(t, path)
				}
				source := clock.NewManual(run.Start)
				cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
				r := ebTargetRoleNew(cloud, clients, fixture.Account, fixture.Region)
				for _, row := range run.Setup {
					r.call(t, row)
				}
				initial := ebScheduledRead(t, r)
				if !run.DiscardSetup {
					ebScheduledAssert(t, initial, nil, make(map[string]string))
				}
				if kind == "sqlite" {
					closeCloud()
					backends, _ = openSQLiteBackends(t, path)
					r.cloud, r.clients, _ = startEventDeliveryCloud(t, backends, source)
					queues := r.clients.sqs(fixture.Account, "test", "")
					for name := range r.queues {
						out, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
						if err != nil {
							t.Fatal(err)
						}
						r.queues[name] = out.QueueUrl
					}
				}
				if err := source.Advance(time.Duration(run.AdvanceSeconds) * time.Second); err != nil {
					t.Fatal(err)
				}
				ebScheduledAssert(t, ebScheduledRead(t, r), run.Expected, make(map[string]string))
				if run.Control != nil {
					out := r.call(t, run.Control.Call).(*eventbridge.PutEventsOutput)
					ids := make(map[string]string)
					for index, entry := range out.Entries {
						ids[fmt.Sprintf("control-%d", index)] = aws.ToString(entry.EventId)
					}
					ebScheduledAssert(t, ebScheduledRead(t, r), run.Control.Expected, ids)
				}
			})
		}
	}
}
