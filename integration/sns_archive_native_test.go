package stackd_test

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type snsArchiveNativeObservation struct {
	awsNativeObservation
	Requested time.Time `json:"request_started"`
}

type snsArchiveNativeFixture struct {
	Account, Region string
	Observations    []snsArchiveNativeObservation
	Receipts        []struct {
		Window, Queue string
		Message       sqstypes.Message
	}
	Windows []struct {
		Label    string
		Finished time.Time
		Counts   map[string]int
	} `json:"poll_windows"`
}

// The native capture contains asynchronous polls, not a prescribed scheduler.
// Select its meaningful operations and compare complete consumer payloads at
// captured observation windows rather than replaying every empty receive.
type snsArchiveNativeProbe struct {
	t             *testing.T
	fixture       snsArchiveNativeFixture
	cloud         *stackd.Stack
	topics        *sns.Client
	queues        *sqs.Client
	clock         *clock.Manual
	hold          *snsRecoveryDiscovery
	shift         time.Duration
	urls          map[string]string
	subscriptions map[string]string
	ids           map[string]string
	sequences     map[string]string
	published     map[string]time.Time
}

func snsArchiveNativeOpen(t *testing.T, backend string) *snsArchiveNativeProbe {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/sns/archive_replay.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture snsArchiveNativeFixture
	awsDecodeJSON(t, data, &fixture)
	// Preserve durations and minute boundaries, including FIFO's dedup window.
	nativeDay := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	shift := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Sub(nativeDay)
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "archive-native.sqlite"))
	}
	hold := &snsRecoveryDiscovery{Repository: backends.SNS}
	hold.replay.Store(true)
	backends.SNS = hold
	source := clock.NewManual(fixture.Observations[0].Requested.Add(shift))
	cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
	p := &snsArchiveNativeProbe{t: t, fixture: fixture, cloud: cloud, topics: admissionSNSClient(clients, fixture.Account, fixture.Region), queues: clients.sqs(fixture.Account, "test", ""), clock: source, hold: hold, shift: shift, urls: map[string]string{}, subscriptions: map[string]string{}, ids: map[string]string{}, sequences: map[string]string{}, published: map[string]time.Time{}}
	for _, receipt := range fixture.Receipts {
		var envelope struct{ MessageId, Timestamp string }
		awsDecodeJSON(t, []byte(aws.ToString(receipt.Message.Body)), &envelope)
		if envelope.MessageId != "" {
			at, err := time.Parse(time.RFC3339Nano, envelope.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			p.published[envelope.MessageId] = at
		}
	}
	return p
}

func (p *snsArchiveNativeProbe) row(label string) snsArchiveNativeObservation {
	p.t.Helper()
	for _, row := range p.fixture.Observations {
		if row.Label == label {
			return row
		}
	}
	p.t.Fatalf("missing native observation %s", label)
	return snsArchiveNativeObservation{}
}

var snsArchiveNativeTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)

func (p *snsArchiveNativeProbe) rebase(value string) string {
	return snsArchiveNativeTimestamp.ReplaceAllStringFunc(value, func(value string) string {
		at, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			p.t.Fatal(err)
		}
		// Keep policy whitespace and timestamp spelling; only the date changes.
		return at.Add(p.shift).Format("2006-01-02") + value[10:]
	})
}

func (p *snsArchiveNativeProbe) advance(at time.Time) {
	p.t.Helper()
	if err := p.clock.Advance(at.Add(p.shift).Sub(p.clock.Now())); err != nil {
		p.t.Fatal(err)
	}
}

func (p *snsArchiveNativeProbe) run(labels ...string) {
	p.t.Helper()
	for _, label := range labels {
		row := p.row(label)
		at := row.Requested
		if row.Operation == "publish" {
			var native sns.PublishOutput
			awsDecodeJSON(p.t, row.Result.Output, &native)
			if timestamp, exists := p.published[aws.ToString(native.MessageId)]; exists {
				at = timestamp
			}
		}
		// Archive beginning is the server acceptance instant, not the client
		// request start. Use the captured readback for that same operation.
		for i, candidate := range p.fixture.Observations {
			if candidate.Label != label || i+1 == len(p.fixture.Observations) {
				continue
			}
			next := p.fixture.Observations[i+1]
			if (row.Operation == "create-topic" || row.Operation == "set-topic-attributes") && next.Operation == "get-topic-attributes" {
				var out sns.GetTopicAttributesOutput
				awsDecodeJSON(p.t, next.Result.Output, &out)
				if begin, err := time.Parse(time.RFC3339Nano, out.Attributes["BeginningArchiveTime"]); err == nil && !begin.Before(at) && begin.Before(next.Requested) {
					at = begin
				}
			}
			break
		}
		p.advance(at)
		row.Input = json.RawMessage(p.rebase(string(row.Input)))
		var client any = p.topics
		if row.Service == "sqs" {
			client = p.queues
		}
		var preserved *sns.GetSubscriptionAttributesOutput
		var rejectedSubscription *string
		if row.Operation == "set-subscription-attributes" && row.Result.Code != "Success" {
			var input sns.SetSubscriptionAttributesInput
			awsDecodeJSON(p.t, row.Input, &input)
			rejectedSubscription = aws.String(p.subscriptions[aws.ToString(input.SubscriptionArn)])
			var err error
			preserved, err = p.topics.GetSubscriptionAttributes(p.t.Context(), &sns.GetSubscriptionAttributesInput{SubscriptionArn: rejectedSubscription})
			if err != nil {
				p.t.Fatal(err)
			}
		}
		var out any
		if !p.t.Run(label, func(t *testing.T) {
			out = snsControlReplay(t, client, row.awsNativeObservation, func(value any) {
				switch in := value.(type) {
				case *sqs.GetQueueAttributesInput:
					in.QueueUrl = aws.String(p.urls[aws.ToString(in.QueueUrl)])
				case *sqs.SetQueueAttributesInput:
					in.QueueUrl = aws.String(p.urls[aws.ToString(in.QueueUrl)])
				case *sns.SetSubscriptionAttributesInput:
					in.SubscriptionArn = aws.String(p.subscriptions[aws.ToString(in.SubscriptionArn)])
				case *sns.GetSubscriptionAttributesInput:
					in.SubscriptionArn = aws.String(p.subscriptions[aws.ToString(in.SubscriptionArn)])
				case *sns.UnsubscribeInput:
					in.SubscriptionArn = aws.String(p.subscriptions[aws.ToString(in.SubscriptionArn)])
				}
			})
		}) {
			p.t.FailNow()
		}
		if row.Result.Code != "Success" {
			if preserved != nil {
				after, err := p.topics.GetSubscriptionAttributes(p.t.Context(), &sns.GetSubscriptionAttributesInput{SubscriptionArn: rejectedSubscription})
				if err != nil {
					p.t.Fatal(err)
				}
				if !reflect.DeepEqual(after.Attributes, preserved.Attributes) {
					p.t.Fatalf("%s changed subscription state despite rejection: got %v, want %v", label, after.Attributes, preserved.Attributes)
				}
			}
			continue
		}
		switch result := out.(type) {
		case *sqs.CreateQueueOutput:
			var native sqs.CreateQueueOutput
			awsDecodeJSON(p.t, row.Result.Output, &native)
			p.urls[aws.ToString(native.QueueUrl)] = aws.ToString(result.QueueUrl)
		case *sns.SubscribeOutput:
			var native sns.SubscribeOutput
			awsDecodeJSON(p.t, row.Result.Output, &native)
			p.subscriptions[aws.ToString(native.SubscriptionArn)] = aws.ToString(result.SubscriptionArn)
		case *sns.PublishOutput:
			var native sns.PublishOutput
			awsDecodeJSON(p.t, row.Result.Output, &native)
			id := aws.ToString(native.MessageId)
			p.ids[id], p.sequences[id] = aws.ToString(result.MessageId), aws.ToString(result.SequenceNumber)
		case *sns.GetTopicAttributesOutput:
			var native sns.GetTopicAttributesOutput
			awsDecodeJSON(p.t, row.Result.Output, &native)
			p.attributes(label, result.Attributes, native.Attributes, "ArchivePolicy", "BeginningArchiveTime")
		case *sns.GetSubscriptionAttributesOutput:
			var native sns.GetSubscriptionAttributesOutput
			awsDecodeJSON(p.t, row.Result.Output, &native)
			p.attributes(label, result.Attributes, native.Attributes, "ReplayPolicy", "ReplayStatus")
		}
	}
}

func (p *snsArchiveNativeProbe) attributes(label string, got, want map[string]string, keys ...string) {
	p.t.Helper()
	for _, key := range keys {
		actual, present := got[key]
		expected, wanted := want[key]
		// Native status polls observe a worker, not an admission guarantee.
		if key == "ReplayStatus" && (expected == "Pending" || expected == "In Progress") && (actual == "Pending" || actual == "In Progress") {
			continue
		}
		if present != wanted || actual != p.rebase(expected) {
			p.t.Fatalf("%s: %s got %q (present %t), want %q (present %t)", label, key, actual, present, p.rebase(expected), wanted)
		}
	}
}

// Select contiguous native setup/control operations, never polling loops.
func (p *snsArchiveNativeProbe) through(first, last string) {
	p.t.Helper()
	active := false
	for _, row := range p.fixture.Observations {
		active = active || row.Label == first
		if active {
			p.run(row.Label)
		}
		if active && row.Label == last {
			return
		}
	}
	p.t.Fatalf("missing native range %s..%s", first, last)
}

func (p *snsArchiveNativeProbe) project(messages []sqstypes.Message, native, fifo bool) map[string][]string {
	p.t.Helper()
	groups := map[string][]string{}
	for _, message := range messages {
		body := aws.ToString(message.Body)
		var envelope map[string]any
		if json.Unmarshal([]byte(body), &envelope) == nil && envelope["Type"] == "Notification" {
			if native {
				id := envelope["MessageId"].(string)
				envelope["MessageId"] = p.ids[id]
				if _, exists := envelope["SequenceNumber"]; exists {
					envelope["SequenceNumber"] = p.sequences[id]
				}
				envelope["Timestamp"] = p.rebase(envelope["Timestamp"].(string))
			}
			if endpoint, exists := envelope["UnsubscribeURL"]; exists {
				parsed, err := url.Parse(endpoint.(string))
				if err != nil {
					p.t.Fatal(err)
				}
				query := parsed.Query()
				if native {
					query.Set("SubscriptionArn", p.subscriptions[query.Get("SubscriptionArn")])
				}
				parsed.Scheme, parsed.Host = "https", "sns.test"
				parsed.RawQuery = query.Encode()
				envelope["UnsubscribeURL"] = parsed.String()
			}
			encoded, err := json.Marshal(envelope)
			if err != nil {
				p.t.Fatal(err)
			}
			body = string(encoded)
		}
		// SQS's transport identity/timing is newly generated for each delivery;
		// SNS's original identity, time and sequence remain in the full body.
		payload := struct {
			Body, Group, Deduplication string
			Attributes                 map[string]sqstypes.MessageAttributeValue
		}{body, message.Attributes["MessageGroupId"], message.Attributes["MessageDeduplicationId"], message.MessageAttributes}
		encoded, err := json.Marshal(payload)
		if err != nil {
			p.t.Fatal(err)
		}
		groups[payload.Group] = append(groups[payload.Group], string(encoded))
	}
	if !fifo {
		for _, values := range groups {
			sort.Strings(values)
		}
	}
	return groups
}

func (p *snsArchiveNativeProbe) receive(windows []string, queues ...string) {
	p.t.Helper()
	p.hold.replay.Store(false)
	defer p.hold.replay.Store(true)
	selected := map[string]bool{}
	var finished time.Time
	for _, label := range windows {
		selected[label] = true
		found := false
		for _, window := range p.fixture.Windows {
			if window.Label == label {
				found = true
				if window.Finished.After(finished) {
					finished = window.Finished
				}
				for _, queue := range queues {
					if _, exists := window.Counts[queue]; !exists {
						p.t.Fatalf("%s has no native observation for %s", label, queue)
					}
				}
			}
		}
		if !found {
			p.t.Fatalf("missing native receipt window %s", label)
		}
	}
	p.advance(finished)
	trailNativeDrain(p.t, p.cloud)
	for _, queue := range queues {
		var wanted []sqstypes.Message
		for _, receipt := range p.fixture.Receipts {
			if selected[receipt.Window] && receipt.Queue == queue {
				wanted = append(wanted, receipt.Message)
			}
		}
		var queueURL string
		for native, local := range p.urls {
			if strings.HasSuffix(native, "-"+queue) {
				queueURL = local
			}
		}
		if queueURL == "" {
			p.t.Fatalf("missing queue %s", queue)
		}
		got := snsAdmissionReceive(p.t, p.cloud, p.queues, &queueURL)
		fifo := strings.HasSuffix(queue, ".fifo")
		actual, expected := p.project(got, false, fifo), p.project(wanted, true, fifo)
		if !reflect.DeepEqual(actual, expected) {
			p.t.Fatalf("%v / %s consumer receipts differ\ngot: %v\nwant: %v", windows, queue, actual, expected)
		}
	}
}

func TestSNSNativeArchiveAdmissionAndLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			p := snsArchiveNativeOpen(t, backend)
			p.through("create-main.fifo", "standard-archive-refusal")
			p.through("create-lifecycle.fifo", "lifecycle-subscribe-new-range")
			p.receive([]string{"lifecycle-after-reenable-replay"}, "lifecycle")
			p.run("lifecycle-replay-final")
			p.through("create-created-active.fifo", "set-replay-archive-disabled")
			p.through("archive-whitespace-retention-input", "archive-after-compact-duplicate")
		})
	}
}

func TestSNSNativeArchiveReplayReceiptsAndTransitions(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			p := snsArchiveNativeOpen(t, backend)
			p.through("create-main.fifo", "live-after-subscriptions")
			p.receive([]string{"live-baseline"}, "wrapped.fifo", "raw.fifo", "standard")
			p.through("bounded-replay-0", "restore-bounded-after-errors")
			p.receive([]string{"bounded-replay-00"}, "wrapped.fifo", "raw.fifo", "standard", "filtered")
			p.run("bounded-status-01-0", "bounded-status-01-1", "bounded-status-01-2", "bounded-status-01-3")
			// EOF before EndingPoint completes without pausing live fanout.
			p.through("create-queue-live-control", "published-after-bounded-ending")
			p.receive([]string{"bounded-paused-with-live-control"}, "wrapped.fifo", "raw.fifo", "standard", "filtered", "live-control")
			p.run("resume-unbounded-0", "resume-unbounded-1", "resume-unbounded-2", "resume-unbounded-3")
			p.receive([]string{"unbounded-catchup-0"}, "wrapped.fifo", "raw.fifo", "standard", "filtered")
			p.run("live-after-unbounded-caught-up")
			p.receive([]string{"resumed-live-proof"}, "wrapped.fifo", "raw.fifo", "standard", "filtered", "live-control")
			// Exact original timestamps prove inclusive start, exclusive end, and
			// a historical end actually encountered leaves the subscriber paused.
			p.through("create-queue-boundary", "subscribe-exact-message-boundaries")
			p.receive([]string{"exact-boundary-replay"}, "boundary")
			p.run("boundary-final-status", "bounded-repeat-existing-group", "bounded-repeat-new-group")
			p.receive([]string{"bounded-repeat-after-completed"}, "boundary", "live-control")
			p.run("equal-start-and-end", "equal-boundary-status")
			p.receive([]string{"equal-boundary-replay"}, "boundary")
			p.run("cancel-start-pending", "before-cancel", "cancel-empty-object", "after-cancel", "after-cancel-live-marker")
			p.receive([]string{"cancel-live-proof"}, "live-control", "standard")
			p.run("replacement-initial-bounded", "replacement-initial-status", "replacement-unbounded", "replacement-updated-status")
			p.receive([]string{"replacement-replay"}, "live-control")
			p.run("replacement-final-status")
			p.receive([]string{"boundary-still-paused-before-resume"}, "boundary")
			p.run("boundary-unbounded-resume")
			p.receive([]string{"boundary-unbounded-catchup-0"}, "boundary")
			p.run("boundary-live-after-catchup")
			p.receive([]string{"boundary-live-after-resume"}, "boundary", "live-control")
			p.run("invalid-replay-future-ending")
			// Active Pending replays retain live fanout. Already paused replays
			// do not resume prematurely; catchup then restores ordinary delivery.
			p.run("pending-fanout-bounded-request", "pending-fanout-bounded-before-publish", "pending-fanout-bounded-same-group-marker", "pending-fanout-bounded-after-publish")
			p.receive([]string{"pending-fanout-bounded-window-0"}, "live-control", "standard")
			p.run("pending-fanout-bounded-after-completed-marker")
			p.receive([]string{"pending-fanout-bounded-after-completed"}, "live-control", "standard")
			p.run("pending-fanout-unbounded-request", "pending-fanout-unbounded-before-publish", "pending-fanout-unbounded-same-group-marker", "pending-fanout-unbounded-after-publish")
			p.receive([]string{"pending-fanout-unbounded-window-0"}, "live-control", "standard")
			p.run("pending-fanout-unbounded-after-completed-marker")
			p.receive([]string{"pending-fanout-unbounded-after-completed"}, "live-control", "standard")
			p.run("pending-active-unbounded-prior-state", "pending-active-unbounded-request", "pending-active-unbounded-before-publish", "pending-active-unbounded-same-group-marker", "pending-active-unbounded-after-publish")
			p.receive([]string{"pending-active-unbounded-window-0", "pending-active-unbounded-window-1"}, "live-control", "standard")
		})
	}
}

func TestSNSNativeArchiveCreateIdempotency(t *testing.T) {
	fixture := snsControlsFixture(t, "archive_create").snsAdmissionFixture
	fixture.Observations[0].Started = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			_, clients, _ := admissionFixtureCloud(t, backend, fixture)
			topics := admissionSNSClient(clients, fixture.Account, fixture.Region)
			for _, row := range fixture.Observations {
				if row.Service != "sns" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					output := snsControlReplay(t, topics, row)
					if attrs, ok := output.(*sns.GetTopicAttributesOutput); ok {
						var native sns.GetTopicAttributesOutput
						awsDecodeJSON(t, row.Result.Output, &native)
						got, present := attrs.Attributes["ArchivePolicy"]
						want, wanted := native.Attributes["ArchivePolicy"]
						if got != want || present != wanted {
							t.Fatalf("duplicate creation changed archive policy: got %q (%t), want %q (%t)", got, present, want, wanted)
						}
					}
				}) {
					t.FailNow()
				}
			}
		})
	}
}
