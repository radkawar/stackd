package stackd_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type ebBusForwardCall struct {
	Service, Operation, Account, Region, Label, Phase string
	Input                                             json.RawMessage
	Output                                            struct {
		Error            struct{ Code, Message string }
		Entries          []struct{ EventId, ErrorCode string }
		FailedEntryCount int32
		Targets          []eventtypes.Target
		QueueUrl         string
	}
	Deliveries []ebBusForwardDelivery
}

type ebBusForwardDelivery struct {
	Sink              string
	Envelope          map[string]any
	BodyBase64        string                                            `json:"body_base64"`
	MessageAttributes map[string]struct{ DataType, StringValue string } `json:"message_attributes"`
}

type ebBusForwardQueue struct{ Label, URL, ARN, Account, Region string }

type ebBusForwardRun struct {
	Name, Prefix string
	Queues       []ebBusForwardQueue
	Calls        []ebBusForwardCall
	History      map[string]struct{ Records []map[string]any }
}

func ebBusForwardFixture(t *testing.T) []ebBusForwardRun {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/eventbridge/bus_forwarding.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Runs []ebBusForwardRun }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Runs
}

type ebBusForwardReplay struct {
	cloud   *stackd.Stack
	clients cloudClients
	run     ebBusForwardRun
	urls    map[string]string
}

func (r *ebBusForwardReplay) events(account, region string) *eventbridge.Client {
	return eventbridge.New(eventbridge.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
}

func (r *ebBusForwardReplay) queues(account, region string) *sqs.Client {
	return sqs.New(sqs.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
}

// The native Python capture spells supplied datetimes with a space. Decode the
// service's actual entry fields rather than rewriting the captured request.
func ebBusForwardEntries(t *testing.T, raw json.RawMessage) *eventbridge.PutEventsInput {
	t.Helper()
	var captured struct {
		Entries []struct {
			Source, DetailType, Detail, EventBusName *string
			Resources                                []string
			Time                                     string
		}
	}
	if err := json.Unmarshal(raw, &captured); err != nil {
		t.Fatal(err)
	}
	input := &eventbridge.PutEventsInput{}
	for _, entry := range captured.Entries {
		value := eventtypes.PutEventsRequestEntry{Source: entry.Source, DetailType: entry.DetailType, Detail: entry.Detail,
			EventBusName: entry.EventBusName, Resources: entry.Resources}
		if entry.Time != "" {
			stamp, err := time.Parse(time.RFC3339, strings.Replace(entry.Time, " ", "T", 1))
			if err != nil {
				t.Fatal(err)
			}
			value.Time = &stamp
		}
		input.Entries = append(input.Entries, value)
	}
	return input
}

func (r *ebBusForwardReplay) invoke(t *testing.T, row ebBusForwardCall) string {
	t.Helper()
	var output any
	var err error
	switch row.Service {
	case "events":
		client := r.events(row.Account, row.Region)
		if row.Operation == "PutEvents" {
			output, err = client.PutEvents(t.Context(), ebBusForwardEntries(t, row.Input))
		} else {
			output, err = awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
		}
	case "iam":
		output, err = awstest.CallSDK(t.Context(), r.clients.iam(row.Account, "test", ""), row.Operation, row.Input)
	case "sqs":
		output, err = awstest.CallSDK(t.Context(), r.queues(row.Account, row.Region), row.Operation, row.Input, func(input any) {
			if in, ok := input.(*sqs.SetQueueAttributesInput); ok {
				in.QueueUrl = aws.String(r.urls[aws.ToString(in.QueueUrl)])
			}
		})
	default:
		t.Fatalf("unsupported captured service %q", row.Service)
	}
	if row.Output.Error.Code != "" {
		assertAPIError(t, err, row.Output.Error.Code)
		return ""
	}
	if err != nil {
		t.Fatalf("%s %s: %v", row.Operation, row.Label, err)
	}
	switch out := output.(type) {
	case *sqs.CreateQueueOutput:
		r.urls[row.Output.QueueUrl] = aws.ToString(out.QueueUrl)
	case *eventbridge.PutTargetsOutput:
		if out.FailedEntryCount != row.Output.FailedEntryCount {
			t.Fatalf("%s target admission: %+v", row.Label, out)
		}
	case *eventbridge.ListTargetsByRuleOutput:
		// Failed updates retain the entire publicly listed target. Explicit
		// replacement clears omitted optional fields, including the DLQ.
		if !reflect.DeepEqual(out.Targets, row.Output.Targets) {
			t.Fatalf("%s listed targets: got %+v, native %+v", row.Label, out.Targets, row.Output.Targets)
		}
	case *eventbridge.PutEventsOutput:
		if out.FailedEntryCount != row.Output.FailedEntryCount || len(out.Entries) != len(row.Output.Entries) {
			t.Fatalf("%s event admission: %+v", row.Label, out)
		}
		for i, entry := range out.Entries {
			if aws.ToString(entry.ErrorCode) != row.Output.Entries[i].ErrorCode {
				t.Fatalf("entry error: %+v", entry)
			}
		}
		return aws.ToString(out.Entries[0].EventId)
	}
	return ""
}

func (r *ebBusForwardReplay) refreshURLs(t *testing.T) {
	t.Helper()
	for _, queue := range r.run.Queues {
		if _, created := r.urls[queue.URL]; !created {
			continue
		}
		name := queue.ARN[strings.LastIndex(queue.ARN, ":")+1:]
		out, err := r.queues(queue.Account, queue.Region).GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		r.urls[queue.URL] = aws.ToString(out.QueueUrl)
	}
}

func (r *ebBusForwardReplay) delivered(t *testing.T, row ebBusForwardCall, eventID string, forwardedAt time.Time, ignoredID string) {
	t.Helper()
	result, err := r.cloud.RunDueJobs(t.Context(), 1000)
	if err != nil || result.More {
		t.Fatalf("delivery did not settle: %+v %v", result, err)
	}
	// Identity maps are scoped to one original submission. Equal native bytes
	// require equal replay bytes, separately from semantic envelope comparison.
	ids := make(map[string]string)
	bodies := make(map[string]string)
	for _, queue := range r.run.Queues {
		url, created := r.urls[queue.URL]
		if !created {
			continue
		}
		client := r.queues(queue.Account, queue.Region)
		out, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(url), MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
		if err != nil {
			t.Fatal(err)
		}
		var wants []ebBusForwardDelivery
		for _, want := range row.Deliveries {
			if want.Sink == queue.Label {
				wants = append(wants, want)
			}
		}
		seen := 0
		for _, message := range out.Messages {
			var envelope map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &envelope); err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: aws.String(url), ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
			if ignoredID != "" && envelope["id"] == ignoredID {
				continue
			}
			if seen >= len(wants) {
				t.Fatalf("%s unexpected %s message: %s", row.Label, queue.Label, aws.ToString(message.Body))
			}
			want := wants[seen]
			seen++
			if len(message.MessageAttributes) != len(want.MessageAttributes) {
				t.Fatalf("%s %s DLQ attribute presence differs: %+v", row.Label, queue.Label, message.MessageAttributes)
			}
			for key, attribute := range want.MessageAttributes {
				actual, present := message.MessageAttributes[key]
				if !present || aws.ToString(actual.DataType) != attribute.DataType {
					t.Fatalf("%s %s missing or changed %s attribute", row.Label, queue.Label, key)
				}
				if key != "ERROR_MESSAGE" && aws.ToString(actual.StringValue) != attribute.StringValue {
					t.Fatalf("%s %s %s: got %q, native %q", row.Label, queue.Label, key, aws.ToString(actual.StringValue), attribute.StringValue)
				}
			}
			actualID, _ := envelope["id"].(string)
			nativeID, _ := want.Envelope["id"].(string)
			original := len(row.Output.Entries) > 0 && nativeID == row.Output.Entries[0].EventId
			if original && actualID != eventID {
				t.Fatalf("same-region forwarding changed original PutEvents id: %s", aws.ToString(message.Body))
			}
			if !original && (actualID == "" || actualID == eventID) {
				t.Fatalf("cross-region forwarding did not regenerate id: %s", aws.ToString(message.Body))
			}
			if previous, ok := ids[nativeID]; ok && previous != actualID {
				t.Fatalf("local forwarding changed regenerated id: %s", aws.ToString(message.Body))
			}
			ids[nativeID] = actualID
			if previous, ok := bodies[want.BodyBase64]; ok && previous != aws.ToString(message.Body) {
				t.Fatal("same-region hop changed event bytes")
			}
			bodies[want.BodyBase64] = aws.ToString(message.Body)
			expected := make(map[string]any, len(want.Envelope))
			for key, value := range want.Envelope {
				expected[key] = value
			}
			expected["id"] = actualID
			input := ebBusForwardEntries(t, row.Input)
			if !original || input.Entries[0].Time == nil {
				expected["time"] = forwardedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
			}
			if !reflect.DeepEqual(envelope, expected) {
				t.Fatalf("%s %s envelope: got %#v, native semantics %#v", row.Label, queue.Label, envelope, expected)
			}
		}
		if seen != len(wants) {
			t.Fatalf("%s %s: got %d deliveries, native %d", row.Label, queue.Label, seen, len(wants))
		}
	}
}

func (r *ebBusForwardReplay) audit(t *testing.T) {
	t.Helper()
	for account, history := range r.run.History {
		expected := make(map[string]map[string]any)
		for _, record := range history.Records {
			request := record["requestParameters"].(map[string]any)
			expected[request["roleArn"].(string)] = record
		}
		client := cloudtrail.New(cloudtrail.Options{Region: r.run.Queues[0].Region, BaseEndpoint: aws.String(r.clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		input := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("AssumeRole")}}, MaxResults: aws.Int32(50)}
		seen := make(map[string]bool)
		for {
			out, err := client.LookupEvents(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range out.Events {
				var record map[string]any
				if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &record); err != nil {
					t.Fatal(err)
				}
				request, _ := record["requestParameters"].(map[string]any)
				role, _ := request["roleArn"].(string)
				if !strings.Contains(role, ":role/"+r.run.Prefix+"-") {
					continue
				}
				want, present := expected[role]
				if !present || seen[role] {
					t.Fatalf("account %s received an unexpected role assumption: %#v", account, record)
				}
				seen[role] = true
				for _, field := range []string{"userIdentity", "recipientAccountId", "eventSource", "eventName", "readOnly", "eventCategory"} {
					if !reflect.DeepEqual(record[field], want[field]) {
						t.Fatalf("account %s role %s changed %s: local %#v, native %#v", account, role, field, record[field], want[field])
					}
				}
			}
			if out.NextToken == nil {
				break
			}
			input.NextToken = out.NextToken
		}
		if len(seen) != len(expected) {
			t.Fatalf("account %s role assumptions: local %v, native %v", account, seen, expected)
		}
	}
}

func TestEventBridgeNativeBusTargetsSDK(t *testing.T) {
	for _, run := range ebBusForwardFixture(t) {
		t.Run(run.Name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					backends := storage.NewMemory()
					if backend == "sqlite" {
						backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "forward.sqlite"))
					}
					source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
					cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
					r := &ebBusForwardReplay{cloud: cloud, clients: clients, run: run, urls: make(map[string]string)}
					for _, row := range run.Calls {
						if row.Operation != "PutEvents" {
							r.invoke(t, row)
							continue
						}
						if !t.Run(row.Label, func(t *testing.T) {
							id := r.invoke(t, row)
							r.delivered(t, row, id, source.Now(), "")
						}) {
							t.FailNow()
						}
					}
					r.audit(t)
				})
			}
		})
	}
}

func ebBusForwardSetup(t *testing.T, r *ebBusForwardReplay) {
	t.Helper()
	for _, row := range r.run.Calls {
		if row.Operation == "PutEvents" {
			return
		}
		r.invoke(t, row)
	}
}

func ebBusForwardSubject(t *testing.T, run ebBusForwardRun, name string) ebBusForwardCall {
	t.Helper()
	for _, row := range run.Calls {
		if row.Operation == "PutEvents" && row.Label == name {
			return row
		}
	}
	t.Fatalf("missing native subject %s", name)
	return ebBusForwardCall{}
}

func ebBusForwardDeleteRule(t *testing.T, client *eventbridge.Client, bus, rule string) {
	t.Helper()
	listed, err := client.ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{Rule: aws.String(rule), EventBusName: aws.String(bus)})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, target := range listed.Targets {
		ids = append(ids, aws.ToString(target.Id))
	}
	if len(ids) != 0 {
		removed, err := client.RemoveTargets(t.Context(), &eventbridge.RemoveTargetsInput{Rule: aws.String(rule), EventBusName: aws.String(bus), Ids: ids})
		if err != nil || removed.FailedEntryCount != 0 {
			t.Fatal("remove source targets", removed, err)
		}
	}
	if _, err := client.DeleteRule(t.Context(), &eventbridge.DeleteRuleInput{Name: aws.String(rule), EventBusName: aws.String(bus)}); err != nil {
		t.Fatal(err)
	}
}

func TestEventBridgeBusForwardingRetainedSQLite(t *testing.T) {
	for _, run := range ebBusForwardFixture(t) {
		if run.Name != "core" && run.Name != "mixed" {
			continue
		}
		t.Run(run.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "retained.sqlite")
			backends, closeDB := openSQLiteBackends(t, path)
			gate := &gatedQueueRepository{Repository: backends.SQS, entered: make(chan struct{}), release: make(chan struct{})}
			backends.SQS = gate
			t.Cleanup(gate.unblock)
			epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
			source := clock.NewManual(epoch)
			cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, source)
			r := &ebBusForwardReplay{cloud: cloud, clients: clients, run: run, urls: make(map[string]string)}
			ebBusForwardSetup(t, r)
			name, bus := "member-good", run.Prefix+"-a"
			if run.Name == "mixed" {
				name, bus = "region-local-local", run.Prefix+"-origin"
			}
			row := ebBusForwardSubject(t, run, name)
			client := r.events(row.Account, row.Region)
			ignoredID := ""
			if run.Name == "mixed" {
				// With no source queue target, the first blocked queue command is
				// downstream of the cross-region admission. Its regenerated wire
				// envelope and retained local-hop state must survive reopening.
				ebBusForwardDeleteRule(t, client, bus, run.Prefix+"-origin-sink")
				filtered := row.Deliveries[:0:0]
				for _, want := range row.Deliveries {
					if want.Sink != "origin-sink" {
						filtered = append(filtered, want)
					}
				}
				row.Deliveries = filtered
			}
			gate.armed.Store(true)
			id := ""
			if run.Name == "core" {
				// A separate one-target admission owns the barrier. Pending
				// deliveries from one event have intentionally unspecified order.
				barrier := ebBusForwardEntries(t, row.Input)
				barrier.Entries[0].Detail = aws.String(`{"case":"retained-barrier"}`)
				out, err := client.PutEvents(t.Context(), barrier)
				if err != nil {
					t.Fatal(err)
				}
				ignoredID = aws.ToString(out.Entries[0].EventId)
			} else {
				id = r.invoke(t, row)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			select {
			case <-gate.entered:
			case <-ctx.Done():
				t.Fatal("queue boundary not reached", ctx.Err())
			}
			if run.Name == "core" {
				id = r.invoke(t, row)
				// Replace both destination and role before deleting the source
				// rule. Already accepted work must use neither replacement.
				out, err := client.PutTargets(t.Context(), &eventbridge.PutTargetsInput{EventBusName: aws.String(bus), Rule: aws.String(run.Prefix + "-" + name), Targets: []eventtypes.Target{{Id: aws.String("forward"), Arn: aws.String("arn:aws:events:us-east-1:" + row.Account + ":event-bus/" + run.Prefix + "-c"), RoleArn: aws.String("arn:aws:iam::" + row.Account + ":role/" + run.Prefix + "-nogrant")}}})
				if err != nil || out.FailedEntryCount != 0 {
					t.Fatal("replace selected target", out, err)
				}
			}
			ebBusForwardDeleteRule(t, client, bus, run.Prefix+"-"+name)
			closeCloud()
			closeDB()
			advanceClock(t, source, time.Hour)
			backends, _ = openSQLiteBackends(t, path)
			r.cloud, r.clients, _ = startEventDeliveryCloud(t, backends, source)
			r.refreshURLs(t)
			r.delivered(t, row, id, epoch, ignoredID)
		})
	}
}

func TestEventBridgeBusForwardingMatchesOriginAccountSDK(t *testing.T) {
	for _, run := range ebBusForwardFixture(t) {
		if run.Name != "core" {
			continue
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(backend, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "origin.sqlite"))
				}
				source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
				cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
				r := &ebBusForwardReplay{cloud: cloud, clients: clients, run: run, urls: make(map[string]string)}
				ebBusForwardSetup(t, r)
				row := ebBusForwardSubject(t, run, "member-good")
				// Tighten the captured receiver sink rather than introspecting
				// matching state. The same forwarded event must match the origin
				// account, not the receiving bus's account.
				for _, account := range []string{row.Account, "917546008205"} {
					pattern, err := json.Marshal(map[string]any{"source": []string{run.Prefix}, "account": []string{account}})
					if err != nil {
						t.Fatal(err)
					}
					_, err = r.events("917546008205", "us-east-1").PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String(run.Prefix + "-member-sink"), EventBusName: aws.String(run.Prefix + "-member"), EventPattern: aws.String(string(pattern))})
					if err != nil {
						t.Fatal(err)
					}
					want := row
					if account != row.Account {
						want.Deliveries = nil
						for _, delivery := range row.Deliveries {
							if delivery.Sink != "member-sink" {
								want.Deliveries = append(want.Deliveries, delivery)
							}
						}
					}
					id := r.invoke(t, row)
					r.delivered(t, want, id, source.Now(), "")
				}
			})
		}
	}
}
