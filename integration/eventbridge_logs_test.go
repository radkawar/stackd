package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type eventLogsObservation struct {
	Label, Service, Operation string
	Input                     json.RawMessage
	Started                   int64 `json:"request_started_ms"`
	Result                    struct {
		Code   string
		Output json.RawMessage
	}
}

type eventLogsFixture struct {
	Observations []eventLogsObservation
	PreviousRuns []struct {
		Observations []eventLogsObservation
	} `json:"previous_runs"`
	Delivery map[string]struct {
		EventID  string                      `json:"event_id"`
		Events   []logtypes.FilteredLogEvent `json:"matched_log_events"`
		Messages []sqstypes.Message
	}
}

func loadEventLogsFixture(t *testing.T, name string) eventLogsFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "eventbridge", name))
	if err != nil {
		t.Fatal(err)
	}
	var fixture eventLogsFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f eventLogsFixture) observation(t *testing.T, label string) eventLogsObservation {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("native Logs destination observation %q is missing", label)
	return eventLogsObservation{}
}

func replayEventLogs(t *testing.T, client any, row eventLogsObservation, prepare ...func(any)) any {
	t.Helper()
	operation := ""
	for _, word := range strings.Split(row.Operation, "-") {
		operation += strings.ToUpper(word[:1]) + word[1:]
	}
	out, err := awstest.CallSDK(t.Context(), client, operation, row.Input, prepare...)
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		return nil
	}
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	return out
}

// Each reopen releases the HTTP server, Stack, then SQLite handles. Cleanup
// follows the same order even if an SDK assertion terminates a subtest.
func eventLogsCloud(t *testing.T, backend string, source clock.Clock) (*stackd.Stack, cloudClients, func() (*stackd.Stack, cloudClients)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event-logs.sqlite")
	var cloud *stackd.Stack
	var c cloudClients
	closeDB := func() {}
	closeCloud := func() {
		if c.server != nil {
			c.server.Close()
			c.server = nil
		}
		if cloud != nil {
			if err := cloud.Close(); err != nil {
				t.Error(err)
			}
			cloud = nil
		}
		closeDB()
		closeDB = func() {}
	}
	open := func() (*stackd.Stack, cloudClients) {
		closeCloud()
		backends := storage.NewMemory()
		if backend == "sqlite" {
			backends, closeDB = openSQLiteBackends(t, path)
		}
		var err error
		cloud, err = stackd.New(stackd.Config{AccountID: "123456789012", Storage: backends, Clock: source})
		if err != nil {
			t.Fatal(err)
		}
		c = cloudClients{httptest.NewServer(cloud)}
		// Register after opening the database so LIFO cleanup closes the server
		// and Stack before openSQLiteBackends' own database cleanup.
		t.Cleanup(closeCloud)
		return cloud, c
	}
	cloud, c = open()
	return cloud, c, open
}

// IAM string-or-set fields have identical semantics regardless of singleton
// spelling or member order. Do not compare AWS's policy serializer. Other
// arrays and all condition names, values, effects and statement IDs stay exact.
func eventLogsPolicyDocument(t *testing.T, document *string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(aws.ToString(document)), &value); err != nil {
		t.Fatal(err)
	}
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				switch key {
				case "Action", "NotAction", "Resource", "NotResource", "Service", "AWS":
					var members []string
					switch child := child.(type) {
					case string:
						members = []string{child}
					case []any:
						for _, member := range child {
							text, ok := member.(string)
							if !ok {
								t.Fatalf("non-string IAM set member: %v", member)
							}
							members = append(members, text)
						}
					default:
						t.Fatalf("unexpected IAM set %s: %v", key, child)
					}
					sort.Strings(members)
					value[key] = members
				default:
					visit(child)
				}
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(value)
	return value
}

func assertEventLogsPolicy(t *testing.T, got, want *logtypes.ResourcePolicy) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatalf("missing policy: got %+v, native %+v", got, want)
	}
	if !reflect.DeepEqual(got.PolicyName, want.PolicyName) || got.PolicyScope != want.PolicyScope ||
		!reflect.DeepEqual(got.ResourceArn, want.ResourceArn) || !reflect.DeepEqual(got.RevisionId, want.RevisionId) ||
		(got.LastUpdatedTime == nil) != (want.LastUpdatedTime == nil) {
		t.Errorf("policy scope, revision or optional field presence differs: got %+v, native %+v", got, want)
	}
	if !reflect.DeepEqual(eventLogsPolicyDocument(t, got.PolicyDocument), eventLogsPolicyDocument(t, want.PolicyDocument)) {
		t.Errorf("stored policy differs: got %s, native %s", aws.ToString(got.PolicyDocument), aws.ToString(want.PolicyDocument))
	}
}

func TestLogsResourcePolicyNativeSDK(t *testing.T) {
	fixture := loadEventLogsFixture(t, "logs_destination.json")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.UnixMilli(fixture.observation(t, "create-group").Started).UTC())
			_, c, reopen := eventLogsCloud(t, backend, source)
			client := logsClient(c, "test")
			replayEventLogs(t, client, fixture.observation(t, "create-group"))
			var scope cloudwatchlogs.DescribeResourcePoliciesInput
			if err := json.Unmarshal(fixture.observation(t, "resource-policy-before-create").Input, &scope); err != nil {
				t.Fatal(err)
			}
			snapshot := func() []logtypes.ResourcePolicy {
				t.Helper()
				var policies []logtypes.ResourcePolicy
				for _, input := range []*cloudwatchlogs.DescribeResourcePoliciesInput{{}, &scope} {
					out, err := client.DescribeResourcePolicies(t.Context(), input)
					if err != nil {
						t.Fatal(err)
					}
					policies = append(policies, out.ResourcePolicies...)
				}
				return policies
			}
			// The earlier failed run attempted a valid document with both selectors.
			// It is not a successful scoped create merely because its label says so.
			previousFailure := false
			for _, run := range fixture.PreviousRuns {
				for _, row := range run.Observations {
					if row.Label == "resource-policy-create-revision-omitted" && row.Result.Code == "InvalidParameterException" {
						before := snapshot()
						replayEventLogs(t, client, row)
						if !reflect.DeepEqual(snapshot(), before) {
							t.Fatal("both-name-and-ARN rejection changed policy state")
						}
						previousFailure = true
					}
				}
			}
			if !previousFailure {
				t.Fatal("native previous-run both-selector failure is missing")
			}
			for _, row := range fixture.Observations {
				if row.Service != "logs" || strings.HasPrefix(row.Label, "cleanup-") ||
					(row.Operation != "put-resource-policy" && row.Operation != "describe-resource-policies" && row.Operation != "delete-resource-policy") {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					if at := time.UnixMilli(row.Started); at.After(source.Now()) {
						advanceClock(t, source, at.Sub(source.Now()))
					}
					if backend == "sqlite" && row.Label == "resource-policy-after-rejected-revisions" {
						before := snapshot()
						_, c = reopen()
						client = logsClient(c, "test")
						if !reflect.DeepEqual(snapshot(), before) {
							t.Fatal("reopen lost policy state or revision guard")
						}
					}
					before := snapshot()
					out := replayEventLogs(t, client, row)
					if row.Result.Code != "Success" {
						if !reflect.DeepEqual(snapshot(), before) {
							t.Fatal("rejected operation changed stored policies or revisions")
						}
						return
					}
					switch out := out.(type) {
					case *cloudwatchlogs.PutResourcePolicyOutput:
						var want cloudwatchlogs.PutResourcePolicyOutput
						if err := json.Unmarshal(row.Result.Output, &want); err != nil {
							t.Fatal(err)
						}
						assertEventLogsPolicy(t, out.ResourcePolicy, want.ResourcePolicy)
						if !reflect.DeepEqual(out.RevisionId, want.RevisionId) {
							t.Errorf("top-level revision: got %v, native %v", out.RevisionId, want.RevisionId)
						}
						if out.ResourcePolicy.PolicyScope == logtypes.PolicyScopeAccount {
							listed, err := client.DescribeResourcePolicies(t.Context(), &cloudwatchlogs.DescribeResourcePoliciesInput{})
							if err != nil || len(listed.ResourcePolicies) != 1 {
								t.Fatal("default scope did not select only the account policy", listed, err)
							}
							assertEventLogsPolicy(t, &listed.ResourcePolicies[0], want.ResourcePolicy)
						}
					case *cloudwatchlogs.DescribeResourcePoliciesOutput:
						var want cloudwatchlogs.DescribeResourcePoliciesOutput
						if err := json.Unmarshal(row.Result.Output, &want); err != nil {
							t.Fatal(err)
						}
						if len(out.ResourcePolicies) != len(want.ResourcePolicies) {
							t.Fatalf("scoped policy selection: got %+v, native %+v", out.ResourcePolicies, want.ResourcePolicies)
						}
						for i := range want.ResourcePolicies {
							assertEventLogsPolicy(t, &out.ResourcePolicies[i], &want.ResourcePolicies[i])
						}
					}
				})
			}
		})
	}
}

func TestEventBridgeLogsNativeDeliverySDK(t *testing.T) {
	runEventBridgeLogsDelivery(t, "logs_destination.json")
}

func TestEventBridgeLogsNativePolicyPrecedenceSDK(t *testing.T) {
	runEventBridgeLogsDelivery(t, "logs_policy_precedence.json")
}

func runEventBridgeLogsDelivery(t *testing.T, file string) {
	t.Helper()
	fixture := loadEventLogsFixture(t, file)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.UnixMilli(fixture.observation(t, "create-group").Started).UTC())
			cloud, c, reopen := eventLogsCloud(t, backend, source)
			var logs *cloudwatchlogs.Client
			var events *eventbridge.Client
			var queues *sqs.Client
			clients := func() {
				logs = logsClient(c, "test")
				events = eventbridge.New(eventbridge.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				queues = c.sqs("test", "test", "")
			}
			clients()
			var queueURL *string
			var group cloudwatchlogs.CreateLogGroupInput
			if err := json.Unmarshal(fixture.observation(t, "create-group").Input, &group); err != nil {
				t.Fatal(err)
			}
			var expected []logtypes.FilteredLogEvent
			assertLogs := func() {
				t.Helper()
				input := cloudwatchlogs.FilterLogEventsInput{LogGroupName: group.LogGroupName}
				var actual []logtypes.FilteredLogEvent
				for {
					out, err := logs.FilterLogEvents(t.Context(), &input)
					if err != nil {
						t.Fatal(err)
					}
					actual = append(actual, out.Events...)
					if out.NextToken == nil {
						break
					}
					if reflect.DeepEqual(input.NextToken, out.NextToken) {
						t.Fatal("Logs pagination did not advance")
					}
					input.NextToken = out.NextToken
				}
				if len(actual) != len(expected) {
					t.Fatalf("delivered Logs corpus: got %+v, native %+v", actual, expected)
				}
				for i, want := range expected {
					if !reflect.DeepEqual(actual[i].Timestamp, want.Timestamp) {
						t.Errorf("Logs timestamp: got %d, native %d", aws.ToInt64(actual[i].Timestamp), aws.ToInt64(want.Timestamp))
					}
					assertEventInputBody(t, aws.ToString(actual[i].Message), aws.ToString(want.Message))
					// Discover the actual stream instead of pinning native UUIDs.
					out, err := logs.GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: input.LogGroupName, LogStreamName: actual[i].LogStreamName, StartFromHead: aws.Bool(true)})
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, event := range out.Events {
						if aws.ToInt64(event.Timestamp) == aws.ToInt64(actual[i].Timestamp) && aws.ToString(event.Message) == aws.ToString(actual[i].Message) {
							found = true
						}
					}
					if !found {
						t.Fatal("filtered event unavailable through its stream", actual[i], out.Events)
					}
				}
			}
			for _, row := range fixture.Observations {
				if strings.HasPrefix(row.Label, "cleanup-") {
					continue
				}
				if at := time.UnixMilli(row.Started); at.After(source.Now()) {
					advanceClock(t, source, at.Sub(source.Now()))
				}
				switch row.Operation {
				case "create-log-group", "put-retention-policy", "put-resource-policy":
					replayEventLogs(t, logs, row)
					continue
				case "delete-resource-policy":
					replayEventLogs(t, logs, row)
					continue
				case "create-event-bus", "put-rule":
					replayEventLogs(t, events, row)
					continue
				case "create-queue":
					queueURL = replayEventLogs(t, queues, row).(*sqs.CreateQueueOutput).QueueUrl
					continue
				case "set-queue-attributes":
					replayEventLogs(t, queues, row, func(input any) {
						// Only the queue endpoint differs from native identity.
						input.(*sqs.SetQueueAttributesInput).QueueUrl = queueURL
					})
					continue
				case "put-targets":
					out := replayEventLogs(t, events, row)
					if out != nil {
						targets := out.(*eventbridge.PutTargetsOutput)
						if targets.FailedEntryCount != 0 || len(targets.FailedEntries) != 0 {
							t.Fatal("native admitted Logs target failed", targets)
						}
					}
					continue
				case "put-events":
				default:
					// Native polls establish the corpus below, not a cadence or
					// transient visibility contract. Policy reads have their own test.
					continue
				}
				stage := strings.TrimPrefix(row.Label, "put-event-")
				accepted := replayEventLogs(t, events, row).(*eventbridge.PutEventsOutput)
				if accepted.FailedEntryCount != 0 || len(accepted.Entries) != 1 || aws.ToString(accepted.Entries[0].EventId) == "" {
					t.Fatal("Logs event admission failed", accepted)
				}
				if backend == "sqlite" {
					cloud, c = reopen()
					clients()
					// Reopening changes the httptest endpoint, not the queue identity.
					var input sqs.CreateQueueInput
					if err := json.Unmarshal(fixture.observation(t, "create-dlq").Input, &input); err != nil {
						t.Fatal(err)
					}
					out, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: input.QueueName})
					if err != nil {
						t.Fatal(err)
					}
					queueURL = out.QueueUrl
				}
				if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
					t.Fatal(err)
				}
				corpus, ok := fixture.Delivery[stage]
				if !ok || corpus.EventID == "" {
					t.Fatalf("missing native %s delivery corpus", stage)
				}
				for _, event := range corpus.Events {
					// Preserve the native envelope's second truncation and Logs
					// timestamp. Only the locally allocated event ID is substituted.
					event.Message = aws.String(strings.ReplaceAll(aws.ToString(event.Message), corpus.EventID, aws.ToString(accepted.Entries[0].EventId)))
					expected = append(expected, event)
				}
				assertLogs()
				out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
				if err != nil {
					t.Fatal(err)
				}
				dlq := corpus
				if stage == "revoked" {
					dlq = fixture.Delivery["revocation_dlq"]
				}
				// Native polls can re-receive an older, unacknowledged failure.
				// We acknowledge each local failure below, so compare only the
				// native messages correlated to this admitted event.
				messages := dlq.Messages
				dlq.Messages = nil
				for _, message := range messages {
					var envelope struct{ ID string }
					if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &envelope); err != nil {
						t.Fatal(err)
					}
					if envelope.ID == dlq.EventID {
						dlq.Messages = append(dlq.Messages, message)
					}
				}
				if len(out.Messages) != len(dlq.Messages) {
					t.Fatalf("%s DLQ delivery: got %+v, native %+v", stage, out.Messages, dlq.Messages)
				}
				if len(dlq.Messages) == 0 {
					if len(corpus.Events) != 1 {
						t.Fatalf("native %s has neither a delivered log nor a DLQ message", stage)
					}
					continue
				}
				if len(dlq.Messages) != 1 || len(corpus.Events) != 0 {
					t.Fatalf("ambiguous native failure corpus for %s", stage)
				}
				want := dlq.Messages[0]
				assertEventInputBody(t, aws.ToString(out.Messages[0].Body), strings.ReplaceAll(aws.ToString(want.Body), dlq.EventID, aws.ToString(accepted.Entries[0].EventId)))
				attributes := make(map[string]string, len(want.MessageAttributes))
				for name, value := range want.MessageAttributes {
					attributes[name] = aws.ToString(value.StringValue)
				}
				assertEventDeliveryAttributes(t, out.Messages[0].MessageAttributes, attributes)
				if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queueURL, ReceiptHandle: out.Messages[0].ReceiptHandle}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
