package stackd_test

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd"
	"stackd/clock"
	computelambda "stackd/compute/lambda"
)

// These captures retain boto3 binary values explicitly rather than losing bytes
// to JSON string conversion. Only request binary wrappers and operation spelling
// need adaptation for the existing SDK replay helper.
func firehoseCapturedCalls(t *testing.T, calls []firehoseNativeCall) firehoseNativeFixture {
	t.Helper()
	var normalize func(any) any
	normalize = func(value any) any {
		switch value := value.(type) {
		case map[string]any:
			if encoded, ok := value["base64"].(string); ok && len(value) == 2 && value["byteLength"] != nil {
				return encoded
			}
			for key, child := range value {
				value[key] = normalize(child)
			}
		case []any:
			for i, child := range value {
				value[i] = normalize(child)
			}
		}
		return value
	}
	for i := range calls {
		var input any
		if err := json.Unmarshal(calls[i].Input, &input); err != nil {
			t.Fatal(err)
		}
		var err error
		calls[i].Input, err = json.Marshal(normalize(input))
		if err != nil {
			t.Fatal(err)
		}
		calls[i].Operation = strings.ReplaceAll(calls[i].Operation, "_", "-")
	}
	return firehoseNativeFixture{Calls: calls}
}

// Setup may have repeated native IAM-propagation attempts under the same label.
func firehoseCapturedRow(t *testing.T, fixture firehoseNativeFixture, label string) firehoseNativeCall {
	t.Helper()
	for i := len(fixture.Calls) - 1; i >= 0; i-- {
		if fixture.Calls[i].Label == label {
			return fixture.Calls[i]
		}
	}
	t.Fatalf("missing captured Firehose call %q", label)
	return firehoseNativeCall{}
}

type firehoseBoundaryRecord struct {
	RecordID, Data              string
	ApproximateArrivalTimestamp float64
	KinesisRecordMetadata       *struct {
		SequenceNumber, PartitionKey, ShardID string
		SubsequenceNumber                     *int64
		ApproximateArrivalTimestamp           float64
	}
}

type firehoseBoundaryEvent struct {
	InvocationID, DeliveryStreamARN, SourceKinesisStreamARN, Region string
	Records                                                         []firehoseBoundaryRecord
}

type firehoseBoundaryFixture struct {
	Calls    []firehoseNativeCall
	Metadata struct {
		Account, Region string
		StartedAt       time.Time
	}
	Resources struct {
		Bucket                      string
		Functions, Streams, Kinesis []string
	}
	RecordCorrelations []struct {
		Label                string
		ProducerCallSequence int
		LambdaRecords        []struct{ Record firehoseBoundaryRecord }
		ConsumerObjects      []struct {
			Key, Kind string
			Error     firehoseProcessingError
		}
	}
	DecodedInvocations []struct{ Event firehoseBoundaryEvent }
	DecodedResponses   []struct {
		Result struct {
			Records []struct{ RecordID, Data string }
		}
	}
}

type firehoseBoundaryWant struct {
	Record                            firehoseBoundaryRecord
	Event                             firehoseBoundaryEvent
	Attempts                          int
	Arrival                           int64
	PublicID, SequenceNumber, ShardID string
}

// Replay malformed outputs, actual function execution failures, retries and KPL
// source records. Native IDs, timing and aggregate packing are not contracts.
func TestFirehoseNativeProcessingBoundaries(t *testing.T) {
	lambdaURLDocker(t)
	var plan struct {
		Source               string
		Setup, Creates, Puts []string
	}
	awsReadFixture(t, "firehose/boundaries_replay.json", &plan)
	var native firehoseBoundaryFixture
	awsReadFixture(t, "firehose/"+plan.Source, &native)
	fixture := firehoseCapturedCalls(t, native.Calls)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(native.Metadata.StartedAt.UTC().Truncate(time.Second))
			runtime := newKinesisReplayRuntime(t)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Metadata.Account, Clock: source, KinesisRuntime: runtime},
				func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					return newLambdaDockerStack(t, config, &computelambda.DockerConfig{Client: runtime.client})
				})
			replay := func(row firehoseNativeCall) any {
				var client any
				switch row.Service {
				case "s3":
					client = s3NativeClient(clients, "test", "test")
				case "iam":
					client = clients.iam("test", "test", "")
				case "logs":
					client = logsClient(clients, "test")
				case "lambda":
					client = lambdaDynamoDBClient(clients)
				case "kinesis":
					client = clients.kinesis("test", "test", "")
				case "firehose":
					client = clients.firehose("test", "test", "")
				default:
					t.Fatalf("unsupported boundary service %s", row.Service)
				}
				return firehoseReplayCall(t, client, row)
			}
			for _, row := range fixture.Calls {
				if slices.Contains(plan.Setup, row.Label) && row.Result.Code == "Success" {
					replay(row)
				}
			}
			for _, name := range native.Resources.Kinesis {
				awaitKinesisActive(t, source, clients.kinesis("test", "test", ""), name)
			}
			for _, name := range native.Resources.Functions {
				if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			for _, label := range plan.Creates {
				replay(firehoseCapturedRow(t, fixture, label))
			}
			for _, name := range native.Resources.Streams {
				awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), name)
			}
			clients = reopen()

			wanted := map[string]*firehoseBoundaryWant{}
			for _, invocation := range native.DecodedInvocations {
				for _, record := range invocation.Event.Records {
					if wanted[record.Data] == nil {
						wanted[record.Data] = &firehoseBoundaryWant{Record: record, Event: invocation.Event}
					}
					wanted[record.Data].Attempts++
				}
			}
			for _, label := range plan.Puts {
				row := firehoseCapturedRow(t, fixture, label)
				arrival := source.Now().UnixMilli()
				out := replay(row)
				for _, correlation := range native.RecordCorrelations {
					if correlation.ProducerCallSequence != row.Sequence {
						continue
					}
					for _, invocation := range correlation.LambdaRecords {
						want := wanted[invocation.Record.Data]
						if want == nil {
							t.Fatalf("missing captured invocation for %s", label)
						}
						want.Arrival = arrival
						switch out := out.(type) {
						case *firehose.PutRecordOutput:
							want.PublicID = aws.ToString(out.RecordId)
						case *kinesis.PutRecordOutput:
							want.SequenceNumber, want.ShardID = aws.ToString(out.SequenceNumber), aws.ToString(out.ShardId)
						default:
							t.Fatalf("unexpected boundary producer %T", out)
						}
					}
				}
			}
			firehoseBoundaryAwaitObjects(t, clients, source, native, wanted)
			firehoseBoundaryAwaitInvocations(t, clients, source, native, wanted)
			// Completed records and their original/raw backup remain durable, and
			// delivery/reopening must not schedule another Lambda execution.
			clients = reopen()
			advanceClock(t, source, 3*time.Minute)
			firehoseBoundaryAwaitObjects(t, clients, source, native, wanted)
			firehoseBoundaryAwaitInvocations(t, clients, source, native, wanted)
		})
	}
}

func firehoseBoundaryAwaitObjects(t *testing.T, clients cloudClients, source *clock.Manual, native firehoseBoundaryFixture, wanted map[string]*firehoseBoundaryWant) {
	t.Helper()
	transformed := map[string]string{}
	for _, response := range native.DecodedResponses {
		for _, record := range response.Result.Records {
			transformed[record.RecordID] = record.Data
		}
	}
	wantBytes := map[string][][]byte{}
	wantErrors := map[string]firehoseProcessingError{}
	for _, correlation := range native.RecordCorrelations {
		for _, consumer := range correlation.ConsumerObjects {
			parts := strings.SplitN(consumer.Key, "/", 3)
			prefix := parts[0] + "/" + parts[1] + "/"
			if consumer.Kind == "processing-error" {
				wantErrors[consumer.Error.RawData] = consumer.Error
				continue
			}
			seen := map[string]bool{}
			for _, invocation := range correlation.LambdaRecords {
				record := invocation.Record
				if seen[record.Data] {
					continue
				}
				seen[record.Data] = true
				encoded := record.Data
				switch consumer.Kind {
				case "raw-backup":
				case "destination":
					var ok bool
					encoded, ok = transformed[record.RecordID]
					if !ok {
						t.Fatalf("missing captured transform for %s", correlation.Label)
					}
				default:
					t.Fatalf("unknown boundary consumer %s", consumer.Kind)
				}
				wantBytes[prefix] = append(wantBytes[prefix], firehoseProcessingDecode(t, encoded))
			}
		}
	}
	firehoseProcessingPoll(t, clients, source, func() bool {
		remaining := map[string][][]byte{}
		for prefix, records := range wantBytes {
			remaining[prefix] = slices.Clone(records)
		}
		seenErrors := map[string]bool{}
		for key, body := range firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, "") {
			if strings.Contains(key, "/errors/") {
				if !strings.Contains(key, "/errors/processing-failed/") {
					t.Fatalf("wrong processing error prefix: %s", key)
				}
				decoder := json.NewDecoder(bytes.NewReader(body))
				for {
					var got firehoseProcessingError
					if err := decoder.Decode(&got); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					want, ok := wantErrors[got.RawData]
					if !ok || seenErrors[got.RawData] {
						t.Fatalf("unexpected/duplicate processing error: %+v", got)
					}
					if got.ErrorCode != want.ErrorCode || got.AttemptsMade != want.AttemptsMade || got.LambdaARN != want.LambdaARN || got.ErrorMessage == "" {
						t.Fatalf("%s consumer error=%+v, native=%+v", key, got, want)
					}
					if got.ArrivalTimestamp != float64(wanted[got.RawData].Arrival) || got.AttemptEndingTimestamp < got.ArrivalTimestamp || got.AttemptEndingTimestamp > float64(source.Now().UnixMilli()) || math.Trunc(got.AttemptEndingTimestamp) != got.AttemptEndingTimestamp {
						t.Fatalf("invalid processing millisecond timestamps: %+v", got)
					}
					seenErrors[got.RawData] = true
				}
				continue
			}
			parts := strings.SplitN(key, "/", 3)
			prefix := parts[0] + "/" + parts[1] + "/"
			for len(body) > 0 {
				match := -1
				for i, record := range remaining[prefix] {
					if len(record) > 0 && bytes.HasPrefix(body, record) && (match < 0 || len(record) > len(remaining[prefix][match])) {
						match = i
					}
				}
				if match < 0 {
					t.Fatalf("corrupt, duplicate or unexpected boundary bytes in %s", key)
				}
				records := remaining[prefix]
				body = body[len(records[match]):]
				remaining[prefix] = append(records[:match], records[match+1:]...)
			}
		}
		for _, records := range remaining {
			if len(records) > 0 {
				return false
			}
		}
		return len(seenErrors) == len(wantErrors)
	})
}

func firehoseBoundaryAwaitInvocations(t *testing.T, clients cloudClients, source *clock.Manual, native firehoseBoundaryFixture, wanted map[string]*firehoseBoundaryWant) {
	t.Helper()
	firehoseProcessingPoll(t, clients, source, func() bool {
		seen, recordIDs, invocationIDs := map[string]int{}, map[string]string{}, map[string]bool{}
		idOwners := map[string]string{}
		for _, name := range native.Resources.Functions {
			pages := cloudwatchlogs.NewFilterLogEventsPaginator(logsClient(clients, "test"), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + name)})
			for pages.HasMorePages() {
				page, err := pages.NextPage(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range page.Events {
					_, text, ok := strings.Cut(aws.ToString(entry.Message), "FH_INPUT ")
					if !ok {
						continue
					}
					var logged struct{ Event firehoseBoundaryEvent }
					if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &logged); err != nil {
						t.Fatal(err)
					}
					event := logged.Event
					if event.InvocationID == "" || invocationIDs[event.InvocationID] {
						t.Fatalf("invocationId reused between actual Lambda attempts: %s", event.InvocationID)
					}
					invocationIDs[event.InvocationID] = true
					for _, record := range event.Records {
						want := wanted[record.Data]
						if want == nil {
							t.Fatalf("unexpected Lambda input %s", record.Data)
						}
						if event.Region != native.Metadata.Region || event.DeliveryStreamARN != want.Event.DeliveryStreamARN || event.SourceKinesisStreamARN != want.Event.SourceKinesisStreamARN {
							t.Fatalf("incorrect source envelope: %+v", event)
						}
						if record.RecordID == "" || record.RecordID == want.PublicID || record.ApproximateArrivalTimestamp != float64(want.Arrival) {
							t.Fatalf("uncorrelated source record: %+v", record)
						}
						if previous := recordIDs[record.Data]; previous != "" && previous != record.RecordID {
							t.Fatalf("recordId changed across attempts for %s", record.Data)
						}
						if owner, exists := idOwners[record.RecordID]; exists && owner != record.Data {
							t.Fatal("distinct source records share a recordId")
						}
						recordIDs[record.Data], idOwners[record.RecordID] = record.RecordID, record.Data
						metadata, expected := record.KinesisRecordMetadata, want.Record.KinesisRecordMetadata
						if expected == nil {
							if metadata != nil {
								t.Fatal("DirectPut acquired Kinesis metadata")
							}
						} else if metadata == nil || metadata.SubsequenceNumber == nil || expected.SubsequenceNumber == nil || *metadata.SubsequenceNumber != *expected.SubsequenceNumber || metadata.SequenceNumber != want.SequenceNumber || metadata.ShardID != want.ShardID || metadata.PartitionKey != expected.PartitionKey || metadata.ApproximateArrivalTimestamp != float64(want.Arrival) {
							t.Fatalf("plain/KPL source metadata does not correlate with accepted producer record: got %+v, native %+v, sequence %s shard %s", metadata, expected, want.SequenceNumber, want.ShardID)
						}
						seen[record.Data]++
						if seen[record.Data] > want.Attempts {
							t.Fatalf("extra Lambda attempts for %s: %d > %d", record.Data, seen[record.Data], want.Attempts)
						}
					}
				}
			}
		}
		for data, want := range wanted {
			if seen[data] != want.Attempts {
				return false
			}
		}
		return true
	})
}
