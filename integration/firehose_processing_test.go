package stackd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd"
	"stackd/clock"
)

type firehoseProcessingCase struct {
	ProducerCallLabel, StreamKind, InputBase64 string
	LambdaRecords                              []struct {
		Record struct{ RecordID string }
	}
	ConsumerObjects []struct {
		Kind, Key string
		Error     firehoseProcessingError
	}
}

type firehoseProcessingError struct {
	RawData, ErrorCode, ErrorMessage         string
	LambdaARN                                string `json:"lambdaARN"`
	AttemptsMade                             int
	ArrivalTimestamp, AttemptEndingTimestamp float64
}

type firehoseProcessingFixture struct {
	firehoseNativeFixture
	Metadata struct {
		Account, Region string
		StartedAt       time.Time
	}
	Resources struct {
		Bucket, Function string
		Streams          []string
	}
	HandlerSource  string
	Cases          []firehoseProcessingCase
	LambdaEvidence []struct{ Message string }
}

// Only the native request selection lives in the small manifest. Producer bytes,
// outcomes, handler code, transformed bytes and configuration all come from the
// captured execution. Container wall time is never equated with the manual clock.
func TestFirehoseNativeLambdaProcessing(t *testing.T) {
	lambdaURLDocker(t)
	var plan struct {
		Source         string
		Setup, Creates []string
		Transitions    []struct{ Change, Describe string }
		Waves          []struct {
			Before, Puts   []string
			Describe       string
			InitialMetrics bool
		}
		InitialMetrics map[string]float64
		Irreversible   struct{ Reject, Target, Describe string }
		Recovery       struct{ Update, Put, PrimaryPrefix, BackupPrefix string }
		LocalRecords   []struct{ Data, Transformed []byte }
	}
	awsReadFixture(t, "firehose/"+"processing_replay.json", &plan)
	var native firehoseProcessingFixture
	awsReadFixture(t, "firehose/"+plan.Source, &native)
	// boto3 uses underscores; the shared SDK replay helper accepts CLI spelling.
	for i := range native.Calls {
		native.Calls[i].Operation = strings.ReplaceAll(native.Calls[i].Operation, "_", "-")
	}
	transformed := firehoseProcessingNativeOutputs(t, native)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			start := native.Metadata.StartedAt.UTC().Truncate(time.Minute)
			source := clock.NewManual(start)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.Metadata.Account, Clock: source},
				func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					return newLambdaDockerStack(t, config, nil)
				})
			replay := func(label string) any {
				row := native.row(t, label)
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
				case "firehose":
					client = clients.firehose("test", "test", "")
				default:
					t.Fatalf("unsupported processing prerequisite %q", row.Service)
				}
				return firehoseReplayCall(t, client, row)
			}
			for _, label := range plan.Setup {
				replay(label)
			}
			if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &native.Resources.Function}, time.Minute); err != nil {
				t.Fatal(err)
			}
			for _, label := range plan.Creates {
				replay(label)
			}
			for _, name := range native.Resources.Streams {
				awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), name)
			}
			for _, transition := range plan.Transitions {
				if transition.Change != "" {
					replay(transition.Change)
				}
				firehoseProcessingDescription(t, clients, native.row(t, transition.Describe))
			}

			selected := map[string]bool{}
			publicIDs := map[string]string{}
			arrivals := map[string]int64{}
			put := func(label string) {
				row := native.row(t, label)
				var input struct {
					Record  firehosetypes.Record
					Records []firehosetypes.Record
				}
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				at := source.Now().UnixMilli()
				out := replay(label)
				var ids []string
				switch result := out.(type) {
				case *firehose.PutRecordOutput:
					input.Records = []firehosetypes.Record{input.Record}
					ids = []string{aws.ToString(result.RecordId)}
				case *firehose.PutRecordBatchOutput:
					if aws.ToInt32(result.FailedPutCount) != 0 || len(result.RequestResponses) != len(input.Records) {
						t.Fatalf("%s admission: %+v", label, result)
					}
					for _, response := range result.RequestResponses {
						if response.ErrorCode != nil {
							t.Fatalf("%s rejected: %+v", label, response)
						}
						ids = append(ids, aws.ToString(response.RecordId))
					}
				default:
					t.Fatalf("%s is not a producer request", label)
				}
				for i, record := range input.Records {
					key := base64.StdEncoding.EncodeToString(record.Data)
					if ids[i] == "" {
						t.Fatal("empty public record ID")
					}
					publicIDs[key], arrivals[key] = ids[i], at
				}
				selected[label] = true
			}
			for _, wave := range plan.Waves {
				for _, label := range wave.Before {
					replay(label)
				}
				if wave.Describe != "" {
					firehoseProcessingDescription(t, clients, native.row(t, wave.Describe))
				}
				for _, label := range wave.Puts {
					put(label)
				}
				firehoseProcessingAwait(t, clients, source, native, selected, transformed, arrivals)
				if wave.InitialMetrics {
					for name, want := range plan.InitialMetrics {
						row := native.row(t, "metrics-early-enabled-"+name)
						firehoseProcessingPoll(t, clients, source, func() bool {
							got := firehoseDeliveryStatistics(t, clients, row, start, source.Now().Add(time.Minute))
							if got.Sum > want {
								t.Fatalf("%s sum=%g exceeds original-byte/native total %g", name, got.Sum, want)
							}
							return got.Sum == want
						})
					}
				}
			}
			// Replay the captured irreversible transition against the stream
			// enabled by UpdateDestination, not only the one enabled at creation.
			var enabled firehose.UpdateDestinationInput
			if err := json.Unmarshal(native.row(t, plan.Irreversible.Target).Input, &enabled); err != nil {
				t.Fatal(err)
			}
			firehoseReplayCall(t, clients.firehose("test", "test", ""), native.row(t, plan.Irreversible.Reject), func(input any) {
				input.(*firehose.UpdateDestinationInput).DeliveryStreamName = enabled.DeliveryStreamName
			})
			firehoseProcessingDescription(t, clients, native.row(t, plan.Irreversible.Describe))

			// Local durability experiment, not a claim about AWS retry cadence:
			// both transformed and backup obligations survive reopening, then only
			// backup is authorized, and primary survives another reopening/retry.
			replay(plan.Recovery.Update)
			role := native.Resources.Function + "-delivery"
			deny := func(prefixes ...string) {
				resources := make([]string, len(prefixes))
				for i, prefix := range prefixes {
					resources[i] = "arn:aws:s3:::" + native.Resources.Bucket + "/" + prefix + "*"
				}
				policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Deny", "Action": "s3:PutObject", "Resource": resources}}})
				if err != nil {
					t.Fatal(err)
				}
				_, err = clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: &role, PolicyName: aws.String("local-output-denial"), PolicyDocument: aws.String(string(policy))})
				if err != nil {
					t.Fatal(err)
				}
			}
			before := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, "")
			deny(plan.Recovery.PrimaryPrefix, plan.Recovery.BackupPrefix)
			put(plan.Recovery.Put)
			firehoseProcessingAwaitInvocations(t, clients, source, native, selected, publicIDs, arrivals)
			// Observe processing completion through its public aggregate before
			// closing; handler return/log publication alone can precede completion.
			metric := native.row(t, "metrics-final-enabled-SucceedProcessing.Records")
			firehoseProcessingPoll(t, clients, source, func() bool {
				return firehoseDeliveryStatistics(t, clients, metric, start, source.Now().Add(time.Minute)).Sum == 2
			})
			clients = reopen()
			advanceClock(t, source, 3*time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			if got := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, ""); !reflect.DeepEqual(got, before) {
				t.Fatal("denied output escaped to S3")
			}
			deny(plan.Recovery.PrimaryPrefix)
			var boundaryRaw []byte
			for _, c := range native.Cases {
				if c.ProducerCallLabel == plan.Recovery.Put {
					boundaryRaw = firehoseProcessingDecode(t, c.InputBase64)
				}
			}
			if len(boundaryRaw) == 0 {
				t.Fatal("native boundary record absent")
			}
			firehoseProcessingPoll(t, clients, source, func() bool {
				objects := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, plan.Recovery.BackupPrefix)
				for key, body := range objects {
					if _, old := before[key]; !old && bytes.Contains(body, boundaryRaw) {
						return true
					}
				}
				return false
			})
			if objects := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, plan.Recovery.PrimaryPrefix); len(objects) != 0 {
				t.Fatal("primary write escaped its denial while backup was independently delivered")
			}
			clients = reopen()
			if _, err := clients.iam("test", "test", "").DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: &role, PolicyName: aws.String("local-output-denial")}); err != nil {
				t.Fatal(err)
			}
			firehoseProcessingAwait(t, clients, source, native, selected, transformed, arrivals)
			firehoseProcessingAwaitInvocations(t, clients, source, native, selected, publicIDs, arrivals)
			var localStream struct{ DeliveryStreamName *string }
			if err := json.Unmarshal(native.row(t, plan.Recovery.Put).Input, &localStream); err != nil {
				t.Fatal(err)
			}
			for _, record := range plan.LocalRecords {
				before := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, plan.Recovery.PrimaryPrefix)
				if _, err := clients.firehose("test", "test", "").PutRecord(t.Context(), &firehose.PutRecordInput{DeliveryStreamName: localStream.DeliveryStreamName, Record: &firehosetypes.Record{Data: record.Data}}); err != nil {
					t.Fatal(err)
				}
				firehoseProcessingPoll(t, clients, source, func() bool {
					for key, body := range firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, plan.Recovery.PrimaryPrefix) {
						if _, old := before[key]; !old && bytes.Equal(body, record.Transformed) {
							return true
						}
					}
					return false
				})
			}
		})
	}
}

func firehoseProcessingDecode(t *testing.T, value string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func firehoseProcessingNativeOutputs(t *testing.T, native firehoseProcessingFixture) map[string][]byte {
	t.Helper()
	byID := map[string][]byte{}
	for _, log := range native.LambdaEvidence {
		_, text, found := strings.Cut(log.Message, "FH_OUTPUT ")
		if !found {
			continue
		}
		var output struct {
			Result struct {
				Records []struct{ RecordID, Data string }
			}
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &output); err != nil {
			t.Fatal(err)
		}
		for _, record := range output.Result.Records {
			byID[record.RecordID] = firehoseProcessingDecode(t, record.Data)
		}
	}
	out := map[string][]byte{}
	for _, c := range native.Cases {
		for _, consumer := range c.ConsumerObjects {
			if consumer.Kind != "transformed-destination" {
				continue
			}
			for _, invocation := range c.LambdaRecords {
				if data, ok := byID[invocation.Record.RecordID]; ok {
					out[c.InputBase64] = data
				}
			}
			if _, ok := out[c.InputBase64]; !ok {
				t.Fatalf("native transformed record lacks captured handler output: %s", c.ProducerCallLabel)
			}
		}
	}
	return out
}

func firehoseProcessingDescription(t *testing.T, clients cloudClients, row firehoseNativeCall) {
	t.Helper()
	var expected firehose.DescribeDeliveryStreamOutput
	if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
		t.Fatal(err)
	}
	actual := firehoseReplayCall(t, clients.firehose("test", "test", ""), row).(*firehose.DescribeDeliveryStreamOutput)
	want, got := expected.DeliveryStreamDescription, actual.DeliveryStreamDescription
	if aws.ToString(got.VersionId) != aws.ToString(want.VersionId) {
		t.Fatalf("%s version=%s want=%s", row.Label, aws.ToString(got.VersionId), aws.ToString(want.VersionId))
	}
	// Parameter order is not semantic. Compare the public normalized values and
	// the destination/backup configuration, not timestamps or generated IDs.
	project := func(d *firehosetypes.ExtendedS3DestinationDescription) any {
		parameters := map[string]string{}
		for _, p := range d.ProcessingConfiguration.Processors {
			for _, v := range p.Parameters {
				parameters[string(v.ParameterName)] = aws.ToString(v.ParameterValue)
			}
		}
		var backup any
		if b := d.S3BackupDescription; b != nil {
			backup = []any{aws.ToString(b.RoleARN), aws.ToString(b.BucketARN), aws.ToString(b.Prefix), b.BufferingHints}
		}
		return []any{parameters, aws.ToBool(d.ProcessingConfiguration.Enabled), d.S3BackupMode, backup, aws.ToString(d.Prefix), d.BufferingHints}
	}
	if !reflect.DeepEqual(project(got.Destinations[0].ExtendedS3DestinationDescription), project(want.Destinations[0].ExtendedS3DestinationDescription)) {
		t.Fatalf("%s normalized processing/backup destination differs: got %+v want %+v", row.Label, project(got.Destinations[0].ExtendedS3DestinationDescription), project(want.Destinations[0].ExtendedS3DestinationDescription))
	}
}

// Poll ordinary consumers while advancing service-owned deadlines; give real
// customer execution wall time without running customer code in the drain gate.
func firehoseProcessingPoll(t *testing.T, clients cloudClients, source *clock.Manual, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for i := 0; time.Now().Before(deadline); i++ {
		trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
		if ready() {
			return
		}
		if i%10 == 0 {
			advanceClock(t, source, 10*time.Second)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("processing consumer did not reach its expected outcome within local replay bound")
}

func firehoseProcessingAwait(t *testing.T, clients cloudClients, source *clock.Manual, native firehoseProcessingFixture, selected map[string]bool, transformed map[string][]byte, arrivals map[string]int64) {
	t.Helper()
	wantBytes := map[string][][]byte{}
	wantErrors := map[string]firehoseProcessingError{}
	for _, c := range native.Cases {
		if !selected[c.ProducerCallLabel] {
			continue
		}
		for _, consumer := range c.ConsumerObjects {
			parts := strings.SplitN(consumer.Key, "/", 3)
			prefix := parts[0] + "/" + parts[1] + "/"
			switch consumer.Kind {
			case "raw-backup":
				wantBytes[prefix] = append(wantBytes[prefix], firehoseProcessingDecode(t, c.InputBase64))
			case "transformed-destination":
				wantBytes[prefix] = append(wantBytes[prefix], transformed[c.InputBase64])
			case "processing-error":
				wantErrors[c.InputBase64] = consumer.Error
			default:
				t.Fatalf("unknown native consumer %s", consumer.Kind)
			}
		}
	}
	firehoseProcessingPoll(t, clients, source, func() bool {
		objects := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), native.Resources.Bucket, "")
		remaining := map[string][][]byte{}
		for prefix, records := range wantBytes {
			remaining[prefix] = append([][]byte(nil), records...)
		}
		seenErrors := map[string]bool{}
		for key, body := range objects {
			if strings.Contains(key, "/errors/") {
				if !strings.Contains(key, "/errors/processing-failed/") {
					t.Fatalf("processing error delivered outside native error-output-type prefix: %s", key)
				}
				decoder := json.NewDecoder(bytes.NewReader(body))
				for {
					var raw map[string]json.RawMessage
					if err := decoder.Decode(&raw); err == io.EOF {
						break
					} else if err != nil {
						t.Fatalf("%s error envelope: %v", key, err)
					}
					encoded, err := json.Marshal(raw)
					if err != nil {
						t.Fatal(err)
					}
					var got firehoseProcessingError
					if err := json.Unmarshal(encoded, &got); err != nil {
						t.Fatal(err)
					}
					want, exists := wantErrors[got.RawData]
					if !exists || seenErrors[got.RawData] {
						t.Fatalf("unexpected/duplicate processing failure in %s: %s", key, encoded)
					}
					if got.ErrorCode != want.ErrorCode || got.LambdaARN != want.LambdaARN || got.AttemptsMade != 1 || got.ErrorMessage == "" {
						t.Fatalf("%s error contract: %s", key, encoded)
					}
					if _, exists := raw["lambdaARN"]; !exists {
						t.Fatal("error envelope lacks native lambdaARN spelling")
					}
					if _, exists := raw["lambdaArn"]; exists {
						t.Fatal("non-native lambdaArn field")
					}
					if got.ArrivalTimestamp != float64(arrivals[got.RawData]) || got.AttemptEndingTimestamp < got.ArrivalTimestamp || got.AttemptEndingTimestamp > float64(source.Now().UnixMilli()) || math.Trunc(got.AttemptEndingTimestamp) != got.AttemptEndingTimestamp {
						t.Fatalf("%s requires numeric millisecond timestamps: %s", key, encoded)
					}
					seenErrors[got.RawData] = true
				}
				continue
			}
			parts := strings.SplitN(key, "/", 3)
			prefix := parts[0] + "/" + parts[1] + "/"
			for len(body) != 0 {
				match := -1
				for i, record := range remaining[prefix] {
					if bytes.HasPrefix(body, record) && len(record) != 0 && (match < 0 || len(record) > len(remaining[prefix][match])) {
						match = i
					}
				}
				if match < 0 {
					t.Fatalf("unexpected, corrupted or duplicate bytes in %s: %q", key, body)
				}
				records := remaining[prefix]
				body = body[len(records[match]):]
				remaining[prefix] = append(records[:match], records[match+1:]...)
			}
		}
		for _, records := range remaining {
			if len(records) != 0 {
				return false
			}
		}
		return len(seenErrors) == len(wantErrors)
	})
}

func firehoseProcessingAwaitInvocations(t *testing.T, clients cloudClients, source *clock.Manual, native firehoseProcessingFixture, selected map[string]bool, publicIDs map[string]string, arrivals map[string]int64) {
	t.Helper()
	want := map[string]bool{}
	for _, c := range native.Cases {
		if selected[c.ProducerCallLabel] {
			want[c.InputBase64] = len(c.LambdaRecords) != 0
		}
	}
	firehoseProcessingPoll(t, clients, source, func() bool {
		seen := map[string]int{}
		ids := map[string]bool{}
		pages := cloudwatchlogs.NewFilterLogEventsPaginator(logsClient(clients, "test"), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + native.Resources.Function)})
		for pages.HasMorePages() {
			page, err := pages.NextPage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range page.Events {
				_, text, found := strings.Cut(aws.ToString(entry.Message), "FH_INPUT ")
				if !found {
					continue
				}
				var logged struct {
					Event struct {
						InvocationID, DeliveryStreamARN, Region string
						Records                                 []map[string]json.RawMessage
					}
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &logged); err != nil {
					t.Fatal(err)
				}
				event := logged.Event
				if event.InvocationID == "" || event.Region != native.Metadata.Region || !strings.HasPrefix(event.DeliveryStreamARN, fmt.Sprintf("arn:aws:firehose:%s:%s:deliverystream/", native.Metadata.Region, native.Metadata.Account)) {
					t.Fatalf("invalid DirectPut envelope: %s", text)
				}
				for _, fields := range event.Records {
					if len(fields) != 3 || fields["recordId"] == nil || fields["approximateArrivalTimestamp"] == nil || fields["data"] == nil {
						t.Fatalf("DirectPut has fabricated metadata or incomplete record: %+v", fields)
					}
					var id, data string
					var arrival float64
					if err := json.Unmarshal(fields["recordId"], &id); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(fields["data"], &data); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(fields["approximateArrivalTimestamp"], &arrival); err != nil {
						t.Fatal(err)
					}
					if !want[data] || id == "" || ids[id] || id == publicIDs[data] || arrival != float64(arrivals[data]) {
						t.Fatalf("uncorrelated/reinvoked DirectPut record %s", data)
					}
					ids[id], seen[data] = true, seen[data]+1
				}
			}
		}
		for data, executes := range want {
			if executes && seen[data] != 1 {
				return false
			}
		}
		return true
	})
}
