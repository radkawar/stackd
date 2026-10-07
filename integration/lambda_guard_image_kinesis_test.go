package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/storage"
	kinesisstore "stackd/storage/kinesis"
	lambdastore "stackd/storage/lambda"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/uuid"
)

const lambdaGuardImageKinesisHandler = `import base64, boto3, json, os, uuid
MARKER = %q

def handler(event, context):
    if 'Records' not in event:
        return {'marker': MARKER, 'event': event}
    decoded = [json.loads(base64.b64decode(r['kinesis']['data'])) for r in event['Records']]
    failed = any(r['poison'] for r in decoded)
    result = {'ids': [r['id'] for r in decoded], 'sum': sum(r['ordinal'] for r in decoded)}
    report = {'marker': MARKER, 'request_id': context.aws_request_id,
              'invoked_arn': context.invoked_function_arn, 'event': event,
              'result': result, 'failed': failed}
    boto3.client('sqs', endpoint_url=os.environ['AWS_ENDPOINT_URL']).send_message(
        QueueUrl=os.environ['RESULT_QUEUE_URL'], MessageBody=json.dumps(report),
        MessageGroupId='image-kinesis', MessageDeduplicationId=str(uuid.uuid4()))
    if failed:
        raise RuntimeError('owned poison record: ' + ','.join(result['ids']))
    return result
`

type lambdaGuardImageKinesisReport struct {
	Marker     string
	RequestID  string `json:"request_id"`
	InvokedARN string `json:"invoked_arn"`
	Event      map[string]any
	Result     struct {
		IDs []string
		Sum int
	}
	Failed bool
}

type lambdaGuardImageKinesisWrite struct {
	Sequence, Shard string
	Data            []byte
	Ordinal         int
	Poison          bool
}

type lambdaGuardImageKinesisFailure struct {
	RequestContext struct {
		RequestID, FunctionARN, Condition string
		ApproximateInvokeCount            int
	}
	KinesisBatchInfo struct {
		StreamARN, ShardID, StartSequenceNumber, EndSequenceNumber      string
		ApproximateArrivalOfFirstRecord, ApproximateArrivalOfLastRecord string
		BatchSize                                                       int
	}
	ResponseContext json.RawMessage
	Payload         json.RawMessage
}

// Local execution evidence, not a newly captured native AWS fixture. The image
// is Docker-built from compute/lambda's installed official Python 3.12 RIC; the
// RIC consumes stackd's Runtime API and Kafka owns the actual source bytes.
// Native kinesis_followup calibrates child retry quota/request identities;
// kinesis_destination calibrates SQS metadata (NOT original payload delivery).
// Read-only authoritative rows anchor scheduling, never supply customer results.
func TestLambdaGuardImageKinesisDockerControls(t *testing.T) {
	lambdaURLDocker(t)
	if os.Getenv("STACKD_KINESIS_DOCKER") != "1" {
		t.Skip("set STACKD_KINESIS_DOCKER=1 to exercise the actual native stream engine")
	}
	calibration := lambdaFixture[lambdaKinesisFixture](t, "kinesis_followup")
	var nativePoison []lambdaDynamoDBInvocation
	for _, invocation := range calibration.Delivery["partial_bisect"].Invocations {
		records := invocation.Event["Records"].([]any)
		if len(records) == 1 && lambdaKinesisRecordData(t, records[0].(map[string]any))["bad"] == true {
			nativePoison = append(nativePoison, invocation)
		}
	}
	if len(nativePoison) != 2 || nativePoison[0].RequestID != nativePoison[1].RequestID {
		t.Fatal("native child retry calibration must contain one initial attempt plus one retry with retained identity")
	}
	nativeDestination := lambdaFixture[lambdaKinesisFixture](t, "kinesis_destination")
	var destinationSchema map[string]any
	for _, message := range nativeDestination.DestinationMessages {
		var document map[string]any
		if err := json.Unmarshal([]byte(message.Body), &document); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(document["requestContext"].(map[string]any)["functionArn"].(string), ":standard_destination") {
			destinationSchema = document
		}
	}
	if destinationSchema == nil || destinationSchema["payload"] != nil {
		t.Fatal("native SQS destination calibration must identify records without embedding customer bytes")
	}
	marker := "GUARD_IMAGE_KINESIS_" + uuid.NewString()
	image := buildLambdaLocalPython312Image(t, fmt.Sprintf(lambdaGuardImageKinesisHandler, marker))
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(calibration.StartedAt)
			var repository lambdastore.Repository
			var streamRepository kinesisstore.Repository
			var nextOpenAt time.Time
			clients, reopen := lambdaKinesisCloud(t, backend, source, func(backends *storage.Backends) {
				repository = backends.Lambda
				streamRepository = backends.Kinesis
				if !nextOpenAt.IsZero() {
					// retainedCloud already joined the old controller. Advancing
					// here cannot race a prior poll into an admitted invocation.
					advanceClock(t, source, nextOpenAt.Sub(source.Now()))
					nextOpenAt = time.Time{}
				}
			})
			var afterRestart func()
			restart := func(at ...time.Time) {
				t.Helper()
				nextOpenAt = source.Now()
				if len(at) != 0 {
					nextOpenAt = at[0]
				}
				clients = reopen()
				if afterRestart != nil {
					afterRestart()
				}
			}
			name := "guard-image-kinesis"
			stream, err := clients.kinesis("test", "test", "").CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &name, ShardCount: aws.Int32(1)})
			if err != nil || stream == nil {
				t.Fatal("creating actual Kafka-backed stream: ", err)
			}
			streamKey := kinesisstore.StreamKey{Scope: kinesisstore.Scope{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"}, Name: name}
			var streamRecord kinesisstore.StreamRecord
			readStream := func() {
				t.Helper()
				if err := streamRepository.View(t.Context(), func(reader kinesisstore.Reader) error {
					var err error
					streamRecord, err = reader.Stream(streamKey)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			readStream()
			// Kinesis requires its one-service-second lifecycle boundary and
			// real Kafka readiness. Move to that boundary only after Close has
			// joined the preceding controller and native image executor.
			restart(streamRecord.Pending.AcceptedAt.Add(time.Second))
			lambdaGuardImageKinesisAwait(t, "actual Kafka-backed stream activation", func() bool {
				readStream()
				return streamRecord.Data.StreamStatus != nil && *streamRecord.Data.StreamStatus == "ACTIVE"
			})
			description, err := clients.kinesis("test", "test", "").DescribeStreamSummary(t.Context(), &kinesis.DescribeStreamSummaryInput{StreamName: &name})
			if err != nil || description.StreamDescriptionSummary.StreamStatus != kinesistypes.StreamStatusActive {
				t.Fatalf("native stream activation did not reach its API: output=%+v error=%v", description, err)
			}
			streamARN := aws.ToString(description.StreamDescriptionSummary.StreamARN)
			queue := func(suffix string, fifo bool) (*string, string) {
				t.Helper()
				input := &sqs.CreateQueueInput{QueueName: aws.String(name + suffix)}
				if fifo {
					input.Attributes = map[string]string{"FifoQueue": "true"}
				}
				created, err := clients.sqs("test", "test", "").CreateQueue(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				attributes, err := clients.sqs("test", "test", "").GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: created.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
				if err != nil {
					t.Fatal(err)
				}
				return created.QueueUrl, attributes.Attributes["QueueArn"]
			}
			resultURL, resultARN := queue("-results.fifo", true)
			failureURL, failureARN := queue("-failures", false)
			role, err := clients.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: &name, AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			logARN := "arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/" + name
			putRolePolicy(t, clients.iam("test", "test", ""), name, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kinesis:DescribeStream","kinesis:DescribeStreamSummary","kinesis:ListShards","kinesis:GetShardIterator","kinesis:GetRecords"],"Resource":%q},{"Effect":"Allow","Action":"sqs:SendMessage","Resource":[%q,%q]},{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":[%q,%q]}]}`, streamARN, resultARN, failureARN, logARN, logARN+":*"))
			created, err := lambdaDynamoDBClient(clients).CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: &name, Role: role.Role.Arn, PackageType: lambdatypes.PackageTypeImage, Code: &lambdatypes.FunctionCode{ImageUri: &image}, Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureX8664}, Timeout: aws.Int32(20), Environment: &lambdatypes.Environment{Variables: map[string]string{"RESULT_QUEUE_URL": aws.ToString(resultURL)}}})
			if err != nil {
				t.Fatal(err)
			}
			functionARN := aws.ToString(created.FunctionArn)
			functionDeleted := false
			installCleanup := func() {
				current := clients
				t.Cleanup(func() {
					if functionDeleted || current.server != clients.server {
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					if _, err := lambdaDynamoDBClient(current).DeleteFunction(ctx, &awslambda.DeleteFunctionInput{FunctionName: &name}); err != nil {
						t.Errorf("deleting exact-owned image function: %v", err)
					} else {
						functionDeleted = true
					}
				})
			}
			afterRestart = installCleanup
			installCleanup()
			if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			probe, err := lambdaDynamoDBClient(clients).Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: &name, Payload: []byte(`{"route":"actual-official-ric"}`)})
			if err != nil {
				t.Fatal(err)
			}
			var probeResult struct {
				Marker string
				Event  map[string]string
			}
			if err := json.Unmarshal(probe.Payload, &probeResult); err != nil || probe.FunctionError != nil || probeResult.Marker != marker || probeResult.Event["route"] != "actual-official-ric" {
				t.Fatalf("customer code did not return through the image Runtime API: error=%v payload=%s", err, probe.Payload)
			}

			written := make(map[string]lambdaGuardImageKinesisWrite)
			var lastWrittenSequence string
			put := func(ids []string, poison string) {
				t.Helper()
				for i, id := range ids {
					data, err := json.Marshal(map[string]any{"id": id, "ordinal": i + 1, "poison": id == poison})
					if err != nil {
						t.Fatal(err)
					}
					// Sequential accepted writes bind batch order to native
					// sequences; PutRecords does not promise per-key ordering.
					out, err := clients.kinesis("test", "test", "").PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: &streamARN, PartitionKey: aws.String("owned-key"), Data: data})
					if err != nil {
						t.Fatal(err)
					}
					written[id] = lambdaGuardImageKinesisWrite{Sequence: aws.ToString(out.SequenceNumber), Shard: aws.ToString(out.ShardId), Data: data, Ordinal: i + 1, Poison: id == poison}
					lastWrittenSequence = written[id].Sequence
				}
			}
			put([]string{"before-latest"}, "")
			mapping, err := lambdaDynamoDBClient(clients).CreateEventSourceMapping(t.Context(), &awslambda.CreateEventSourceMappingInput{FunctionName: &name, EventSourceArn: &streamARN, StartingPosition: lambdatypes.EventSourcePositionLatest, Enabled: aws.Bool(true), BatchSize: aws.Int32(4), MaximumBatchingWindowInSeconds: aws.Int32(2), MaximumRetryAttempts: aws.Int32(1), MaximumRecordAgeInSeconds: aws.Int32(60), BisectBatchOnFunctionError: aws.Bool(true), DestinationConfig: &lambdatypes.DestinationConfig{OnFailure: &lambdatypes.OnFailure{Destination: &failureARN}}, MetricsConfig: &lambdatypes.EventSourceMappingMetricsConfig{Metrics: []lambdatypes.EventSourceMappingMetric{lambdatypes.EventSourceMappingMetricEventCount}}})
			if err != nil {
				t.Fatal(err)
			}
			id := aws.ToString(mapping.UUID)
			key := lambdastore.EventSourceMappingKey{Scope: lambdastore.Scope{Partition: "aws", Account: "000000000000", Region: "us-east-1"}, UUID: id}
			settleMapping := func() {
				t.Helper()
				var retained lambdastore.EventSourceMappingRecord
				readMapping := func() {
					t.Helper()
					if err := repository.View(t.Context(), func(reader lambdastore.Reader) error {
						var err error
						retained, err = reader.EventSourceMapping(key)
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
				readMapping()
				restart(retained.TransitionAt)
				lambdaGuardImageKinesisAwait(t, "committed native mapping transition", func() bool {
					readMapping()
					return retained.State == "Enabled" && retained.TransitionAt.IsZero()
				})
			}
			settleMapping()
			latest := lambdaGuardImageKinesisAwaitShard(t, repository, key, func(shard lambdastore.StreamShardRecord) bool {
				return shard.Checkpoint != "" && !shard.ReadComplete && !shard.Complete && len(shard.Lanes[0].Records) == 0 && len(shard.Lanes[0].Batches) == 0 && lambdaGuardImageKinesisPollCount(t, repository, key, source.Now()) > 0
			})
			// The source commits an opaque high-water position at Kafka's
			// exclusive end, not necessarily the sequence of the last record.
			// Preserve that actual boundary across a joined, frozen reopen;
			// Enabled alone and an invented record-sequence equality are not
			// evidence that LATEST has been established.
			restartPolled := func(at ...time.Time) {
				t.Helper()
				target := source.Now()
				if len(at) != 0 {
					target = at[0]
				}
				before := lambdaGuardImageKinesisPollCount(t, repository, key, target)
				restart(target)
				lambdaGuardImageKinesisAwait(t, "actual source poll after reopen", func() bool {
					return lambdaGuardImageKinesisPollCount(t, repository, key, target) > before
				})
			}
			restartPolled()
			lambdaGuardImageKinesisAwaitShard(t, repository, key, func(shard lambdastore.StreamShardRecord) bool {
				return shard.Checkpoint == latest.Checkpoint && len(shard.Lanes[0].Records) == 0 && len(shard.Lanes[0].Batches) == 0
			})
			latestIterator, err := clients.kinesis("test", "test", "").GetShardIterator(t.Context(), &kinesis.GetShardIteratorInput{StreamARN: &streamARN, ShardId: &latest.Key.ShardID, ShardIteratorType: kinesistypes.ShardIteratorTypeAfterSequenceNumber, StartingSequenceNumber: &latest.Checkpoint})
			if err != nil {
				t.Fatal(err)
			}
			latestPage, err := clients.kinesis("test", "test", "").GetRecords(t.Context(), &kinesis.GetRecordsInput{StreamARN: &streamARN, ShardIterator: latestIterator.ShardIterator})
			if err != nil || len(latestPage.Records) != 0 || latestPage.NextShardIterator == nil {
				t.Fatalf("retained LATEST boundary did not exclude the original Kafka record: output=%+v error=%v", latestPage, err)
			}
			destinationsDone := func() {
				t.Helper()
				lambdaGuardImageKinesisAwait(t, "committed native failure-destination completion", func() bool {
					var failures []lambdastore.StreamFailure
					if err := repository.View(t.Context(), func(reader lambdastore.Reader) error {
						var err error
						failures, err = reader.StreamFailures()
						return err
					}); err != nil {
						t.Fatal(err)
					}
					return len(failures) == 0
				})
			}
			controls := func(window int32, size int32) {
				t.Helper()
				out, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
				if err != nil {
					t.Fatal(err)
				}
				if out.StartingPosition != lambdatypes.EventSourcePositionLatest || aws.ToInt32(out.BatchSize) != size || aws.ToInt32(out.MaximumBatchingWindowInSeconds) != window || aws.ToInt32(out.MaximumRetryAttempts) != 1 || aws.ToInt32(out.MaximumRecordAgeInSeconds) != 60 || !aws.ToBool(out.BisectBatchOnFunctionError) || out.DestinationConfig == nil || out.DestinationConfig.OnFailure == nil || aws.ToString(out.DestinationConfig.OnFailure.Destination) != failureARN {
					t.Fatalf("image mapping controls did not retain their configured values: %+v", out)
				}
			}

			// Underfilled records share a window and survive both storage backends.
			// Reopens wake an actual poll at a frozen service instant; no advancing
			// clock until an output happens, wall-clock quiet period, or mock locks.
			put([]string{"window-1", "window-2"}, "")
			latestPage, err = clients.kinesis("test", "test", "").GetRecords(t.Context(), &kinesis.GetRecordsInput{StreamARN: &streamARN, ShardIterator: latestPage.NextShardIterator})
			if err != nil || len(latestPage.Records) != 2 {
				t.Fatalf("immutable native LATEST iterator did not retain post-mapping writes: output=%+v error=%v", latestPage, err)
			}
			for i, recordID := range []string{"window-1", "window-2"} {
				original := written[recordID]
				if aws.ToString(latestPage.Records[i].SequenceNumber) != original.Sequence || string(latestPage.Records[i].Data) != string(original.Data) {
					t.Fatalf("native LATEST boundary lost original successor bytes: %+v", latestPage.Records)
				}
			}
			restartPolled()
			pending := lambdaGuardImageKinesisAwaitShard(t, repository, key, func(shard lambdastore.StreamShardRecord) bool {
				return shard.Checkpoint == written["window-2"].Sequence && len(shard.Lanes[0].Records) == 2 && len(shard.Lanes[0].Batches) == 0
			})
			windowDue := pending.Lanes[0].Records[0].CapturedAt.Add(2 * time.Second)
			restartPolled(windowDue.Add(-250 * time.Millisecond))
			restart() // Join the preceding pre-deadline poll before checking absence.
			controls(2, 4)
			if messages := lambdaGuardImageKinesisDrain(t, clients, resultURL); len(messages) != 0 {
				t.Fatalf("underfilled batch invoked before its window: %s", messages)
			}
			restartPolled(windowDue)
			lambdaGuardImageKinesisAwaitShard(t, repository, key, func(shard lambdastore.StreamShardRecord) bool {
				return shard.Checkpoint == written["window-2"].Sequence && len(shard.Lanes[0].Records) == 0 && len(shard.Lanes[0].Batches) == 0
			})
			windowReport := lambdaGuardImageKinesisReports(t, clients, resultURL, 1)
			lambdaGuardImageKinesisAssertReport(t, windowReport[0], []string{"window-1", "window-2"}, written, marker, functionARN, streamARN, aws.ToString(role.Role.Arn))

			// An exception (not partial acknowledgement) bisects 4 -> 2 -> 1.
			// Only the poison singleton spends its one retry; healthy halves finish.
			put([]string{"bisect-1", "bisect-2", "bisect-3", "bisect-4"}, "bisect-2")
			batch := func(records int, sizes []int, attempts int) lambdastore.StreamShardRecord {
				t.Helper()
				return lambdaGuardImageKinesisAwaitShard(t, repository, key, func(shard lambdastore.StreamShardRecord) bool {
					lane := shard.Lanes[0]
					if shard.Checkpoint != lastWrittenSequence || len(lane.Records) != records || len(lane.Batches) != len(sizes) {
						return false
					}
					for i, size := range sizes {
						if lane.Batches[i].Count != size {
							return false
						}
					}
					return len(sizes) == 0 || lane.Batches[0].Attempts == attempts
				})
			}
			restartPolled()
			bisected := batch(4, []int{2, 2}, 0)
			if !source.Now().Before(bisected.Lanes[0].Records[0].CapturedAt.Add(2 * time.Second)) {
				t.Fatal("full native batch did not invoke before its batching window")
			}
			restartPolled()
			batch(4, []int{1, 1, 2}, 0)
			restartPolled()
			batch(3, []int{1, 2}, 0)
			restartPolled()
			retrying := batch(3, []int{1, 2}, 1)
			restartPolled(retrying.Lanes[0].Batches[0].Due)
			batch(2, []int{2}, 0)
			restartPolled()
			batch(0, nil, 0)
			restartPolled()
			destinationsDone()
			reports := lambdaGuardImageKinesisReports(t, clients, resultURL, 6)
			want := [][]string{{"bisect-1", "bisect-2", "bisect-3", "bisect-4"}, {"bisect-1", "bisect-2"}, {"bisect-1"}, {"bisect-2"}, {"bisect-2"}, {"bisect-3", "bisect-4"}}
			for i := range want {
				lambdaGuardImageKinesisAssertReport(t, reports[i], want[i], written, marker, functionARN, streamARN, aws.ToString(role.Role.Arn))
			}
			if reports[3].RequestID != reports[4].RequestID || reports[0].RequestID == reports[1].RequestID || reports[1].RequestID == reports[3].RequestID {
				t.Fatal("real RIC retry and bisected-child request identities differ from native calibration")
			}
			exhausted := lambdaGuardImageKinesisMessages(t, clients, failureURL, 1)[0]
			lambdaGuardImageKinesisAssertFailure(t, clients, exhausted, destinationSchema, "RetryAttemptsExhausted", len(nativePoison), reports[4].RequestID, functionARN, streamARN, written["bisect-2"])

			// A longer window cannot postpone the source-arrival age limit. The
			// record is healthy customer input: an invocation would be observable.
			if _, err := lambdaDynamoDBClient(clients).UpdateEventSourceMapping(t.Context(), &awslambda.UpdateEventSourceMappingInput{UUID: &id, MaximumBatchingWindowInSeconds: aws.Int32(120)}); err != nil {
				t.Fatal(err)
			}
			settleMapping()
			put([]string{"expired-without-invocation"}, "")
			restartPolled()
			aging := batch(1, nil, 0)
			ageDue := aging.Lanes[0].Records[0].CreatedAt.Add(60 * time.Second)
			restartPolled(ageDue.Add(-250 * time.Millisecond))
			restart()
			controls(120, 4)
			if messages := lambdaGuardImageKinesisDrain(t, clients, resultURL); len(messages) != 0 {
				t.Fatalf("customer invoked inside the long batching/age window: %s", messages)
			}
			restartPolled(ageDue)
			batch(0, nil, 0)
			restartPolled()
			destinationsDone()
			aged := lambdaGuardImageKinesisMessages(t, clients, failureURL, 1)[0]
			lambdaGuardImageKinesisAssertFailure(t, clients, aged, destinationSchema, "RecordAgeExceeded", 1, "", functionARN, streamARN, written["expired-without-invocation"])
			if messages := lambdaGuardImageKinesisDrain(t, clients, resultURL); len(messages) != 0 {
				t.Fatalf("expired record entered customer image code: %s", messages)
			}

			// A fresh successor proves progress beyond the discarded original and
			// detects replay of pre-LATEST, acknowledged, or exhausted source bytes.
			if _, err := lambdaDynamoDBClient(clients).UpdateEventSourceMapping(t.Context(), &awslambda.UpdateEventSourceMappingInput{UUID: &id, BatchSize: aws.Int32(1), MaximumBatchingWindowInSeconds: aws.Int32(0)}); err != nil {
				t.Fatal(err)
			}
			settleMapping()
			put([]string{"after-expiry"}, "")
			restartPolled()
			batch(0, nil, 0)
			final := lambdaGuardImageKinesisReports(t, clients, resultURL, 1)
			lambdaGuardImageKinesisAssertReport(t, final[0], []string{"after-expiry"}, written, marker, functionARN, streamARN, aws.ToString(role.Role.Arn))
			controls(0, 1)
			if extra := lambdaGuardImageKinesisDrain(t, clients, failureURL); len(extra) != 0 {
				t.Fatalf("healthy records or exhausted originals produced extra failure messages: %s", extra)
			}
			if _, err := lambdaDynamoDBClient(clients).DeleteEventSourceMapping(t.Context(), &awslambda.DeleteEventSourceMappingInput{UUID: &id}); err != nil {
				t.Fatal(err)
			}
			if _, err := lambdaDynamoDBClient(clients).DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: &name}); err != nil {
				t.Fatal(err)
			}
			functionDeleted = true
			t.Logf("GUARD_IMAGE_KINESIS_REAL_RIC native Kafka/LATEST/window/retry/bisect/age/SQS passed; backend=%s marker=%s", backend, marker)
		})
	}
}

func lambdaGuardImageKinesisAwait(t *testing.T, label string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("frozen-clock actual engine barrier did not settle: ", label)
}

func lambdaGuardImageKinesisAwaitShard(t *testing.T, repository lambdastore.Repository, key lambdastore.EventSourceMappingKey, ready func(lambdastore.StreamShardRecord) bool) lambdastore.StreamShardRecord {
	t.Helper()
	var snapshot lambdastore.StreamShardRecord
	lambdaGuardImageKinesisAwait(t, "retained native stream checkpoint/batch", func() bool {
		var shards []lambdastore.StreamShardRecord
		if err := repository.View(t.Context(), func(reader lambdastore.Reader) error {
			var err error
			shards, err = reader.StreamShards(key)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(shards) == 0 {
			return false
		}
		if len(shards) != 1 || len(shards[0].Lanes) != 1 {
			t.Fatalf("isolated one-shard/one-lane fixture changed: %+v", shards)
		}
		snapshot = shards[0]
		return ready(snapshot)
	})
	return snapshot
}

func lambdaGuardImageKinesisPollCount(t *testing.T, repository lambdastore.Repository, key lambdastore.EventSourceMappingKey, at time.Time) int64 {
	t.Helper()
	var samples []lambdastore.MetricSample
	err := repository.View(t.Context(), func(reader lambdastore.Reader) error {
		var err error
		samples, err = reader.MetricSamples(lambdastore.MetricPublicationKey{Function: lambdastore.FunctionKey{Scope: key.Scope}, Minute: at.UTC().Truncate(time.Minute), EventSourceMappingUUID: key.UUID})
		return err
	})
	if err != nil && err != lambdastore.ErrNotFound {
		t.Fatal(err)
	}
	var count int64
	for _, sample := range samples {
		if sample.Name == "PolledEventCount" {
			count += sample.SampleCount
		}
	}
	return count
}

func lambdaGuardImageKinesisDrain(t *testing.T, clients cloudClients, queueURL *string) []string {
	t.Helper()
	var bodies []string
	for {
		out, err := clients.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			return bodies
		}
		for _, message := range out.Messages {
			bodies = append(bodies, aws.ToString(message.Body))
			if _, err := clients.sqs("test", "test", "").DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queueURL, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func lambdaGuardImageKinesisMessages(t *testing.T, clients cloudClients, queueURL *string, count int) []string {
	t.Helper()
	var messages []string
	lambdaGuardImageKinesisAwait(t, "consumer-visible SQS messages", func() bool {
		messages = append(messages, lambdaGuardImageKinesisDrain(t, clients, queueURL)...)
		return len(messages) >= count
	})
	if len(messages) != count {
		t.Fatalf("consumer got %d messages, want exactly %d: %s", len(messages), count, messages)
	}
	return messages
}

func lambdaGuardImageKinesisReports(t *testing.T, clients cloudClients, queueURL *string, count int) []lambdaGuardImageKinesisReport {
	t.Helper()
	messages := lambdaGuardImageKinesisMessages(t, clients, queueURL, count)
	reports := make([]lambdaGuardImageKinesisReport, len(messages))
	for i, message := range messages {
		if err := json.Unmarshal([]byte(message), &reports[i]); err != nil {
			t.Fatal(err)
		}
	}
	return reports
}

func lambdaGuardImageKinesisAssertReport(t *testing.T, report lambdaGuardImageKinesisReport, ids []string, written map[string]lambdaGuardImageKinesisWrite, marker, functionARN, streamARN, roleARN string) {
	t.Helper()
	if report.Marker != marker || report.InvokedARN != functionARN || report.RequestID == "" || !reflect.DeepEqual(report.Result.IDs, ids) {
		t.Fatalf("customer-code image report lost its result or identity: %+v want IDs=%v", report, ids)
	}
	records, ok := report.Event["Records"].([]any)
	if !ok || len(records) != len(ids) {
		t.Fatalf("customer Runtime API batch size: %+v", report)
	}
	sum, failed := 0, false
	for i, id := range ids {
		record := records[i].(map[string]any)
		actual := lambdaKinesisRecordData(t, record)
		original := written[id]
		data := record["kinesis"].(map[string]any)
		if actual["id"] != id || actual["ordinal"] != float64(original.Ordinal) || actual["poison"] != original.Poison || record["eventSourceARN"] != streamARN || record["eventSource"] != "aws:kinesis" || record["invokeIdentityArn"] != roleARN || record["eventID"] != original.Shard+":"+original.Sequence || data["sequenceNumber"] != original.Sequence || data["partitionKey"] != "owned-key" {
			t.Fatalf("actual image batch did not retain original Kafka record %s: %+v", id, record)
		}
		if arrival, ok := data["approximateArrivalTimestamp"].(float64); !ok || arrival <= 0 {
			t.Fatalf("image record lacks original arrival timestamp: %+v", record)
		}
		sum += original.Ordinal
		failed = failed || original.Poison
	}
	if report.Result.Sum != sum || report.Failed != failed {
		t.Fatalf("actual Python customer calculation/failure differs: %+v want sum=%d failed=%v", report, sum, failed)
	}
}

func lambdaGuardImageKinesisAssertFailure(t *testing.T, clients cloudClients, body string, native map[string]any, condition string, attempts int, requestID, functionARN, streamARN string, original lambdaGuardImageKinesisWrite) {
	t.Helper()
	var failure lambdaGuardImageKinesisFailure
	if err := json.Unmarshal([]byte(body), &failure); err != nil {
		t.Fatal(err)
	}
	info, request := failure.KinesisBatchInfo, failure.RequestContext
	if request.Condition != condition || request.FunctionARN != functionARN || request.RequestID == "" || request.ApproximateInvokeCount != attempts || requestID != "" && request.RequestID != requestID || info.StreamARN != streamARN || info.ShardID != original.Shard || info.StartSequenceNumber != original.Sequence || info.EndSequenceNumber != original.Sequence || info.BatchSize != 1 || len(failure.Payload) != 0 {
		t.Fatalf("SQS failure lost the exhausted original identity/context: %s", body)
	}
	if condition == "RetryAttemptsExhausted" {
		var response struct {
			StatusCode                     int
			ExecutedVersion, FunctionError string
		}
		if err := json.Unmarshal(failure.ResponseContext, &response); err != nil || response.StatusCode != 200 || response.ExecutedVersion != "$LATEST" || response.FunctionError != "Unhandled" {
			t.Fatalf("actual RIC handler exception did not reach failure context: error=%v body=%s", err, body)
		}
	} else if len(failure.ResponseContext) != 0 {
		t.Fatalf("uninvoked expired record manufactured customer execution context: %s", body)
	}
	var actual map[string]any
	if err := json.Unmarshal([]byte(body), &actual); err != nil {
		t.Fatal(err)
	}
	keys := func(document map[string]any) []string {
		result := make([]string, 0, len(document))
		for key := range document {
			result = append(result, key)
		}
		sort.Strings(result)
		return result
	}
	if !reflect.DeepEqual(keys(actual["KinesisBatchInfo"].(map[string]any)), keys(native["KinesisBatchInfo"].(map[string]any))) || !reflect.DeepEqual(keys(actual["requestContext"].(map[string]any)), keys(native["requestContext"].(map[string]any))) {
		t.Fatalf("SQS metadata differs from native destination schema: %s", body)
	}
	// Native SQS destinations contain metadata only. Resolve that exact sequence
	// through the real source API to prove it still identifies the original bytes.
	iterator, err := clients.kinesis("test", "test", "").GetShardIterator(t.Context(), &kinesis.GetShardIteratorInput{StreamARN: &streamARN, ShardId: &info.ShardID, ShardIteratorType: kinesistypes.ShardIteratorTypeAtSequenceNumber, StartingSequenceNumber: &info.StartSequenceNumber})
	if err != nil {
		t.Fatal(err)
	}
	var records []kinesistypes.Record
	lambdaGuardImageKinesisAwait(t, "original failed native source record", func() bool {
		out, err := clients.kinesis("test", "test", "").GetRecords(t.Context(), &kinesis.GetRecordsInput{StreamARN: &streamARN, ShardIterator: iterator.ShardIterator, Limit: aws.Int32(1)})
		if err != nil {
			t.Fatal(err)
		}
		records = out.Records
		return len(records) != 0
	})
	if len(records) != 1 || aws.ToString(records[0].SequenceNumber) != original.Sequence || string(records[0].Data) != string(original.Data) {
		t.Fatalf("failure metadata did not recover the original Kafka bytes: %+v", records)
	}
	first, err := time.Parse(time.RFC3339Nano, info.ApproximateArrivalOfFirstRecord)
	if err != nil {
		t.Fatal(err)
	}
	last, err := time.Parse(time.RFC3339Nano, info.ApproximateArrivalOfLastRecord)
	if err != nil || records[0].ApproximateArrivalTimestamp == nil || !first.Equal(*records[0].ApproximateArrivalTimestamp) || !last.Equal(first) {
		t.Fatalf("failure metadata changed original native arrival: error=%v body=%s record=%+v", err, body, records[0])
	}
}
