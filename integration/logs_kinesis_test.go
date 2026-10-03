package stackd_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/google/uuid"
	"stackd"
	"stackd/clock"
	"stackd/storage"
	logstorage "stackd/storage/logs"
)

type logsKinesisFixture struct {
	CapturedAt   time.Time `json:"captured_at"`
	Observations []eventLogsObservation
	Records      []struct {
		Envelope     subscriptionEnvelope
		PartitionKey string
	}
}

type logsKinesisReplay struct {
	Source string
	Setup  []string
	Steps  []struct{ Calls, Stages []string }
}

func decodeLogsKinesis(t *testing.T, raw []byte) subscriptionEnvelope {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	var out subscriptionEnvelope
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A real command-owner fence proves all completed delivery effects have been
// observed. Empty polls and sleep durations are not treated as evidence of loss.
func logsKinesisFence(t *testing.T, source *clock.Manual, client *kinesis.Client, arn string) []kinesistypes.Record {
	t.Helper()
	advanceClock(t, source, time.Second)
	fence, err := client.PutRecord(t.Context(), &kinesis.PutRecordInput{StreamARN: &arn, PartitionKey: aws.String("logs-fence"), Data: []byte("logs-fence")})
	if err != nil {
		t.Fatal(err)
	}
	iterator, err := client.GetShardIterator(t.Context(), &kinesis.GetShardIteratorInput{StreamARN: &arn, ShardId: fence.ShardId, ShardIteratorType: kinesistypes.ShardIteratorTypeTrimHorizon})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var records []kinesistypes.Record
	for ctx.Err() == nil {
		advanceClock(t, source, 200*time.Millisecond)
		page, err := client.GetRecords(ctx, &kinesis.GetRecordsInput{StreamARN: &arn, ShardIterator: iterator.ShardIterator})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Records {
			if aws.ToString(r.SequenceNumber) == aws.ToString(fence.SequenceNumber) {
				return records
			}
			records = append(records, r)
		}
		iterator.ShardIterator = page.NextShardIterator
	}
	t.Fatal("Kinesis delivery fence not observed", ctx.Err())
	return nil
}

func TestLogsKinesisNativeReplaySDK(t *testing.T) {
	var plan logsKinesisReplay
	raw, err := os.ReadFile("../testdata/logs/kinesis_replay.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	var native logsKinesisFixture
	raw, err = os.ReadFile(plan.Source)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &native); err != nil {
		t.Fatal(err)
	}
	rows := eventLogsFixture{Observations: native.Observations}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runtime := newKinesisReplayRuntime(t)
			source := clock.NewManual(native.CapturedAt)
			var cloud *stackd.Stack
			var backends *storage.Backends
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source, KinesisRuntime: runtime}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				backends = config.Storage
				var err error
				cloud, err = stackd.New(config)
				if err != nil {
					t.Fatal(err)
				}
				return cloud, httptest.NewServer(cloud)
			})
			logs := func() *cloudwatchlogs.Client { return logsClient(clients, "test") }
			streams := func() *kinesis.Client { return clients.kinesis("test", "test", "") }
			roles := func() *iam.Client { return clients.iam("test", "test", "") }
			var streamName, streamARN, group, roleARN, roleName string
			call := func(label string) any {
				t.Helper()
				row := rows.observation(t, label)
				var client any = logs()
				switch row.Service {
				case "kinesis":
					client = streams()
				case "iam":
					client = roles()
				}
				return replayEventLogs(t, client, row, func(v any) {
					switch in := v.(type) {
					case *kinesis.CreateStreamInput:
						streamName = aws.ToString(in.StreamName)
					case *cloudwatchlogs.CreateLogGroupInput:
						group = aws.ToString(in.LogGroupName)
					case *iam.CreateRoleInput:
						if label == "create-role-delivery" {
							roleName = aws.ToString(in.RoleName)
							roleARN = "arn:aws:iam::123456789012:role/" + roleName
						}
					}
				})
			}
			for _, label := range plan.Setup {
				call(label)
				if label == "create-stream" {
					summary := awaitKinesisActive(t, source, streams(), streamName)
					streamARN = aws.ToString(summary.StreamDescriptionSummary.StreamARN)
				}
			}
			var stages []string
			for _, step := range plan.Steps {
				for _, label := range step.Calls {
					call(label)
				}
				stages = append(stages, step.Stages...)
				trailNativeDrain(t, cloud)
				records := logsKinesisFence(t, source, streams(), streamARN)
				assertLogsKinesisNative(t, native, records, stages, logs(), group)
				clients = reopen()
			}
			described, err := logs().DescribeSubscriptionFilters(t.Context(), &cloudwatchlogs.DescribeSubscriptionFiltersInput{LogGroupName: &group})
			if err != nil {
				t.Fatal(err)
			}
			logicalRole := ""
			for _, filter := range described.SubscriptionFilters {
				if aws.ToString(filter.FilterName) == "logical" {
					logicalRole = aws.ToString(filter.RoleArn)
				}
			}
			if logicalRole != roleARN {
				t.Fatal("logical subscription lost the explicitly supplied role", described)
			}
			// Stable pagination remains bound to scope/prefix across durable reopening.
			var destination cloudwatchlogs.PutDestinationInput
			if err := json.Unmarshal(rows.observation(t, "destination-create").Input, &destination); err != nil {
				t.Fatal(err)
			}
			first, err := logs().DescribeDestinations(t.Context(), &cloudwatchlogs.DescribeDestinationsInput{DestinationNamePrefix: aws.String(streamName), Limit: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			if len(first.Destinations) != 1 || first.NextToken == nil {
				t.Fatal("destination first page", first)
			}
			clients = reopen()
			second, err := logs().DescribeDestinations(t.Context(), &cloudwatchlogs.DescribeDestinationsInput{DestinationNamePrefix: aws.String(streamName), Limit: aws.Int32(1), NextToken: first.NextToken})
			if err != nil {
				t.Fatal(err)
			}
			if len(second.Destinations) != 1 || aws.ToString(first.Destinations[0].DestinationName) >= aws.ToString(second.Destinations[0].DestinationName) {
				t.Fatal("destination pagination lost order", first, second)
			}
			var tagFixture eventLogsFixture
			tagRaw, err := os.ReadFile("../testdata/aws/logs/kinesis-destination-tags.json")
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tagRaw, &tagFixture); err != nil {
				t.Fatal(err)
			}
			for _, row := range tagFixture.Observations {
				if row.Service != "logs" {
					continue
				}
				out := replayEventLogs(t, logs(), row)
				switch out := out.(type) {
				case *cloudwatchlogs.PutDestinationOutput:
					if aws.ToInt64(out.Destination.CreationTime) != aws.ToInt64(second.Destinations[0].CreationTime) {
						t.Fatal("destination update replaced its creation identity", out)
					}
				case *cloudwatchlogs.ListTagsForResourceOutput:
					var expected struct{ Tags map[string]string }
					if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
						t.Fatal(err)
					}
					if !maps.Equal(out.Tags, expected.Tags) {
						t.Fatal("destination tag merge differs from native", out.Tags, expected.Tags)
					}
				}
			}
			// Explicit resource-policy denial must override an account-root identity grant.
			call("destination-deny-policy")
			call("logical-explicit-deny")
			call("destination-policy")
			// Caller PassRole is distinct from the service role's stream permission.
			callerRole := call("create-role-caller").(*iam.CreateRoleOutput).Role
			call("grant-caller-no-passrole")
			var assume sts.AssumeRoleInput
			if err := json.Unmarshal(rows.observation(t, "assume-no-passrole-caller").Input, &assume); err != nil {
				t.Fatal(err)
			}
			session, err := clients.sts("test", "test", "").AssumeRole(t.Context(), &assume)
			if err != nil {
				t.Fatal(err)
			}
			restricted := cloudwatchlogs.New(cloudwatchlogs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			for _, label := range []string{"direct-passrole-denied", "destination-passrole-denied"} {
				replayEventLogs(t, restricted, rows.observation(t, label))
			}
			replayLogsDestinationPolicies(t, logs(), restricted, destination, group, aws.ToString(callerRole.RoleId))
			call("destination-policy")

			// Cross-account routing is a local IAM invariant, not claimed native evidence.
			const sender = "111111111111"
			foreign := logsClient(clients, sender)
			if _, err := foreign.CreateLogGroup(t.Context(), &cloudwatchlogs.CreateLogGroupInput{LogGroupName: &group}); err != nil {
				t.Fatal(err)
			}
			if _, err := foreign.CreateLogStream(t.Context(), &cloudwatchlogs.CreateLogStreamInput{LogGroupName: &group, LogStreamName: aws.String("cross")}); err != nil {
				t.Fatal(err)
			}
			foreignSub := cloudwatchlogs.PutSubscriptionFilterInput{LogGroupName: &group, FilterName: aws.String("cross"), FilterPattern: aws.String(""), DestinationArn: first.Destinations[0].Arn}
			_, err = foreign.PutSubscriptionFilter(t.Context(), &foreignSub)
			assertAPIError(t, err, "AccessDeniedException")
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"logs:PutSubscriptionFilter","Resource":"%s"}]}`, sender, aws.ToString(first.Destinations[0].Arn))
			if _, err := logs().PutDestinationPolicy(t.Context(), &cloudwatchlogs.PutDestinationPolicyInput{DestinationName: destination.DestinationName, AccessPolicy: &policy}); err != nil {
				t.Fatal(err)
			}
			// Logical registration checks resource policy; actual delivery rechecks trust
			// with the sender account independently of recipient role ownership.
			if _, err := foreign.PutSubscriptionFilter(t.Context(), &foreignSub); err != nil {
				t.Fatal(err)
			}
			untrusted := "untrusted-source-record"
			if _, err := foreign.PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{LogGroupName: &group, LogStreamName: aws.String("cross"), LogEvents: []logtypes.InputLogEvent{{Timestamp: aws.Int64(source.Now().UnixMilli()), Message: &untrusted}}}); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			for _, r := range logsKinesisFence(t, source, streams(), streamARN) {
				if !bytes.HasPrefix(r.Data, []byte{0x1f, 0x8b}) {
					continue
				}
				e := decodeLogsKinesis(t, r.Data)
				for _, event := range e.LogEvents {
					if event.Message == untrusted {
						t.Fatal("untrusted source reached Kinesis")
					}
				}
			}
			trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logs.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnLike":{"aws:SourceArn":["arn:aws:logs:us-east-1:123456789012:*","arn:aws:logs:us-east-1:%s:*"]}}}]}`, sender)
			if _, err := roles().UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: &roleName, PolicyDocument: &trust}); err != nil {
				t.Fatal(err)
			}
			if _, err := foreign.PutSubscriptionFilter(t.Context(), &foreignSub); err != nil {
				t.Fatal(err)
			}
			message := "cross-account-real-record"
			if _, err := foreign.PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{LogGroupName: &group, LogStreamName: aws.String("cross"), LogEvents: []logtypes.InputLogEvent{{Timestamp: aws.Int64(source.Now().UnixMilli()), Message: &message}}}); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			found := false
			for _, r := range logsKinesisFence(t, source, streams(), streamARN) {
				if !bytes.HasPrefix(r.Data, []byte{0x1f, 0x8b}) {
					continue
				}
				e := decodeLogsKinesis(t, r.Data)
				for _, event := range e.LogEvents {
					if event.Message == message {
						found = e.Owner == sender && e.LogGroup == group && e.LogStream == "cross"
					}
				}
			}
			if !found {
				t.Fatal("authorized cross-account Logs record did not reach real Kinesis")
			}

			// Revoke the target role: a nonretryable denial disables source delivery and
			// source arrivals during the disable interval are skipped, not queued forever.
			call("deny-delivery-stream")
			skipped := "permission-denied-local"
			if _, err := foreign.PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{LogGroupName: &group, LogStreamName: aws.String("cross"), LogEvents: []logtypes.InputLogEvent{{Timestamp: aws.Int64(source.Now().UnixMilli()), Message: &skipped}}}); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			call("restore-delivery-stream")
			// Restore source trust for retained native subscriptions and policy for owner.
			call("destination-policy")
			// Repointing a logical destination must affect only future batches, not
			// already accepted work's stream, role or partition key.
			if _, err := logs().DeleteSubscriptionFilter(t.Context(), &cloudwatchlogs.DeleteSubscriptionFilterInput{LogGroupName: &group, FilterName: aws.String("direct")}); err != nil {
				t.Fatal(err)
			}
			subscription := cloudwatchlogs.PutSubscriptionFilterInput{LogGroupName: &group, FilterName: aws.String("logical"), FilterPattern: aws.String(""), DestinationArn: first.Destinations[0].Arn, Distribution: logtypes.DistributionRandom}
			if _, err := logs().PutSubscriptionFilter(t.Context(), &subscription); err != nil {
				t.Fatal(err)
			}
			nextName := streamName + "-next"
			nextStreams := func() *kinesis.Client {
				options := streams().Options()
				options.Region = "us-west-2"
				return kinesis.New(options)
			}
			if _, err := nextStreams().CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &nextName, ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			nextStream := aws.ToString(awaitKinesisActive(t, source, nextStreams(), nextName).StreamDescriptionSummary.StreamARN)
			nextRole, err := roles().CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: &nextName, AssumeRolePolicyDocument: &trust})
			if err != nil {
				t.Fatal(err)
			}
			nextPolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kinesis:PutRecord","Resource":"%s"}]}`, nextStream)
			if _, err := roles().PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: &nextName, PolicyName: aws.String("write"), PolicyDocument: &nextPolicy}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Second)
			batch := make([]kinesistypes.PutRecordsRequestEntry, 500)
			for i := range batch {
				batch[i] = kinesistypes.PutRecordsRequestEntry{PartitionKey: aws.String("quota"), Data: []byte("quota")}
			}
			for range 2 {
				out, err := streams().PutRecords(t.Context(), &kinesis.PutRecordsInput{StreamARN: &streamARN, Records: batch})
				if err != nil || aws.ToInt32(out.FailedRecordCount) != 0 {
					t.Fatal("fill shard", out, err)
				}
			}
			retained := "retained-after-reopen"
			input := cloudwatchlogs.PutLogEventsInput{LogGroupName: &group, LogStreamName: aws.String("alpha"), LogEvents: []logtypes.InputLogEvent{{Timestamp: aws.Int64(source.Now().UnixMilli()), Message: &retained}}}
			if _, err := logs().PutLogEvents(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			var pending logstorage.SubscriptionDelivery
			if err := backends.Logs.View(t.Context(), func(r logstorage.Reader) error {
				job, ok, err := r.NextSubscriptionDelivery()
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("throttled delivery not retained")
				}
				pending, err = r.SubscriptionDelivery(job.Key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if pending.Attempts != 1 || pending.PartitionKey == "" || pending.RoleARN != roleARN {
				t.Fatal("invalid retained delivery", pending)
			}
			if _, err := logs().PutDestination(t.Context(), &cloudwatchlogs.PutDestinationInput{DestinationName: destination.DestinationName, TargetArn: &nextStream, RoleArn: nextRole.Role.Arn}); err != nil {
				t.Fatal(err)
			}
			// Deleting the source stream cannot destroy accepted compressed work.
			if _, err := logs().DeleteLogStream(t.Context(), &cloudwatchlogs.DeleteLogStreamInput{LogGroupName: &group, LogStreamName: aws.String("alpha")}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			advanceClock(t, source, time.Second)
			trailNativeDrain(t, cloud)
			matched := 0
			for _, r := range logsKinesisFence(t, source, streams(), streamARN) {
				if !bytes.HasPrefix(r.Data, []byte{0x1f, 0x8b}) {
					continue
				}
				e := decodeLogsKinesis(t, r.Data)
				for _, event := range e.LogEvents {
					if event.Message == retained {
						matched++
						if aws.ToString(r.PartitionKey) != pending.PartitionKey || !bytes.Equal(r.Data, pending.Payload) {
							t.Fatal("retry changed retained bytes or routing")
						}
					}
					if event.Message == skipped {
						t.Fatal("denied delivery was appended")
					}
				}
			}
			if matched != 1 {
				t.Fatalf("retained delivery count=%d", matched)
			}
			subscription.FieldSelectionCriteria = aws.String(`@aws.region = "us-east-1" AND @aws.account = "123456789012"`)
			subscription.EmitSystemFields = []string{"@aws.account", "@aws.region", "@source.log"}
			if _, err := logs().PutSubscriptionFilter(t.Context(), &subscription); err != nil {
				t.Fatal(err)
			}
			nextMessage := "uses-updated-logical-target"
			if _, err := logs().PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{LogGroupName: &group, LogStreamName: aws.String("beta"), LogEvents: []logtypes.InputLogEvent{{Timestamp: aws.Int64(source.Now().UnixMilli()), Message: &nextMessage}}}); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			subscription.FieldSelectionCriteria = aws.String(`@aws.region = "us-west-2"`)
			if _, err := logs().PutSubscriptionFilter(t.Context(), &subscription); err != nil {
				t.Fatal(err)
			}
			excluded := "destination-region-is-not-source-region"
			if _, err := logs().PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{LogGroupName: &group, LogStreamName: aws.String("beta"), LogEvents: []logtypes.InputLogEvent{{Timestamp: aws.Int64(source.Now().UnixMilli()), Message: &excluded}}}); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			nextCount := 0
			for _, r := range logsKinesisFence(t, source, nextStreams(), nextStream) {
				if !bytes.HasPrefix(r.Data, []byte{0x1f, 0x8b}) {
					continue
				}
				e := decodeLogsKinesis(t, r.Data)
				for _, event := range e.LogEvents {
					if event.Message == retained {
						t.Fatal("configuration update rerouted an admitted batch")
					}
					if event.Message == excluded {
						t.Fatal("field selection used target instead of source region")
					}
					if event.Message == nextMessage {
						nextCount++
						want := map[string]string{"@aws.account": "123456789012", "@aws.region": "us-east-1", "@source.log": group}
						if !maps.Equal(event.ExtractedFields, want) {
							t.Fatal("source system fields changed across regional delivery", event)
						}
					}
				}
			}
			if nextCount != 1 {
				t.Fatal("updated logical target did not receive exactly one new batch", nextCount)
			}
			call("delete-logical-destination")
			call("delete-logical-destination-again")
			call("logical-missing-destination")
		})
	}
}

func replayLogsDestinationPolicies(t *testing.T, owner, caller *cloudwatchlogs.Client, destination cloudwatchlogs.PutDestinationInput, group, callerID string) {
	t.Helper()
	var fixture struct {
		Prefix       string `json:"owned_prefix"`
		Observations []struct {
			eventLogsObservation
			Actor string
		}
	}
	raw, err := os.ReadFile("../testdata/aws/logs/destination-principals.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var nativeCaller struct {
		Role struct {
			ID string `json:"RoleId"`
		}
	}
	for _, row := range fixture.Observations {
		if row.Label == "create-caller-role" {
			if err := json.Unmarshal(row.Result.Output, &nativeCaller); err != nil {
				t.Fatal(err)
			}
		}
	}
	replace := strings.NewReplacer(fixture.Prefix, aws.ToString(destination.DestinationName), nativeCaller.Role.ID, callerID)
	for _, row := range fixture.Observations {
		if row.Service != "logs" || row.Operation != "put-destination-policy" && row.Operation != "put-subscription-filter" {
			continue
		}
		if !t.Run(row.Label, func(t *testing.T) {
			client := owner
			if row.Actor == "owned-role-session" {
				client = caller
			}
			replayEventLogs(t, client, row.eventLogsObservation, func(input any) {
				switch in := input.(type) {
				case *cloudwatchlogs.PutDestinationPolicyInput:
					in.DestinationName = destination.DestinationName
					in.AccessPolicy = aws.String(replace.Replace(aws.ToString(in.AccessPolicy)))
				case *cloudwatchlogs.PutSubscriptionFilterInput:
					in.LogGroupName = &group
					in.FilterName = aws.String("logical")
					in.DestinationArn = aws.String(replace.Replace(aws.ToString(in.DestinationArn)))
				}
			})
		}) {
			t.FailNow()
		}
	}
}

func assertLogsKinesisNative(t *testing.T, native logsKinesisFixture, records []kinesistypes.Record, stages []string, logs *cloudwatchlogs.Client, group string) {
	t.Helper()
	wanted := map[subscriptionEventKey]subscriptionLogEvent{}
	for _, r := range native.Records {
		e := r.Envelope
		if e.MessageType != "DATA_MESSAGE" {
			continue
		}
		for _, event := range e.LogEvents {
			for _, stage := range stages {
				if strings.Contains(event.Message, `"stage": "`+stage+`"`) {
					for _, filter := range e.SubscriptionFilters {
						wanted[subscriptionKey(filter, e.LogStream, event)] = event
					}
				}
			}
		}
	}
	if len(wanted) == 0 {
		t.Fatal("native stages contain no observed events")
	}
	stored, err := logs.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &group})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, e := range stored.Events {
		ids[fmt.Sprintf("%s/%d/%s", aws.ToString(e.LogStreamName), aws.ToInt64(e.Timestamp), aws.ToString(e.Message))] = aws.ToString(e.EventId)
	}
	received := map[subscriptionEventKey]subscriptionLogEvent{}
	controls := 0
	randomKeys := map[string]string{}
	for _, r := range records {
		if !bytes.HasPrefix(r.Data, []byte{0x1f, 0x8b}) {
			continue
		}
		e := decodeLogsKinesis(t, r.Data)
		if e.MessageType == "CONTROL_MESSAGE" {
			var expected subscriptionEnvelope
			for _, v := range native.Records {
				if v.Envelope.MessageType == "CONTROL_MESSAGE" {
					expected = v.Envelope
					break
				}
			}
			if len(e.LogEvents) != 1 || len(expected.LogEvents) != 1 {
				t.Fatal("invalid control", e)
			}
			expected.LogEvents[0].Timestamp = e.LogEvents[0].Timestamp
			if !reflect.DeepEqual(e, expected) {
				t.Fatalf("control differs from native: %+v != %+v", e, expected)
			}
			if aws.ToString(r.PartitionKey) != "3e21f5e8240cbb048271af4fdb892a1c" {
				t.Fatal("control routing differs", r.PartitionKey)
			}
			controls++
			continue
		}
		if e.Owner != "123456789012" || e.LogGroup != group || len(e.SubscriptionFilters) != 1 {
			t.Fatal("unexpected data envelope", e)
		}
		if len(aws.ToString(r.PartitionKey)) == 32 {
			sum := md5.Sum([]byte(e.Owner + ":" + e.LogGroup + ":" + e.LogStream))
			if aws.ToString(r.PartitionKey) != hex.EncodeToString(sum[:]) {
				t.Fatal("ByLogStream routing changed", r.PartitionKey)
			}
		}
		for _, event := range e.LogEvents {
			for _, stage := range []string{"random-first", "random-second"} {
				if strings.Contains(event.Message, `"stage": "`+stage+`"`) {
					key := aws.ToString(r.PartitionKey)
					if _, err := uuid.Parse(key); err != nil {
						t.Fatal("Random partition key is not native UUID", key)
					}
					randomKeys[stage] = key
				}
			}
		}
		for _, event := range e.LogEvents {
			key := subscriptionKey(e.SubscriptionFilters[0], e.LogStream, event)
			nativeEvent, ok := wanted[key]
			if !ok {
				t.Fatal("unexpected subscription event", key)
			}
			nativeEvent.ID = ids[fmt.Sprintf("%s/%d/%s", e.LogStream, event.Timestamp, event.Message)]
			if nativeEvent.ID == "" || !reflect.DeepEqual(nativeEvent, event) {
				t.Fatal("subscription changed accepted source event", nativeEvent, event)
			}
			received[key] = event
		}
	}
	if controls == 0 {
		t.Fatal("real admission emitted no native control envelope")
	}
	if len(randomKeys) == 2 && randomKeys["random-first"] == randomKeys["random-second"] {
		t.Fatal("Random distribution reused a per-stream key")
	}
	if len(received) != len(wanted) {
		t.Fatalf("delivered %d native event identities, want %d", len(received), len(wanted))
	}
}
