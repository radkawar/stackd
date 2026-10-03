package stackd_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

// Configured composition from the official SubscriptionFilters Firehose example:
// https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html#FirehoseExample
// Native Kinesis subscription inputs supply real payloads and shared Logs failure
// boundaries; they are not evidence of native Firehose admission or control wording.
func TestLogsFirehoseConfiguredDeliverySDK(t *testing.T) {
	var plan struct {
		Source string
		Logs   struct {
			Source                  string
			DestinationSetup, Setup []string
			Deliveries              []struct {
				Calls, Stages []string
				OnlyKeep      bool
			}
		}
	}
	awsReadFixture(t, "firehose/"+"source_replay.json", &plan)
	var destination firehoseNativeFixture
	awsReadFixture(t, "firehose/"+plan.Source, &destination)
	var native logsKinesisFixture
	raw, err := os.ReadFile(plan.Logs.Source)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &native); err != nil {
		t.Fatal(err)
	}
	rows := eventLogsFixture{Observations: native.Observations}
	const account = "123456789012"
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(native.CapturedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: source})
			for _, label := range plan.Logs.DestinationSetup {
				row := destination.row(t, label)
				row.Input = bytes.ReplaceAll(row.Input, []byte(destination.Account), []byte(account))
				var client any = clients.iam("test", "test", "")
				if row.Service == "s3" {
					client = s3NativeClient(clients, "test", "test")
				}
				firehoseReplayCall(t, client, row)
			}
			var captured firehose.CreateDeliveryStreamInput
			if err := json.Unmarshal(bytes.ReplaceAll(destination.row(t, "create-main").Input, []byte(destination.Account), []byte(account)), &captured); err != nil {
				t.Fatal(err)
			}
			config := captured.ExtendedS3DestinationConfiguration
			// The official example is DirectPut with uncompressed S3 delivery;
			// the Logs records themselves remain gzip members all the way to S3.
			name := "logs-firehose-" + backend
			created, err := clients.firehose("test", "test", "").CreateDeliveryStream(t.Context(), &firehose.CreateDeliveryStreamInput{
				DeliveryStreamName:                 &name,
				ExtendedS3DestinationConfiguration: &firehosetypes.ExtendedS3DestinationConfiguration{BucketARN: config.BucketARN, RoleARN: config.RoleARN, Prefix: config.Prefix, BufferingHints: config.BufferingHints, CompressionFormat: config.CompressionFormat},
			})
			if err != nil {
				t.Fatal(err)
			}
			awaitFirehoseActive(t, source, clients.firehose("test", "test", ""), name)
			streamARN := aws.ToString(created.DeliveryStreamARN)
			bucket := strings.TrimPrefix(aws.ToString(config.BucketARN), "arn:aws:s3:::")
			var subscription cloudwatchlogs.PutSubscriptionFilterInput
			if err := json.Unmarshal(rows.observation(t, "direct-by-log-stream").Input, &subscription); err != nil {
				t.Fatal(err)
			}
			subscription.DestinationArn = &streamARN
			group := aws.ToString(subscription.LogGroupName)
			call := func(label string, client any) any {
				t.Helper()
				row := rows.observation(t, label)
				if client == nil {
					client = logsClient(clients, "test")
					if row.Service == "iam" {
						client = clients.iam("test", "test", "")
					}
				}
				return replayEventLogs(t, client, row, func(v any) {
					switch in := v.(type) {
					case *cloudwatchlogs.PutSubscriptionFilterInput:
						in.DestinationArn = &streamARN
					case *iam.PutRolePolicyInput:
						if label == "grant-delivery-stream" || label == "grant-badtrust-stream" {
							in.PolicyDocument = aws.String(allow(`"firehose:PutRecord"`, streamARN))
						}
					}
				})
			}
			for _, label := range plan.Logs.Setup {
				call(label, nil)
			}
			// Neither an untrusted role with PutRecord nor a trusted role without
			// PutRecord may register a filter by borrowing the caller's authority.
			call("grant-badtrust-stream", nil)
			call("direct-bad-trust", nil)
			call("direct-no-stream-permission", nil)
			call("grant-delivery-stream", nil)
			var assume sts.AssumeRoleInput
			if err := json.Unmarshal(rows.observation(t, "assume-no-passrole-caller").Input, &assume); err != nil {
				t.Fatal(err)
			}
			session, err := clients.sts("test", "test", "").AssumeRole(t.Context(), &assume)
			if err != nil {
				t.Fatal(err)
			}
			caller := cloudwatchlogs.New(cloudwatchlogs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			call("direct-passrole-denied", caller)
			filters, err := logsClient(clients, "test").DescribeSubscriptionFilters(t.Context(), &cloudwatchlogs.DescribeSubscriptionFiltersInput{LogGroupName: &group})
			if err != nil {
				t.Fatal(err)
			}
			if len(filters.SubscriptionFilters) != 0 {
				t.Fatal("failed destination/PassRole admission installed a subscription", filters)
			}
			var callerPolicy iam.PutRolePolicyInput
			if err := json.Unmarshal(rows.observation(t, "grant-caller-no-passrole").Input, &callerPolicy); err != nil {
				t.Fatal(err)
			}
			callerPolicy.PolicyDocument = aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:PutSubscriptionFilter","Resource":"arn:aws:logs:us-east-1:%s:log-group:%s"},{"Effect":"Allow","Action":"iam:PassRole","Resource":%q,"Condition":{"StringEquals":{"iam:PassedToService":"logs.amazonaws.com"}}}]}`, account, group, aws.ToString(subscription.RoleArn)))
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &callerPolicy); err != nil {
				t.Fatal(err)
			}
			call("direct-by-log-stream", caller)
			// This remains an explicit local capability boundary, not an invented
			// native PutDestination result for a Firehose physical target.
			_, err = logsClient(clients, "test").PutDestination(t.Context(), &cloudwatchlogs.PutDestinationInput{DestinationName: aws.String("firehose-logical"), TargetArn: &streamARN, RoleArn: subscription.RoleArn})
			assertAPIError(t, err, "UnsupportedOperationException")
			stages := map[string]bool{}
			for _, step := range plan.Logs.Deliveries {
				for _, label := range step.Calls {
					call(label, nil)
				}
				for _, stage := range step.Stages {
					stages[stage] = step.OnlyKeep
				}
				// The delivery interval has not elapsed: reopen with either queued
				// Logs work or accepted, buffered Firehose bytes still outstanding.
				clients = reopen()
				complete := false
				for range 100 {
					objects := firehoseConsumerObjects(t, s3NativeClient(clients, "test", "test"), bucket, aws.ToString(config.Prefix))
					complete = logsFirehoseMatches(t, native, stages, objects, logsClient(clients, "test"), group)
					if complete {
						break
					}
					advanceClock(t, source, 5*time.Second)
				}
				if !complete {
					t.Fatalf("S3 never received configured Logs DATA_MESSAGE and CONTROL_MESSAGE envelopes for stages %v", stages)
				}
			}
		})
	}
}

// Each S3 object may contain multiple concatenated gzip members. Decode all
// envelopes without treating a Firehose object boundary as a Logs batch boundary.
func logsFirehoseMatches(t *testing.T, native logsKinesisFixture, stages map[string]bool, objects map[string][]byte, logs *cloudwatchlogs.Client, group string) bool {
	t.Helper()
	wanted := map[subscriptionEventKey]subscriptionLogEvent{}
	for _, record := range native.Records {
		e := record.Envelope
		if e.MessageType != "DATA_MESSAGE" {
			continue
		}
		for _, event := range e.LogEvents {
			var marker struct{ Stage, Kind string }
			if err := json.Unmarshal([]byte(event.Message), &marker); err != nil {
				t.Fatal(err)
			}
			onlyKeep, selected := stages[marker.Stage]
			if !selected || onlyKeep && marker.Kind != "keep" {
				continue
			}
			for _, filter := range e.SubscriptionFilters {
				if filter == "direct" {
					wanted[subscriptionKey(filter, e.LogStream, event)] = event
				}
			}
		}
	}
	if len(wanted) == 0 {
		t.Fatal("selected Logs fixture stages have no native data")
	}
	ids := map[subscriptionEventKey]string{}
	pages := cloudwatchlogs.NewFilterLogEventsPaginator(logs, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &group})
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			key := subscriptionEventKey{Filter: "direct", Stream: aws.ToString(event.LogStreamName), Message: aws.ToString(event.Message), Timestamp: aws.ToInt64(event.Timestamp)}
			ids[key] = aws.ToString(event.EventId)
		}
	}
	received := map[subscriptionEventKey]bool{}
	control := false
	for _, body := range objects {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("S3 object is not a gzip Logs payload: %v", err)
		}
		decoder := json.NewDecoder(reader)
		for {
			var envelope subscriptionEnvelope
			err := decoder.Decode(&envelope)
			if err == io.EOF {
				break
			}
			if err != nil {
				reader.Close()
				t.Fatal(err)
			}
			if envelope.MessageType == "CONTROL_MESSAGE" {
				// Controls check destination reachability; they are not source log
				// events. Their cadence, text, and timestamps are not pinned.
				control = true
				continue
			}
			if envelope.MessageType != "DATA_MESSAGE" || envelope.Owner != "123456789012" || envelope.LogGroup != group || !reflect.DeepEqual(envelope.SubscriptionFilters, []string{"direct"}) {
				reader.Close()
				t.Fatalf("invalid configured Logs data envelope: %+v", envelope)
			}
			for _, event := range envelope.LogEvents {
				key := subscriptionKey("direct", envelope.LogStream, event)
				expected, ok := wanted[key]
				if !ok {
					reader.Close()
					t.Fatalf("unexpected or filtered-out source event reached S3: %+v", key)
				}
				expected.ID = ids[key]
				if expected.ID == "" || !reflect.DeepEqual(event, expected) {
					reader.Close()
					t.Fatalf("S3 changed accepted Logs event identity or payload: %+v != %+v", event, expected)
				}
				received[key] = true
			}
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return control && len(received) == len(wanted)
}
