package stackd_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestFirehoseNativeControls(t *testing.T) {
	var fixture firehoseNativeFixture
	awsReadFixture(t, "firehose/"+"controls.json.gz", &fixture)
	var plan struct {
		Rows, AdvanceBefore, ReopenAfter []int
		ListPeers                        []string
	}
	awsReadFixture(t, "firehose/"+"controls_replay.json", &plan)
	rows := make(map[int]firehoseNativeCall, len(fixture.Calls))
	for _, row := range fixture.Calls {
		rows[row.Sequence] = row
	}
	nativeAudit := make(map[string]json.RawMessage, len(fixture.CloudTrailProjections))
	for _, raw := range fixture.CloudTrailProjections {
		document := ecsControlBody(t, raw)
		nativeAudit[document["requestID"].(string)] = raw
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt.Truncate(time.Second))
			cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
			_, key, secret := cloud.user(t, fixture.Account, "Delegated")
			putUserPolicy(t, cloud.iam(fixture.Account, "test", ""), "Delegated", allow(`"*"`, "*"))
			var session *sts.AssumeRoleOutput
			expectedAudit := map[string]firehoseAuditExpected{}
			for _, sequence := range plan.Rows {
				row, exists := rows[sequence]
				if !exists {
					t.Fatalf("missing native row %d", sequence)
				}
				if slices.Contains(plan.AdvanceBefore, sequence) {
					advanceClock(t, source, 2*time.Second)
				}
				if row.Operation == "DescribeDeliveryStream" {
					var expected firehose.DescribeDeliveryStreamOutput
					if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
						t.Fatal(err)
					}
					var input firehose.DescribeDeliveryStreamInput
					if err := json.Unmarshal(row.Input, &input); err != nil {
						t.Fatal(err)
					}
					caller := cloud.firehose(key, secret, "")
					if expected.DeliveryStreamDescription != nil && expected.DeliveryStreamDescription.DeliveryStreamStatus == "ACTIVE" {
						awaitFirehoseActive(t, source, caller, aws.ToString(input.DeliveryStreamName))
					}
					if row.Result.Code == "ResourceNotFoundException" {
						for range 100 {
							if _, err := caller.DescribeDeliveryStream(t.Context(), &input); err != nil {
								break
							}
							advanceClock(t, source, time.Second)
						}
					}
				}
				if !t.Run(fmt.Sprintf("%03d_%s", sequence, row.Label), func(t *testing.T) {
					var client any
					var wire *awstest.WireClient
					switch row.Service {
					case "iam":
						client = cloud.iam(key, secret, "")
					case "s3":
						client = s3NativeClient(cloud, key, secret)
					case "sts":
						client = cloud.sts(key, secret, "")
					case "firehose":
						selected := cloud.firehose(key, secret, "")
						if row.Caller == "owned-assumed-role" {
							if session == nil {
								t.Fatal("fixture references an unestablished role session")
							}
							selected = cloud.firehose(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
						}
						options := selected.Options()
						wire = &awstest.WireClient{Client: options.HTTPClient}
						options.HTTPClient = wire
						client = firehose.New(options)
					default:
						t.Fatalf("unhandled fixture service %q", row.Service)
					}
					out, callErr := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
					if row.Result.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						assertAPIError(t, callErr, row.Result.Code)
					}
					var requestIDs []string
					if len(row.RequestIDs) != 0 {
						if err := json.Unmarshal(row.RequestIDs, &requestIDs); err != nil {
							t.Fatal(err)
						}
					}
					for _, id := range requestIDs {
						if raw, found := nativeAudit[id]; found {
							document := ecsControlBody(t, raw)
							localID, expected := firehoseAuditExpectation(t, row.Label, document, out, callErr, source.Now())
							expectedAudit[localID] = expected
							break
						}
					}
					if assumed, ok := out.(*sts.AssumeRoleOutput); ok {
						session = assumed
					}
					if row.Service == "firehose" && row.Result.Code == "Success" {
						want, got := ecsControlBody(t, row.Result.Output), ecsControlBody(t, wire.Body)
						firehoseNormalizeResponse(want)
						firehoseNormalizeResponse(got)
						if !reflect.DeepEqual(want, got) {
							t.Fatalf("native semantic response mismatch\n got %s\nwant %s", mustKinesisJSON(t, got), mustKinesisJSON(t, want))
						}
					}
				}) {
					return
				}
				if sequence == 19 {
					// Other owned probes were active in the native account. Their
					// names and DirectPut types are needed for exact list-page replay;
					// their unrelated destination configurations are not compared.
					for _, name := range plan.ListPeers {
						var input firehose.CreateDeliveryStreamInput
						if err := json.Unmarshal(rows[12].Input, &input); err != nil {
							t.Fatal(err)
						}
						input.DeliveryStreamName, input.Tags = &name, nil
						if _, err := cloud.firehose(key, secret, "").CreateDeliveryStream(t.Context(), &input); err != nil {
							t.Fatal(err)
						}
					}
				}
				if slices.Contains(plan.ReopenAfter, sequence) {
					cloud = reopen()
				}
			}
			history := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(cloud.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			firehoseAssertHistory(t, history, expectedAudit)
		})
	}
}

// Preserve response field presence and values, except provider-generated IDs and
// timestamps. Lifecycle durations are local policy, not a replay of wall sleeps.
func firehoseNormalizeResponse(value any) {
	switch v := value.(type) {
	case map[string]any:
		delete(v, "ResponseMetadata")
		for key, item := range v {
			switch key {
			case "CreateTimestamp", "LastUpdateTimestamp", "DeliveryStartTimestamp":
				v[key] = "timestamp"
			case "RecordId":
				v[key] = "record-id"
			default:
				firehoseNormalizeResponse(item)
			}
		}
	case []any:
		for _, item := range v {
			firehoseNormalizeResponse(item)
		}
	}
}
