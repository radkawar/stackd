package stackd_test

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
	"stackd/clock"
)

// Rows name their original call sequence; audit and log projections also name
// native event IDs. Service-time advances exercise transitions, not AWS latency.
func TestCloudTrailKMSNativeReplay(t *testing.T) {
	for _, name := range []string{"controls", "precedence", "delivery"} {
		t.Run(name, func(t *testing.T) {
			var fixture struct {
				Calls []struct {
					s3KMSCall
					Advance string
				}
				ReopenCalls []s3KMSCall
				LogBucket   string
				Logs        []trailKMSLog
				Audits      []struct {
					Sequence int
					EventID  string
					Output   map[string]any
				}
			}
			awsReadFixture(t, "cloudtrail/kms_"+name+"_replay.json.gz", &fixture)
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					source := clock.NewManual(time.Date(2026, 9, 19, 22, 0, 0, 0, time.UTC))
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
					replay := newS3KMSReplay(clients)
					for _, row := range fixture.Calls {
						if row.Reopen {
							replay.clients = reopen()
						}
						if row.Advance != "" {
							duration, err := time.ParseDuration(row.Advance)
							if err != nil {
								t.Fatal(err)
							}
							advanceClock(t, source, duration)
							trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
						}
						replay.call(t, row.s3KMSCall)
					}
					replay.clients = reopen()
					for _, row := range fixture.ReopenCalls {
						replay.call(t, row)
					}
					if len(fixture.Logs) != 0 {
						trailKMSLogs(t, replay, fixture.LogBucket, fixture.Logs)
					}

					// These are positive observations, not claims that uncaptured
					// denied calls produced no event. Denied S3 admission still
					// produced a successful KMS call for its exact object ARN.
					records := make(map[string][]map[string]any)
					for _, audit := range fixture.Audits {
						var want map[string]any
						if err := json.Unmarshal(replay.rebind(t, audit.Output), &want); err != nil {
							t.Fatal(err)
						}
						region := want["awsRegion"].(string)
						if _, ok := records[region]; !ok {
							records[region] = trailKMSGenerateRecords(t, replay.cloudtrailClient("caller", region))
						}
						label := fmt.Sprintf("kms_%s_evidence.json.gz:%d event %s", name, audit.Sequence, audit.EventID)
						var found map[string]any
						for _, record := range records[region] {
							if reflect.DeepEqual(record["requestParameters"], want["requestParameters"]) && record["errorCode"] == want["errorCode"] {
								found = record
								break
							}
						}
						if found == nil {
							t.Fatalf("%s: missing native GenerateDataKey outcome for %#v", label, want["requestParameters"])
						}
						s3NativeProjection(t, label, want, found)
					}
				})
			}
		})
	}
}

type trailKMSLog struct {
	Marker, KeyARN, EventID string
	Record                  map[string]any
}

func trailKMSLogs(t *testing.T, replay *s3KMSReplay, bucket string, observations []trailKMSLog) {
	t.Helper()
	var expected []trailKMSLog
	if err := json.Unmarshal(replay.rebind(t, observations), &expected); err != nil {
		t.Fatal(err)
	}
	client := replay.s3Client("caller")
	pages := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket})
	seen := make(map[string]bool)
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range page.Contents {
			key := aws.ToString(object.Key)
			if !strings.HasSuffix(key, ".json.gz") {
				continue
			}
			out, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: object.Key})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(out.Body)
			closeErr := out.Body.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("reading encrypted log: %v %v", err, closeErr)
			}
			if out.ServerSideEncryption != "aws:kms" || aws.ToString(out.ContentEncoding) != "gzip" || aws.ToString(out.ContentType) != "application/json" {
				t.Fatalf("encrypted log metadata differs from native: %+v", out)
			}
			for _, record := range trailNativeRecords(t, map[string][]byte{key: body}) {
				params, _ := record["requestParameters"].(map[string]any)
				for _, want := range expected {
					if params["key"] != want.Marker {
						continue
					}
					if aws.ToString(out.SSEKMSKeyId) != want.KeyARN {
						t.Fatalf("native event %s: marker %s used key %s; want %s", want.EventID, want.Marker, aws.ToString(out.SSEKMSKeyId), want.KeyARN)
					}
					s3NativeProjection(t, "native event "+want.EventID, want.Record, record)
					seen[want.Marker] = true
				}
			}
		}
	}
	for _, want := range expected {
		if !seen[want.Marker] {
			t.Fatalf("missing retained native event %s for %s", want.EventID, want.Marker)
		}
	}
}

func trailKMSGenerateRecords(t *testing.T, client *cloudtrail.Client) []map[string]any {
	t.Helper()
	pages := cloudtrail.NewLookupEventsPaginator(client, &cloudtrail.LookupEventsInput{
		LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("GenerateDataKey")}},
		MaxResults:       aws.Int32(50),
	})
	var records []map[string]any
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			var record map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &record); err != nil {
				t.Fatal(err)
			}
			records = append(records, record)
		}
	}
	return records
}
