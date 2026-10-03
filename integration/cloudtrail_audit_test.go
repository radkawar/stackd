package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go/middleware"

	"stackd/clock"
	"stackd/storage"
)

// auditNativeRecords reads the native documents, never the capture's derived
// commentary or LookupEvents resource aliases. The data capture repeats some
// documents in its correlations; the original delivered log is authoritative.
func auditNativeRecords(t *testing.T, name string) []map[string]any {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "cloudtrail", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		NativeEvents []struct {
			Event map[string]any `json:"event"`
		} `json:"nativeEvents"`
		Delivery struct {
			GzipObjects []struct {
				Records []map[string]any `json:"Records"`
			} `json:"gzip_objects"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	seen := map[string]bool{}
	appendRecord := func(record map[string]any) {
		id, _ := record["eventID"].(string)
		if !seen[id] {
			records = append(records, record)
			seen[id] = true
		}
	}
	for _, row := range fixture.NativeEvents {
		appendRecord(row.Event)
	}
	for _, object := range fixture.Delivery.GzipObjects {
		for _, record := range object.Records {
			appendRecord(record)
		}
	}
	return records
}

func auditLookupRecord(t *testing.T, client *cloudtrail.Client, requestID, eventName string) map[string]any {
	t.Helper()
	pages := cloudtrail.NewLookupEventsPaginator(client, &cloudtrail.LookupEventsInput{
		MaxResults:       aws.Int32(50),
		LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: &eventName}},
	})
	var found map[string]any
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
			if record["requestID"] == requestID && record["eventName"] == eventName {
				if found != nil {
					t.Fatalf("duplicate %s outcome for request %s", eventName, requestID)
				}
				found = record
			}
		}
	}
	if found == nil {
		t.Fatalf("missing %s outcome for request %s", eventName, requestID)
	}
	return found
}

func auditLatestRecord(t *testing.T, client *cloudtrail.Client, eventName string) map[string]any {
	t.Helper()
	page, err := client.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{
		MaxResults:       aws.Int32(1),
		LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: &eventName}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("missing %s outcome", eventName)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(aws.ToString(page.Events[0].CloudTrailEvent)), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestCloudTrailManagementSelectorsReachRealConsumers(t *testing.T) {
	body, err := os.ReadFile("../testdata/cloudtrail/audit/management_selectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name     string
			Selector trailtypes.EventSelector
			Events   []string
		}
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Cases {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "selectors.sqlite"))
				}
				source := clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC))
				cloud, c, _ := startEventDeliveryCloud(t, backends, source)
				client, trails := c.kms(eventDeliveryAccount, "test", ""), trailNativeClient(c)
				key, err := client.CreateKey(t.Context(), &kms.CreateKeyInput{})
				if err != nil {
					t.Fatal(err)
				}
				trailNativeProvision(t, c, controls, objects, false)
				queue := trailNativeQueue(t, c)
				_, err = eventDeliveryClient(c, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{
					Name: aws.String("native-cloudtrail"), State: eventtypes.RuleStateEnabledWithAllCloudtrailManagementEvents,
					EventPattern: aws.String(`{"source":["aws.kms"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventName":["Encrypt","DisableKey"]}}`),
				})
				if err != nil {
					t.Fatal(err)
				}
				_, err = trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{
					TrailName: aws.String(controls.Identity["trail_name"]), EventSelectors: []trailtypes.EventSelector{scenario.Selector},
				})
				if err != nil {
					t.Fatal(err)
				}
				s3NativeReplay(t, trails, controls, "start-logging")
				encrypted, err := client.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyMetadata.KeyId, Plaintext: []byte("private selector exercise")})
				if err != nil {
					t.Fatal(err)
				}
				disabled, err := client.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.KeyId})
				if err != nil {
					t.Fatal(err)
				}
				history := map[string]map[string]any{}
				for operation, metadata := range map[string]middleware.Metadata{"Encrypt": encrypted.ResultMetadata, "DisableKey": disabled.ResultMetadata} {
					requestID, ok := awsmiddleware.GetRequestIDMetadata(metadata)
					if !ok || requestID == "" {
						t.Fatal("SDK request correlation missing")
					}
					// Both outcomes remain in history, even when the configured
					// trail excludes their source or read/write classification.
					history[requestID] = auditLookupRecord(t, trails, requestID, operation)
				}
				advanceClock(t, source, 6*time.Minute)
				trailNativeDrain(t, cloud)
				logs := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(c, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
				var delivered []map[string]any
				for _, event := range trailQueueMessages(t, c, queue) {
					if event["source"] != "aws.kms" {
						t.Fatalf("unexpected consumer source: %#v", event)
					}
					delivered = append(delivered, event["detail"].(map[string]any))
				}
				for destination, records := range map[string][]map[string]any{"S3": logs, "EventBridge/SQS": delivered} {
					var names []string
					for _, record := range records {
						requestID, _ := record["requestID"].(string)
						want := history[requestID]
						if want == nil {
							continue
						}
						if !reflect.DeepEqual(record, want) {
							t.Fatalf("%s changed native history record: got %#v; history %#v", destination, record, want)
						}
						names = append(names, record["eventName"].(string))
					}
					slices.Sort(names)
					if !slices.Equal(names, scenario.Events) {
						t.Fatalf("%s selected %v; want %v", destination, names, scenario.Events)
					}
				}
			})
		}
	}
}
