package stackd_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
	trailstorage "stackd/storage/cloudtrail"
)

func trailNativeClient(c cloudClients) *cloudtrail.Client {
	return cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func trailNativeProvision(t *testing.T, c cloudClients, controls, objects s3NativeFixture, preflight bool) {
	t.Helper()
	client, trails := s3NativeClient(c, eventDeliveryAccount, "test"), trailNativeClient(c)
	for _, key := range []string{"source_bucket", "log_bucket"} {
		s3NativeReplay(t, client, objects, "create-"+objects.Identity[key])
	}
	if preflight {
		for _, policy := range []string{"no-policy", "missing-get-acl", "missing-put", "wrong-source-arn", "wrong-source-account", "wrong-acl"} {
			if policy != "no-policy" {
				s3NativeReplay(t, client, objects, "log-policy-"+policy)
			}
			s3NativeReplay(t, trails, controls, "create-trail-"+policy)
			_, err := trails.GetTrail(t.Context(), &cloudtrail.GetTrailInput{Name: aws.String(controls.Identity["trail_name"])})
			assertAPIError(t, err, "TrailNotFoundException")
		}
	}
	s3NativeReplay(t, client, objects, "log-policy-correct")
	s3NativeReplay(t, trails, controls, "create-trail-correct-both-conditions")
	if !preflight {
		return
	}
	for _, label := range []string{"new-trail-get-trail", "new-trail-describe-trails", "new-trail-get-trail-status", "new-trail-get-event-selectors", "create-trail-repeated"} {
		s3NativeReplay(t, trails, controls, label)
	}
	for _, policy := range []string{"arn-only", "account-only", "correct"} {
		s3NativeReplay(t, client, objects, "log-policy-"+policy)
		s3NativeReplay(t, trails, controls, "update-trail-"+policy)
	}
	for _, label := range []string{"update-trail-wrong-prefix", "get-trail-after-rejected-update", "put-basic-owned", "put-advanced-replaces-basic", "get-advanced-replacement", "reject-both-selector-types", "reject-empty-basic", "reject-empty-advanced", "reject-invalid-read-write", "reject-advanced-missing-category", "get-selectors-after-rejections", "put-basic-replaces-advanced", "get-basic-replacement"} {
		s3NativeReplay(t, trails, controls, label)
	}
	// Unknown native resource-type failures must leave the installed selectors intact.
	types := s3NativeLoad(t, "cloudtrail", "owned_selector_resource_types")
	for _, label := range []string{"resource-type-AWS::NoSuchService::MadeUp", "resource-type-AWS::IAM::Role"} {
		row := types.row(t, label)
		row.Input = json.RawMessage(strings.ReplaceAll(string(row.Input), types.Identity["trail_name"], controls.Identity["trail_name"]))
		types.Observations = []s3NativeObservation{row}
		s3NativeReplay(t, trails, types, label)
		types = s3NativeLoad(t, "cloudtrail", "owned_selector_resource_types")
		s3NativeReplay(t, trails, controls, "get-basic-replacement")
	}
}

func trailNativeDrain(t *testing.T, cloud *stackd.Stack) {
	t.Helper()
	for range 100 {
		out, err := cloud.RunDueJobs(t.Context(), 100)
		if err != nil {
			t.Fatal(err)
		}
		if !out.More {
			return
		}
	}
	t.Fatal("CloudTrail delivery failed to quiesce")
}

func trailNativeStatus(t *testing.T, client *cloudtrail.Client, name string, logging, success bool) *cloudtrail.GetTrailStatusOutput {
	t.Helper()
	out, err := client.GetTrailStatus(t.Context(), &cloudtrail.GetTrailStatusInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToBool(out.IsLogging) != logging || (out.LatestDeliveryTime != nil) != success {
		t.Fatalf("logging/delivery status is not backed by completed S3 delivery: %+v", out)
	}
	if !success && aws.ToString(out.LatestDeliveryAttemptSucceeded) != "" {
		t.Fatalf("premature delivery success: %+v", out)
	}
	return out
}

func trailNativeObjects(t *testing.T, client *s3.Client, bucket, prefix string) map[string][]byte {
	t.Helper()
	listing, err := client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToBool(listing.IsTruncated) {
		t.Fatal("unexpected truncated delivery listing")
	}
	out := make(map[string][]byte)
	for _, object := range listing.Contents {
		key := aws.ToString(object.Key)
		if strings.HasSuffix(key, "/") && aws.ToInt64(object.Size) == 0 {
			continue
		} // Native prefix marker, not a gzip log.
		if !strings.HasSuffix(key, ".json.gz") {
			t.Fatalf("unexpected log-bucket object: %s", key)
		}
		got, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: object.Key})
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(got.Body)
		got.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got.ServerSideEncryption != "AES256" {
			t.Fatalf("log object is not SSE-S3: %+v", got)
		}
		out[key] = data
	}
	return out
}

func trailNativeRecords(t *testing.T, objects map[string][]byte) []map[string]any {
	t.Helper()
	var records []map[string]any
	for key, body := range objects {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s is not gzip: %v", key, err)
		}
		data, err := io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("gzip checksum/body: %v %v", err, closeErr)
		}
		var document struct {
			Records []map[string]any `json:"Records"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Records) == 0 {
			t.Fatal("delivery produced empty Records")
		}
		records = append(records, document.Records...)
	}
	return records
}

func (f s3NativeFixture) record(t *testing.T, label string) map[string]any {
	t.Helper()
	for _, correlation := range f.Correlations {
		if correlation.Label != label {
			continue
		}
		for _, file := range f.DeliveredLogs {
			for _, record := range file.Records {
				if record["eventID"] == correlation.EventID {
					return record
				}
			}
		}
	}
	t.Fatalf("native gzip has no correlated record for %s", label)
	return nil
}

func trailNativeRecord(t *testing.T, want, got map[string]any, requestID, key string) {
	t.Helper()
	for _, field := range []string{"eventVersion", "eventSource", "eventName", "awsRegion", "readOnly", "resources", "eventType", "managementEvent", "recipientAccountId", "eventCategory", "responseElements"} {
		actual, present := got[field]
		if !present || !reflect.DeepEqual(want[field], actual) {
			t.Fatalf("record %s field %s: got %#v (present %v), native %#v", requestID, field, actual, present, want[field])
		}
	}
	for _, field := range []string{"errorCode", "errorMessage"} {
		expected, expectedPresent := want[field]
		actual, present := got[field]
		if present != expectedPresent || (present && (actual == "" || (field == "errorCode" && actual != expected))) {
			t.Fatalf("record %s native error presence/code %s: %#v", requestID, field, got)
		}
	}
	expectedParams := want["requestParameters"].(map[string]any)
	actualParams, ok := got["requestParameters"].(map[string]any)
	if !ok {
		t.Fatalf("missing request parameters: %#v", got)
	}
	if len(expectedParams) != len(actualParams) {
		t.Fatalf("request parameter presence differs: got %#v native %#v", actualParams, expectedParams)
	}
	for field, value := range expectedParams {
		if field == "Host" {
			if actualParams[field] == nil || actualParams[field] == "" {
				t.Fatal("missing request Host")
			}
			continue
		}
		if !reflect.DeepEqual(value, actualParams[field]) {
			t.Fatalf("request parameter %s: got %#v native %#v", field, actualParams[field], value)
		}
	}
	if got["requestID"] != requestID || got["eventID"] == nil || got["eventID"] == "" {
		t.Fatalf("lost request/event correlation: %#v", got)
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(got["eventTime"])); err != nil {
		t.Fatalf("invalid event timestamp: %v", err)
	}
	identity, ok := got["userIdentity"].(map[string]any)
	if !ok || identity["type"] != "IAMUser" || identity["userName"] != "Delegated" || identity["accountId"] != eventDeliveryAccount || identity["arn"] != "arn:aws:iam::"+eventDeliveryAccount+":user/Delegated" || identity["accessKeyId"] != key || identity["principalId"] == "" {
		t.Fatalf("SDK caller identity was not retained: %#v", identity)
	}
	expectedAdditional := want["additionalEventData"].(map[string]any)
	actualAdditional, ok := got["additionalEventData"].(map[string]any)
	if !ok {
		t.Fatalf("missing additional event data: %#v", got)
	}
	for _, field := range []string{"httpStatusCode", "SSEApplied", "objectSize"} {
		if expected, exists := expectedAdditional[field]; exists && !reflect.DeepEqual(expected, actualAdditional[field]) {
			t.Fatalf("%v record %s additional data %s: got %#v native %#v", got["eventName"], requestID, field, actualAdditional[field], expected)
		}
	}
}

func trailNativeQueue(t *testing.T, c cloudClients) *string {
	t.Helper()
	queue, err := c.sqs(eventDeliveryAccount, "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("native-cloudtrail"), Attributes: map[string]string{"SqsManagedSseEnabled": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := eventDeliveryClient(c, eventDeliveryAccount).PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("native-cloudtrail"), EventPattern: aws.String(`{"source":["aws.s3"],"detail-type":["AWS API Call via CloudTrail"]}`), State: eventtypes.RuleStateEnabled})
	if err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":native-cloudtrail"
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, arn, aws.ToString(rule.RuleArn))
	if _, err := c.sqs(eventDeliveryAccount, "test", "").SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
		t.Fatal(err)
	}
	out, err := eventDeliveryClient(c, eventDeliveryAccount).PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("native-cloudtrail"), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: &arn}}})
	if err != nil || out.FailedEntryCount != 0 {
		t.Fatalf("CloudTrail target: %+v %v", out, err)
	}
	return queue.QueueUrl
}

func trailNativeMessages(t *testing.T, c cloudClients, url *string) []map[string]any {
	t.Helper()
	// Only active-window messages establish the envelope contract. Native
	// before-start/after-stop windows do not prove immediate propagation.
	data, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "cloudtrail", "eventbridge_delivery.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Messages []struct {
			Window  string                `json:"received_in_window"`
			Message struct{ Body string } `json:"sqs_message"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var native map[string]any
	for _, row := range fixture.Messages {
		if strings.HasPrefix(row.Window, "active-") {
			if err := json.Unmarshal([]byte(row.Message.Body), &native); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if native == nil {
		t.Fatal("native fixture lacks an active CloudTrail EventBridge message")
	}
	var records []map[string]any
	for _, event := range trailQueueMessages(t, c, url) {
		for _, field := range []string{"version", "source", "detail-type", "account", "region", "resources"} {
			if !reflect.DeepEqual(native[field], event[field]) {
				t.Fatalf("EventBridge envelope %s: got %#v native %#v", field, event[field], native[field])
			}
		}
		detail, ok := event["detail"].(map[string]any)
		if !ok || event["id"] == nil || event["id"] == "" || event["time"] != detail["eventTime"] {
			t.Fatalf("EventBridge lost event identity/time/detail: %#v", event)
		}
		records = append(records, detail)
	}
	return records
}

func trailQueueMessages(t *testing.T, c cloudClients, url *string) []map[string]any {
	t.Helper()
	var records []map[string]any
	client := c.sqs(eventDeliveryAccount, "test", "")
	for range 100 {
		out, err := client.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url, MaxNumberOfMessages: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			return records
		}
		for _, message := range out.Messages {
			var event map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &event); err != nil {
				t.Fatal(err)
			}
			records = append(records, event)
			if _, err := client.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: url, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Fatal("SQS replay did not quiesce")
	return nil
}

func TestCloudTrailNativeS3DeliverySDKReplayAndRecovery(t *testing.T) {
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	binary := s3NativeLoad(t, "s3", "owned_binary_headers")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 13, 17, 12, 0, 0, time.UTC))
			path := filepath.Join(t.TempDir(), "trail.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			cloud, c, closeStack := startEventDeliveryCloud(t, backends, source)
			trailNativeProvision(t, c, controls, objects, true)
			trails, root := trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			_, key, secret := c.user(t, eventDeliveryAccount, "Delegated")
			putUserPolicy(t, c.iam(eventDeliveryAccount, "test", ""), "Delegated", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
			client := s3NativeClient(c, key, secret)
			queue := trailNativeQueue(t, c)
			s3NativeReplay(t, trails, controls, "put-final-owned-advanced")
			for _, label := range []string{"source-object-private-acl", "source-object-no-acl-default-checksum"} {
				s3NativeReplay(t, client, objects, label)
			}
			s3NativeReplay(t, client, binary, "post-propagation-trigger-put")
			trailNativeDrain(t, cloud)
			if messages := trailNativeMessages(t, c, queue); len(messages) != 0 {
				t.Fatalf("nonlogging trail published events: %#v", messages)
			}
			trailNativeStatus(t, trails, controls.Identity["trail_name"], false, false)
			s3NativeReplay(t, trails, controls, "start-logging")
			s3NativeReplay(t, trails, controls, "start-logging-repeat")
			expected := make(map[string]map[string]any)
			labels := []string{"revoked-put", "revoked-head-default", "revoked-head-checksum", "revoked-get", "revoked-range", "revoked-list", "revoked-delete", "revoked-head-missing", "revoked-get-missing", "revoked-delete-missing"}
			for _, label := range labels {
				_, id := s3NativeReplay(t, client, objects, label)
				if id == "" {
					t.Fatalf("%s missing request ID", label)
				}
				expected[id] = controls.record(t, label)
			}
			// Replacement and Stop occur before the worker runs. Accepted records must
			// remain; later calls must not be retroactively admitted with old selectors.
			replacement := &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(controls.Identity["trail_name"]), EventSelectors: []trailtypes.EventSelector{{IncludeManagementEvents: aws.Bool(false), ReadWriteType: trailtypes.ReadWriteTypeAll, DataResources: []trailtypes.DataResource{{Type: aws.String("AWS::S3::Object"), Values: []string{"arn:aws:s3:::" + objects.Identity["source_bucket"] + "/excluded/"}}}}}}
			if _, err := trails.PutEventSelectors(t.Context(), replacement); err != nil {
				t.Fatal(err)
			}
			if _, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(objects.Identity["source_bucket"]), Key: aws.String("data/not-selected"), Body: strings.NewReader("excluded by current selectors")}); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "cleanup-stop-logging")
			// Stop status is immediate; effective admission has a service-time
			// propagation window, as demonstrated by native post-stop deliveries.
			advanceClock(t, source, 2*time.Minute)
			if _, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(objects.Identity["source_bucket"]), Key: aws.String("excluded/not-logging"), Body: strings.NewReader("excluded by current logging state")}); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, root, objects, "revoke-log-bucket-policy")
			trailNativeDrain(t, cloud)
			messages := trailNativeMessages(t, c, queue)
			if len(messages) != len(expected) {
				t.Fatalf("default bus trail gating: got %d want %d", len(messages), len(expected))
			}
			for _, record := range messages {
				id, _ := record["requestID"].(string)
				want, ok := expected[id]
				if !ok {
					t.Fatalf("unadmitted EventBridge event: %#v", record)
				}
				trailNativeRecord(t, want, record, id, key)
			}
			trailNativeStatus(t, trails, controls.Identity["trail_name"], false, false)
			if logs := trailNativeObjects(t, root, objects.Identity["log_bucket"], "owned/AWSLogs/"); len(logs) != 0 {
				t.Fatalf("logs delivered before batch deadline: %#v", logs)
			}
			var batch trailstorage.DeliveryRecord
			err := backends.CloudTrail.View(t.Context(), func(r trailstorage.Reader) error {
				tr, err := r.Trail(trailstorage.TrailKey{Scope: trailstorage.Scope{Partition: "aws", AccountID: eventDeliveryAccount, Region: "us-east-1"}, Name: controls.Identity["trail_name"]})
				if err != nil {
					return err
				}
				batch, err = r.OpenDelivery(tr.ID, tr.Key.AccountID, "us-east-1", trailstorage.DestinationS3)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 5*time.Minute)
			trailNativeDrain(t, cloud)
			failed := trailNativeStatus(t, trails, controls.Identity["trail_name"], false, false)
			if aws.ToString(failed.LatestDeliveryError) == "" {
				t.Fatalf("revoked delivery did not expose failure: %+v", failed)
			}
			if logs := trailNativeObjects(t, root, objects.Identity["log_bucket"], "owned/AWSLogs/"); len(logs) != 0 {
				t.Fatalf("revoked service principal wrote logs: %#v", logs)
			}
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				cloud, c, _ = startEventDeliveryCloud(t, backends, source)
				trails, root = trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			}
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, cloud)
			var retryAt time.Time
			err = backends.CloudTrail.View(t.Context(), func(r trailstorage.Reader) error {
				current, err := r.Delivery(batch.ID)
				if err != nil {
					return err
				}
				if current.ObjectKey != batch.ObjectKey || !current.Sealed || current.EventCount != len(expected) || current.Attempts < 2 {
					return fmt.Errorf("retry lost sealed batch/key: %+v, initial %+v", current, batch)
				}
				retryAt = current.Due
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, root, objects, "log-policy-correct")
			if !retryAt.After(source.Now()) {
				t.Fatalf("failed delivery lost its retry deadline: %s", retryAt)
			}
			advanceClock(t, source, retryAt.Sub(source.Now()))
			trailNativeDrain(t, cloud)
			trailNativeStatus(t, trails, controls.Identity["trail_name"], false, true)
			delivered := trailNativeObjects(t, root, objects.Identity["log_bucket"], "owned/AWSLogs/")
			if len(delivered) != 1 || delivered[batch.ObjectKey] == nil {
				t.Fatalf("retry changed key or duplicated objects: keys %#v expected %s", reflect.ValueOf(delivered).MapKeys(), batch.ObjectKey)
			}
			records := trailNativeRecords(t, delivered)
			if len(records) != len(expected) {
				t.Fatalf("accepted Records lost/duplicated: got %d want %d", len(records), len(expected))
			}
			seen := make(map[string]bool)
			eventIDs := make(map[string]bool)
			for _, record := range records {
				id, _ := record["requestID"].(string)
				want, ok := expected[id]
				if !ok || seen[id] {
					t.Fatalf("unadmitted/duplicate gzip record: %#v", record)
				}
				seen[id] = true
				eventID := fmt.Sprint(record["eventID"])
				if eventIDs[eventID] {
					t.Fatal("duplicate event identity")
				}
				eventIDs[eventID] = true
				trailNativeRecord(t, want, record, id, key)
			}
			for _, message := range messages {
				for _, record := range records {
					if message["requestID"] == record["requestID"] && !reflect.DeepEqual(message, record) {
						t.Fatalf("EventBridge and gzip records diverged: %#v %#v", message, record)
					}
				}
			}
			lookup, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("PutObject")}}})
			if err != nil || len(lookup.Events) != 0 {
				t.Fatalf("LookupEvents exposed Data events: %+v %v", lookup, err)
			}
			advanceClock(t, source, 10*time.Minute)
			trailNativeDrain(t, cloud)
			if again := trailNativeObjects(t, root, objects.Identity["log_bucket"], "owned/AWSLogs/"); !reflect.DeepEqual(delivered, again) {
				t.Fatal("completed batch retried with changed gzip or duplicate key")
			}
			s3NativeReplay(t, trails, controls, "cleanup-delete-trail")
			s3NativeReplay(t, trails, controls, "cleanup-get-trail-absent")
		})
	}
}

type trailAppendFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *trailAppendFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "s3.amazonaws.com" && call.EventName == "PutObject" && f.fail.Swap(false) {
		return errors.New("injected failure after real S3 API journal append")
	}
	return nil
}

func TestCloudTrailS3JournalFailureRollsBackSDKMutation(t *testing.T) {
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "rollback.sqlite"))
			}
			failure := &trailAppendFailure{Storage: backends.Journal}
			backends.Journal = failure
			source := clock.NewManual(time.Date(2026, 9, 13, 17, 12, 0, 0, time.UTC))
			cloud, c, _ := startEventDeliveryCloud(t, backends, source)
			trailNativeProvision(t, c, controls, objects, false)
			trails, client := trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			queue := trailNativeQueue(t, c)
			s3NativeReplay(t, trails, controls, "put-final-owned-advanced")
			bucket, key := objects.Identity["source_bucket"], "data/rollback.bin"
			original := []byte("original authenticated ciphertext")
			if _, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(original)}); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "start-logging")
			failure.fail.Store(true)
			_, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader("must not commit")})
			if err == nil {
				t.Fatal("journal failure reported mutation success")
			}
			// Stop before verification reads: only the failed mutation could have been
			// admitted, and its old ciphertext must still be readable through the SDK.
			s3NativeReplay(t, trails, controls, "cleanup-stop-logging")
			advanceClock(t, source, 2*time.Minute)
			got, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(got.Body)
			got.Body.Close()
			if err != nil || !bytes.Equal(body, original) {
				t.Fatalf("failed mutation changed object: %q %v", body, err)
			}
			journalRows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			successes := 0
			for _, event := range journalRows {
				call := event.APICallCompleted
				if call != nil && call.EventSource == "s3.amazonaws.com" && call.EventName == "PutObject" && call.ErrorCode == "" {
					for _, resource := range call.EventResources {
						if resource.ARN == "arn:aws:s3:::"+bucket+"/"+key {
							successes++
						}
					}
				}
			}
			if successes != 1 {
				t.Fatalf("failed append leaked committed successful event: %d", successes)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			records := trailNativeMessages(t, c, queue)
			if len(records) != 1 || records[0]["eventName"] != "PutObject" || records[0]["errorCode"] != "InternalError" {
				t.Fatalf("failed mutation lost its independent error outcome or emitted success: %#v", records)
			}
			logs := trailNativeRecords(t, trailNativeObjects(t, client, objects.Identity["log_bucket"], "owned/AWSLogs/"))
			if len(logs) != 1 || !reflect.DeepEqual(logs[0], records[0]) {
				t.Fatalf("failed API outcome diverged between targets: %#v %#v", records, logs)
			}
			trailNativeStatus(t, trails, controls.Identity["trail_name"], false, true)
		})
	}
}

func TestCloudTrailDeleteCancelsAcceptedSDKBatch(t *testing.T) {
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "delete.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 17, 12, 0, 0, time.UTC))
			cloud, c, closeStack := startEventDeliveryCloud(t, backends, source)
			trailNativeProvision(t, c, controls, objects, false)
			trails, client := trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			s3NativeReplay(t, trails, controls, "put-final-owned-advanced")
			s3NativeReplay(t, trails, controls, "start-logging")
			s3NativeReplay(t, client, objects, "revoked-put")
			s3NativeReplay(t, trails, controls, "cleanup-delete-trail")
			s3NativeReplay(t, trails, controls, "cleanup-get-trail-absent")
			// Reusing the same ARN cannot attach the old accepted batch to the new
			// incarnation, including after reopening a database with pending work.
			s3NativeReplay(t, trails, controls, "create-trail-correct-both-conditions")
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				cloud, c, _ = startEventDeliveryCloud(t, backends, source)
				trails, client = trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			if logs := trailNativeObjects(t, client, objects.Identity["log_bucket"], "owned/AWSLogs/"); len(logs) != 0 {
				t.Fatalf("deleted trail batch delivered under recreated ARN: %#v", logs)
			}
			trailNativeStatus(t, trails, controls.Identity["trail_name"], false, false)
			s3NativeReplay(t, client, objects, "revoked-get")
		})
	}
}
