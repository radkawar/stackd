package stackd_test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd/clock"
	"stackd/storage"
)

type trailControlCase struct {
	Label     string
	TrailName string `json:"trail_name"`
	Policy    json.RawMessage
	Markers   []struct {
		Key  string
		Size int64 `json:"list_size"`
		Head struct{ Output map[string]any }
	} `json:"marker_observations"`
}

type trailControlFixture struct {
	Observations []s3NativeObservation
	Supplemental []s3NativeObservation `json:"supplemental_configuration_observations"`
	Cases        []trailControlCase
	Management   []map[string]any `json:"management_lookup_events"`
	Lookup       struct {
		Events []struct {
			Event map[string]any `json:"CloudTrailEvent"`
		} `json:"owned_events"`
	} `json:"lookup_correlation"`
	Correlations []struct {
		Label   string `json:"source_observation_label"`
		EventID string `json:"cloudtrail_event_id"`
	} `json:"correlation_mapping"`
	Messages []struct {
		Message struct{ Body string } `json:"sqs_message"`
	}
}

func trailControlLoad(t *testing.T, name string) trailControlFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "cloudtrail", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f trailControlFixture
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	// These CLI captures use kebab-case operation names; inputs remain the
	// original modeled inputs, including the independently varied policies.
	for _, rows := range [][]s3NativeObservation{f.Observations, f.Supplemental} {
		for i := range rows {
			parts := strings.Split(rows[i].Operation, "-")
			for j, part := range parts {
				if part != "" {
					parts[j] = strings.ToUpper(part[:1]) + part[1:]
				}
			}
			rows[i].Operation = strings.Join(parts, "")
			if rows[i].Result.Code == "" && rows[i].Result.HTTPStatus == 200 {
				rows[i].Result.Code = "Success"
			}
		}
	}
	return f
}

func trailControlMarker(t *testing.T, client *s3.Client, bucket, prefix string, c trailControlCase) {
	t.Helper()
	listed, err := client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: aws.String(prefix + "/")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToBool(listed.IsTruncated) || len(listed.Contents) != len(c.Markers) {
		t.Fatalf("%s marker listing: %+v; native %#v", c.Label, listed, c.Markers)
	}
	key := prefix + "/AWSLogs/" + eventDeliveryAccount + "/CloudTrail/"
	got, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if len(c.Markers) == 0 {
		assertAPIError(t, err, "NoSuchKey")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(got.Body)
	closeErr := got.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("marker body: %v %v", readErr, closeErr)
	}
	marker := c.Markers[0]
	if key != marker.Key || aws.ToString(listed.Contents[0].Key) != marker.Key || aws.ToInt64(listed.Contents[0].Size) != marker.Size || len(body) != 0 || aws.ToInt64(got.ContentLength) != 0 {
		t.Fatalf("%s marker is not the actual native zero-byte object: %+v, %q", c.Label, got, body)
	}
	fields := map[string]any{"ETag": aws.ToString(got.ETag), "ContentType": aws.ToString(got.ContentType), "ContentEncoding": aws.ToString(got.ContentEncoding), "ServerSideEncryption": string(got.ServerSideEncryption)}
	for field, value := range fields {
		if !reflect.DeepEqual(value, marker.Head.Output[field]) {
			t.Fatalf("%s marker %s: got %#v native %#v", c.Label, field, value, marker.Head.Output[field])
		}
	}
}

func TestCloudTrailNativePrincipalGatesAndMarkers(t *testing.T) {
	f := trailControlLoad(t, "owned_service_principal")
	replay := s3NativeFixture{Observations: f.Observations}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "principal.sqlite")
			backends, closeDB := storage.NewMemory(), func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 18, 13, 0, 0, time.UTC))
			_, c, closeStack := startEventDeliveryCloud(t, backends, source)
			client, trails := s3NativeClient(c, eventDeliveryAccount, "test"), trailNativeClient(c)
			createBucket := replay.row(t, "create-owned-bucket")
			var bucketInput s3.CreateBucketInput
			if err := json.Unmarshal(createBucket.Input, &bucketInput); err != nil {
				t.Fatal(err)
			}
			bucket := aws.ToString(bucketInput.Bucket)
			s3NativeReplay(t, client, replay, createBucket.Label)
			check := func(t *testing.T, tc trailControlCase) {
				row := replay.row(t, tc.Label+"-create")
				var input cloudtrail.CreateTrailInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				trailControlMarker(t, client, bucket, aws.ToString(input.S3KeyPrefix), tc)
				got, err := trails.GetTrail(t.Context(), &cloudtrail.GetTrailInput{Name: &tc.TrailName})
				if row.Result.Code != "Success" {
					assertAPIError(t, err, "TrailNotFoundException")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got.Trail == nil || !aws.ToBool(got.Trail.RecursiveLogging) {
					t.Fatalf("successful native create lost recursive logging: %+v", got)
				}
				trailNativeStatus(t, trails, tc.TrailName, false, false)
			}
			for _, tc := range f.Cases {
				if tc.Label == "baseline-after" {
					continue
				} // Same unconditional control as baseline-before.
				t.Run(tc.Label, func(t *testing.T) {
					if _, err := client.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: aws.String(string(tc.Policy))}); err != nil {
						t.Fatal(err)
					}
					s3NativeReplay(t, trails, replay, tc.Label+"-create")
					check(t, tc)
				})
			}
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				_, c, _ = startEventDeliveryCloud(t, backends, source)
				client, trails = s3NativeClient(c, eventDeliveryAccount, "test"), trailNativeClient(c)
				for _, tc := range f.Cases {
					if tc.Label != "baseline-after" {
						t.Run("reopened/"+tc.Label, func(t *testing.T) { check(t, tc) })
					}
				}
			}
			// Deleting a successful trail does not roll back its independently committed marker.
			tc := f.Cases[0]
			if _, err := trails.DeleteTrail(t.Context(), &cloudtrail.DeleteTrailInput{Name: &tc.TrailName}); err != nil {
				t.Fatal(err)
			}
			var input cloudtrail.CreateTrailInput
			if err := json.Unmarshal(replay.row(t, tc.Label+"-create").Input, &input); err != nil {
				t.Fatal(err)
			}
			trailControlMarker(t, client, bucket, aws.ToString(input.S3KeyPrefix), tc)
		})
	}
}

func trailControlNativeEvent(t *testing.T, f trailControlFixture, row s3NativeObservation) map[string]any {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal(row.Input, &input); err != nil {
		t.Fatal(err)
	}
	for _, event := range f.Management {
		if event["eventName"] != row.Operation {
			continue
		}
		identity, _ := event["userIdentity"].(map[string]any)
		if identity["invokedBy"] != nil {
			continue
		} // Resource Explorer reads were not probe controls.
		if row.Result.Code == "Success" && event["errorCode"] != nil || row.Result.Code != "Success" && event["errorCode"] != row.Result.Code {
			continue
		}
		parameters, _ := event["requestParameters"].(map[string]any)
		if recursive, exists := input["RecursiveLogging"]; exists && parameters["recursiveLogging"] != recursive {
			continue
		}
		return event
	}
	t.Fatalf("no native management event for %s %s", row.Label, row.Input)
	return nil
}

func trailControlHistory(t *testing.T, client *cloudtrail.Client, expected map[string]map[string]any) {
	t.Helper()
	input := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("cloudtrail.amazonaws.com")}}, MaxResults: aws.Int32(50)}
	found := make(map[string]bool)
	for range 20 {
		out, err := client.LookupEvents(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			var got map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &got); err != nil {
				t.Fatal(err)
			}
			id, _ := got["requestID"].(string)
			want, ok := expected[id]
			if !ok {
				continue
			}
			if found[id] {
				t.Fatalf("control %s produced duplicate management events", id)
			}
			found[id] = true
			for _, field := range []string{"eventSource", "eventName", "awsRegion", "requestParameters", "responseElements", "readOnly", "eventType", "managementEvent", "eventCategory", "recipientAccountId", "errorCode"} {
				expectedValue, expectedPresent := want[field]
				actual, present := got[field]
				if present != expectedPresent || !reflect.DeepEqual(expectedValue, actual) {
					t.Fatalf("%s %s: got %#v (present %v), native %#v (present %v)", got["eventName"], field, actual, present, expectedValue, expectedPresent)
				}
			}
			if aws.ToString(event.EventId) == "" || got["eventID"] != aws.ToString(event.EventId) || got["eventName"] != aws.ToString(event.EventName) || aws.ToString(event.ReadOnly) != strconv.FormatBool(got["readOnly"].(bool)) {
				t.Fatalf("LookupEvents lost public event correlation: %+v %#v", event, got)
			}
		}
		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}
	for id, want := range expected {
		if !found[id] {
			t.Errorf("LookupEvents omitted SDK request %s (%s)", id, want["eventName"])
		}
	}
}

func TestCloudTrailNativeManagementSDKProjections(t *testing.T) {
	f := trailControlLoad(t, "eventbridge_delivery")
	replay := s3NativeFixture{Observations: f.Observations}
	_, c, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)))
	trails, client := trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
	for _, row := range f.Observations {
		if row.Operation == "CreateBucket" || row.Label == "owned-log-policy" {
			if _, _, err := s3NativeInvoke(t, client, row, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	expected := make(map[string]map[string]any)
	invoke := func(row s3NativeObservation) map[string]any {
		got, id, err := s3NativeInvoke(t, trails, row, nil)
		if row.Result.Code == "Success" {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertAPIError(t, err, row.Result.Code)
			var response *smithyhttp.ResponseError
			if !errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
				t.Fatalf("%s native HTTP error: %v", row.Label, err)
			}
			id = response.Response.Header.Get("x-amzn-RequestId")
		}
		if id == "" {
			t.Fatalf("%s lacks SDK request correlation", row.Label)
		}
		expected[id] = trailControlNativeEvent(t, f, row)
		return got
	}
	for _, label := range []string{"create-trail", "owned-data-selectors", "get-owned-selectors", "before-start-status", "start-logging"} {
		invoke(replay.row(t, label))
	}
	for _, row := range f.Supplemental {
		got := invoke(row)
		if row.Operation == "UpdateTrail" || row.Operation == "GetTrail" {
			s3NativeProjection(t, row.Label, row.Result.Output, got)
		}
	}
	for _, label := range []string{"stop-logging", "stopped-status", "cleanup-stop-trail", "cleanup-delete-trail", "verify-trail-absent"} {
		invoke(replay.row(t, label))
	}
	trailControlHistory(t, trails, expected)
}

func TestCloudTrailNativeLookupTimestampProjection(t *testing.T) {
	f := trailControlLoad(t, "owned_service_principal")
	replay := s3NativeFixture{Observations: f.Observations}
	_, c, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Date(2026, 9, 13, 18, 13, 10, 0, time.UTC)))
	trails := trailNativeClient(c)
	expected := make(map[string]map[string]any)
	for _, label := range []string{"owned-lookup-timestamp-cli", "owned-lookup-timestamp-raw"} {
		row := replay.row(t, label)
		var native struct {
			StartTime, EndTime float64
			LookupAttributes   []trailtypes.LookupAttribute
			MaxResults         int32
		}
		if err := json.Unmarshal(row.Input, &native); err != nil {
			t.Fatal(err)
		}
		epoch := func(v float64) *time.Time {
			seconds := int64(v)
			timestamp := time.Unix(seconds, int64((v-float64(seconds))*1e9)).UTC()
			return &timestamp
		}
		// Unlike the CLI, the SDK sends the fractional epochs from the fixture.
		out, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{StartTime: epoch(native.StartTime), EndTime: epoch(native.EndTime), LookupAttributes: native.LookupAttributes, MaxResults: &native.MaxResults})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Events) != 0 {
			t.Fatalf("unique nonexistent resource returned history: %+v", out.Events)
		}
		id, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
		if !ok || id == "" {
			t.Fatal("LookupEvents lacks request correlation")
		}
		resource := aws.ToString(native.LookupAttributes[0].AttributeValue)
		for _, owned := range f.Lookup.Events {
			params := owned.Event["requestParameters"].(map[string]any)
			attributes := params["lookupAttributes"].([]any)
			if attributes[0].(map[string]any)["attributeValue"] == resource {
				expected[id] = owned.Event
			}
		}
		if expected[id] == nil {
			t.Fatalf("native timestamp event missing for %s", label)
		}
	}
	trailControlHistory(t, trails, expected)
}

func trailControlPut(t *testing.T, client *s3.Client, bucket, key string) string {
	t.Helper()
	out, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader("independent source: " + key)})
	if err != nil {
		t.Fatal(err)
	}
	id, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	if !ok || id == "" {
		t.Fatal("PutObject lacks request correlation")
	}
	return id
}

func trailControlRecords(t *testing.T, records []map[string]any) map[string]map[string]any {
	t.Helper()
	indexed := make(map[string]map[string]any)
	for _, record := range records {
		id, _ := record["requestID"].(string)
		if id == "" {
			t.Fatalf("delivered record lacks request correlation: %#v", record)
		}
		// Recovery can repeat target acceptance before the source acknowledges
		// it. Compare admitted identities and immutable content, not receipt count.
		if previous := indexed[id]; previous != nil && !reflect.DeepEqual(previous, record) {
			t.Fatalf("redelivery changed the accepted record: before %#v after %#v", previous, record)
		}
		indexed[id] = record
	}
	return indexed
}

func TestCloudTrailStopPropagationSDKAndRecovery(t *testing.T) {
	native := trailControlLoad(t, "eventbridge_delivery")
	var propagation map[string]any
	for _, correlation := range native.Correlations {
		if correlation.Label != "after-stop-put-0" {
			continue
		}
		for _, message := range native.Messages {
			var event struct{ Detail map[string]any }
			if err := json.Unmarshal([]byte(message.Message.Body), &event); err != nil {
				t.Fatal(err)
			}
			if event.Detail["eventID"] == correlation.EventID {
				propagation = event.Detail
			}
		}
	}
	if propagation == nil {
		t.Fatal("native fixture lacks a positively correlated post-stop delivery")
	}
	controls, objects := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery"), s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stop.sqlite")
			backends, closeDB := storage.NewMemory(), func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 17, 12, 0, 0, time.UTC))
			cloud, c, closeStack := startEventDeliveryCloud(t, backends, source)
			trailNativeProvision(t, c, controls, objects, false)
			trails, client := trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			queue := trailNativeQueue(t, c)
			s3NativeReplay(t, trails, controls, "put-final-owned-advanced")
			s3NativeReplay(t, trails, controls, "start-logging")
			bucket, name := objects.Identity["source_bucket"], controls.Identity["trail_name"]
			accepted := []string{trailControlPut(t, client, bucket, "owned/before-stop")}
			s3NativeReplay(t, trails, controls, "cleanup-stop-logging")
			trailNativeStatus(t, trails, name, false, false)
			accepted = append(accepted, trailControlPut(t, client, bucket, "owned/immediately-after-stop"))
			advanceClock(t, source, time.Minute)
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				cloud, c, _ = startEventDeliveryCloud(t, backends, source)
				trails, client = trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			}
			trailNativeStatus(t, trails, name, false, false)
			accepted = append(accepted, trailControlPut(t, client, bucket, "owned/within-stop-window"))
			s3NativeReplay(t, trails, controls, "cleanup-stop-logging")
			// Two service minutes is the documented local boundary, not an AWS timing
			// assertion. Repeating Stop halfway through must not extend that boundary.
			advanceClock(t, source, time.Minute)
			rejected := []string{trailControlPut(t, client, bucket, "owned/at-local-cutoff")}
			s3NativeReplay(t, trails, controls, "cleanup-stop-logging")
			rejected = append(rejected, trailControlPut(t, client, bucket, "owned/after-expired-repeat"))
			trailNativeDrain(t, cloud)
			delivered := trailControlRecords(t, trailNativeMessages(t, c, queue))
			if len(delivered) != len(accepted) {
				t.Fatalf("stop admitted wrong source calls: %#v", delivered)
			}
			for _, id := range accepted {
				record := delivered[id]
				if record == nil {
					t.Fatalf("desired IsLogging=false suppressed still-effective request %s", id)
				}
				for _, field := range []string{"eventName", "eventSource", "readOnly", "eventCategory", "managementEvent"} {
					if !reflect.DeepEqual(record[field], propagation[field]) {
						t.Fatalf("post-stop %s differs from native: %#v", field, record)
					}
				}
			}
			for _, id := range rejected {
				if delivered[id] != nil {
					t.Fatalf("expired Stop restarted admission: %s", id)
				}
			}
			advanceClock(t, source, 4*time.Minute)
			trailNativeDrain(t, cloud)
			logs := trailControlRecords(t, trailNativeRecords(t, trailNativeObjects(t, client, objects.Identity["log_bucket"], "owned/AWSLogs/")))
			if !reflect.DeepEqual(logs, delivered) {
				t.Fatalf("stop/reopen lost accepted bytes or admitted expired calls: logs %#v messages %#v", logs, delivered)
			}
			trailNativeStatus(t, trails, name, false, true)
		})
	}
}

func TestCloudTrailRecursiveLoggingSDKAndRecovery(t *testing.T) {
	controls, objects := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery"), s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recursive.sqlite")
			backends, closeDB := storage.NewMemory(), func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 17, 12, 0, 0, time.UTC))
			cloud, c, closeStack := startEventDeliveryCloud(t, backends, source)
			trailNativeProvision(t, c, controls, objects, false)
			trails, client := trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			name, bucket, logsBucket := controls.Identity["trail_name"], objects.Identity["source_bucket"], objects.Identity["log_bucket"]
			queue := trailNativeQueue(t, c)
			_, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: &name, EventSelectors: []trailtypes.EventSelector{{IncludeManagementEvents: aws.Bool(false), ReadWriteType: trailtypes.ReadWriteTypeWriteOnly, DataResources: []trailtypes.DataResource{{Type: aws.String("AWS::S3::Object"), Values: []string{"arn:aws:s3:::" + bucket + "/", "arn:aws:s3:::" + logsBucket + "/"}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "start-logging")
			firstID := trailControlPut(t, client, bucket, "owned/recursive-source")
			trailNativeDrain(t, cloud)
			accepted := trailControlRecords(t, trailNativeMessages(t, c, queue))
			if len(accepted) != 1 || accepted[firstID] == nil {
				t.Fatalf("independent source event missing: %#v", accepted)
			}
			// The first real gzip write becomes the source of the next gzip batch when
			// recursion is enabled. Follow its public S3 key back to the earlier bytes.
			advanceClock(t, source, 5*time.Minute)
			trailNativeDrain(t, cloud)
			children := trailControlRecords(t, trailNativeMessages(t, c, queue))
			firstObjects := trailNativeObjects(t, client, logsBucket, "owned/AWSLogs/")
			firstRecords := trailControlRecords(t, trailNativeRecords(t, firstObjects))
			if !reflect.DeepEqual(firstRecords, accepted) || len(children) != 1 {
				t.Fatalf("first recursive delivery: logs %#v child calls %#v", firstRecords, children)
			}
			for id, record := range children {
				identity, _ := record["userIdentity"].(map[string]any)
				parameters, _ := record["requestParameters"].(map[string]any)
				key, _ := parameters["key"].(string)
				if record["eventName"] != "PutObject" || identity["invokedBy"] != "cloudtrail.amazonaws.com" || parameters["bucketName"] != logsBucket || firstObjects[key] == nil {
					t.Fatalf("recursive event cannot be correlated to actual log bytes: %#v", record)
				}
				accepted[id] = record
			}
			advanceClock(t, source, 5*time.Minute)
			trailNativeDrain(t, cloud)
			secondRecords := trailControlRecords(t, trailNativeRecords(t, trailNativeObjects(t, client, logsBucket, "owned/AWSLogs/")))
			if !reflect.DeepEqual(secondRecords, accepted) {
				t.Fatalf("recursive PutObject was not retained in the next gzip: %#v", secondRecords)
			}
			for id, record := range trailControlRecords(t, trailNativeMessages(t, c, queue)) {
				accepted[id] = record
			}
			updated, err := trails.UpdateTrail(t.Context(), &cloudtrail.UpdateTrailInput{Name: &name, RecursiveLogging: aws.Bool(false)})
			if err != nil {
				t.Fatal(err)
			}
			if updated.RecursiveLogging == nil || *updated.RecursiveLogging {
				t.Fatalf("recursive logging update rejected: %+v", updated)
			}
			// The update's preflight marker was accepted under the old setting; it and
			// every previously accepted batch must survive the configuration cutover.
			trailNativeDrain(t, cloud)
			for id, record := range trailControlRecords(t, trailNativeMessages(t, c, queue)) {
				accepted[id] = record
			}
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				cloud, c, _ = startEventDeliveryCloud(t, backends, source)
				trails, client = trailNativeClient(c), s3NativeClient(c, eventDeliveryAccount, "test")
			}
			got, err := trails.GetTrail(t.Context(), &cloudtrail.GetTrailInput{Name: &name})
			if err != nil {
				t.Fatal(err)
			}
			if got.Trail == nil || got.Trail.RecursiveLogging == nil || *got.Trail.RecursiveLogging {
				t.Fatalf("recursive setting did not persist: %+v", got)
			}
			independentID := trailControlPut(t, client, bucket, "owned/nonrecursive-source")
			destinationID := trailControlPut(t, client, logsBucket, "owned/independent-destination-write")
			trailNativeDrain(t, cloud)
			independent := trailControlRecords(t, trailNativeMessages(t, c, queue))
			if len(independent) != 2 || independent[independentID] == nil || independent[destinationID] == nil {
				t.Fatalf("false recursive logging suppressed an independent source or destination write: %#v", independent)
			}
			for id, record := range independent {
				accepted[id] = record
			}
			advanceClock(t, source, 5*time.Minute)
			trailNativeDrain(t, cloud)
			settled := trailNativeObjects(t, client, logsBucket, "owned/AWSLogs/")
			finalRecords := trailControlRecords(t, trailNativeRecords(t, settled))
			if !reflect.DeepEqual(finalRecords, accepted) {
				t.Fatalf("recursive cutover lost accepted or independent source records: %#v", finalRecords)
			}
			if messages := trailNativeMessages(t, c, queue); len(messages) != 0 {
				t.Fatalf("false recursive logging published its log writes: %#v", messages)
			}
			advanceClock(t, source, 10*time.Minute)
			trailNativeDrain(t, cloud)
			if later := trailNativeObjects(t, client, logsBucket, "owned/AWSLogs/"); !reflect.DeepEqual(later, settled) {
				t.Fatal("false recursive logging generated another gzip batch without a source event")
			}
			if messages := trailNativeMessages(t, c, queue); len(messages) != 0 {
				t.Fatalf("recursive logging resumed without a source: %#v", messages)
			}
		})
	}
}
