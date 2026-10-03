package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
	trailstorage "stackd/storage/cloudtrail"
)

// These fixtures retain CLI inputs verbatim: in particular, nil and pointers to
// empty ARN strings must reach different UpdateTrail branches.
func trailLogsFixture(t *testing.T, name string) s3NativeFixture {
	t.Helper()
	return s3NativeFixture{Observations: trailControlLoad(t, name).Observations}
}

func trailLogsReplay(t *testing.T, client any, f s3NativeFixture, label string) any {
	t.Helper()
	row := f.row(t, label)
	out, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		var response *smithyhttp.ResponseError
		if !errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
			t.Fatalf("%s HTTP error: %v; native %d", label, err, row.Result.HTTPStatus)
		}
		return nil
	}
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return out
}

func trailLogsProvision(t *testing.T, c cloudClients, f s3NativeFixture) {
	t.Helper()
	buckets := s3NativeClient(c, eventDeliveryAccount, "test")
	trailLogsReplay(t, buckets, f, "create-bucket")
	trailLogsReplay(t, buckets, f, "bucket-policy")
	trailLogsReplay(t, logsClient(c, eventDeliveryAccount), f, "create-group")
	trailLogsReplay(t, c.iam(eventDeliveryAccount, "test", ""), f, "create-role")
}

func trailLogsConfiguration(t *testing.T, client *cloudtrail.Client, f s3NativeFixture, label string) {
	t.Helper()
	row := f.row(t, label)
	got := trailLogsReplay(t, client, f, label).(*cloudtrail.GetTrailOutput)
	want := row.Result.Output["Trail"].(map[string]any)
	for field, value := range map[string]*string{
		"CloudWatchLogsLogGroupArn": got.Trail.CloudWatchLogsLogGroupArn,
		"CloudWatchLogsRoleArn":     got.Trail.CloudWatchLogsRoleArn,
	} {
		expected, present := want[field]
		if present != (value != nil) || present && expected != aws.ToString(value) {
			t.Fatalf("%s retained destination %s = %v, native %#v", label, field, value, expected)
		}
	}
}

func TestCloudTrailNativeLogsControlsAndPreflightSDK(t *testing.T) {
	f := trailLogsFixture(t, "logs_destination")
	clearing := trailLogsFixture(t, "logs_role_updates")
	c := clockCloud(t, stackd.Config{})
	trailLogsProvision(t, c, f)
	trails, logs, roles := trailNativeClient(c), logsClient(c, eventDeliveryAccount), c.iam(eventDeliveryAccount, "test", "")
	var create cloudtrail.CreateTrailInput
	if err := json.Unmarshal(f.row(t, "create-configured-trail-0").Input, &create); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"create-group-without-role", "create-role-without-group", "create-malformed-group", "create-malformed-role", "create-role-without-logs-policy"} {
		trailLogsReplay(t, trails, f, label)
		_, err := trails.GetTrail(t.Context(), &cloudtrail.GetTrailInput{Name: create.Name})
		assertAPIError(t, err, "TrailNotFoundException")
	}
	var streams cloudwatchlogs.DescribeLogStreamsInput
	if err := json.Unmarshal(f.row(t, "streams-after-failed-create").Input, &streams); err != nil {
		t.Fatal(err)
	}
	before, err := logs.DescribeLogStreams(t.Context(), &streams)
	if err != nil || len(before.LogStreams) != 0 {
		t.Fatalf("denied CreateLogStream left streams: %+v %v", before, err)
	}
	trailLogsReplay(t, roles, f, "role-policy-CreateLogStream")
	trailLogsReplay(t, trails, f, "create-role-missing-put-events")
	_, err = trails.GetTrail(t.Context(), &cloudtrail.GetTrailInput{Name: create.Name})
	assertAPIError(t, err, "TrailNotFoundException")
	after := trailLogsReplay(t, logs, f, "streams-after-failed-create").(*cloudwatchlogs.DescribeLogStreamsOutput)
	nativeStreams := f.row(t, "streams-after-failed-create").Result.Output["logStreams"].([]any)
	if len(after.LogStreams) != len(nativeStreams) {
		t.Fatalf("failed PutLogEvents rolled back successful preflight stream: %+v", after)
	}
	for _, stream := range after.LogStreams {
		// The preflight stream is unsuffixed in this observation. Delivery stream
		// allocation is independent and is deliberately not pinned to native _3.
		if aws.ToString(stream.LogStreamName) != nativeStreams[0].(map[string]any)["logStreamName"] {
			t.Fatalf("unexpected preflight stream: %+v", stream)
		}
		out, err := logs.GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: streams.LogGroupName, LogStreamName: stream.LogStreamName})
		if err != nil || len(out.Events) != 0 {
			t.Fatalf("denied preflight PutLogEvents wrote records: %+v %v", out, err)
		}
	}
	trailLogsReplay(t, roles, f, "role-policy-CreateLogStream-PutLogEvents")
	trailLogsReplay(t, trails, f, "create-configured-trail-0")
	trailLogsConfiguration(t, trails, f, "get-configured-trail")
	for _, label := range []string{"update-omitted-destination", "update-group-without-star", "update-missing-role", "update-pair-without-star", "update-pair-missing-group", "update-pair-wrong-region", "update-pair-missing-role"} {
		trailLogsReplay(t, trails, f, label)
		trailLogsConfiguration(t, trails, f, label+"-get")
	}
	for _, label := range []string{"configured-empty-role-only", "configured-both-empty", "configured-empty-group-nonempty-role", "configured-nonempty-group-empty-role"} {
		trailLogsReplay(t, trails, f, "restore-configured-destination")
		trailLogsReplay(t, trails, clearing, label)
		trailLogsConfiguration(t, trails, clearing, label+"-immediate-get")
	}
	trailLogsReplay(t, trails, f, "restore-configured-destination")
	trailLogsReplay(t, trails, f, "remove-group-only")
	trailLogsConfiguration(t, trails, f, "remove-group-only-get")
}

// Advance to the actual persisted CloudTrail deadline, not a native polling or
// propagation interval. This also exercises retained retry scheduling after reopen.
func trailLogsNextDelivery(t *testing.T, cloud *stackd.Stack, backends *storage.Backends, source *clock.Manual) {
	t.Helper()
	var due time.Time
	if err := backends.CloudTrail.View(t.Context(), func(r trailstorage.Reader) error {
		job, ok, err := r.NextDelivery()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no pending CloudTrail delivery")
		}
		due = job.Due
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if due.After(source.Now()) {
		advanceClock(t, source, due.Sub(source.Now()))
	}
	trailNativeDrain(t, cloud)
}

func trailLogsEvents(t *testing.T, client *cloudwatchlogs.Client, group, pattern string) map[string]logtypes.FilteredLogEvent {
	t.Helper()
	input := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &group, FilterPattern: &pattern}
	found := make(map[string]logtypes.FilteredLogEvent)
	for range 100 {
		out, err := client.FilterLogEvents(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range out.Events {
			var record map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(event.Message)), &record); err != nil {
				t.Fatalf("Logs message is not a CloudTrail JSON event: %v", err)
			}
			id, ok := record["requestID"].(string)
			if !ok || id == "" || record["Records"] != nil || record["detail"] != nil {
				t.Fatalf("Logs has a gzip/Records or EventBridge envelope: %#v", record)
			}
			if _, exists := found[id]; exists {
				continue // CloudTrail delivery is at least once.
			}
			found[id] = event
		}
		if out.NextToken == nil {
			return found
		}
		input.NextToken = out.NextToken
	}
	t.Fatal("Logs pagination failed to terminate")
	return nil
}

func trailLogsTag(t *testing.T, client *s3.Client, f s3NativeFixture, label string) string {
	t.Helper()
	out := trailLogsReplay(t, client, f, label).(*s3.PutBucketTaggingOutput)
	id, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	if !ok || id == "" {
		t.Fatal("source management call lost request correlation")
	}
	return id
}

func TestCloudTrailNativeLogsIndependentDeliveryAndRecoverySDK(t *testing.T) {
	f := trailLogsFixture(t, "logs_destination")
	var create cloudtrail.CreateTrailInput
	if err := json.Unmarshal(f.row(t, "create-configured-trail-0").Input, &create); err != nil {
		t.Fatal(err)
	}
	var groupInput cloudwatchlogs.CreateLogGroupInput
	if err := json.Unmarshal(f.row(t, "create-group").Input, &groupInput); err != nil {
		t.Fatal(err)
	}
	group := aws.ToString(groupInput.LogGroupName)
	nativeMessage := f.row(t, "get-delivered-record").Result.Output["events"].([]any)[0].(map[string]any)
	var nativeRecord map[string]any
	if err := json.Unmarshal([]byte(nativeMessage["message"].(string)), &nativeRecord); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trail-logs.sqlite")
			backends, closeDB := storage.NewMemory(), func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 22, 16, 21, 0, time.UTC))
			cloud, c, closeStack := startEventDeliveryCloud(t, backends, source)
			trailLogsProvision(t, c, f)
			trails, logs, buckets := trailNativeClient(c), logsClient(c, eventDeliveryAccount), s3NativeClient(c, eventDeliveryAccount, "test")
			trailLogsReplay(t, c.iam(eventDeliveryAccount, "test", ""), f, "role-policy-CreateLogStream-PutLogEvents")
			trailLogsReplay(t, trails, f, "create-configured-trail-0")
			_, key, secret := c.user(t, eventDeliveryAccount, "Delegated")
			putUserPolicy(t, c.iam(eventDeliveryAccount, "test", ""), "Delegated", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:PutBucketTagging","Resource":"*"}}`)
			caller := s3NativeClient(c, key, secret)
			trailLogsReplay(t, trails, f, "select-write-management")
			trailLogsReplay(t, trails, f, "start-logging")
			eventTime := source.Now()
			id := trailLogsTag(t, caller, f, "management-tag-delivery-after-propagation")
			trailLogsReplay(t, c.iam(eventDeliveryAccount, "test", ""), f, "role-policy-CreateLogStream")
			var failed *cloudtrail.GetTrailStatusOutput
			for range 20 {
				trailLogsNextDelivery(t, cloud, backends, source)
				var err error
				failed, err = trails.GetTrailStatus(t.Context(), &cloudtrail.GetTrailStatusInput{Name: create.Name})
				if err != nil {
					t.Fatal(err)
				}
				if failed.LatestDeliveryTime != nil && aws.ToString(failed.LatestCloudWatchLogsDeliveryError) != "" {
					break
				}
			}
			if failed.LatestDeliveryTime == nil || failed.LatestCloudWatchLogsDeliveryTime != nil || aws.ToString(failed.LatestCloudWatchLogsDeliveryError) == "" || aws.ToString(failed.LatestDeliveryError) != "" {
				t.Fatalf("Logs denial stalled or contaminated S3 status: %+v", failed)
			}
			s3Records := trailControlRecords(t, trailNativeRecords(t, trailNativeObjects(t, buckets, aws.ToString(create.S3BucketName), "owned/AWSLogs/")))
			if s3Records[id] == nil || trailLogsEvents(t, logs, group, `{ $.eventName = "PutBucketTagging" }`)[id].Message != nil {
				t.Fatal("denied Logs must leave the selected event delivered only to S3")
			}
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, closeDB = openSQLiteBackends(t, path)
				cloud, c, closeStack = startEventDeliveryCloud(t, backends, source)
				trails, logs, buckets = trailNativeClient(c), logsClient(c, eventDeliveryAccount), s3NativeClient(c, eventDeliveryAccount, "test")
				caller = s3NativeClient(c, key, secret)
				retained := trailNativeStatus(t, trails, aws.ToString(create.Name), true, true)
				if aws.ToString(retained.LatestCloudWatchLogsDeliveryError) == "" || retained.LatestCloudWatchLogsDeliveryTime != nil {
					t.Fatalf("reopen lost independent failed Logs status: %+v", retained)
				}
			}
			trailLogsReplay(t, c.iam(eventDeliveryAccount, "test", ""), f, "role-policy-CreateLogStream-PutLogEvents")
			recoveryStarted := source.Now()
			var delivered logtypes.FilteredLogEvent
			for range 20 {
				trailLogsNextDelivery(t, cloud, backends, source)
				delivered = trailLogsEvents(t, logs, group, `{ $.eventName = "PutBucketTagging" }`)[id]
				if delivered.Message != nil {
					break
				}
			}
			if delivered.Message == nil {
				t.Fatal("restored role did not recover retained Logs work")
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(delivered.Message)), &got); err != nil {
				t.Fatal(err)
			}
			// Reuse native CloudTrail field structure and source input. Host, caller,
			// transport diagnostics and IDs are instance/request identities; eventTime
			// and Logs timestamp are checked separately rather than normalized together.
			trailNativeRecord(t, nativeRecord, got, id, key)
			if !reflect.DeepEqual(got, s3Records[id]) || got["eventTime"] != eventTime.Format(time.RFC3339) {
				t.Fatalf("Logs did not retain the exact independently delivered S3 event: %#v", got)
			}
			stamp := time.UnixMilli(aws.ToInt64(delivered.Timestamp))
			if !stamp.After(eventTime) || stamp.Before(recoveryStarted) || stamp.After(source.Now()) {
				t.Fatalf("Logs timestamp %s must represent delivery, not old eventTime %s", stamp, eventTime)
			}
			if !strings.HasPrefix(aws.ToString(delivered.LogStreamName), eventDeliveryAccount+"_CloudTrail_us-east-1") {
				t.Fatalf("delivery escaped role-scoped native stream prefix: %+v", delivered)
			}
			success := trailNativeStatus(t, trails, aws.ToString(create.Name), true, true)
			if success.LatestCloudWatchLogsDeliveryTime == nil || aws.ToString(success.LatestCloudWatchLogsDeliveryError) != "" {
				t.Fatalf("recovered Logs status: %+v", success)
			}

			// Retire an accepted Logs batch before its worker executes. S3 must retain
			// the same source request, and neither destination may replay old Logs work.
			retired := trailLogsTag(t, caller, f, "management-tag-delivery-initial")
			trailLogsReplay(t, trails, f, "remove-group-only")
			trailLogsConfiguration(t, trails, f, "remove-group-only-get")
			removed := trailNativeStatus(t, trails, aws.ToString(create.Name), true, true)
			if removed.LatestCloudWatchLogsDeliveryTime != nil || removed.LatestCloudWatchLogsDeliveryError != nil || !removed.LatestDeliveryTime.Equal(*success.LatestDeliveryTime) {
				t.Fatalf("removal failed to retire only Logs status: %+v", removed)
			}
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, closeDB = openSQLiteBackends(t, path)
				cloud, c, closeStack = startEventDeliveryCloud(t, backends, source)
				trails, logs, buckets = trailNativeClient(c), logsClient(c, eventDeliveryAccount), s3NativeClient(c, eventDeliveryAccount, "test")
				caller = s3NativeClient(c, key, secret)
				trailLogsConfiguration(t, trails, f, "remove-group-only-get")
			}
			afterRemoval := trailLogsTag(t, caller, f, "management-tag-after-destination-removal")
			trailLogsNextDelivery(t, cloud, backends, source)
			s3Records = trailControlRecords(t, trailNativeRecords(t, trailNativeObjects(t, buckets, aws.ToString(create.S3BucketName), "owned/AWSLogs/")))
			oldLogs := trailLogsEvents(t, logs, group, `{ $.eventName = "PutBucketTagging" }`)
			if s3Records[retired] == nil || s3Records[afterRemoval] == nil || oldLogs[retired].Message != nil || oldLogs[afterRemoval].Message != nil || !reflect.DeepEqual(oldLogs[id], delivered) {
				t.Fatal("removal/reopen lost S3 work, retained retired Logs work, or changed delivered history")
			}

			// Replace a configured destination while another accepted batch is open.
			trailLogsReplay(t, trails, f, "restore-configured-destination")
			replaced := trailLogsTag(t, caller, f, "management-tag-delivery-initial")
			replacement := group + "-replacement"
			if _, err := logs.CreateLogGroup(t.Context(), &cloudwatchlogs.CreateLogGroupInput{LogGroupName: &replacement}); err != nil {
				t.Fatal(err)
			}
			var policy iam.PutRolePolicyInput
			if err := json.Unmarshal(f.row(t, "role-policy-CreateLogStream-PutLogEvents").Input, &policy); err != nil {
				t.Fatal(err)
			}
			policy.PolicyDocument = aws.String(strings.ReplaceAll(aws.ToString(policy.PolicyDocument), group+":", replacement+":"))
			if _, err := c.iam(eventDeliveryAccount, "test", "").PutRolePolicy(t.Context(), &policy); err != nil {
				t.Fatal(err)
			}
			if _, err := trails.UpdateTrail(t.Context(), &cloudtrail.UpdateTrailInput{Name: create.Name, CloudWatchLogsLogGroupArn: aws.String(strings.ReplaceAll(aws.ToString(create.CloudWatchLogsLogGroupArn), group+":", replacement+":")), CloudWatchLogsRoleArn: create.CloudWatchLogsRoleArn}); err != nil {
				t.Fatal(err)
			}
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				cloud, c, _ = startEventDeliveryCloud(t, backends, source)
				trails, logs, buckets = trailNativeClient(c), logsClient(c, eventDeliveryAccount), s3NativeClient(c, eventDeliveryAccount, "test")
				caller = s3NativeClient(c, key, secret)
			}
			fresh := trailLogsTag(t, caller, f, "management-tag-delivery-after-propagation")
			for range 20 {
				trailLogsNextDelivery(t, cloud, backends, source)
				if trailLogsEvents(t, logs, replacement, `{ $.eventName = "PutBucketTagging" }`)[fresh].Message != nil {
					break
				}
			}
			newLogs := trailLogsEvents(t, logs, replacement, `{ $.eventName = "PutBucketTagging" }`)
			oldLogs = trailLogsEvents(t, logs, group, `{ $.eventName = "PutBucketTagging" }`)
			s3Records = trailControlRecords(t, trailNativeRecords(t, trailNativeObjects(t, buckets, aws.ToString(create.S3BucketName), "owned/AWSLogs/")))
			if newLogs[fresh].Message == nil || newLogs[replaced].Message != nil || oldLogs[replaced].Message != nil || oldLogs[fresh].Message != nil || s3Records[replaced] == nil || s3Records[fresh] == nil {
				t.Fatal("replacement rerouted retired Logs work or lost independent S3 delivery")
			}
			replacementStatus := trailNativeStatus(t, trails, aws.ToString(create.Name), true, true)
			if replacementStatus.LatestCloudWatchLogsDeliveryTime == nil || aws.ToString(replacementStatus.LatestCloudWatchLogsDeliveryError) != "" || !reflect.DeepEqual(oldLogs[id], delivered) {
				t.Fatalf("replacement/reopen lost Logs success or retained history: %+v", replacementStatus)
			}
		})
	}
}
