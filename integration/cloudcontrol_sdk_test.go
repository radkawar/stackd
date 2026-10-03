package stackd_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
)

func TestCloudControlNativeLifecycleAndRetainedOwnerState(t *testing.T) {
	var fixture struct {
		Account, Region, Name string
		Cleanup               struct{ Complete bool }
		Calls                 []struct {
			Label, Code string
			Output      json.RawMessage
		}
	}
	awsReadFixture(t, "cloudformation/cloudcontrol_lifecycle.json", &fixture)
	if !fixture.Cleanup.Complete {
		t.Fatal("native capture left owned resources")
	}
	codes := map[string]string{}
	for _, row := range fixture.Calls {
		codes[row.Label] = row.Code
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			client := func(region string) *cloudcontrol.Client {
				return cloudcontrol.New(cloudcontrol.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), HTTPClient: c.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")})
			}
			logs := func() *cloudwatchlogs.Client {
				return cloudwatchlogs.New(cloudwatchlogs.Options{Region: fixture.Region, BaseEndpoint: aws.String(c.server.URL), HTTPClient: c.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")})
			}
			checkError := func(label string, err error) {
				t.Helper()
				var api smithy.APIError
				if !errors.As(err, &api) || api.ErrorCode() != codes[label] {
					t.Fatalf("%s: native %s, local %v", label, codes[label], err)
				}
			}
			wait := func(token string, wanted cctypes.OperationStatus) cctypes.ProgressEvent {
				t.Helper()
				for range 40 {
					out, err := client(fixture.Region).GetResourceRequestStatus(t.Context(), &cloudcontrol.GetResourceRequestStatusInput{RequestToken: aws.String(token)})
					if err != nil {
						t.Fatal(err)
					}
					if out.ProgressEvent.OperationStatus == wanted {
						return *out.ProgressEvent
					}
					if out.ProgressEvent.OperationStatus != cctypes.OperationStatusInProgress && out.ProgressEvent.OperationStatus != cctypes.OperationStatusCancelInProgress {
						t.Fatalf("unexpected progress %#v", out.ProgressEvent)
					}
					advanceClock(t, source, time.Second)
					if _, err := c.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000); err != nil {
						t.Fatal(err)
					}
				}
				t.Fatal("resource request did not settle")
				return cctypes.ProgressEvent{}
			}
			typ := aws.String("AWS::Logs::LogGroup")
			name := fixture.Name
			desired := `{"LogGroupName":"` + name + `","RetentionInDays":1,"Tags":[{"Key":"owner","Value":"` + name + `"}]}`
			input := &cloudcontrol.CreateResourceInput{TypeName: typ, DesiredState: aws.String(desired), ClientToken: aws.String("create-retained")}
			created, err := client(fixture.Region).CreateResource(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			token := aws.ToString(created.ProgressEvent.RequestToken)
			if created.ProgressEvent.OperationStatus != cctypes.OperationStatusInProgress {
				t.Fatalf("missing async acceptance: %#v", created.ProgressEvent)
			}
			wait(token, cctypes.OperationStatusSuccess)
			c = reopen()
			repeated, err := client(fixture.Region).CreateResource(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(repeated.ProgressEvent.RequestToken) != token {
				t.Fatal("idempotent request changed after restart")
			}
			listed, err := client(fixture.Region).ListResourceRequests(t.Context(), &cloudcontrol.ListResourceRequestsInput{ResourceRequestStatusFilter: &cctypes.ResourceRequestStatusFilter{Operations: []cctypes.Operation{cctypes.OperationCreate}, OperationStatuses: []cctypes.OperationStatus{cctypes.OperationStatusSuccess}}})
			if err != nil {
				t.Fatal(err)
			}
			if len(listed.ResourceRequestStatusSummaries) != 1 || aws.ToString(listed.ResourceRequestStatusSummaries[0].RequestToken) != token {
				t.Fatalf("retained request listing does not identify the accepted operation: %#v", listed.ResourceRequestStatusSummaries)
			}
			_, err = client(fixture.Region).CreateResource(t.Context(), &cloudcontrol.CreateResourceInput{TypeName: typ, DesiredState: aws.String(`{"LogGroupName":"different"}`), ClientToken: input.ClientToken})
			checkError("token-conflict", err)
			_, err = client("us-west-2").GetResourceRequestStatus(t.Context(), &cloudcontrol.GetResourceRequestStatusInput{RequestToken: aws.String(token)})
			var missingToken *cctypes.RequestTokenNotFoundException
			if !errors.As(err, &missingToken) {
				t.Fatalf("request scope leak: %v", err)
			}
			get := func() map[string]any {
				t.Helper()
				out, err := client(fixture.Region).GetResource(t.Context(), &cloudcontrol.GetResourceInput{TypeName: typ, Identifier: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToString(out.ResourceDescription.Identifier) != name {
					t.Fatal("wrong primary identifier")
				}
				var model map[string]any
				if err = json.Unmarshal([]byte(aws.ToString(out.ResourceDescription.Properties)), &model); err != nil {
					t.Fatal(err)
				}
				return model
			}
			if got := get()["RetentionInDays"]; got != float64(1) {
				t.Fatalf("retained resource retention %v", got)
			}
			updated, err := client(fixture.Region).UpdateResource(t.Context(), &cloudcontrol.UpdateResourceInput{TypeName: typ, Identifier: aws.String(name), PatchDocument: aws.String(`[{"op":"test","path":"/RetentionInDays","value":1},{"op":"replace","path":"/RetentionInDays","value":3}]`)})
			if err != nil {
				t.Fatal(err)
			}
			wait(aws.ToString(updated.ProgressEvent.RequestToken), cctypes.OperationStatusSuccess)
			for _, row := range []struct{ label, patch string }{
				{"immutable", `[{"op":"replace","path":"/LogGroupName","value":"renamed"}]`},
				{"readonly", `[{"op":"add","path":"/Arn","value":"not-an-arn"}]`},
				{"test-failure", `[{"op":"test","path":"/RetentionInDays","value":99}]`},
			} {
				_, err := client(fixture.Region).UpdateResource(t.Context(), &cloudcontrol.UpdateResourceInput{TypeName: typ, Identifier: aws.String(name), PatchDocument: aws.String(row.patch)})
				checkError(row.label, err)
			}
			if got := get()["RetentionInDays"]; got != float64(3) {
				t.Fatalf("failed patch altered owner: %v", got)
			}
			duplicate, err := client(fixture.Region).CreateResource(t.Context(), &cloudcontrol.CreateResourceInput{TypeName: typ, DesiredState: aws.String(desired)})
			if err != nil {
				t.Fatal(err)
			}
			if got := wait(aws.ToString(duplicate.ProgressEvent.RequestToken), cctypes.OperationStatusFailed); got.ErrorCode != cctypes.HandlerErrorCodeAlreadyExists {
				t.Fatalf("duplicate error %#v", got)
			}
			absent, err := client(fixture.Region).DeleteResource(t.Context(), &cloudcontrol.DeleteResourceInput{TypeName: typ, Identifier: aws.String(name + "-missing")})
			if err != nil {
				t.Fatal(err)
			}
			if got := wait(aws.ToString(absent.ProgressEvent.RequestToken), cctypes.OperationStatusFailed); got.ErrorCode != cctypes.HandlerErrorCodeNotFound {
				t.Fatalf("absent delete %#v", got)
			}
			_, err = client(fixture.Region).CancelResourceRequest(t.Context(), &cloudcontrol.CancelResourceRequestInput{RequestToken: aws.String(token)})
			checkError("cancel-complete", err)
			// A delete has a persisted existence checkpoint before its owner
			// effect. With service time paused, cancellation can prevent that
			// next effect without racing a wall-clock worker.
			pending, err := client(fixture.Region).DeleteResource(t.Context(), &cloudcontrol.DeleteResourceInput{TypeName: typ, Identifier: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client(fixture.Region).DeleteResource(t.Context(), &cloudcontrol.DeleteResourceInput{TypeName: typ, Identifier: aws.String(name)})
			var concurrent *cctypes.ConcurrentOperationException
			if !errors.As(err, &concurrent) {
				t.Fatalf("concurrent operation admitted: %v", err)
			}
			canceled, err := client(fixture.Region).CancelResourceRequest(t.Context(), &cloudcontrol.CancelResourceRequestInput{RequestToken: pending.ProgressEvent.RequestToken})
			if err != nil {
				t.Fatal(err)
			}
			c = reopen()
			wait(aws.ToString(canceled.ProgressEvent.RequestToken), cctypes.OperationStatusCancelComplete)
			if got := get()["RetentionInDays"]; got != float64(3) {
				t.Fatalf("cancel changed live resource: %v", got)
			}
			// The provisioned log group accepts actual data-plane records.
			if _, err = logs().CreateLogStream(t.Context(), &cloudwatchlogs.CreateLogStreamInput{LogGroupName: aws.String(name), LogStreamName: aws.String("actual")}); err != nil {
				t.Fatal(err)
			}
			if _, err = logs().PutLogEvents(t.Context(), &cloudwatchlogs.PutLogEventsInput{LogGroupName: aws.String(name), LogStreamName: aws.String("actual"), LogEvents: []logtypes.InputLogEvent{{Message: aws.String("cloudcontrol-real-owner"), Timestamp: aws.Int64(source.Now().UnixMilli())}}}); err != nil {
				t.Fatal(err)
			}
			events, err := logs().GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: aws.String(name), LogStreamName: aws.String("actual")})
			if err != nil {
				t.Fatal(err)
			}
			if len(events.Events) != 1 || aws.ToString(events.Events[0].Message) != "cloudcontrol-real-owner" {
				t.Fatalf("real owner events %#v", events.Events)
			}
			// A retained delete cannot use the caller session beyond its documented
			// 24-hour lifetime, even though its request remains queryable for seven days.
			expired, err := client(fixture.Region).DeleteResource(t.Context(), &cloudcontrol.DeleteResourceInput{TypeName: typ, Identifier: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 24*time.Hour)
			if got := wait(aws.ToString(expired.ProgressEvent.RequestToken), cctypes.OperationStatusFailed); got.ErrorCode != cctypes.HandlerErrorCodeInvalidCredentials {
				t.Fatalf("expired caller authority %#v", got)
			}
			if got := get()["RetentionInDays"]; got != float64(3) {
				t.Fatalf("expired delete altered owner: %v", got)
			}
			deleted, err := client(fixture.Region).DeleteResource(t.Context(), &cloudcontrol.DeleteResourceInput{TypeName: typ, Identifier: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			wait(aws.ToString(deleted.ProgressEvent.RequestToken), cctypes.OperationStatusSuccess)
			_, err = client(fixture.Region).GetResource(t.Context(), &cloudcontrol.GetResourceInput{TypeName: typ, Identifier: aws.String(name)})
			checkError("read-deleted", err)
			advanceClock(t, source, 7*24*time.Hour)
			_, err = client(fixture.Region).GetResourceRequestStatus(t.Context(), &cloudcontrol.GetResourceRequestStatusInput{RequestToken: aws.String(token)})
			if !errors.As(err, &missingToken) {
				t.Fatalf("request did not expire after seven days: %v", err)
			}
		})
	}
}
