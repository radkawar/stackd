package stackd_test

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http/protocol/awsquery"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestCloudWatchNativeDashboards(t *testing.T) {
	for _, fixture := range []string{"dashboards.json", "dashboard_size.json", "dashboard_widgets.json", "dashboards_authority.json"} {
		for _, backend := range []string{"memory", "sqlite"} {
			for _, protocol := range []string{"rpc", "query"} {
				t.Run(fixture+"/"+backend+"/"+protocol, func(t *testing.T) { replayCloudWatchDashboards(t, fixture, backend, protocol) })
			}
		}
	}
}

type dashboardModification struct{ native, local time.Time }

func replayCloudWatchDashboards(t *testing.T, filename, backend, protocol string) {
	t.Helper()
	var fixture struct {
		Account               string `json:"caller_account"`
		Region                string
		ActorARN              string `json:"actor_arn"`
		Observations, Cleanup []awsNativeObservation
		Audit                 struct {
			MatchedEvents []struct{ Event map[string]any } `json:"matched_events"`
		}
	}
	awsReadFixture(t, "cloudwatch/"+filename, &fixture)
	rows := append(slices.Clone(fixture.Observations), fixture.Cleanup...)
	slices.SortStableFunc(rows, func(a, b awsNativeObservation) int { return cmp.Compare(a.Started, b.Started) })
	source := clock.NewManual(time.UnixMilli(rows[0].Started).UTC())
	var cloud *stackd.Stack
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		var server *httptest.Server
		cloud, server = startPublicCloud(t, config)
		return cloud, server
	})
	_, user, _ := strings.Cut(fixture.ActorARN, ":user/")
	arn, key, secret := clients.user(t, fixture.Account, user)
	putUserPolicy(t, clients.iam(fixture.Account, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	identities := map[string]aws.Credentials{arn: {AccessKeyID: key, SecretAccessKey: secret}}
	principalIDs, sessionDates := map[string]string{}, map[string]string{}
	nativeAudits, expected := map[string]map[string]any{}, map[string]map[string]any{}
	messages := map[string]string{}
	for _, row := range fixture.Audit.MatchedEvents {
		if row.Event["eventSource"] == "monitoring.amazonaws.com" {
			nativeAudits[row.Event["requestID"].(string)] = row.Event
		}
	}
	modifications := map[string]dashboardModification{}
	var bucket string
	prefix := "AWSLogs/"
	for _, row := range rows {
		// A CLI-side validation failure did not reach AWS. Physical native audit
		// objects belong to the capture, while this replay has its own log keys.
		if row.Result.Code == "CLIError" || row.Service == "s3api" && row.Operation != "create-bucket" && row.Operation != "put-bucket-policy" {
			continue
		}
		if !t.Run(row.Label, func(t *testing.T) {
			when := time.UnixMilli(row.Started).UTC()
			if when.After(source.Now()) {
				advanceClock(t, source, when.Sub(source.Now()))
			}
			identity, ok := identities[cmp.Or(row.ActorARN, fixture.ActorARN)]
			if !ok {
				t.Fatalf("native actor has no replayed IAM/STS identity: %s", row.ActorARN)
			}
			region := cmp.Or(row.Region, fixture.Region)
			var client any
			switch row.Service {
			case "cloudwatch":
				options := cloudwatch.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1}
				if protocol == "query" {
					options.Protocol = awsquery.New(&smithy.ServiceSchema{Version: "2010-08-01"})
				}
				client = cloudwatch.New(options)
			case "sts":
				client = clients.sts(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
			case "iam":
				client = clients.iam(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
			case "cloudtrail":
				client = organizationTrailClient(clients, fixture.Account, region)
			case "s3api":
				options := s3NativeClient(clients, fixture.Account, "test").Options()
				options.Region = region
				client = s3.New(options)
				if row.Operation == "create-bucket" {
					var input s3.CreateBucketInput
					awsDecodeJSON(t, row.Input, &input)
					bucket = aws.ToString(input.Bucket)
				}
			default:
				t.Fatalf("unexpected native service %q", row.Service)
			}
			output, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
			awsNativeResult(t, row, err)
			if native := nativeAudits[row.Result.RequestID]; native != nil {
				encoded, marshalErr := json.Marshal(native)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				var want map[string]any
				awsDecodeJSON(t, encoded, &want)
				want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
				actor := cmp.Or(row.ActorARN, fixture.ActorARN)
				identityDocument := want["userIdentity"].(map[string]any)
				identityDocument["principalId"], identityDocument["accessKeyId"] = principalIDs[actor], identity.AccessKeyID
				if session, ok := identityDocument["sessionContext"].(map[string]any); ok {
					roleID, _, _ := strings.Cut(principalIDs[actor], ":")
					session["sessionIssuer"].(map[string]any)["principalId"] = roleID
					session["attributes"].(map[string]any)["creationDate"] = sessionDates[actor]
				}
				id := nativeAuditRequestID(t, output, err)
				expected[id] = want
				var apiError smithy.APIError
				if errors.As(err, &apiError) {
					messages[id] = apiError.ErrorMessage()
				}
			}
			if err != nil {
				return
			}
			switch output := output.(type) {
			case *cloudtrail.CreateTrailOutput:
				if output.S3KeyPrefix != nil {
					prefix = strings.Trim(*output.S3KeyPrefix, "/") + "/AWSLogs/"
				}
			case *sts.GetCallerIdentityOutput:
				principalIDs[aws.ToString(output.Arn)] = aws.ToString(output.UserId)
			case *sts.AssumeRoleOutput:
				actor := aws.ToString(output.AssumedRoleUser.Arn)
				identities[actor] = aws.Credentials{AccessKeyID: aws.ToString(output.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(output.Credentials.SecretAccessKey), SessionToken: aws.ToString(output.Credentials.SessionToken)}
				principalIDs[actor], sessionDates[actor] = aws.ToString(output.AssumedRoleUser.AssumedRoleId), source.Now().UTC().Format(time.RFC3339)
			default:
				if row.Service == "cloudwatch" {
					compareNativeDashboard(t, row, output, modifications)
				}
			}
			if row.Operation == "delete-dashboards" {
				var input cloudwatch.DeleteDashboardsInput
				awsDecodeJSON(t, row.Input, &input)
				for _, name := range input.DashboardNames {
					delete(modifications, name)
				}
			}
			trailNativeDrain(t, cloud)
			// Reads following creation, replacement and tag changes also exercise
			// restoration, not just the original provider's in-memory object graph.
			if backend == "sqlite" && row.Operation == "untag-resource" {
				clients = reopen()
			}
		}) {
			return
		}
	}
	if len(nativeAudits) == 0 {
		return
	}
	advanceClock(t, source, 6*time.Minute)
	trailNativeDrain(t, cloud)
	options := s3NativeClient(clients, fixture.Account, "test").Options()
	options.Region = fixture.Region
	for _, event := range trailNativeRecords(t, trailNativeObjects(t, s3.New(options), bucket, prefix)) {
		id, _ := event["requestID"].(string)
		if want := expected[id]; want != nil {
			assertNativeAuditEvent(t, event, want, messages[id])
			for _, field := range []string{"userIdentity", "apiVersion"} {
				actual, present := event[field]
				native, nativePresent := want[field]
				if present != nativePresent || !reflect.DeepEqual(actual, native) {
					t.Fatalf("dashboard audit %s differs: got %#v, native %#v", field, actual, native)
				}
			}
			delete(expected, id)
		}
	}
	if len(expected) != 0 {
		t.Fatalf("%d request-correlated native dashboard audits were not delivered", len(expected))
	}
}

func compareNativeDashboard(t *testing.T, row awsNativeObservation, output any, modifications map[string]dashboardModification) {
	t.Helper()
	switch output := output.(type) {
	case *cloudwatch.GetDashboardOutput:
		var native cloudwatch.GetDashboardOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		var actualBody, nativeBody any
		awsDecodeJSON(t, []byte(aws.ToString(output.DashboardBody)), &actualBody)
		awsDecodeJSON(t, []byte(aws.ToString(native.DashboardBody)), &nativeBody)
		if aws.ToString(output.DashboardArn) != aws.ToString(native.DashboardArn) || aws.ToString(output.DashboardName) != aws.ToString(native.DashboardName) || !reflect.DeepEqual(actualBody, nativeBody) {
			t.Fatalf("retained dashboard differs: got %+v, native %+v", output, native)
		}
	case *cloudwatch.PutDashboardOutput:
		var native cloudwatch.PutDashboardOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		var actualPaths, nativePaths []string
		for _, warning := range output.DashboardValidationMessages {
			actualPaths = append(actualPaths, aws.ToString(warning.DataPath))
		}
		for _, warning := range native.DashboardValidationMessages {
			nativePaths = append(nativePaths, aws.ToString(warning.DataPath))
		}
		slices.Sort(actualPaths)
		slices.Sort(nativePaths)
		if !slices.Equal(actualPaths, nativePaths) {
			t.Fatalf("warning locations differ: got %+v, native %+v", output.DashboardValidationMessages, native.DashboardValidationMessages)
		}
	case *cloudwatch.ListDashboardsOutput:
		var native cloudwatch.ListDashboardsOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		if len(output.DashboardEntries) != len(native.DashboardEntries) {
			t.Fatalf("dashboard membership differs: got %+v, native %+v", output, native)
		}
		for i, entry := range output.DashboardEntries {
			want := native.DashboardEntries[i]
			name := aws.ToString(entry.DashboardName)
			if name != aws.ToString(want.DashboardName) || aws.ToString(entry.DashboardArn) != aws.ToString(want.DashboardArn) || aws.ToInt64(entry.Size) != aws.ToInt64(want.Size) {
				t.Fatalf("dashboard metadata differs: got %+v, native %+v", entry, want)
			}
			if previous, ok := modifications[name]; ok {
				if want.LastModified.Equal(previous.native) != entry.LastModified.Equal(previous.local) || want.LastModified.After(previous.native) != entry.LastModified.After(previous.local) {
					t.Fatalf("dashboard modification transition differs: got %v -> %v, native %v -> %v", previous.local, entry.LastModified, previous.native, want.LastModified)
				}
			}
			modifications[name] = dashboardModification{*want.LastModified, *entry.LastModified}
		}
		if (output.NextToken == nil) != (native.NextToken == nil) {
			t.Fatalf("dashboard continuation differs: got %+v, native %+v", output, native)
		}
	case *cloudwatch.ListTagsForResourceOutput:
		var native cloudwatch.ListTagsForResourceOutput
		awsDecodeJSON(t, row.Result.Output, &native)
		actualTags, nativeTags := map[string]string{}, map[string]string{}
		for _, tag := range output.Tags {
			actualTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		for _, tag := range native.Tags {
			nativeTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		if !reflect.DeepEqual(actualTags, nativeTags) {
			t.Fatalf("dashboard tags differ: got %v, native %v", actualTags, nativeTags)
		}
	}
}
