package stackd_test

import (
	"cmp"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestEventBridgeNativeTargetDiscovery(t *testing.T) {
	for _, name := range []string{"target_lookup.json", "target_lookup_authority.json"} {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) { replayEventBridgeTargetDiscovery(t, name, backend) })
		}
	}
}

func replayEventBridgeTargetDiscovery(t *testing.T, name, backend string) {
	t.Helper()
	var fixture struct {
		Account               string `json:"caller_account"`
		Region                string
		Observations, Cleanup []awsNativeObservation
		Audit                 struct {
			MatchedEvents []struct{ Event map[string]any } `json:"matched_events"`
		}
	}
	awsReadFixture(t, "eventbridge/"+name, &fixture)
	rows := append(slices.Clone(fixture.Observations), fixture.Cleanup...)
	slices.SortStableFunc(rows, func(a, b awsNativeObservation) int { return cmp.Compare(a.Started, b.Started) })
	source := clock.NewManual(time.UnixMilli(rows[0].Started).UTC())
	var cloud *stackd.Stack
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		var server *httptest.Server
		cloud, server = startPublicCloud(t, config)
		return cloud, server
	})
	_, user, _ := strings.Cut(rows[0].ActorARN, ":user/")
	arn, key, secret := clients.user(t, fixture.Account, user)
	putUserPolicy(t, clients.iam(fixture.Account, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	identities := map[string]aws.Credentials{arn: {AccessKeyID: key, SecretAccessKey: secret}}
	principalIDs, sessionDates := map[string]string{}, map[string]string{}
	replacements := map[string]string{}
	nativeAudits, expected := map[string]map[string]any{}, map[string]map[string]any{}
	for _, row := range fixture.Audit.MatchedEvents {
		if row.Event["eventName"] == "ListRuleNamesByTarget" {
			nativeAudits[row.Event["requestID"].(string)] = row.Event
		}
	}
	var bucket string
	prefix := "AWSLogs/"
	for _, row := range rows {
		// Native object names belong to the probe's audit sink, not this replay.
		if row.Service == "s3api" && row.Operation != "create-bucket" && row.Operation != "put-bucket-policy" {
			continue
		}
		// One cross-bus token call returned 500; it is not a deterministic oracle.
		if row.Result.HTTPStatus >= 500 {
			continue
		}
		if !t.Run(row.Label, func(t *testing.T) {
			when := time.UnixMilli(row.Started).UTC()
			if when.After(source.Now()) {
				advanceClock(t, source, when.Sub(source.Now()))
			}
			identity, ok := identities[row.ActorARN]
			if !ok {
				t.Fatalf("native actor has no replayed IAM/STS identity: %s", row.ActorARN)
			}
			region := cmp.Or(row.Region, fixture.Region)
			request := string(row.Input)
			for native, local := range replacements {
				request = strings.ReplaceAll(request, native, local)
			}
			input := json.RawMessage(request)
			var client any
			wire := &awstest.WireClient{Client: clients.server.Client()}
			switch row.Service {
			case "events":
				options := eventbridge.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken), HTTPClient: wire, RetryMaxAttempts: 1}
				if row.Operation == "list-rule-names-by-target" {
					options.APIOptions = append(options.APIOptions, awstest.JSONBody(input))
					// Keep SDK signing/decoding while sending the native invalid body.
					input = json.RawMessage(`{"TargetArn":"request"}`)
				}
				client = eventbridge.New(options)
			case "sqs":
				options := clients.sqs(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken).Options()
				options.Region = region
				client = sqs.New(options)
			case "sts":
				client = clients.sts(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
			case "iam":
				client = clients.iam(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
			case "kms":
				client = clients.kmsRegion(region, identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
			case "cloudtrail":
				client = organizationTrailClient(clients, fixture.Account, region)
			case "s3api":
				options := s3NativeClient(clients, fixture.Account, "test").Options()
				options.Region = region
				client = s3.New(options)
				if row.Operation == "create-bucket" {
					var in s3.CreateBucketInput
					awsDecodeJSON(t, input, &in)
					bucket = aws.ToString(in.Bucket)
				}
			default:
				t.Fatalf("unexpected native service %q", row.Service)
			}
			output, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
			awsNativeResult(t, row, err)
			if native := nativeAudits[row.Result.RequestID]; native != nil {
				body, marshalErr := json.Marshal(native)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				text := string(body)
				for original, local := range replacements {
					text = strings.ReplaceAll(text, original, local)
				}
				var want map[string]any
				awsDecodeJSON(t, []byte(text), &want)
				want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
				identityDocument := want["userIdentity"].(map[string]any)
				identityDocument["principalId"], identityDocument["accessKeyId"] = principalIDs[row.ActorARN], identity.AccessKeyID
				if session, ok := identityDocument["sessionContext"].(map[string]any); ok {
					roleID, _, _ := strings.Cut(principalIDs[row.ActorARN], ":")
					session["sessionIssuer"].(map[string]any)["principalId"] = roleID
					session["attributes"].(map[string]any)["creationDate"] = sessionDates[row.ActorARN]
				}
				expected[nativeAuditRequestID(t, output, err)] = want
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
			case *kms.CreateKeyOutput:
				var native kms.CreateKeyOutput
				awsDecodeJSON(t, row.Result.Output, &native)
				replacements[aws.ToString(native.KeyMetadata.KeyId)] = aws.ToString(output.KeyMetadata.KeyId)
			case *sqs.CreateQueueOutput:
				var native sqs.CreateQueueOutput
				awsDecodeJSON(t, row.Result.Output, &native)
				replacements[aws.ToString(native.QueueUrl)] = aws.ToString(output.QueueUrl)
			case *eventbridge.PutTargetsOutput:
				var native eventbridge.PutTargetsOutput
				awsDecodeJSON(t, row.Result.Output, &native)
				if output.FailedEntryCount != native.FailedEntryCount {
					t.Fatalf("target admission differs: %+v, native %+v", output, native)
				}
			case *eventbridge.ListRuleNamesByTargetOutput:
				var native, actual map[string]any
				awsDecodeJSON(t, row.Result.Output, &native)
				awsDecodeJSON(t, wire.Body, &actual)
				if token, ok := native["NextToken"].(string); ok {
					if output.NextToken == nil || *output.NextToken == "" {
						t.Fatal("native page has a continuation but local page does not")
					}
					replacements[token], actual["NextToken"] = *output.NextToken, token
				}
				if wire.Status != row.Result.HTTPStatus || !reflect.DeepEqual(actual, native) {
					t.Fatalf("target discovery differs: HTTP %d %+v; native HTTP %d %+v", wire.Status, actual, row.Result.HTTPStatus, native)
				}
			}
			trailNativeDrain(t, cloud)
			if row.Operation == "disable-rule" || row.Operation == "delete-queue" {
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
			assertNativeAuditEvent(t, event, want, "")
			for _, field := range []string{"userIdentity", "apiVersion"} {
				actual, present := event[field]
				native, nativePresent := want[field]
				if present != nativePresent || !reflect.DeepEqual(actual, native) {
					t.Fatalf("lookup audit %s differs: got %#v, native %#v", field, actual, native)
				}
			}
			delete(expected, id)
		}
	}
	if len(expected) != 0 {
		t.Fatalf("%d correlated native lookup audits were not delivered", len(expected))
	}
}
