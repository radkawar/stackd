package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestLogsNativeControlAudit(t *testing.T) {
	var capture nativeControlAuditCapture
	awsReadFixture(t, "cloudtrail/logs_controls.json", &capture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 26, 23, 0, 0, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: capture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			key, secret, identity := buildAuditActor(t, c, capture.Account)
			config := aws.Config{Region: capture.Region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1}
			actors := map[string]*cloudwatchlogs.Client{"owner": cloudwatchlogs.NewFromConfig(config)}
			actorKeys := map[string]string{"owner": key}
			tokens := sts.NewFromConfig(config)
			trails := cloudtrail.NewFromConfig(aws.Config{Region: capture.Region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			bindings := map[string]string{capture.Identity.UserID: identity["principalId"].(string)}
			for _, call := range capture.Calls {
				if call.ExpectedCategory == "" && call.Operation != "GetFederationToken" && call.Operation != "TagLogGroup" && call.Operation != "UntagLogGroup" {
					continue
				}
				if call.Label == "stream-get-missing" {
					// This capture observed a stale read immediately after deletion;
					// ingestion.json observed ResourceNotFoundException. Neither fixes
					// a guaranteed visibility delay, so do not pin that timing here.
					continue
				}
				if !t.Run(call.Label, func(t *testing.T) {
					var client any = actors[call.Caller]
					if call.Operation == "GetFederationToken" {
						client = tokens
					}
					output, callErr := awstest.CallSDK(t.Context(), client, call.Operation, ec2AuditReplace(t, call.Input, bindings))
					if call.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						assertAPIError(t, callErr, call.Code)
					}
					if session, ok := output.(*sts.GetFederationTokenOutput); ok && callErr == nil {
						reader := config
						reader.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
						actors["reader"] = cloudwatchlogs.NewFromConfig(reader)
						actorKeys["reader"] = aws.ToString(session.Credentials.AccessKeyId)
						return
					}
					for _, row := range capture.History.Events {
						if row.Event["requestID"] != call.RequestID {
							continue
						}
						body, err := json.Marshal(row.Event)
						if err != nil {
							t.Fatal(err)
						}
						var want map[string]any
						awsDecodeJSON(t, ec2AuditReplace(t, body, bindings), &want)
						requestID := nativeAuditRequestID(t, output, callErr)
						got := auditLookupRecord(t, trails, requestID, call.Operation)
						want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
						if result, ok := output.(*cloudwatchlogs.PutResourcePolicyOutput); ok && callErr == nil {
							response := want["responseElements"].(map[string]any)
							response["resourcePolicy"].(map[string]any)["lastUpdatedTime"] = float64(aws.ToInt64(result.ResourcePolicy.LastUpdatedTime))
						}
						assertNativeAuditEvent(t, got, want, "")
						if !reflect.DeepEqual(got["apiVersion"], want["apiVersion"]) {
							t.Fatalf("apiVersion: got %v want %v", got["apiVersion"], want["apiVersion"])
						}
						expectedIdentity := want["userIdentity"].(map[string]any)
						expectedIdentity["accessKeyId"] = actorKeys[call.Caller]
						if call.Caller == "reader" {
							context := expectedIdentity["sessionContext"].(map[string]any)
							context["attributes"].(map[string]any)["creationDate"] = source.Now().UTC().Format(time.RFC3339)
						}
						if !reflect.DeepEqual(got["userIdentity"], expectedIdentity) {
							t.Fatalf("session identity: got %v want %v", got["userIdentity"], expectedIdentity)
						}
						for _, resource := range row.LookupMetadata.Resources {
							pages := cloudtrail.NewLookupEventsPaginator(trails, &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyResourceName, AttributeValue: new(resource.Name)}}})
							found := false
							for pages.HasMorePages() {
								page, err := pages.NextPage(t.Context())
								if err != nil {
									t.Fatal(err)
								}
								for _, event := range page.Events {
									var record map[string]any
									awsDecodeJSON(t, []byte(aws.ToString(event.CloudTrailEvent)), &record)
									if record["requestID"] == requestID {
										found = true
									}
								}
							}
							if !found {
								t.Fatalf("native resource search %q omitted request %s", resource.Name, requestID)
							}
						}
						return
					}
					if call.Operation != "TagLogGroup" && call.Operation != "UntagLogGroup" {
						t.Fatalf("native audit outcome missing for request %s", call.RequestID)
					}
				}) {
					return
				}
			}
		})
	}
}

func TestLogsNativeSubscriptionAdmissionAudit(t *testing.T) {
	var capture struct {
		Account    string `json:"account"`
		Region     string `json:"region"`
		CloudTrail struct {
			Events []nativeAuditObservation `json:"events"`
		} `json:"cloudtrail"`
	}
	awsReadFixture(t, "cloudtrail/logs_subscription_history.json", &capture)
	body, err := os.ReadFile("../testdata/cloudtrail/audit/logs_subscription_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	awsDecodeJSON(t, body, &labels)
	observations := make(map[string]nativeAuditObservation)
	for _, row := range capture.CloudTrail.Events {
		observations[row.Label] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 26, 23, 0, 0, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: capture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			config := aws.Config{Region: capture.Region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1}
			logs, trails := cloudwatchlogs.NewFromConfig(config), cloudtrail.NewFromConfig(config)
			for _, label := range labels {
				t.Run(label, func(t *testing.T) {
					row, ok := observations[label]
					if !ok {
						t.Fatalf("native outcome missing: %s", label)
					}
					input, err := json.Marshal(row.Event["requestParameters"])
					if err != nil {
						t.Fatal(err)
					}
					output, callErr := awstest.CallSDK(t.Context(), logs, "PutSubscriptionFilter", input)
					assertAPIError(t, callErr, row.Event["errorCode"].(string))
					got := auditLookupRecord(t, trails, nativeAuditRequestID(t, output, callErr), "PutSubscriptionFilter")
					row.Event["eventTime"] = source.Now().UTC().Format(time.RFC3339)
					assertNativeAuditEvent(t, got, row.Event, "")
					if got["apiVersion"] != row.Event["apiVersion"] {
						t.Fatalf("apiVersion: got %v want %v", got["apiVersion"], row.Event["apiVersion"])
					}
				})
			}
		})
	}
}
