package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// Query execution has an actual-engine executable proof; this replay covers
// catalog and saved-query controls without replacing Trino with a test executor.
func TestAnalyticsNativeControlAudit(t *testing.T) {
	var capture nativeControlAuditCapture
	awsReadFixture(t, "cloudtrail/service_controls_delivery.json", &capture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 26, 18, 0, 0, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: capture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			key, secret, identity := buildAuditActor(t, c, capture.Account)
			config := aws.Config{Region: capture.Region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1}
			actors := map[string]map[string]any{"owner": analyticsAuditClients(config)}
			actorKeys := map[string]string{"owner": key}
			trails := cloudtrail.NewFromConfig(aws.Config{Region: capture.Region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			bindings := map[string]string{capture.Identity.UserID: identity["principalId"].(string)}
			var sessionCreated string
			for _, call := range capture.Calls {
				if strings.HasPrefix(call.Label, "cleanup-") {
					continue
				}
				setup := call.Label == "create-reader" || call.Label == "reader-policy" || call.Label == "create-database" || call.Label == "create-workgroup"
				assume := call.Operation == "AssumeRole" && call.Code == "Success"
				if !setup && !assume && call.Service != "glue" && call.Service != "athena" {
					continue
				}
				if strings.HasPrefix(call.Label, "reader-ready-") {
					continue
				}
				switch call.Operation {
				case "StartQueryExecution", "GetQueryExecution", "GetQueryResults":
					continue
				}
				if !t.Run(call.Label, func(t *testing.T) {
					var native map[string]any
					for _, row := range capture.History.Events {
						if row.Event["requestID"] == call.RequestID {
							if native != nil {
								t.Fatalf("multiple native records for control request %s", call.RequestID)
							}
							native = row.Event
						}
					}
					if !setup && !assume && native == nil {
						t.Fatalf("native control request not captured: %s", call.RequestID)
					}
					input := ec2AuditReplace(t, call.Input, bindings)
					if native != nil {
						// Boto3 generated this token before sending its request. Replay
						// that observed input instead of comparing unrelated SDK nonces.
						if request, ok := native["requestParameters"].(map[string]any); ok {
							if token, ok := request["clientRequestToken"].(string); ok {
								var fields map[string]any
								awsDecodeJSON(t, input, &fields)
								fields["ClientRequestToken"] = token
								var err error
								input, err = json.Marshal(fields)
								if err != nil {
									t.Fatal(err)
								}
							}
						}
					}
					output, callErr := awstest.CallSDK(t.Context(), actors[call.Caller][call.Service], call.Operation, input)
					if call.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						assertAPIError(t, callErr, call.Code)
					}
					if callErr == nil {
						switch result := output.(type) {
						case *iam.CreateRoleOutput:
							var observed struct {
								Role struct {
									ID string `json:"RoleId"`
								} `json:"Role"`
							}
							awsDecodeJSON(t, call.Output, &observed)
							bindings[observed.Role.ID] = aws.ToString(result.Role.RoleId)
						case *sts.AssumeRoleOutput:
							role := *result.Credentials
							roleConfig := config
							roleConfig.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(role.AccessKeyId), aws.ToString(role.SecretAccessKey), aws.ToString(role.SessionToken))
							actors["reader"] = analyticsAuditClients(roleConfig)
							actorKeys["reader"] = aws.ToString(role.AccessKeyId)
							sessionCreated = source.Now().UTC().Format(time.RFC3339)
						case *athena.CreateNamedQueryOutput:
							var observed struct {
								ID string `json:"NamedQueryId"`
							}
							awsDecodeJSON(t, call.Output, &observed)
							bindings[observed.ID] = aws.ToString(result.NamedQueryId)
						}
					}
					// The probe did not harvest setup IDs; they establish resources,
					// not additional native conformance claims.
					if setup || assume {
						return
					}
					body, err := json.Marshal(native)
					if err != nil {
						t.Fatal(err)
					}
					var want map[string]any
					awsDecodeJSON(t, ec2AuditReplace(t, body, bindings), &want)
					got := auditLookupRecord(t, trails, nativeAuditRequestID(t, output, callErr), call.Operation)
					want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
					assertNativeAuditEvent(t, got, want, "")
					if !reflect.DeepEqual(got["apiVersion"], want["apiVersion"]) {
						t.Fatalf("native apiVersion: got %v want %v", got["apiVersion"], want["apiVersion"])
					}
					expectedIdentity := want["userIdentity"].(map[string]any)
					expectedIdentity["accessKeyId"] = actorKeys[call.Caller]
					if call.Caller == "reader" {
						context := expectedIdentity["sessionContext"].(map[string]any)
						attributes := context["attributes"].(map[string]any)
						attributes["creationDate"] = sessionCreated
					}
					if !reflect.DeepEqual(got["userIdentity"], expectedIdentity) {
						t.Fatalf("native identity/session context: got %v want %v", got["userIdentity"], expectedIdentity)
					}
				}) {
					return
				}
			}
		})
	}
}

func analyticsAuditClients(config aws.Config) map[string]any {
	return map[string]any{
		"glue":   glue.NewFromConfig(config),
		"athena": athena.NewFromConfig(config),
		"iam":    iam.NewFromConfig(config),
		"sts":    sts.NewFromConfig(config),
	}
}
