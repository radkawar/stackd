package stackd_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewaymanagementapi"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type gatewayTimelineFixture struct {
	Account, Region  string
	Mode             string
	Identity         struct{ Arn string }
	ReplayExclusions map[string]string `json:"replay_exclusions"`
	HandlerSource    string            `json:"handler_source"`
	Observations     []gatewaySDKObservation
	HTTP             []struct {
		Label, API, Path, Method string
		Phase                    string
		StartedAt                time.Time         `json:"started_at"`
		RequestHeaders           map[string]string `json:"request_headers"`
		Result                   struct {
			Status  int
			Body    map[string]any
			Headers [][]string
		}
	}
}

type gatewaySDKObservation struct {
	Label, Service, Operation, Endpoint, Phase string
	StartedAt                                  time.Time `json:"started_at"`
	Actor                                      struct{ Arn string }
	Input                                      map[string]any
	Result                                     struct {
		Code       string
		HTTPStatus int `json:"http_status"`
		Output     map[string]any
	}
	RawResponse struct {
		BodyBase64 string `json:"body_base64"`
	} `json:"raw_response"`
}

func TestAPIGatewayNativeLambdaAuthorizers(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real authorizer runtimes")
	}
	for _, name := range []string{"rest_lambda_authorizers", "http_lambda_authorizers", "rest_authorizer_roles", "http_authorizer_roles", "rest_authorizer_service_context", "http_authorizer_service_context", "rest_authorizer_principal_type", "http_authorizer_principal_type"} {
		var fixture gatewayTimelineFixture
		awsReadFixture(t, "apigateway/"+name+".json", &fixture)
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				source := clock.NewManual(fixture.Observations[0].StartedAt)
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(c stackd.Config) (*stackd.Stack, *httptest.Server) { return newLambdaDockerStack(t, c, nil) })
				defaultCredentials := credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")
				for _, row := range fixture.Observations {
					if row.Service == "organizations" && row.Operation == "DescribeOrganization" && row.Result.Code == "Success" {
						// The native account already belonged to an organization;
						// recreate that prerequisite, not the real organization itself.
						org := organizations.New(organizations.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: defaultCredentials, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
						if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: "ALL"}); err != nil {
							t.Fatal(err)
						}
						break
					}
				}
				actors := map[string]credentials.StaticCredentialsProvider{}
				if fixture.Mode != "" {
					defaultCredentials = gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn)
					actors[fixture.Identity.Arn] = defaultCredentials
				}
				type step struct {
					at    time.Time
					index int
					http  bool
				}
				var steps []step
				for i, row := range fixture.Observations {
					steps = append(steps, step{row.StartedAt, i, false})
				}
				for i, row := range fixture.HTTP {
					steps = append(steps, step{row.StartedAt, i, true})
				}
				sort.SliceStable(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })
				bindings := map[string]string{}
				invocations := map[string]string{}
				origins := map[string]int{}
				cacheProbe, cachedID := -1, ""
				successProbe := -1
				apiID := ""
				reopened := false
				httpCalls := 0
				for _, step := range steps {
					if step.at.After(source.Now()) {
						source.Advance(step.at.Sub(source.Now()))
					}
					if !step.http {
						row := fixture.Observations[step.index]
						// Readiness is a probe purpose, not a read-only operation.
						// Replay successful calls: they can mint sessions or create
						// resources subsequently consumed by the semantic observations.
						readiness := strings.Contains(row.Label, "ready-") && row.Result.Code != "Success"
						if strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-") || row.Service == "logs" && row.Operation != "CreateLogGroup" || readiness || fixture.ReplayExclusions[row.Label] != "" || row.Operation == "CreateFunction" && row.Result.Code != "Success" {
							continue
						}
						// Native flush propagation alternated old/new results. Replay its accepted
						// control call, then test deterministic invalidation independently below;
						// these snapshots do not establish globally converged regional behavior.
						flush := row.Operation == "FlushStageAuthorizersCache" || row.Operation == "ResetAuthorizersCache"
						input := gatewayClone(t, row.Input)
						gatewaySubstitute(input, bindings)
						if row.Operation == "CreateFunction" {
							input["Runtime"] = "python3.12"
							input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
						}
						creds := defaultCredentials
						if row.Actor.Arn != "" {
							var ok bool
							creds, ok = actors[row.Actor.Arn]
							if !ok {
								t.Fatalf("%s has no established actor %s", row.Label, row.Actor.Arn)
							}
						}
						client := gatewaySDKClient(t, row.Service, aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
						encoded, _ := json.Marshal(input)
						out, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
						if row.Result.Code != "Success" {
							assertAPIError(t, err, row.Result.Code)
							continue
						}
						if err != nil {
							t.Fatalf("%s: %v", row.Label, err)
						}
						if session, ok := out.(*sts.AssumeRoleOutput); ok {
							nativeActor := row.Result.Output["AssumedRoleUser"].(map[string]any)["Arn"].(string)
							actors[nativeActor] = credentials.NewStaticCredentialsProvider(*session.Credentials.AccessKeyId, *session.Credentials.SecretAccessKey, *session.Credentials.SessionToken)
						}
						encoded, _ = json.Marshal(out)
						var actual map[string]any
						awsDecodeJSON(t, encoded, &actual)
						switch row.Operation {
						case "CreateAuthorizer", "UpdateAuthorizer", "GetAuthorizer":
							var roleARNs [2]any
							for index, output := range []map[string]any{row.Result.Output, actual} {
								for key, value := range output {
									if strings.EqualFold(key, "AuthorizerCredentials") || strings.EqualFold(key, "AuthorizerCredentialsArn") {
										roleARNs[index] = value
									}
								}
							}
							if roleARNs[0] != roleARNs[1] {
								t.Fatalf("%s retained credentials=%v native=%v", row.Label, roleARNs[1], roleARNs[0])
							}
						}
						gatewayBind(row.Result.Output, actual, bindings)
						if row.Operation == "CreateApi" {
							apiID = actual["ApiId"].(string)
						}
						if row.Operation == "CreateRestApi" {
							apiID = actual["Id"].(string)
						}
						if row.Operation == "CreateFunction" {
							function := actual["FunctionName"].(string)
							if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &function}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
								state, stateErr := client.(*awslambda.Client).GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &function})
								if stateErr != nil {
									t.Fatalf("%s: %v; function diagnosis: %v", row.Label, err, stateErr)
								}
								t.Fatalf("%s: %v; state=%s reason=%s: %s", row.Label, err, state.State, state.StateReasonCode, aws.ToString(state.StateReason))
							}
						}
						if flush {
							break
						}
						continue
					}
					row := fixture.HTTP[step.index]
					if row.Phase == "readiness" || fixture.ReplayExclusions[row.Label] != "" || strings.HasPrefix(row.Label, "ready-") || strings.HasPrefix(row.Label, "permission-repaired-") || row.Label == "final-backend-log-marker" {
						continue
					}
					request, err := http.NewRequestWithContext(t.Context(), row.Method, clients.server.URL+"/_stackd/execute-api/"+apiID+row.Path, nil)
					if err != nil {
						t.Fatal(err)
					}
					for key, value := range row.RequestHeaders {
						request.Header.Set(key, value)
					}
					response, err := clients.server.Client().Do(request)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != row.Result.Status {
						t.Fatalf("%s status=%d native=%d: %s", row.Label, response.StatusCode, row.Result.Status, body)
					}
					httpCalls++
					if row.Result.Status != 200 {
						var actual map[string]any
						awsDecodeJSON(t, body, &actual)
						if len(actual) != len(row.Result.Body) {
							t.Fatalf("%s error envelope differs: %s", row.Label, body)
						}
						for key, expected := range row.Result.Body {
							value, present := actual[key]
							if !present || expected == nil && value != nil {
								t.Fatalf("%s error field %s differs: %s", row.Label, key, body)
							}
							if expected != nil {
								if text, ok := value.(string); !ok || text == "" {
									t.Fatalf("%s error diagnosis missing", row.Label)
								}
							}
						}
						for _, header := range row.Result.Headers {
							if len(header) == 2 && strings.EqualFold(header[0], "x-amzn-ErrorType") && response.Header.Get(header[0]) != header[1] {
								t.Fatalf("%s native error classification lost: %v", row.Label, response.Header)
							}
						}
						continue
					}
					var actual map[string]any
					awsDecodeJSON(t, body, &actual)
					want := gatewayAuthorizerContext(t, row.Result.Body, row.API)
					got := gatewayAuthorizerContext(t, actual, row.API)
					idKey := "invocationUUID"
					eventKey := "eventJSON"
					if row.API == "rest" {
						idKey = "invocation"
						eventKey = "event"
					}
					nativeID, _ := want[idKey].(string)
					localID, _ := got[idKey].(string)
					if nativeID == "" || localID == "" {
						t.Fatalf("%s missing actual authorizer invocation", row.Label)
					}
					if successProbe < 0 {
						successProbe = step.index
					}
					if previous, ok := invocations[nativeID]; ok && previous != localID {
						t.Fatalf("%s cached authorizer was invoked again", row.Label)
					}
					if _, hit := invocations[nativeID]; hit {
						if cacheProbe < 0 {
							cacheProbe, cachedID = origins[nativeID], localID
						}
					} else {
						origins[nativeID] = step.index
					}
					for before, after := range invocations {
						if before != nativeID && after == localID {
							t.Fatalf("%s reused authorizer across distinct native invocations", row.Label)
						}
					}
					invocations[nativeID] = localID
					if len(want) != len(got) {
						t.Fatalf("%s authorizer context fields differ: native=%v local=%v", row.Label, want, got)
					}
					for key, value := range want {
						if _, present := got[key]; !present {
							t.Fatalf("%s missing authorizer context field %s", row.Label, key)
						}
						switch key {
						case idKey, eventKey, "integrationLatency", "lambdaRequestId":
							continue
						}
						if !reflect.DeepEqual(value, got[key]) {
							t.Fatalf("%s context %s=%v native=%v", row.Label, key, got[key], value)
						}
					}
					var nativeEvent, localEvent map[string]any
					awsDecodeJSON(t, []byte(want[eventKey].(string)), &nativeEvent)
					awsDecodeJSON(t, []byte(got[eventKey].(string)), &localEvent)
					gatewaySubstitute(nativeEvent, bindings)
					for _, event := range []map[string]any{nativeEvent, localEvent} {
						if identities, ok := event["identitySource"].([]any); ok {
							sort.Slice(identities, func(i, j int) bool { return identities[i].(string) < identities[j].(string) })
						}
					}
					for _, key := range []string{"version", "type", "methodArn", "routeArn", "identitySource", "authorizationToken", "resource", "path", "httpMethod", "routeKey", "rawPath", "rawQueryString", "queryStringParameters", "multiValueQueryStringParameters", "pathParameters", "stageVariables"} {
						_, nativePresent := nativeEvent[key]
						_, localPresent := localEvent[key]
						if nativePresent != localPresent {
							t.Fatalf("%s authorizer %s field presence differs", row.Label, key)
						}
						if !reflect.DeepEqual(nativeEvent[key], localEvent[key]) {
							t.Fatalf("%s authorizer %s=%v native=%v", row.Label, key, localEvent[key], nativeEvent[key])
						}
					}
					if !reopened && len(invocations) > 4 {
						clients = reopen()
						reopened = true
					}
				}
				if cacheProbe < 0 && fixture.Mode == "" {
					t.Fatal("native sequence did not establish a cached authorization")
				}
				probe := cacheProbe
				if fixture.Mode != "" {
					probe = successProbe
				}
				row := fixture.HTTP[probe]
				for attempt := range 2 {
					request, err := http.NewRequestWithContext(t.Context(), row.Method, clients.server.URL+"/_stackd/execute-api/"+apiID+row.Path, nil)
					if err != nil {
						t.Fatal(err)
					}
					for key, value := range row.RequestHeaders {
						request.Header.Set(key, value)
					}
					response, err := clients.server.Client().Do(request)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusOK {
						t.Fatalf("post-reset authorization: %d: %s", response.StatusCode, body)
					}
					var actual map[string]any
					awsDecodeJSON(t, body, &actual)
					context := gatewayAuthorizerContext(t, actual, row.API)
					key := "invocationUUID"
					if row.API == "rest" {
						key = "invocation"
					}
					id, ok := context[key].(string)
					if !ok || id == "" {
						t.Fatal("post-reset authorizer did not execute")
					}
					if attempt == 0 {
						if id == cachedID {
							t.Fatal("reset retained the previous cached authorization")
						}
						cachedID = id
						clients = reopen()
					} else if fixture.Mode == "" && id != cachedID {
						t.Fatal("cached authorization was lost across reopening")
					} else if fixture.Mode != "" && id == cachedID {
						t.Fatal("uncached role authorizer reused an invocation across reopening")
					}
				}
				t.Logf("replayed %d native HTTP outcomes with real authorizers", httpCalls)
			})
		}
	}
}

func gatewaySDKClient(t *testing.T, service string, config aws.Config) any {
	t.Helper()
	switch service {
	case "iam":
		return iam.NewFromConfig(config)
	case "lambda":
		return awslambda.NewFromConfig(config)
	case "logs":
		return cloudwatchlogs.NewFromConfig(config)
	case "sts":
		return sts.NewFromConfig(config)
	case "organizations":
		return organizations.NewFromConfig(config)
	case "apigateway":
		return apigateway.NewFromConfig(config)
	case "apigatewayv2":
		return apigatewayv2.NewFromConfig(config)
	case "apigatewaymanagementapi":
		return apigatewaymanagementapi.NewFromConfig(config)
	default:
		t.Fatalf("unhandled fixture service %s", service)
		return nil
	}
}

func gatewayAuthorizerContext(t *testing.T, body map[string]any, kind string) map[string]any {
	t.Helper()
	event, ok := body["event"].(map[string]any)
	if !ok {
		t.Fatalf("missing integration event: %v", body)
	}
	request, ok := event["requestContext"].(map[string]any)
	if !ok {
		t.Fatal("missing integration context")
	}
	authorizer, ok := request["authorizer"].(map[string]any)
	if !ok {
		t.Fatal("missing authorizer context")
	}
	if kind != "rest" {
		authorizer, ok = authorizer["lambda"].(map[string]any)
		if !ok {
			t.Fatal("missing HTTP Lambda authorizer context")
		}
	}
	return authorizer
}

func TestAPIGatewayNativeAuthorizerQuota(t *testing.T) {
	var evidence struct {
		PriorCaptures []gatewayTimelineFixture `json:"prior_captures"`
	}
	awsReadFixture(t, "apigateway/http_authorizer_roles.json", &evidence)
	// The first owned capture reached the native limit before control probes.
	fixture := evidence.PriorCaptures[0]
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			newClient := func() *apigatewayv2.Client {
				return apigatewayv2.New(apigatewayv2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			client := newClient()
			bindings := map[string]string{}
			first := ""
			rejected := false
			for _, row := range fixture.Observations {
				if row.Operation != "CreateApi" && row.Operation != "CreateAuthorizer" {
					continue
				}
				input := gatewayClone(t, row.Input)
				gatewaySubstitute(input, bindings)
				encoded, _ := json.Marshal(input)
				if row.Result.Code != "Success" {
					clients = reopen()
					client = newClient()
				}
				out, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
				if row.Result.Code != "Success" {
					assertAPIError(t, err, row.Result.Code)
					var response *smithyhttp.ResponseError
					if !errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
						t.Fatalf("%s: status differs from native %d: %v", row.Label, row.Result.HTTPStatus, err)
					}
					rejected = true
					var retry apigatewayv2.CreateAuthorizerInput
					awsDecodeJSON(t, encoded, &retry)
					other, err := client.CreateApi(t.Context(), &apigatewayv2.CreateApiInput{Name: aws.String("independent-quota"), ProtocolType: "HTTP"})
					if err != nil {
						t.Fatal(err)
					}
					independent := retry
					independent.ApiId = other.ApiId
					if _, err := client.CreateAuthorizer(t.Context(), &independent); err != nil {
						t.Fatalf("another API consumed this API's quota: %v", err)
					}
					if _, err := client.DeleteAuthorizer(t.Context(), &apigatewayv2.DeleteAuthorizerInput{ApiId: retry.ApiId, AuthorizerId: &first}); err != nil {
						t.Fatal(err)
					}
					if _, err := client.CreateAuthorizer(t.Context(), &retry); err != nil {
						t.Fatalf("deletion did not release authorizer capacity: %v", err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
				if created, ok := out.(*apigatewayv2.CreateAuthorizerOutput); ok && first == "" {
					first = aws.ToString(created.AuthorizerId)
				}
				encoded, _ = json.Marshal(out)
				var actual map[string]any
				awsDecodeJSON(t, encoded, &actual)
				gatewayBind(row.Result.Output, actual, bindings)
			}
			if !rejected {
				t.Fatal("native fixture did not exercise quota rejection")
			}
		})
	}
}
