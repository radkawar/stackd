package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go/middleware"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestAPIGatewayNativeWebSocketAuthorizerAdmission(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to provision the native fixture's Lambda; no authorizer invocation is required")
	}
	var fixture gatewayTimelineFixture
	awsReadFixture(t, "apigateway/websocket_authorizer_admission.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Observations[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return newLambdaDockerStack(t, config, nil)
			})
			bindings := map[string]string{}
			admissions := 0
			for _, row := range fixture.Observations {
				// IAM propagation and Lambda readiness are infrastructure timing,
				// not admission outcomes. Provision the successful native function.
				if row.Operation == "CreateFunction" && row.Result.Code != "Success" || strings.HasPrefix(row.Label, "function-ready-") {
					continue
				}
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				if !t.Run(row.Label, func(t *testing.T) {
					input := gatewayClone(t, row.Input)
					gatewaySubstitute(input, bindings)
					if row.Operation == "CreateFunction" {
						input["Runtime"] = "python3.12"
						input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
					}
					wire := &awstest.WireClient{Client: clients.server.Client()}
					config := aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: wire, RetryMaxAttempts: 1}
					if row.Service == "apigatewayv2" && row.Operation == "CreateAuthorizer" {
						// AWS accepts omitted REQUEST identities despite the SDK's
						// required trait. Preserve its serializer and signed request,
						// but let the service judge these native admission inputs.
						config.APIOptions = []func(*middleware.Stack) error{func(stack *middleware.Stack) error {
							_, err := stack.Initialize.Remove("OperationInputValidation")
							return err
						}}
					}
					client := gatewaySDKClient(t, row.Service, config)
					encoded, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					_, err = awstest.CallSDK(t.Context(), client, row.Operation, encoded)
					var expected awsNativeObservation
					expected.Label = row.Label
					expected.Result.Code, expected.Result.HTTPStatus = row.Result.Code, row.Result.HTTPStatus
					awsNativeResult(t, expected, err)
					if wire.Status != row.Result.HTTPStatus {
						t.Fatalf("HTTP %d, native %d: %s", wire.Status, row.Result.HTTPStatus, wire.Body)
					}
					if row.Service != "apigatewayv2" {
						if row.Operation == "CreateFunction" {
							function := input["FunctionName"].(string)
							if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &function}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
								t.Fatal(err)
							}
						}
						return
					}
					admissions++
					if row.Result.Code == "Success" {
						actual := map[string]any{}
						if len(wire.Body) != 0 {
							awsDecodeJSON(t, wire.Body, &actual)
						}
						// Bind generated IDs only at creation; never bind names,
						// settings or IDs again on reads and rejected mutations.
						for operation, field := range map[string]string{"CreateApi": "ApiId", "CreateAuthorizer": "AuthorizerId", "CreateRoute": "RouteId"} {
							if row.Operation != operation {
								continue
							}
							key := strings.ToLower(field[:1]) + field[1:]
							id, ok := actual[key].(string)
							if !ok || id == "" {
								t.Fatalf("missing generated %s: %s", field, wire.Body)
							}
							gatewayBind(map[string]any{field: row.Result.Output[field]}, map[string]any{field: id}, bindings)
						}
						if strings.Contains(row.Operation, "Authorizer") || strings.Contains(row.Operation, "Route") {
							want := gatewayClone(t, row.Result.Output)
							gatewaySubstitute(want, bindings)
							gatewayWSAdmissionCanonical(want)
							gatewayWSAdmissionCanonical(actual)
							if !reflect.DeepEqual(actual, want) {
								t.Fatalf("complete control response differs\ngot %s\nnative with generated bindings %s", mustGatewayWSManagementJSON(t, actual), mustGatewayWSManagementJSON(t, want))
							}
						}
					}
					// Reopen after mutations, including rejected updates/deletes.
					// The fixture's following gets/lists prove both retained state
					// and atomic rejection rather than merely checking status codes.
					if strings.HasPrefix(row.Operation, "Update") || strings.HasPrefix(row.Operation, "Delete") || row.Result.Code == "Success" && (row.Operation == "CreateAuthorizer" || row.Operation == "CreateRoute") {
						clients = reopen()
					}
				}) {
					t.FailNow()
				}
			}
			t.Logf("replayed %d native WebSocket control observations, including complete authorizer/route state and field presence", admissions)
		})
	}
}

// Botocore output uses modeled field names, whereas REST-JSON wire members
// start lowercase. Only resource-list ordering is nonsemantic; identity source
// order and absent/null/empty values remain untouched.
func gatewayWSAdmissionCanonical(object map[string]any) {
	for key, value := range object {
		canonical := strings.ToLower(key[:1]) + key[1:]
		if canonical != key {
			delete(object, key)
			object[canonical] = value
		}
		if items, ok := value.([]any); ok && canonical == "items" {
			for _, item := range items {
				gatewayWSAdmissionCanonical(item.(map[string]any))
			}
			sort.Slice(items, func(i, j int) bool {
				a, _ := json.Marshal(items[i])
				b, _ := json.Marshal(items[j])
				return string(a) < string(b)
			})
		}
	}
}
