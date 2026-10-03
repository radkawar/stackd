package stackd_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"stackd"
	"stackd/internal/awstest"
)

type gatewayFixture struct {
	Account, Region string
	HandlerSource   string `json:"handler_source"`
	Observations    []struct {
		Label, Service, Operation string
		Input                     map[string]any
		Result                    struct {
			Code   string
			Output map[string]any
		}
	}
	HTTP []struct {
		Label, API, Path, Method, Authorization string
		Result                                  struct {
			Status int
			Body   map[string]any
		}
	}
}

// Native REST and HTTP APIs deliberately differ in JWT admission and payload
// projection. Replay the same captured application with real Lambda containers
// and retained storage; no handler stand-in can satisfy this contract.
func TestAPIGatewayNativeDeployedLambda(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real Gateway Lambda replay")
	}
	var fixture gatewayFixture
	awsReadFixture(t, "apigateway/deployed_lambda_authorization.json", &fixture)
	audits := gatewayNativeAudits(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return newLambdaDockerStack(t, config, nil)
			})
			bindings := map[string]string{}
			var httpID, restID, idToken, accessToken, functionName string
			invokeHTTP := func(afterRevoke bool) {
				for _, row := range fixture.HTTP {
					if strings.Contains(row.Label, "before-deployment") || strings.Contains(row.Label, "after-revocation") != afterRevoke {
						continue
					}
					if !t.Run(row.Label, func(t *testing.T) {
						id := httpID
						if row.API == "rest" {
							id = restID
						}
						request, err := http.NewRequestWithContext(t.Context(), row.Method, clients.server.URL+"/_stackd/execute-api/"+id+row.Path, nil)
						if err != nil {
							t.Fatal(err)
						}
						request.Header.Set("User-Agent", "stackd-native-gateway-probe")
						request.Header.Set("X-Probe", row.Label)
						request.Header.Set("Accept-Encoding", "identity")
						switch row.Authorization {
						case "id":
							request.Header.Set("Authorization", "Bearer "+idToken)
						case "access":
							request.Header.Set("Authorization", "Bearer "+accessToken)
						case "invalid":
							request.Header.Set("Authorization", "Bearer invalid-jwt")
						case "iam":
							digest := sha256.Sum256(nil)
							if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: fixture.Account, SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), "execute-api", fixture.Region, time.Now()); err != nil {
								t.Fatal(err)
							}
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
							t.Fatalf("status %d native %d: %s", response.StatusCode, row.Result.Status, body)
						}
						if response.StatusCode == 200 {
							var got struct {
								Event    map[string]any
								Function string
							}
							awsDecodeJSON(t, body, &got)
							if got.Function != functionName {
								t.Fatalf("unexpected executed function %q", got.Function)
							}
							want := gatewayClone(t, row.Result.Body["event"].(map[string]any))
							gatewayCompareEvent(t, got.Event, want, bindings)
						}
					}) {
						t.FailNow()
					}
				}
			}
			for _, row := range fixture.Observations {
				if strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-") || strings.HasPrefix(row.Label, "account-") {
					continue
				}
				if strings.HasPrefix(row.Label, "create-function-") && row.Result.Code != "Success" {
					continue
				}
				if strings.HasPrefix(row.Label, "function-ready-") {
					continue
				}
				if row.Label == "revoke-refresh" {
					clients = reopen()
					invokeHTTP(false)
				}
				input := gatewayClone(t, row.Input)
				gatewaySubstitute(input, bindings)
				if row.Operation == "CreateFunction" {
					input["Runtime"] = "python3.12"
					input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
				}
				if row.Label == "create-user" {
					input["TemporaryPassword"] = "GatewayNative1!password"
				}
				if row.Label == "set-password" {
					input["Password"] = "GatewayNative1!password"
				}
				if row.Label == "login" {
					input["AuthParameters"].(map[string]any)["PASSWORD"] = "GatewayNative1!password"
				}
				if row.Label == "http-authorizer" {
					claims, _ := cognitoVerifiedJWT(t, clients, idToken)
					input["JwtConfiguration"].(map[string]any)["Issuer"] = claims["iss"]
				}
				wire := &awstest.WireClient{Client: clients.server.Client()}
				creds := credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")
				endpoint := aws.String(clients.server.URL)
				var client any
				switch row.Service {
				case "apigateway":
					client = apigateway.New(apigateway.Options{Region: fixture.Region, BaseEndpoint: endpoint, Credentials: creds, HTTPClient: wire, RetryMaxAttempts: 1})
				case "apigatewayv2":
					client = apigatewayv2.New(apigatewayv2.Options{Region: fixture.Region, BaseEndpoint: endpoint, Credentials: creds, HTTPClient: wire, RetryMaxAttempts: 1})
				case "cognito-idp":
					client = cognitoidentityprovider.New(cognitoidentityprovider.Options{Region: fixture.Region, BaseEndpoint: endpoint, Credentials: creds, HTTPClient: wire, RetryMaxAttempts: 1})
				case "iam":
					client = iam.New(iam.Options{Region: fixture.Region, BaseEndpoint: endpoint, Credentials: creds, HTTPClient: wire, RetryMaxAttempts: 1})
				case "lambda":
					client = awslambda.New(awslambda.Options{Region: fixture.Region, BaseEndpoint: endpoint, Credentials: creds, HTTPClient: wire, RetryMaxAttempts: 1})
				default:
					t.Fatalf("unhandled native producer %s", row.Service)
				}
				encoded, _ := json.Marshal(input)
				output, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
				if row.Result.Code != "Success" {
					assertAPIError(t, err, row.Result.Code)
					gatewayAudit(t, clients, fixture, row.Label, row.Operation, audits[row.Label], output, err, bindings)
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
				decoded, _ := json.Marshal(output)
				var actual map[string]any
				awsDecodeJSON(t, decoded, &actual)
				gatewayBind(row.Result.Output, actual, bindings)
				gatewayAudit(t, clients, fixture, row.Label, row.Operation, audits[row.Label], output, err, bindings)
				switch row.Label {
				case "create-http":
					httpID = actual["ApiId"].(string)
					bindings["$HTTP_API"] = httpID
				case "create-rest":
					restID = actual["Id"].(string)
					bindings["$REST_API"] = restID
				case "http-route-ANY /echo":
					bindings["$HTTP_ROUTE"] = actual["RouteId"].(string)
				case "rest-resource-echo":
					bindings["$REST_RESOURCE"] = actual["Id"].(string)
				case "login":
					tokens := actual["AuthenticationResult"].(map[string]any)
					idToken, accessToken = tokens["IdToken"].(string), tokens["AccessToken"].(string)
				}
				if row.Operation == "CreateFunction" {
					functionName = actual["FunctionName"].(string)
					lambda := client.(*awslambda.Client)
					if err := awslambda.NewFunctionActiveWaiter(lambda).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &functionName}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
						t.Fatal(err)
					}
				}
			}
			invokeHTTP(true)
			clients = gatewayDeploymentTransitions(t, fixture, clients, reopen, bindings)
			for _, row := range fixture.Observations {
				if (row.Service != "apigateway" && row.Service != "apigatewayv2") || (!strings.HasPrefix(row.Label, "cleanup-") && !strings.HasPrefix(row.Label, "absence-")) {
					continue
				}
				input := gatewayClone(t, row.Input)
				gatewaySubstitute(input, bindings)
				creds := credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")
				var client any
				if row.Service == "apigateway" {
					client = apigateway.New(apigateway.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				} else {
					client = apigatewayv2.New(apigatewayv2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				encoded, _ := json.Marshal(input)
				output, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
				if row.Result.Code != "Success" {
					assertAPIError(t, err, row.Result.Code)
				} else if err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
				gatewayAudit(t, clients, fixture, row.Label, row.Operation, audits[row.Label], output, err, bindings)
			}
		})
	}
}

func gatewayDeploymentTransitions(t *testing.T, native gatewayFixture, clients cloudClients, reopen func() cloudClients, bindings map[string]string) cloudClients {
	t.Helper()
	var fixture struct {
		Steps []struct {
			Service, Operation string
			Input              map[string]any
			Status             int
			Reopen             bool
		}
	}
	awsReadFixture(t, "apigateway/deployment_transitions.json", &fixture)
	for index, step := range fixture.Steps {
		gatewaySubstitute(step.Input, bindings)
		creds := credentials.NewStaticCredentialsProvider(native.Account, "test", "")
		var client any
		id, path := bindings["$HTTP_API"], "/echo"
		if step.Service == "http" {
			client = apigatewayv2.New(apigatewayv2.Options{Region: native.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
		} else {
			id, path = bindings["$REST_API"], "/dev/echo"
			client = apigateway.New(apigateway.Options{Region: native.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
		}
		input, err := json.Marshal(step.Input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := awstest.CallSDK(t.Context(), client, step.Operation, input); err != nil {
			t.Fatalf("deployment step %d %s: %v", index, step.Operation, err)
		}
		if step.Reopen {
			clients = reopen()
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, clients.server.URL+"/_stackd/execute-api/"+id+path, nil)
		if err != nil {
			t.Fatal(err)
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
		if response.StatusCode != step.Status {
			t.Fatalf("deployment step %d %s: status %d want %d: %s", index, step.Operation, response.StatusCode, step.Status, body)
		}
	}
	return clients
}

func gatewayClone(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	awsDecodeJSON(t, raw, &out)
	return out
}
func gatewaySubstitute(value any, bindings map[string]string) {
	switch object := value.(type) {
	case map[string]any:
		for key, child := range object {
			if text, ok := child.(string); ok {
				object[key] = gatewayReplace(text, bindings)
			} else {
				gatewaySubstitute(child, bindings)
			}
		}
	case []any:
		for index, child := range object {
			if text, ok := child.(string); ok {
				object[index] = gatewayReplace(text, bindings)
			} else {
				gatewaySubstitute(child, bindings)
			}
		}
	}
}
func gatewayReplace(text string, bindings map[string]string) string {
	if value, ok := bindings[text]; ok {
		return value
	}
	for old, value := range bindings {
		if len(old) > 3 {
			text = strings.ReplaceAll(text, old, value)
		}
	}
	return text
}
func gatewayBind(native, local any, bindings map[string]string) {
	switch expected := native.(type) {
	case map[string]any:
		actual, _ := local.(map[string]any)
		for key, value := range expected {
			for name, result := range actual {
				if strings.EqualFold(key, name) {
					gatewayBind(value, result, bindings)
					break
				}
			}
		}
	case []any:
		actual, _ := local.([]any)
		// AWS list order is not an identity. Match retained resources before
		// binding their generated fields; positional binding corrupts IDs
		// already learned from creation when a list arrives in another order.
		for _, value := range expected {
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			for _, candidate := range actual {
				result, ok := candidate.(map[string]any)
				if !ok {
					continue
				}
				matched := false
				for key, field := range object {
					switch strings.ToLower(key) {
					case "routekey", "path", "name", "stagename", "id", "routeid", "authorizerid", "integrationid", "deploymentid":
						text, ok := field.(string)
						if !ok || text == "" {
							continue
						}
						if bound, ok := bindings[text]; ok {
							text = bound
						}
						for name, member := range result {
							if strings.EqualFold(key, name) && member == text {
								matched = true
							}
						}
					}
				}
				if matched {
					gatewayBind(value, candidate, bindings)
					break
				}
			}
		}
	case string:
		if actual, ok := local.(string); ok && expected != actual && expected != "" {
			bindings[expected] = actual
		}
	}
}
func gatewayCompareEvent(t *testing.T, got, want map[string]any, bindings map[string]string) {
	t.Helper()
	// Compare customer data and field presence; only generated deployment,
	// network identity and signed-token claims differ between the two clouds.
	for _, event := range []map[string]any{got, want} {
		for _, member := range []string{"headers", "multiValueHeaders"} {
			if headers, ok := event[member].(map[string]any); ok {
				for key := range headers {
					switch strings.ToLower(key) {
					case "host", "x-amzn-trace-id", "x-forwarded-for", "x-forwarded-port", "x-forwarded-proto", "x-amz-date":
						delete(headers, key)
					}
				}
			}
		}
		context := event["requestContext"].(map[string]any)
		for _, key := range []string{"apiId", "accountId", "domainName", "domainPrefix", "requestId", "extendedRequestId", "time", "timeEpoch", "requestTime", "requestTimeEpoch", "deploymentId", "resourceId"} {
			delete(context, key)
		}
		if identity, ok := context["identity"].(map[string]any); ok {
			for _, key := range []string{"sourceIp", "principalOrgId", "accessKey", "caller", "user", "userArn", "accountId"} {
				delete(identity, key)
			}
		}
		if h, ok := context["http"].(map[string]any); ok {
			delete(h, "sourceIp")
		}
		if auth, ok := context["authorizer"].(map[string]any); ok {
			if iam, ok := auth["iam"].(map[string]any); ok {
				for _, key := range []string{"accessKey", "accountId", "callerId", "principalOrgId", "userArn", "userId"} {
					delete(iam, key)
				}
			}
			claims, _ := auth["claims"].(map[string]any)
			if jwt, ok := auth["jwt"].(map[string]any); ok {
				claims, _ = jwt["claims"].(map[string]any)
			}
			for _, key := range []string{"aud", "client_id", "auth_time", "event_id", "exp", "iat", "iss", "jti", "origin_jti", "sub"} {
				delete(claims, key)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		t.Fatalf("payload differs\ngot %s\nnative %s", a, b)
	}
}
