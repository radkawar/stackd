package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd/storage"
)

type lambdaPolicyObservation struct {
	Label, Actor, Service, Operation string
	Input                            map[string]any
	Result                           struct {
		Code       string
		Output     map[string]any
		HTTPStatus int `json:"http_status"`
	}
}

type lambdaPolicyFixture struct {
	Observations []lambdaPolicyObservation
}

// A bijection, rather than replacing every revision with a placeholder, checks
// both stable revisions and revisions that must change. Unknown input revisions
// remain the native stale value; known ones address the actual local revision.
type lambdaPolicyRevisions map[string]string

func (r lambdaPolicyRevisions) observe(t *testing.T, native, local string) {
	t.Helper()
	if native == "" || local == "" {
		t.Fatalf("missing revision: native=%q local=%q", native, local)
	}
	if previous, ok := r[native]; ok {
		if previous != local {
			t.Fatalf("unchanged native revision %s changed locally: %s -> %s", native, previous, local)
		}
		return
	}
	for other, previous := range r {
		if previous == local {
			t.Fatalf("different native revisions %s and %s collapsed to %s", other, native, local)
		}
	}
	r[native] = local
}

type lambdaPolicyHTTP struct {
	client aws.HTTPClient
	status int
}

func (c *lambdaPolicyHTTP) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if response != nil {
		c.status = response.StatusCode
	}
	return response, err
}

type lambdaPolicyOperation func(context.Context, map[string]any) (map[string]any, error)

func lambdaPolicyBind[I, O any](call func(context.Context, *I, ...func(*awslambda.Options)) (*O, error)) lambdaPolicyOperation {
	return func(ctx context.Context, fields map[string]any) (map[string]any, error) {
		data, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		var input I
		if err := json.Unmarshal(data, &input); err != nil {
			return nil, err
		}
		output, err := call(ctx, &input)
		if err != nil {
			return nil, err
		}
		data, err = json.Marshal(output)
		if err != nil {
			return nil, err
		}
		var result map[string]any
		err = json.Unmarshal(data, &result)
		return result, err
	}
}

func lambdaPolicyComparable(t *testing.T, output map[string]any) map[string]any {
	t.Helper()
	// SDK struct JSON includes nil optional members and transport metadata that
	// the wire response omits. Keep empty objects: destination emptiness matters.
	for key, value := range output {
		if value == nil || key == "ResultMetadata" || key == "LastModified" {
			delete(output, key)
			continue
		}
		if nested, ok := value.(map[string]any); ok {
			lambdaPolicyComparable(t, nested)
		}
		if key == "Policy" || key == "Statement" {
			if text, ok := value.(string); ok {
				var parsed any
				if err := json.Unmarshal([]byte(text), &parsed); err != nil {
					t.Fatal(err)
				}
				output[key] = parsed
			}
		}
	}
	return output
}

// This replay covers control-plane observations, not native readiness polling,
// IAM propagation delays, invocation delivery, or reserved concurrency. Nonempty
// destinations, published versions/aliases, Function URLs, and organization
// membership authorization are outside this replay. The organization case only
// checks the captured PrincipalOrgID statement rendering.
func TestLambdaPolicyNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			policyFixture := lambdaFixture[lambdaPolicyFixture](t, "event_policy")
			invocationFixture := lambdaFixture[lambdaPolicyFixture](t, "event_invocation")
			edgeFixture := lambdaFixture[lambdaPolicyFixture](t, "event_edge_cases")
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "lambda-policy.sqlite"))
			}
			execution := lambdaEventsConnect(t, backends, nil)
			lambdaEventsProvision(t, execution, lambdaFixture[lambdaEventsFixture](t, "event_invocation"))
			server := execution.server
			c := cloudClients{server}
			transport := &lambdaPolicyHTTP{client: server.Client()}
			client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: transport, RetryMaxAttempts: 1})
			ctx := t.Context()
			const name = "stackd-lambda-event-owned"
			const arn = "arn:aws:lambda:us-east-1:000000000000:function:" + name
			root := c.iam("test", "test", "")
			configuration := &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}
			operations := map[string]lambdaPolicyOperation{
				"add-permission":                      lambdaPolicyBind(client.AddPermission),
				"get-policy":                          lambdaPolicyBind(client.GetPolicy),
				"remove-permission":                   lambdaPolicyBind(client.RemovePermission),
				"get-function-configuration":          lambdaPolicyBind(client.GetFunctionConfiguration),
				"update-function-configuration":       lambdaPolicyBind(client.UpdateFunctionConfiguration),
				"put-function-event-invoke-config":    lambdaPolicyBind(client.PutFunctionEventInvokeConfig),
				"update-function-event-invoke-config": lambdaPolicyBind(client.UpdateFunctionEventInvokeConfig),
				"get-function-event-invoke-config":    lambdaPolicyBind(client.GetFunctionEventInvokeConfig),
				"delete-function-event-invoke-config": lambdaPolicyBind(client.DeleteFunctionEventInvokeConfig),
			}
			revisions := lambdaPolicyRevisions{}
			replay := func(t *testing.T, row lambdaPolicyObservation) {
				t.Helper()
				if row.Actor != "authorized-probe-caller" || row.Service != "lambda" {
					t.Fatalf("non-control observation selected: %s", row.Label)
				}
				operation, ok := operations[row.Operation]
				if !ok {
					t.Fatalf("unbound fixture operation %s", row.Operation)
				}
				input := make(map[string]any, len(row.Input))
				for key, value := range row.Input {
					input[key] = value
				}
				// The edge capture used a second empty function for config probes;
				// the preceding config replay has already deleted our config.
				if input["FunctionName"] == name+"-control" {
					input["FunctionName"] = name
				}
				if revision, ok := input["RevisionId"].(string); ok {
					if local, known := revisions[revision]; known {
						input["RevisionId"] = local
					}
				}
				transport.status = 0
				actual, err := operation(ctx, input)
				if transport.status != row.Result.HTTPStatus {
					t.Fatalf("HTTP status=%d, native=%d: %v", transport.status, row.Result.HTTPStatus, err)
				}
				if row.Result.Code != "Success" {
					assertAPIError(t, err, row.Result.Code)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := row.Result.Output
				if value, ok := want["FunctionArn"].(string); ok {
					want["FunctionArn"] = strings.Replace(value, name+"-control", name, 1)
				}
				// Deployment responses expose transient revisions while AWS
				// prepares code. Only settled configuration participates in the
				// revision bijection; no native polling snapshots are asserted.
				if row.Operation == "get-function-configuration" || row.Operation == "update-function-configuration" {
					keys := []string{"FunctionName", "FunctionArn", "Description"}
					if row.Operation == "get-function-configuration" {
						keys = append(keys, "RevisionId")
					}
					project := func(source map[string]any) map[string]any {
						result := map[string]any{}
						for _, key := range keys {
							result[key] = source[key]
						}
						return result
					}
					actual, want = project(actual), project(want)
				}
				if native, ok := want["RevisionId"].(string); ok {
					local, _ := actual["RevisionId"].(string)
					revisions.observe(t, native, local)
					want["RevisionId"] = local
				}
				actual, want = lambdaPolicyComparable(t, actual), lambdaPolicyComparable(t, want)
				if !reflect.DeepEqual(actual, want) {
					t.Fatalf("SDK output=%#v; native=%#v", actual, want)
				}
			}
			var beforeDeploymentPolicy string
			for _, row := range policyFixture.Observations {
				if row.Service != "lambda" || row.Operation == "create-function" || strings.HasPrefix(row.Label, "wait_description_update_") && row.Label != "wait_description_update_1" {
					continue
				}
				if row.Label == "update_function_description" {
					current, err := client.GetPolicy(ctx, &awslambda.GetPolicyInput{FunctionName: aws.String(name)})
					if err != nil {
						t.Fatal(err)
					}
					beforeDeploymentPolicy = aws.ToString(current.RevisionId)
				}
				if !t.Run("event_policy/"+row.Label, func(t *testing.T) { replay(t, row) }) {
					t.FailNow()
				}
				if row.Label == "update_function_description" {
					if err := awslambda.NewFunctionUpdatedWaiter(client, fastLambdaUpdatedWaiter).Wait(ctx, configuration, time.Minute); err != nil {
						t.Fatal(err)
					}
				}
				if row.Label == "policy_after_function_update" {
					current, err := client.GetPolicy(ctx, &awslambda.GetPolicyInput{FunctionName: aws.String(name)})
					if err != nil || aws.ToString(current.RevisionId) != beforeDeploymentPolicy {
						t.Fatalf("function update changed resource policy revision: %#v %v", current, err)
					}
				}
			}
			for _, row := range invocationFixture.Observations {
				if row.Label == "grant_caller_resource_only" {
					break // Later observations concern invocation and IAM propagation.
				}
				if row.Service == "lambda" && strings.Contains(row.Operation, "event-invoke-config") {
					if !t.Run("event_invocation/"+row.Label, func(t *testing.T) { replay(t, row) }) {
						t.FailNow()
					}
				}
			}
			// Restore the EventRule prerequisite from the native invocation run.
			for _, row := range policyFixture.Observations {
				if row.Label == "add_source_conditions" {
					if !t.Run("event_edge_cases/seed_event_rule", func(t *testing.T) { replay(t, row) }) {
						t.FailNow()
					}
				}
			}
			for _, row := range edgeFixture.Observations {
				if strings.Contains(row.Operation, "event-invoke-config") || row.Operation == "add-permission" || row.Operation == "remove-permission" {
					if !t.Run("event_edge_cases/"+row.Label, func(t *testing.T) { replay(t, row) }) {
						t.FailNow()
					}
				}
			}
			t.Run("resource_only_configuration_grant", func(t *testing.T) {
				// Additional authorization contract, not an uncaptured AWS claim.
				userARN, key, secret := c.user(t, "test", "policy-config-reader")
				options := client.Options()
				options.Credentials = credentials.NewStaticCredentialsProvider(key, secret, "")
				reader := awslambda.New(options)
				denied := func() {
					t.Helper()
					_, err := reader.GetFunctionConfiguration(ctx, configuration)
					assertAPIError(t, err, "AccessDeniedException")
					var status interface{ HTTPStatusCode() int }
					if !errors.As(err, &status) || status.HTTPStatusCode() != http.StatusForbidden {
						t.Fatalf("configuration denial status: %v", err)
					}
				}
				denied()
				_, err := client.AddPermission(ctx, &awslambda.AddPermissionInput{FunctionName: aws.String(name), StatementId: aws.String("ConfigurationReader"), Action: aws.String("lambda:GetFunctionConfiguration"), Principal: aws.String(userARN)})
				if err != nil {
					t.Fatal(err)
				}
				got, err := reader.GetFunctionConfiguration(ctx, configuration)
				if err != nil || aws.ToString(got.FunctionArn) != arn || aws.ToString(got.Description) != "owned policy revision separation probe" {
					t.Fatalf("resource-only configuration read: %#v %v", got, err)
				}
				putUserPolicy(t, root, "policy-config-reader", fmt.Sprintf(`{"Statement":[{"Effect":"Deny","Action":"lambda:GetFunctionConfiguration","Resource":%q}]}`, arn))
				denied()
				_, err = root.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: aws.String("policy-config-reader"), PolicyName: aws.String("access")})
				if err != nil {
					t.Fatal(err)
				}
				_, err = client.RemovePermission(ctx, &awslambda.RemovePermissionInput{FunctionName: aws.String(name), StatementId: aws.String("ConfigurationReader")})
				if err != nil {
					t.Fatal(err)
				}
				denied()
			})
		})
	}
}
