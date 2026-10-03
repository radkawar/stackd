package stackd_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd/clock"
	"stackd/storage"
)

type lambdaConcurrencyObservation struct {
	Label, Service, Operation string
	Input                     json.RawMessage
	Result                    struct {
		Code          string
		Output        json.RawMessage
		HTTPStatus    int               `json:"http_status"`
		PayloadBase64 string            `json:"payload_base64"`
		Body          map[string]any    `json:"response_body_decoded"`
		Headers       map[string]string `json:"response_headers"`
	}
}

type lambdaConcurrencyFixture struct {
	Account, Prefix string
	Observations    []lambdaConcurrencyObservation
	CloudTrail      struct {
		Events []struct {
			Label  string `json:"observation_label"`
			Event  map[string]any
			Lookup struct{ Resources []trailtypes.Resource }
		} `json:"correlated_events"`
	}
}

func (f lambdaConcurrencyFixture) row(t *testing.T, label string) lambdaConcurrencyObservation {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("native concurrency fixture lacks %s", label)
	return lambdaConcurrencyObservation{}
}

func lambdaConcurrencyLocal[T any](t *testing.T, value T) T {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var local T
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(data), "000000000000", "000000000000")), &local); err != nil {
		t.Fatal(err)
	}
	return local
}

type lambdaConcurrencyHTTP struct {
	client    aws.HTTPClient
	requestID string
}

func (c *lambdaConcurrencyHTTP) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if response != nil {
		c.requestID = response.Header.Get("X-Amzn-RequestId")
	}
	return response, err
}

// Replay only service observations. CLI ParamValidation rows never reached AWS;
// published versions and aliases are not provisioned merely to reject qualifiers.
func TestLambdaConcurrencyAdmissionNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaConcurrencyLocal(t, lambdaFixture[lambdaConcurrencyFixture](t, "concurrency_admission"))
			source := clock.NewManual(time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "concurrency.sqlite"))
			}
			c := lambdaEventsConnect(t, backends, source)
			clients := cloudClients{c.server}
			root := clients.iam("test", "test", "")
			transport := &lambdaConcurrencyHTTP{client: c.server.Client()}
			options := c.lambda.Options()
			options.HTTPClient = transport
			admin := awslambda.New(options)
			client := admin
			revisions := lambdaPolicyRevisions{}
			stamps := map[string]lambdaPolicyRevisions{}
			nativeAudit := map[string]map[string]any{}
			for _, entry := range f.CloudTrail.Events {
				nativeAudit[entry.Label] = entry.Event
			}
			auditIDs := map[string]string{}
			for _, row := range f.Observations {
				// The first revision probe accidentally addressed a deleted function. The
				// later metadata capture contains the actual reservation/revision sequence.
				if strings.HasPrefix(row.Label, "revision_") || strings.Contains(row.Label, "cleanup") || strings.HasPrefix(row.Label, "cloudtrail") || strings.HasPrefix(row.Label, "wait_") || strings.HasPrefix(row.Label, "metadata_wait_") {
					continue
				}
				if row.Operation == "assume-role" {
					// Reuse the captured effective grants with an SDK-created principal. This
					// tests Lambda's current IAM resource/action decisions, not STS issuance.
					fields := lambdaAdmissionInput[map[string]any](t, row.Input)
					name := (*fields)["RoleSessionName"].(string)
					_, key, secret := clients.user(t, "test", name)
					putUserPolicy(t, root, name, (*fields)["Policy"].(string))
					options.Credentials = credentials.NewStaticCredentialsProvider(key, secret, "")
					client = awslambda.New(options)
					continue
				}
				if strings.HasPrefix(row.Label, "metadata_") {
					client = admin
				}
				if row.Operation == "create-role" {
					if row.Label == "create_authorization_role" {
						continue
					}
					if _, err := root.CreateRole(t.Context(), lambdaAdmissionInput[iam.CreateRoleInput](t, row.Input)); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if row.Service != "lambda" || row.Result.Code == "ParamValidation" {
					continue
				}
				if row.Operation == "create-function" {
					if row.Result.Code != "Success" {
						continue
					} // Native IAM propagation.
					input := lambdaAdmissionInput[awslambda.CreateFunctionInput](t, row.Input)
					input.Publish = false
					if _, err := admin.CreateFunction(t.Context(), input); err != nil {
						t.Fatal(err)
					}
					if err := awslambda.NewFunctionActiveWaiter(admin, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute); err != nil {
						t.Fatal(err)
					}
					continue
				}
				operations := map[string]lambdaPolicyOperation{
					"get-function-concurrency":    lambdaPolicyBind(client.GetFunctionConcurrency),
					"put-function-concurrency":    lambdaPolicyBind(client.PutFunctionConcurrency),
					"delete-function-concurrency": lambdaPolicyBind(client.DeleteFunctionConcurrency),
					"get-function-configuration":  lambdaPolicyBind(admin.GetFunctionConfiguration),
					"get-account-settings":        lambdaPolicyBind(client.GetAccountSettings),
				}
				call := operations[row.Operation]
				if call == nil {
					continue
				}
				// Send tokens that the typed int32 SDK cannot represent through the
				// same signed gateway, including their native audit projection.
				if row.Label == "invalid_boolean" || row.Label == "invalid_int32_overflow" {
					fields := lambdaAdmissionInput[map[string]any](t, row.Input)
					payload, err := json.Marshal(map[string]any{"ReservedConcurrentExecutions": (*fields)["ReservedConcurrentExecutions"]})
					if err != nil {
						t.Fatal(err)
					}
					request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, c.server.URL+"/2017-10-31/functions/"+(*fields)["FunctionName"].(string)+"/concurrency", bytes.NewReader(payload))
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Content-Type", "application/json")
					response, body := lambdaRawRequest(t, c.server, request, payload, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
					if response.Header.Get("X-Amzn-Errortype") != row.Result.Code {
						t.Fatalf("%s: HTTP %d %s; native=%s", row.Label, response.StatusCode, body, row.Result.Code)
					}
					auditIDs[row.Label] = response.Header.Get("X-Amzn-RequestId")
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					input := *lambdaAdmissionInput[map[string]any](t, row.Input)
					actual, err := call(t.Context(), input)
					if _, ok := nativeAudit[row.Label]; ok {
						auditIDs[row.Label] = transport.requestID
					}
					if row.Result.Code != "Success" {
						assertAPIError(t, err, row.Result.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					want := *lambdaAdmissionInput[map[string]any](t, row.Result.Output)
					switch row.Operation {
					case "get-function-configuration":
						name := input["FunctionName"].(string)
						revisions.observe(t, want["RevisionId"].(string), actual["RevisionId"].(string))
						if stamps[name] == nil {
							stamps[name] = lambdaPolicyRevisions{}
						}
						stamps[name].observe(t, want["LastModified"].(string), actual["LastModified"].(string))
					case "get-function-concurrency", "put-function-concurrency":
						if !reflect.DeepEqual(lambdaPolicyComparable(t, actual), want) {
							t.Fatalf("concurrency=%#v; native=%#v", actual, want)
						}
					}
				}) {
					t.FailNow()
				}
			}
			// Compare native service projections by SDK request, not event count: audit
			// delivery may retry, but each returned document must describe that request.
			trails := organizationsAuditClient(clients, "test", "us-east-1")
			trailNativeDrain(t, c.cloud)
			for _, label := range []string{"missing_get", "get_one", "put_one", "delete_reserved", "iam_exact_get_alias", "invalid_int32_overflow"} {
				want := nativeAudit[label]
				id := auditIDs[label]
				if want == nil || id == "" {
					t.Fatalf("missing native/SDK audit correlation for %s", label)
				}
				got := auditLookupRecord(t, trails, id, want["eventName"].(string))
				for _, key := range []string{"eventSource", "eventName", "readOnly", "eventType", "eventCategory", "requestParameters", "responseElements", "errorCode"} {
					if !reflect.DeepEqual(got[key], want[key]) {
						t.Fatalf("%s audit %s=%#v; native=%#v", label, key, got[key], want[key])
					}
				}
				var nativeResources []trailtypes.Resource
				for _, entry := range f.CloudTrail.Events {
					if entry.Label == label {
						nativeResources = entry.Lookup.Resources
						break
					}
				}
				pages := cloudtrail.NewLookupEventsPaginator(trails, &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String(want["eventName"].(string))}}})
				matched := false
				for pages.HasMorePages() {
					page, err := pages.NextPage(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					for _, event := range page.Events {
						document := lambdaQueueObject(t, aws.ToString(event.CloudTrailEvent))
						if document["requestID"] != id {
							continue
						}
						matched = true
						if len(event.Resources) != len(nativeResources) || (len(nativeResources) != 0 && !reflect.DeepEqual(event.Resources, nativeResources)) {
							t.Fatalf("%s lookup resources=%+v; native=%+v", label, event.Resources, nativeResources)
						}
					}
				}
				if !matched {
					t.Fatalf("lookup lost request %s", id)
				}
			}
		})
	}
}

// Native numeric conversion precedes IAM, existence, quota validation and audit.
// Replay raw tokens because an SDK int32 cannot express fractional or wide input.
func TestLambdaConcurrencyNumericNativeWire(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	type wireResult struct {
		Path     string          `json:"request_path"`
		Body     string          `json:"request_raw_body"`
		Status   int             `json:"http_status"`
		Error    string          `json:"error_type"`
		Response json.RawMessage `json:"response"`
	}
	f := lambdaConcurrencyLocal(t, lambdaFixture[struct {
		FunctionName string `json:"function_name"`
		Observations []struct {
			Label, Principal, Target string
			Put                      wireResult
			PostGet                  wireResult `json:"post_get"`
		}
		AuthorizationSession struct {
			Policy json.RawMessage
		} `json:"authorization_session"`
	}](t, "concurrency_numeric"))
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "numeric.sqlite"))
			}
			r := lambdaConcurrencyProvision(t, backends, clock.NewManual(time.Date(2026, 9, 14, 19, 0, 0, 0, time.UTC)))
			clients := cloudClients{r.c.server}
			_, key, secret := clients.user(t, "test", "numeric-denied")
			// Exercise the captured effective deny with a signed IAM principal;
			// federation issuance is independent of Lambda's input precedence.
			putUserPolicy(t, r.root, "numeric-denied", strings.ReplaceAll(string(f.AuthorizationSession.Policy), f.FunctionName, aws.ToString(r.name)))
			for _, row := range f.Observations {
				if !t.Run(row.Label+"/"+row.Principal+"/"+row.Target, func(t *testing.T) {
					credential := aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
					if row.Principal == "explicit_deny_federated_session" {
						credential = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
					}
					payload := []byte(row.Put.Body)
					path := strings.ReplaceAll(row.Put.Path, f.FunctionName, aws.ToString(r.name))
					request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, r.c.server.URL+path, bytes.NewReader(payload))
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Content-Type", "application/json")
					response, body := lambdaRawRequest(t, r.c.server, request, payload, credential)
					if response.StatusCode != row.Put.Status || response.Header.Get("X-Amzn-Errortype") != row.Put.Error {
						t.Fatalf("HTTP %d %s: %s; native=%d %s", response.StatusCode, response.Header.Get("X-Amzn-Errortype"), body, row.Put.Status, row.Put.Error)
					}
					if row.Put.Status == http.StatusOK {
						actual := lambdaAdmissionInput[awslambda.PutFunctionConcurrencyOutput](t, body)
						native := lambdaAdmissionInput[awslambda.PutFunctionConcurrencyOutput](t, row.Put.Response)
						if !reflect.DeepEqual(actual.ReservedConcurrentExecutions, native.ReservedConcurrentExecutions) {
							t.Fatalf("put=%v; native=%v", actual.ReservedConcurrentExecutions, native.ReservedConcurrentExecutions)
						}
					}
					name := aws.ToString(r.name)
					if row.Target == "missing_owned_name" {
						name += "-missing"
					}
					actual, err := r.c.lambda.GetFunctionConcurrency(t.Context(), &awslambda.GetFunctionConcurrencyInput{FunctionName: &name})
					if row.PostGet.Error != "" {
						assertAPIError(t, err, row.PostGet.Error)
					} else {
						if err != nil {
							t.Fatal(err)
						}
						native := lambdaAdmissionInput[awslambda.GetFunctionConcurrencyOutput](t, row.PostGet.Response)
						if !reflect.DeepEqual(actual.ReservedConcurrentExecutions, native.ReservedConcurrentExecutions) {
							t.Fatalf("retained reservation=%v; native=%v", actual.ReservedConcurrentExecutions, native.ReservedConcurrentExecutions)
						}
					}
				}) {
					t.FailNow()
				}
			}
		})
	}
}
