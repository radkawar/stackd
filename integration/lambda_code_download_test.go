package stackd_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type lambdaDownloadObservation struct {
	lambdaConcurrencyObservation
	StartedAt time.Time `json:"started_at"`
}

type lambdaDownloadCase struct {
	Label     string
	URLID     string    `json:"url_id"`
	StartedAt time.Time `json:"started_at"`
	Request   struct {
		Method  string
		Headers map[string]string
	}
	Response struct {
		Status     int
		Headers    map[string]string
		BodySHA256 string `json:"body_sha256_hex"`
		Error      struct{ Code string }
	}
}

type lambdaDownloadFixture struct {
	Observations []lambdaDownloadObservation
	Downloads    []lambdaDownloadCase
	Artifacts    map[string]struct {
		ZIP []byte `json:"zip_base64"`
	}
}

// Replay native API and download observations in their original order. Natural
// ten-minute expiry runs on service time; only real container readiness waits
// on wall time. The inconclusive caller-revocation attempt is not a contract.
func TestLambdaFunctionDownloadsNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaConcurrencyLocal(t, lambdaFixture[lambdaDownloadFixture](t, "function_download"))
			source := clock.NewManual(f.Observations[0].StartedAt)
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "downloads.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			c := lambdaEventsConnect(t, backends, source)
			root := (cloudClients{c.server}).iam("test", "test", "")
			urls := map[string]string{}
			type step struct {
				at                    time.Time
				observation, download int
			}
			steps := make([]step, 0, len(f.Observations)+len(f.Downloads))
			for i, row := range f.Observations {
				steps = append(steps, step{row.StartedAt, i, -1})
			}
			for i, row := range f.Downloads {
				steps = append(steps, step{row.StartedAt, -1, i})
			}
			slices.SortStableFunc(steps, func(a, b step) int { return a.at.Compare(b.at) })
			var functionName string
			for _, step := range steps {
				if step.at.After(source.Now()) {
					advanceClock(t, source, step.at.Sub(source.Now()))
				}
				if step.download >= 0 {
					row := f.Downloads[step.download]
					if backend == "sqlite" && row.Label == "original_url_age_120_seconds_after_deletion" {
						// Keep the public origin stable, as required for any issued URL.
						// All functions are already deleted: retrieval must depend only
						// on persisted archives and service signing material.
						origin, err := url.Parse(urls[row.URLID])
						if err != nil {
							t.Fatal(err)
						}
						address := c.server.Listener.Addr().String()
						if err := c.cloud.Close(); err != nil {
							t.Fatal(err)
						}
						c.server.Close()
						closeDatabase()
						backends, closeDatabase = openSQLiteBackends(t, path)
						cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source, PublicEndpoint: origin.Scheme + "://" + origin.Host})
						if err != nil {
							t.Fatal(err)
						}
						listener, err := net.Listen("tcp4", address)
						if err != nil {
							t.Fatal(err)
						}
						server := httptest.NewUnstartedServer(cloud)
						server.Listener.Close()
						server.Listener = listener
						server.Start()
						server.URL = c.server.URL
						t.Cleanup(func() {
							if err := cloud.Close(); err != nil {
								t.Error(err)
							}
							server.Close()
						})
						c.cloud, c.server = cloud, server
					}
					if !t.Run(row.Label, func(t *testing.T) {
						request, err := http.NewRequestWithContext(t.Context(), row.Request.Method, urls[row.URLID], nil)
						if err != nil {
							t.Fatal(err)
						}
						// The runtime endpoint uses Docker's hostname. Route its host
						// connection locally without changing the signed HTTP Host.
						request.Host = request.URL.Host
						target, _ := url.Parse(c.server.URL)
						request.URL.Host = target.Host
						for k, v := range row.Request.Headers {
							request.Header.Set(k, v)
						}
						response, err := c.server.Client().Do(request)
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(response.Body)
						response.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
						if response.StatusCode != row.Response.Status {
							t.Fatalf("HTTP %d %s; native=%d", response.StatusCode, body, row.Response.Status)
						}
						if response.StatusCode < 300 {
							digest := sha256.Sum256(body)
							if hex.EncodeToString(digest[:]) != row.Response.BodySHA256 {
								t.Fatalf("download returned the wrong immutable ZIP or range: %x", digest)
							}
							for _, key := range []string{"ETag", "Content-Type", "Content-Length", "Content-Range", "Accept-Ranges"} {
								if response.Header.Get(key) != row.Response.Headers[key] {
									t.Fatalf("%s=%q; native=%q", key, response.Header.Get(key), row.Response.Headers[key])
								}
							}
						} else if row.Response.Error.Code != "" {
							var actual struct{ Code string }
							if err := xml.Unmarshal(body, &actual); err != nil {
								t.Fatal(err)
							}
							if actual.Code != row.Response.Error.Code {
								t.Fatalf("error=%s; native=%s", actual.Code, row.Response.Error.Code)
							}
						}
					}) {
						t.FailNow()
					}
					continue
				}
				row := f.Observations[step.observation]
				if strings.HasPrefix(row.Label, "owned_caller_") {
					continue
				}
				switch row.Operation {
				case "create-role":
					in := lambdaAdmissionInput[iam.CreateRoleInput](t, row.Input)
					// The local root occupies the native caller's trust entry;
					// Lambda's service-principal trust remains unchanged.
					in.AssumeRolePolicyDocument = aws.String(strings.ReplaceAll(aws.ToString(in.AssumeRolePolicyDocument), "arn:aws:iam::000000000000:user/Delegated", "arn:aws:iam::000000000000:root"))
					if _, err := root.CreateRole(t.Context(), in); err != nil {
						t.Fatal(err)
					}
					continue
				case "create-function":
					if row.Result.Code != "Success" {
						continue
					} // Native role propagation.
					in := lambdaAdmissionInput[awslambda.CreateFunctionInput](t, row.Input)
					in.Code = &lambdatypes.FunctionCode{ZipFile: f.Artifacts["original"].ZIP}
					functionName = aws.ToString(in.FunctionName)
					if _, err := c.lambda.CreateFunction(t.Context(), in); err != nil {
						t.Fatal(err)
					}
					continue
				case "update-function-code":
					_, err := c.lambda.UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: &functionName, ZipFile: f.Artifacts["updated"].ZIP})
					if err != nil {
						t.Fatal(err)
					}
					continue
				case "delete-role":
					if _, err := root.DeleteRole(t.Context(), lambdaAdmissionInput[iam.DeleteRoleInput](t, row.Input)); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if row.Service != "lambda" {
					continue
				}
				if row.Label == "active_unqualified_no_reservation" {
					if err := awslambda.NewFunctionActiveV2Waiter(c.lambda, func(o *awslambda.FunctionActiveV2WaiterOptions) {
						o.MinDelay = 50 * time.Millisecond
						o.MaxDelay = time.Second
					}).Wait(t.Context(), &awslambda.GetFunctionInput{FunctionName: &functionName}, time.Minute); err != nil {
						t.Fatal(err)
					}
				}
				if row.Label == "updated_active_fresh_url" {
					if err := awslambda.NewFunctionUpdatedV2Waiter(c.lambda, func(o *awslambda.FunctionUpdatedV2WaiterOptions) {
						o.MinDelay = 50 * time.Millisecond
						o.MaxDelay = time.Second
					}).Wait(t.Context(), &awslambda.GetFunctionInput{FunctionName: &functionName}, time.Minute); err != nil {
						t.Fatal(err)
					}
				}
				if !t.Run(row.Label, func(t *testing.T) {
					operations := map[string]lambdaPolicyOperation{
						"get-function":                lambdaPolicyBind(c.lambda.GetFunction),
						"put-function-concurrency":    lambdaPolicyBind(c.lambda.PutFunctionConcurrency),
						"delete-function-concurrency": lambdaPolicyBind(c.lambda.DeleteFunctionConcurrency),
						"delete-function":             lambdaPolicyBind(c.lambda.DeleteFunction),
					}
					call := operations[row.Operation]
					if call == nil {
						t.Fatalf("unhandled native operation %s", row.Operation)
					}
					actual, err := call(t.Context(), *lambdaAdmissionInput[map[string]any](t, row.Input))
					if row.Result.Code != "Success" {
						assertAPIError(t, err, row.Result.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if row.Operation == "get-function" {
						want := *lambdaAdmissionInput[map[string]any](t, row.Result.Output)
						config := actual["Configuration"].(map[string]any)
						wantConfig := want["Configuration"].(map[string]any)
						for _, key := range []string{"FunctionArn", "CodeSha256", "CodeSize"} {
							if !reflect.DeepEqual(config[key], wantConfig[key]) {
								t.Fatalf("%s=%v; native=%v", key, config[key], wantConfig[key])
							}
						}
						if !reflect.DeepEqual(actual["Concurrency"], want["Concurrency"]) {
							t.Fatalf("concurrency=%v; native=%v", actual["Concurrency"], want["Concurrency"])
						}
						urls[row.Label] = actual["Code"].(map[string]any)["Location"].(string)
					}
				}) {
					t.FailNow()
				}
			}
		})
	}
}
