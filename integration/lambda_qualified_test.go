package stackd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func lambdaQualifiedObservation(t *testing.T, f lambdaQualifiedFixture, label string) lambdaQualifiedRow {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native observation %s", label)
	return lambdaQualifiedRow{}
}

func (r *lambdaQualifiedReplay) queue(t *testing.T, suffix string) *string {
	t.Helper()
	for native, local := range r.queues {
		if strings.HasSuffix(native, "-"+suffix) {
			return aws.String(local)
		}
	}
	t.Fatalf("fixture omitted queue %s", suffix)
	return nil
}

func (r *lambdaQualifiedReplay) accept(t *testing.T, row lambdaQualifiedRow) string {
	t.Helper()
	input := lambdaAdmissionInput[awslambda.InvokeInput](t, lambdaQualifiedJSON(t, r.input(t, row)))
	out, err := r.c.lambda.Invoke(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if int(out.StatusCode) != row.Result.HTTPStatus || len(out.Payload) != 0 || out.FunctionError != nil || out.ExecutedVersion != nil {
		t.Fatalf("native async acceptance mismatch: %+v", out)
	}
	id, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	if !ok || id == "" {
		t.Fatal("async acceptance omitted correlation ID")
	}
	return id
}

func lambdaQualifiedBody(t *testing.T, body *string) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal([]byte(aws.ToString(body)), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestLambdaQualifiedRetriesNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaFixture[lambdaQualifiedFixture](t, "qualified_retries")
			r := newLambdaQualifiedReplay(t, backend)
			// Both cases use independent configured aliases. Establish their complete
			// native setup before driving nominal retry opportunities with service time.
			for _, row := range f.Observations {
				if strings.HasPrefix(row.Label, "cleanup_") {
					break
				}
				if row.Operation == "invoke" || row.Operation == "update-alias" || row.Label == "retarget_readback_retarget_to_2" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) { r.replay(t, row) }) {
					t.FailNow()
				}
			}
			advanceClock(t, r.clock, 2*time.Minute)
			for _, native := range f.CaseSummaries {
				t.Run(native.Case, func(t *testing.T) {
					row := lambdaQualifiedObservation(t, f, "invoke_"+native.Case)
					id := r.accept(t, row)
					start := r.clock.Now()
					var versions []string
					for attempt := range native.Versions {
						message := lambdaEventsReceive(t, r.c, r.queue(t, "marker"), 1)[0]
						marker := lambdaQualifiedBody(t, message.Body)
						if marker["request_id"] != id || marker["invoked_function_arn"] != native.RequestContext["functionArn"] {
							t.Fatalf("retry lost requested identity: %#v", marker)
						}
						version, _ := marker["function_version"].(string)
						versions = append(versions, version)
						if marker["deployment"] != version {
							t.Fatalf("executed artifact/context disagree: %#v", marker)
						}
						if attempt == len(native.Versions)-1 {
							break
						}
						delay := time.Minute
						if attempt == 1 {
							delay = 3 * time.Minute
						}
						lambdaEventsAwaitRetry(t, r.c, start.Add(delay))
						if native.Case == "retarget" && attempt == 0 {
							r.replay(t, lambdaQualifiedObservation(t, f, "retarget_retarget_to_2"))
							r.replay(t, lambdaQualifiedObservation(t, f, "retarget_readback_retarget_to_2"))
						}
						advanceClock(t, r.clock, start.Add(delay).Sub(r.clock.Now()))
					}
					if !reflect.DeepEqual(versions, native.Versions) {
						t.Fatalf("attempt deployments=%v; native=%v", versions, native.Versions)
					}
					message := lambdaEventsReceive(t, r.c, r.queue(t, "destination"), 1)[0]
					destination := lambdaQualifiedBody(t, message.Body)
					context := destination["requestContext"].(map[string]any)
					if context["requestId"] != id || context["functionArn"] != native.RequestContext["functionArn"] || context["condition"] != native.RequestContext["condition"] || context["approximateInvokeCount"] != native.RequestContext["approximateInvokeCount"] {
						t.Fatalf("terminal retry identity/budget=%#v; native=%#v", context, native.RequestContext)
					}
					r.compare(t, destination["responseContext"].(map[string]any), native.ResponseContext, "")
					advanceClock(t, r.clock, 3*time.Minute)
					lambdaEventsQuiet(t, r.c, r.queue(t, "marker"), r.queue(t, "destination"))
				})
			}
		})
	}
}

func TestLambdaQualifiedRetrySuccessNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaFixture[struct {
				lambdaQualifiedFixture
				CaseSummaries map[string]struct {
					RuntimeMarkers       []map[string]any `json:"runtime_markers"`
					TerminalDestinations []map[string]any `json:"terminal_destinations"`
				} `json:"case_summaries"`
			}](t, "qualified_deletion_retry")
			r := newLambdaQualifiedReplay(t, backend)
			objects := s3NativeClient(cloudClients{r.c.server}, "test", "test")
			for _, row := range f.Observations {
				if row.Operation == "invoke" {
					break
				}
				if row.Operation == "get-account-settings" {
					continue // native account capacity diagnostic, not owned resource setup
				}
				if row.Service == "s3" && row.Operation == "create-bucket" {
					if _, err := objects.CreateBucket(t.Context(), lambdaAdmissionInput[s3.CreateBucketInput](t, lambdaQualifiedJSON(t, row.Input))); err != nil {
						t.Fatal(err)
					}
				} else {
					r.replay(t, row)
				}
			}
			advanceClock(t, r.clock, 2*time.Minute)
			// One replay per distinct transition; duplicate native trials remain
			// corroborating evidence rather than repeated local test cases.
			for _, name := range []string{"stable1", "retarget1"} {
				t.Run(name, func(t *testing.T) {
					native := f.CaseSummaries[name]
					id := r.accept(t, lambdaQualifiedObservation(t, f.lambdaQualifiedFixture, "invoke-"+name))
					retryAt := r.clock.Now().Add(time.Minute)
					for attempt, expected := range native.RuntimeMarkers {
						message := lambdaEventsReceive(t, r.c, r.queue(t, "marker"), 1)[0]
						marker := lambdaQualifiedBody(t, message.Body)
						if marker["request_id"] != id {
							t.Fatalf("retry changed invocation identity: %#v", marker)
						}
						r.compare(t, marker, expected, "")
						if attempt == len(native.RuntimeMarkers)-1 {
							break
						}
						lambdaEventsAwaitRetry(t, r.c, retryAt)
						if name == "retarget1" {
							r.replay(t, lambdaQualifiedObservation(t, f.lambdaQualifiedFixture, "retarget-"+name))
						} else {
							row := lambdaQualifiedObservation(t, f.lambdaQualifiedFixture, "put-control-success-"+name)
							body, err := base64.StdEncoding.DecodeString(row.Input["Body"].(string))
							if err != nil {
								t.Fatal(err)
							}
							if _, err := objects.PutObject(t.Context(), &s3.PutObjectInput{
								Bucket: aws.String(row.Input["Bucket"].(string)), Key: aws.String(row.Input["Key"].(string)), Body: bytes.NewReader(body),
							}); err != nil {
								t.Fatal(err)
							}
						}
						advanceClock(t, r.clock, retryAt.Sub(r.clock.Now()))
					}
					for _, expected := range native.TerminalDestinations {
						message := lambdaEventsReceive(t, r.c, r.queue(t, "destination"), 1)[0]
						destination := lambdaQualifiedBody(t, message.Body)
						request := destination["requestContext"].(map[string]any)
						want := expected["requestContext"].(map[string]any)
						if request["requestId"] != id || request["approximateInvokeCount"] != want["approximateInvokeCount"] {
							t.Fatalf("successful retry destination=%#v; native=%#v", request, want)
						}
						r.compare(t, destination, expected, "")
					}
					advanceClock(t, r.clock, 3*time.Minute)
					lambdaEventsQuiet(t, r.c, r.queue(t, "marker"), r.queue(t, "destination"))
				})
			}
		})
	}
}

func TestLambdaQualifiedConfigNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaFixture[lambdaQualifiedFixture](t, "qualified_config")
			r := newLambdaQualifiedReplay(t, backend)
			cases := map[string][]string{}
			for _, native := range f.CaseMatrix {
				cases[native.InvokeLabel] = native.DestinationQueues
			}
			skipUntil := 0
			for i, row := range f.Observations {
				if i < skipUntil {
					continue
				}
				if strings.HasPrefix(row.Label, "cleanup_") {
					break
				}
				if row.Operation == "list-function-event-invoke-configs" && row.Result.Code == "Success" {
					if !t.Run(row.Label, func(t *testing.T) {
						skipUntil = i + r.inventoryPages(t, f.Observations[i:], "FunctionEventInvokeConfigs", "FunctionArn")
					}) {
						t.FailNow()
					}
					continue
				}
				if row.Operation != "invoke" {
					if !t.Run(row.Label, func(t *testing.T) { r.replay(t, row) }) {
						t.FailNow()
					}
					continue
				}
				// Native early hot/deletion samples crossed different per-scope
				// propagation boundaries. They are not a portable exact-delay SLA.
				// Check the pre-boundary old settings below, then replay the paired
				// settled cases after the existing two-minute representative boundary.
				if row.Label == "invoke_deleted_v" || row.Label == "invoke_deleted_a" || row.Label == "invoke_deleted_latest_alias" {
					continue
				}
				if row.Label == "invoke_fresh_u" || row.Label == "invoke_settled_hot_u" || row.Label == "invoke_redeployed_u" || row.Label == "invoke_settled_deleted_v" {
					advanceClock(t, r.clock, 2*time.Minute)
				}
				if !t.Run(row.Label, func(t *testing.T) {
					queues, found := cases[row.Label]
					if !found {
						t.Fatalf("native case matrix omitted %s", row.Label)
					}
					evidenceLabel := row.Label
					if strings.HasPrefix(row.Label, "invoke_hot_") {
						evidenceLabel = strings.Replace(row.Label, "invoke_hot_", "invoke_fresh_", 1)
						queues = cases[evidenceLabel]
					}
					id := r.accept(t, row)
					message := lambdaEventsReceive(t, r.c, r.queue(t, "marker"), 1)[0]
					marker := lambdaQualifiedBody(t, message.Body)
					if marker["request_id"] != id {
						t.Fatalf("runtime lost acceptance ID: %#v", marker)
					}
					input := lambdaAdmissionInput[awslambda.InvokeInput](t, lambdaQualifiedJSON(t, r.input(t, row)))
					var event map[string]any
					if err := json.Unmarshal(input.Payload, &event); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(marker["event"], event) {
						t.Fatalf("runtime executed wrong accepted event: %#v", marker)
					}
					var nativeMarker map[string]any
					for _, candidate := range f.RuntimeMarkers {
						if reflect.DeepEqual(candidate.Body["event"], marker["event"]) {
							nativeMarker = candidate.Body
							break
						}
					}
					if nativeMarker == nil {
						t.Fatalf("unexpected runtime event %#v", marker)
					}
					r.compare(t, marker, nativeMarker, "")
					for _, queue := range queues {
						message := lambdaEventsReceive(t, r.c, r.queue(t, queue), 1)[0]
						actual := lambdaQualifiedBody(t, message.Body)
						var native map[string]any
						evidenceRow := lambdaQualifiedObservation(t, f, evidenceLabel)
						evidenceInput := lambdaAdmissionInput[awslambda.InvokeInput](t, lambdaQualifiedJSON(t, r.input(t, evidenceRow)))
						var evidenceEvent map[string]any
						if err := json.Unmarshal(evidenceInput.Payload, &evidenceEvent); err != nil {
							t.Fatal(err)
						}
						for _, candidate := range f.DestinationRecords {
							if candidate.Queue == queue && reflect.DeepEqual(candidate.Body["requestPayload"], evidenceEvent) {
								native = *lambdaAdmissionInput[map[string]any](t, lambdaQualifiedJSON(t, candidate.Body))
								break
							}
						}
						if native == nil {
							t.Fatalf("missing native destination for %s", evidenceLabel)
						}
						native["requestPayload"] = event
						if response, ok := native["responsePayload"].(map[string]any); ok {
							response["event"] = event
						}
						if actual["requestContext"].(map[string]any)["requestId"] != id {
							t.Fatalf("destination lost acceptance ID: %#v", actual)
						}
						r.compare(t, actual, native, "")
					}
					// All queues are now drained. This also proves no inheritance for
					// unconfigured versions/aliases and no duplicate cross-scope delivery.
					lambdaEventsQuiet(t, r.c, r.queue(t, "unqualified"), r.queue(t, "version"), r.queue(t, "alias"))
				}) {
					t.FailNow()
				}
			}
		})
	}
}
