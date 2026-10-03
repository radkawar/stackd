package stackd_test

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"stackd/internal/awstest"
)

type lambdaQualifiedAuditFixture struct {
	lambdaQualifiedFixture
	Context struct {
		Function string `json:"owned_function"`
		Bucket   string `json:"owned_bucket"`
	} `json:"context"`
	DataEvents    []map[string]any `json:"data_events"`
	QueueMessages []struct {
		Queue string
		Body  map[string]any
	} `json:"queue_messages"`
	MetricsObservation struct {
		DimensionSets []map[string]string `json:"dimension_sets"`
	} `json:"metrics_observation"`
}

func lambdaQualifiedAuditLoad(t *testing.T) lambdaQualifiedAuditFixture {
	t.Helper()
	f := lambdaFixture[lambdaQualifiedAuditFixture](t, "qualified_audit")
	for i := range f.Observations {
		f.Observations[i].Operation = strings.ReplaceAll(f.Observations[i].Operation, "_", "-")
	}
	return f
}

// Use the existing SDK bindings and fixture normalization, without the serial
// HTTP-status recorder: a held Invoke and mutations must really overlap.
func lambdaQualifiedAuditCommand(t *testing.T, r *lambdaQualifiedReplay, row lambdaQualifiedRow) {
	t.Helper()
	if r.setup(t, row) {
		return
	}
	if row.Service != "lambda" {
		return
	}
	if row.Operation == "get-function-configuration" {
		return // official waiter below replaces native readiness sampling
	}
	operation := lambdaQualifiedOperations(r.c.lambda)[row.Operation]
	if operation == nil {
		t.Fatalf("unbound qualified command %s", row.Operation)
	}
	out, err := operation(t.Context(), r.input(t, row))
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	r.compare(t, out, row.Result.Output, "")
	if row.Operation == "create-function" || row.Operation == "update-function-code" {
		r.ready(t, row.Input["FunctionName"].(string))
	}
}

func lambdaQualifiedAuditClient(r *lambdaQualifiedReplay) {
	options := r.c.lambda.Options()
	options.HTTPClient = r.c.server.Client()
	r.c.lambda = awslambda.New(options)
}

func lambdaQualifiedAuditInput(t *testing.T, r *lambdaQualifiedReplay, row lambdaQualifiedRow) *awslambda.InvokeInput {
	t.Helper()
	return lambdaAdmissionInput[awslambda.InvokeInput](t, lambdaQualifiedJSON(t, r.input(t, row)))
}

func lambdaQualifiedAuditHold(t *testing.T, r *lambdaQualifiedReplay, row lambdaQualifiedRow) <-chan lambdaConcurrencyResult {
	t.Helper()
	input := lambdaQualifiedAuditInput(t, r, row)
	done := make(chan lambdaConcurrencyResult, 1)
	go func() {
		out, err := r.c.lambda.Invoke(t.Context(), input)
		done <- lambdaConcurrencyResult{out, err}
	}()
	return done
}

func lambdaQualifiedAuditPending(t *testing.T, done <-chan lambdaConcurrencyResult) {
	t.Helper()
	select {
	case result := <-done:
		t.Fatalf("native occupancy boundary lost: blocker already completed: %+v, %v", result.out, result.err)
	default:
	}
}

func lambdaQualifiedAuditFinish(t *testing.T, r *lambdaQualifiedReplay, done <-chan lambdaConcurrencyResult, row lambdaQualifiedRow, marker map[string]any) {
	t.Helper()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if int(result.out.StatusCode) != row.Result.HTTPStatus || result.out.FunctionError != nil || aws.ToString(result.out.ExecutedVersion) != row.Result.Output["ExecutedVersion"] {
			t.Fatalf("blocker runtime outcome differs: %+v", result.out)
		}
		id := nativeAuditRequestID(t, result.out, nil)
		if marker["request_id"] != id {
			t.Fatalf("occupied slot belonged to a different request: %#v, SDK %s", marker, id)
		}
		r.compare(t, lambdaQualifiedBody(t, aws.String(string(result.out.Payload))), row.Result.Output["Payload"].(map[string]any), "")
	case <-time.After(time.Minute):
		t.Fatal("native blocker did not complete")
	}
}

func lambdaQualifiedAuditDestination(t *testing.T, r *lambdaQualifiedReplay, got, want map[string]any, id string) {
	t.Helper()
	if got["requestContext"].(map[string]any)["requestId"] != id {
		t.Fatalf("destination dropped accepted request ownership: %#v", got)
	}
	r.compare(t, got, want, "")
	for _, field := range []string{"responsePayload", "responseContext"} {
		_, present := got[field]
		_, nativePresent := want[field]
		if present != nativePresent {
			t.Fatalf("destination %s presence=%v, native=%v", field, present, nativePresent)
		}
	}
	if !reflect.DeepEqual(got["responseContext"], want["responseContext"]) {
		t.Fatalf("destination response (including omissions)=%#v; native=%#v", got["responseContext"], want["responseContext"])
	}
	if response, ok := got["responsePayload"].(map[string]any); ok && response["request_id"] != id {
		t.Fatalf("destination contains another runtime request: %#v", response)
	}
}

func (f lambdaQualifiedAuditFixture) message(t *testing.T, queue, label string) map[string]any {
	t.Helper()
	for _, message := range f.QueueMessages {
		payload, _ := message.Body["event"].(map[string]any)
		if queue == "destinations" {
			payload, _ = message.Body["requestPayload"].(map[string]any)
		}
		if message.Queue == queue && payload["tag"] == label {
			return message.Body
		}
	}
	t.Fatalf("missing native %s message for %s", queue, label)
	return nil
}

// Compare only captured projection, preserving presence. Transport identities and
// wall-clock timestamps are intentionally not an oracle for this local replay.
func lambdaQualifiedAuditProjection(t *testing.T, got, want map[string]any) {
	t.Helper()
	for _, key := range []string{"eventName", "eventSource", "eventType", "readOnly", "eventCategory", "managementEvent", "requestParameters", "responseElements", "resources", "additionalEventData", "errorCode", "errorMessage"} {
		actual, present := got[key]
		expected, nativePresent := want[key]
		if present != nativePresent || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s %s=%#v (present %v), native=%#v (present %v)", got["requestID"], key, actual, present, expected, nativePresent)
		}
	}
	if want["userIdentity"].(map[string]any)["type"] == "AWSService" {
		for _, key := range []string{"userIdentity", "sourceIPAddress", "userAgent"} {
			if !reflect.DeepEqual(got[key], want[key]) {
				t.Fatalf("service dispatch %s=%#v, native=%#v", key, got[key], want[key])
			}
		}
	}
}

func lambdaQualifiedAuditTrail(t *testing.T, r *lambdaQualifiedReplay, f lambdaQualifiedAuditFixture) *cloudtrail.Client {
	t.Helper()
	objects := s3NativeClient(cloudClients{r.c.server}, "test", "test")
	trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: r.c.server.Client(), RetryMaxAttempts: 1})
	for _, command := range []struct {
		label, operation string
		client           any
	}{
		{"create-owned-bucket", "CreateBucket", objects}, {"owned-bucket-policy", "PutBucketPolicy", objects},
		{"create-owned-trail", "CreateTrail", trails}, {"restrict-owned-data-selectors", "PutEventSelectors", trails},
		{"start-owned-trail", "StartLogging", trails},
	} {
		native := lambdaQualifiedObservation(t, f.lambdaQualifiedFixture, command.label)
		if _, err := awstest.CallSDK(t.Context(), command.client, command.operation, lambdaQualifiedJSON(t, native.Input)); err != nil {
			t.Fatal(err)
		}
	}
	return trails
}

func TestLambdaQualifiedAuditNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaQualifiedAuditLoad(t)
			r := newLambdaQualifiedReplay(t, backend)
			lambdaQualifiedAuditClient(r)
			row := func(label string) lambdaQualifiedRow {
				return lambdaQualifiedObservation(t, f.lambdaQualifiedFixture, label)
			}
			c := cloudClients{r.c.server}
			objects := s3NativeClient(c, "test", "test")
			trails := lambdaQualifiedAuditTrail(t, r, f)
			for _, native := range f.Observations {
				if native.Operation == "invoke" {
					break
				}
				lambdaQualifiedAuditCommand(t, r, native)
			}
			advanceClock(t, r.clock, 2*time.Minute)
			selection := lambdaAdmissionInput[cloudtrail.PutEventSelectorsInput](t, lambdaQualifiedJSON(t, row("restrict-owned-data-selectors").Input))
			allSelectors := selection.AdvancedEventSelectors
			// Derived selector distinction, not a claim of a native negative poll:
			// native documents have BASE resources even for qualified requests.
			selection.AdvancedEventSelectors = allSelectors[1:]
			if _, err := trails.PutEventSelectors(t.Context(), selection); err != nil {
				t.Fatal(err)
			}
			excluded, err := r.c.lambda.Invoke(t.Context(), lambdaQualifiedAuditInput(t, r, row("late-audit-DryRun")))
			if err != nil {
				t.Fatal(err)
			}
			excludedID := nativeAuditRequestID(t, excluded, nil)
			selection.AdvancedEventSelectors = allSelectors[:1]
			if _, err := trails.PutEventSelectors(t.Context(), selection); err != nil {
				t.Fatal(err)
			}
			expected := map[string][]map[string]any{}
			for _, scope := range []string{"unqualified", "$LATEST", "1", "audit"} {
				for _, kind := range []string{"RequestResponse", "Event", "DryRun"} {
					label := "late-" + scope + "-" + kind
					native := row(label)
					out, err := r.c.lambda.Invoke(t.Context(), lambdaQualifiedAuditInput(t, r, native))
					if err != nil {
						t.Fatal(err)
					}
					if int(out.StatusCode) != native.Result.HTTPStatus || out.FunctionError != nil {
						t.Fatalf("%s: %+v", label, out)
					}
					id := nativeAuditRequestID(t, out, nil)
					nativeID := native.Result.Output["ResponseMetadata"].(map[string]any)["RequestId"]
					for _, event := range f.DataEvents {
						if event["requestID"] == nativeID {
							expected[id] = append(expected[id], event)
						}
					}
					if len(expected[id]) == 0 {
						t.Fatalf("missing positive native audit for %s", label)
					}
					if kind != "RequestResponse" && (len(out.Payload) != 0 || out.ExecutedVersion != nil) {
						t.Fatalf("%s unexpectedly executed synchronously: %+v", label, out)
					}
					if kind != "DryRun" {
						marker := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "markers"), 1)[0].Body)
						if marker["request_id"] != id {
							t.Fatalf("runtime lost request: %#v", marker)
						}
						r.compare(t, marker, f.message(t, "markers", label), "")
						if kind == "RequestResponse" && aws.ToString(out.ExecutedVersion) != marker["function_version"] {
							t.Fatal("SDK executed version differs from runtime")
						}
					}
					if kind == "Event" {
						got := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "destinations"), 1)[0].Body)
						lambdaQualifiedAuditDestination(t, r, got, f.message(t, "destinations", label), id)
					}
				}
			}
			lambdaEventsQuiet(t, r.c, r.queue(t, "markers"), r.queue(t, "destinations"))
			// ListMetrics proves complete dimension identities, not per-metric
			// sample counts or which metric names possess each identity.
			advanceClock(t, r.clock, time.Minute)
			trailNativeDrain(t, r.c.cloud)
			metrics := metricsClient(c, "test")
			pages := cloudwatch.NewListMetricsPaginator(metrics, &cloudwatch.ListMetricsInput{Namespace: aws.String("AWS/Lambda")})
			gotDimensions, wantDimensions := map[string]bool{}, map[string]bool{}
			for pages.HasMorePages() {
				page, err := pages.NextPage(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for _, metric := range page.Metrics {
					dimensions := map[string]string{}
					for _, dimension := range metric.Dimensions {
						dimensions[aws.ToString(dimension.Name)] = aws.ToString(dimension.Value)
					}
					if dimensions["FunctionName"] == f.Context.Function {
						gotDimensions[string(lambdaQualifiedJSON(t, dimensions))] = true
					}
				}
			}
			for _, dimensions := range f.MetricsObservation.DimensionSets {
				resource := dimensions["Resource"]
				if strings.Contains(resource, ":deleted") || strings.HasSuffix(resource, ":retained") {
					continue
				}
				wantDimensions[string(lambdaQualifiedJSON(t, dimensions))] = true
			}
			if !reflect.DeepEqual(gotDimensions, wantDimensions) {
				t.Fatalf("qualified metric dimensions=%v, native=%v", gotDimensions, wantDimensions)
			}
			advanceClock(t, r.clock, 6*time.Minute)
			trailNativeDrain(t, r.c.cloud)
			seen := map[string]int{}
			for _, got := range trailNativeRecords(t, trailNativeObjects(t, objects, f.Context.Bucket, "owned/AWSLogs/")) {
				id, _ := got["requestID"].(string)
				if id == excludedID {
					t.Fatal("qualified selector matched native base resource")
				}
				candidates := expected[id]
				if candidates == nil {
					t.Fatalf("unexpected selected audit: %#v", got)
				}
				matched := false
				for _, want := range candidates {
					if want["eventName"] == got["eventName"] {
						lambdaQualifiedAuditProjection(t, got, want)
						matched = true
						seen[id+"/"+got["eventName"].(string)]++
						break
					}
				}
				if !matched {
					t.Fatalf("unexpected dispatch audit: %#v", got)
				}
			}
			for id, events := range expected {
				for _, event := range events {
					if seen[id+"/"+event["eventName"].(string)] != 1 {
						t.Fatalf("missing or duplicated correlated audit %s/%s", id, event["eventName"])
					}
				}
			}
		})
	}
}

func TestLambdaQualifiedAcceptedOwnershipNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaQualifiedAuditLoad(t)
			r := newLambdaQualifiedReplay(t, backend)
			lambdaQualifiedAuditClient(r)
			row := func(label string) lambdaQualifiedRow {
				return lambdaQualifiedObservation(t, f.lambdaQualifiedFixture, label)
			}
			executionRole := row("create-owned-execution-role").Input["RoleName"]
			for _, native := range f.Observations {
				if native.Label == "warm-blocker" {
					break
				}
				if native.Operation == "invoke" || native.Operation == "get-account-settings" {
					continue
				}
				if native.Service == "sts" || native.Service == "iam" && native.Input["RoleName"] != executionRole {
					continue // this boundary does not use the separate denied caller
				}
				lambdaQualifiedAuditCommand(t, r, native)
			}
			lambdaQualifiedAuditTrail(t, r, f)
			advanceClock(t, r.clock, 2*time.Minute)
			blocker := row("real-blocker")
			done := lambdaQualifiedAuditHold(t, r, blocker)
			entered := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "markers"), 1)[0].Body)
			r.compare(t, entered, f.message(t, "markers", "real-blocker"), "")
			lambdaQualifiedAuditPending(t, done)
			_, err := r.c.lambda.Invoke(t.Context(), lambdaQualifiedAuditInput(t, r, row("verify-slot-occupied")))
			assertAPIError(t, err, row("verify-slot-occupied").Result.Code)
			deletedID := r.accept(t, row("queued-deleted-admission"))
			retainedID := r.accept(t, row("queued-retained-admission"))
			// Drive an actual throttled dispatch before changing the requested alias.
			// This nominal local deadline is synchronization, not an AWS retry SLA.
			lambdaEventsAwaitRetry(t, r.c, r.clock.Now().Add(time.Second))
			lambdaQualifiedAuditCommand(t, r, row("delete-alias-before-blocker-completes"))
			lambdaQualifiedAuditPending(t, done)
			lambdaQualifiedAuditFinish(t, r, done, blocker, entered)
			advanceClock(t, r.clock, time.Second)
			ids := map[string]string{"queued-deleted": deletedID, "queued-retained": retainedID}
			for _, message := range lambdaEventsReceive(t, r.c, r.queue(t, "destinations"), 2) {
				got := lambdaQualifiedBody(t, message.Body)
				label := got["requestPayload"].(map[string]any)["tag"].(string)
				id := ids[label]
				if id == "" {
					t.Fatalf("unexpected or duplicate destination: %#v", got)
				}
				lambdaQualifiedAuditDestination(t, r, got, f.message(t, "destinations", label), id)
				delete(ids, label)
			}
			if len(ids) != 0 {
				t.Fatalf("accepted ownership lost: %v", ids)
			}
			retained := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "markers"), 1)[0].Body)
			if retained["request_id"] != retainedID {
				t.Fatalf("deleted alias entered runtime, or retained request identity lost: %#v", retained)
			}
			r.compare(t, retained, f.message(t, "markers", "queued-retained"), "")
			lambdaEventsQuiet(t, r.c, r.queue(t, "markers"), r.queue(t, "destinations"))
			advanceClock(t, r.clock, 6*time.Minute)
			trailNativeDrain(t, r.c.cloud)
			// Correlate all positively captured phases without pinning AWS's
			// number or cadence of throttled redispatches.
			nativeID := row("queued-deleted-admission").Result.Output["ResponseMetadata"].(map[string]any)["RequestId"]
			nativePhases := map[string]map[string]any{}
			phase := func(event map[string]any) string {
				service := event["userIdentity"].(map[string]any)["type"] == "AWSService"
				if event["eventName"] == "InvokeExecution" {
					return "throttled"
				}
				if service {
					return "missing"
				}
				return "accepted"
			}
			for _, event := range f.DataEvents {
				if event["requestID"] == nativeID {
					nativePhases[phase(event)] = event
				}
			}
			seen := map[string]bool{}
			objects := s3NativeClient(cloudClients{r.c.server}, "test", "test")
			for _, event := range trailNativeRecords(t, trailNativeObjects(t, objects, f.Context.Bucket, "owned/AWSLogs/")) {
				if event["requestID"] != deletedID {
					continue
				}
				key := phase(event)
				want := nativePhases[key]
				if want == nil {
					t.Fatalf("uncaptured deleted dispatch phase: %#v", event)
				}
				lambdaQualifiedAuditProjection(t, event, want)
				seen[key] = true
			}
			for _, key := range []string{"accepted", "throttled", "missing"} {
				if !seen[key] {
					t.Fatalf("accepted request %s lost %s audit", deletedID, key)
				}
			}
			// retry2's bounded absence has no terminal oracle and is not replayed.
		})
	}
}

func TestLambdaQualifiedBusyMutationNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaFixture[lambdaQualifiedFixture](t, "qualified_invocation")
			r := newLambdaQualifiedReplay(t, backend)
			lambdaQualifiedAuditClient(r)
			row := func(label string) lambdaQualifiedRow { return lambdaQualifiedObservation(t, f, "busy__"+label) }
			for _, native := range f.Observations {
				if !strings.HasPrefix(native.Label, "busy__") {
					continue
				}
				if native.Operation == "invoke" {
					break
				}
				if native.Operation == "get-account-settings" || native.Result.Code != "Success" {
					continue
				}
				lambdaQualifiedAuditCommand(t, r, native)
			}
			advanceClock(t, r.clock, 2*time.Minute)
			nativeMessage := func(label string, destination bool) map[string]any {
				for _, message := range f.DestinationRecords {
					key := "event"
					if destination {
						key = "requestPayload"
					}
					payload, _ := message.Body[key].(map[string]any)
					if payload["case"] == label {
						return message.Body
					}
				}
				t.Fatalf("missing native busy message %s destination=%v", label, destination)
				return nil
			}
			blocker := row("synchronous_owned_blocker")
			done := lambdaQualifiedAuditHold(t, r, blocker)
			entered := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "alias"), 1)[0].Body)
			r.compare(t, entered, nativeMessage("busy_blocker", false), "")
			lambdaQualifiedAuditPending(t, done)
			accepted := row("event_admitted_while_v1_busy")
			caller := r.actors[accepted.Actor]
			if caller == nil {
				t.Fatalf("missing native caller %s", accepted.Actor)
			}
			out, err := caller.Invoke(t.Context(), lambdaQualifiedAuditInput(t, r, accepted))
			if err != nil {
				t.Fatal(err)
			}
			if int(out.StatusCode) != accepted.Result.HTTPStatus || len(out.Payload) != 0 || out.ExecutedVersion != nil || out.FunctionError != nil {
				t.Fatalf("qualified async acceptance=%+v", out)
			}
			id := nativeAuditRequestID(t, out, nil)
			lambdaEventsAwaitRetry(t, r.c, r.clock.Now().Add(time.Second))
			lambdaQualifiedAuditCommand(t, r, row("switch_alias_while_v1_busy"))
			lambdaQualifiedAuditCommand(t, r, row("revoke_caller_after_event_admission"))
			lambdaQualifiedAuditPending(t, done)
			lambdaQualifiedAuditFinish(t, r, done, blocker, entered)
			advanceClock(t, r.clock, time.Second)
			marker := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "alias"), 1)[0].Body)
			if marker["request_id"] != id {
				t.Fatalf("retarget dropped accepted request: %#v", marker)
			}
			r.compare(t, marker, nativeMessage("busy_alias_switch", false), "")
			destination := lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "alias"), 1)[0].Body)
			lambdaQualifiedAuditDestination(t, r, destination, nativeMessage("busy_alias_switch", true), id)
			id = r.accept(t, row("event_admitted_before_alias_version_deletion"))
			marker = lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "alias"), 1)[0].Body)
			if marker["request_id"] != id {
				t.Fatalf("deletion marker lost request: %#v", marker)
			}
			r.compare(t, marker, nativeMessage("delete_accepted", false), "")
			lambdaQualifiedAuditCommand(t, r, row("delete_alias_while_accepted_running"))
			lambdaQualifiedAuditCommand(t, r, row("delete_version_while_accepted_running"))
			// Reads establish actual deletion, while the positive marker establishes
			// runtime entry. Successful destination must still retain version two.
			lambdaQualifiedAuditCommand(t, r, row("alias_after_delete_accepted"))
			_, err = r.c.lambda.GetFunctionConfiguration(t.Context(), lambdaAdmissionInput[awslambda.GetFunctionConfigurationInput](t, lambdaQualifiedJSON(t, row("version_after_delete_accepted").Input)))
			assertAPIError(t, err, row("version_after_delete_accepted").Result.Code)
			destination = lambdaQualifiedBody(t, lambdaEventsReceive(t, r.c, r.queue(t, "alias"), 1)[0].Body)
			lambdaQualifiedAuditDestination(t, r, destination, nativeMessage("delete_accepted", true), id)
			lambdaEventsQuiet(t, r.c, r.queue(t, "alias"))
		})
	}
}
