package stackd_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

type lambdaTelemetryRecord struct {
	Kind, Boot, Label, Path, Transport, Method string
	Raw                                        string
	Compressed                                 string `json:"raw_gzip_base64"`
	Result                                     struct {
		Status  int
		Body    string
		Headers map[string]string
	}
}

type lambdaTelemetryFixture struct {
	Observations []lambdaExtensionLifecycleRow
	Deliveries   []struct {
		Body struct{ Records []lambdaTelemetryRecord }
	}
}

func (f lambdaTelemetryFixture) row(t *testing.T, label string) lambdaExtensionLifecycleRow {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native telemetry observation %s", label)
	return lambdaExtensionLifecycleRow{}
}

func (f lambdaTelemetryFixture) records() []lambdaTelemetryRecord {
	var records []lambdaTelemetryRecord
	for _, delivery := range f.Deliveries {
		records = append(records, delivery.Body.Records...)
	}
	return records
}

func lambdaTelemetryInvoke(t *testing.T, r *lambdaExtensionLifecycleReplay, f lambdaTelemetryFixture, label string) map[string]any {
	t.Helper()
	_, payload := r.invoke(t, label)
	if payload["marker"] != f.row(t, label).FunctionPayload["marker"] {
		t.Fatalf("%s marker differs from native: %+v", label, payload)
	}
	return payload
}

// The collector is inside the extension container; all evidence arrives over
// its real execution-role-authenticated SQS calls, never a host-side API probe.
func lambdaTelemetryAwait(t *testing.T, r *lambdaExtensionLifecycleReplay, records *[]lambdaTelemetryRecord, ready func([]lambdaTelemetryRecord) bool) {
	t.Helper()
	*records = nil
	cursor := 0
	r.wait(t, "native telemetry delivery boundary", func() bool {
		for ; cursor < len(r.bodies); cursor++ {
			var body struct{ Records []lambdaTelemetryRecord }
			if err := json.Unmarshal(lambdaQualifiedJSON(t, r.bodies[cursor]), &body); err != nil {
				t.Fatal(err)
			}
			*records = append(*records, body.Records...)
		}
		return ready(*records)
	})
}

func lambdaTelemetryEvents(t *testing.T, record lambdaTelemetryRecord) []map[string]any {
	t.Helper()
	if record.Kind != "delivery" {
		return nil
	}
	raw := []byte(record.Raw)
	if record.Compressed != "" {
		compressed, err := base64.StdEncoding.DecodeString(record.Compressed)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		raw, err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if record.Transport == "TCP" {
		if !bytes.HasSuffix(raw, []byte("\n")) {
			t.Fatalf("TCP delivery is not NDJSON: %q", raw)
		}
		var events []map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		for decoder.More() {
			var event map[string]any
			if err := decoder.Decode(&event); err != nil {
				t.Fatal(err)
			}
			events = append(events, event)
		}
		return events
	}
	return *lambdaAdmissionInput[[]map[string]any](t, raw)
}

func lambdaTelemetryAPI(records []lambdaTelemetryRecord, boot, label string) *lambdaTelemetryRecord {
	for i := range records {
		if records[i].Kind == "api" && records[i].Boot == boot && records[i].Label == label {
			return &records[i]
		}
	}
	return nil
}

func lambdaTelemetryAPIOutcome(t *testing.T, record *lambdaTelemetryRecord) any {
	t.Helper()
	var body any
	if err := json.Unmarshal([]byte(record.Result.Body), &body); err != nil {
		t.Fatal(err)
	}
	if object, ok := body.(map[string]any); ok {
		return object["errorType"]
	}
	return body
}

func lambdaTelemetryCompareAPIs(t *testing.T, r *lambdaExtensionLifecycleReplay, actual *[]lambdaTelemetryRecord, native []lambdaTelemetryRecord, boot, nativeBoot string, labels ...string) {
	t.Helper()
	lambdaTelemetryAwait(t, r, actual, func(records []lambdaTelemetryRecord) bool {
		for _, label := range labels {
			if lambdaTelemetryAPI(records, boot, label) == nil {
				return false
			}
		}
		return true
	})
	for _, label := range labels {
		got, want := lambdaTelemetryAPI(*actual, boot, label), lambdaTelemetryAPI(native, nativeBoot, label)
		if want == nil {
			t.Fatalf("native boot %s lacks API %s", nativeBoot, label)
		}
		if got.Result.Status != want.Result.Status || !reflect.DeepEqual(lambdaTelemetryAPIOutcome(t, got), lambdaTelemetryAPIOutcome(t, want)) {
			t.Fatalf("%s: status/body %d %s; native %d %s", label, got.Result.Status, got.Result.Body, want.Result.Status, want.Result.Body)
		}
	}
}

func lambdaTelemetryBoot(payload map[string]any) string {
	return payload["extension"].(map[string]any)["boot"].(string)
}

// Compare a witnessed marker at each selected destination, not a global event
// count or ordering: native collectors themselves have bounded observation gaps.
func lambdaTelemetryMarkers(t *testing.T, r *lambdaExtensionLifecycleReplay, actual *[]lambdaTelemetryRecord, native []lambdaTelemetryRecord, boot, nativeBoot, marker string, paths ...string) {
	t.Helper()
	type delivery struct {
		method, transport string
		event             any
	}
	wanted := map[string]delivery{}
	for _, record := range native {
		if record.Boot != nativeBoot {
			continue
		}
		for _, path := range paths {
			if record.Path != path {
				continue
			}
			for _, event := range lambdaTelemetryEvents(t, record) {
				if text, ok := event["record"].(string); ok && strings.Contains(text, marker) {
					wanted[path] = delivery{record.Method, record.Transport, text}
				}
			}
		}
	}
	if len(wanted) != len(paths) {
		t.Fatalf("native marker %s missing selected destinations: %+v", marker, wanted)
	}
	lambdaTelemetryAwait(t, r, actual, func(records []lambdaTelemetryRecord) bool {
		found := map[string]bool{}
		for _, record := range records {
			want, ok := wanted[record.Path]
			if !ok || record.Boot != boot || record.Method != want.method || record.Transport != want.transport {
				continue
			}
			for _, event := range lambdaTelemetryEvents(t, record) {
				if event["record"] == want.event {
					found[record.Path] = true
				}
			}
		}
		return len(found) == len(wanted)
	})
}

func TestLambdaExtensionSubscriptionsNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for native extension subscription replay")
	}
	f := lambdaFixture[lambdaTelemetryFixture](t, "extensions_subscriptions")
	validation := lambdaFixture[lambdaTelemetryFixture](t, "extensions_subscription_validation")
	r := newLambdaExtensionLifecycleReplay(t, "memory", "extensions_subscriptions")
	var actual []lambdaTelemetryRecord
	before := lambdaTelemetryInvoke(t, r, f, "positive-before")
	boot, nativeBoot := lambdaTelemetryBoot(before), lambdaTelemetryBoot(f.row(t, "positive-before").FunctionPayload)
	lambdaTelemetryCompareAPIs(t, r, &actual, f.records(), boot, nativeBoot,
		"telemetry-initial", "init-telemetry-exact-duplicate", "init-telemetry-changed-destination-types",
		"init-logs-exact-duplicate", "init-logs-changed-destination-types", "init-telemetry-identity-to-logs", "init-logs-identity-to-telemetry")
	// The independent admission capture establishes error classes before any
	// successful subscription; do not pin diagnostic wording or replay its grid.
	lambdaTelemetryCompareAPIs(t, r, &actual, validation.records(), boot, lambdaTelemetryBoot(validation.row(t, "positive-before").FunctionPayload),
		"telemetry-id-missing", "logs-id-malformed", "validate-t-timeout-24", "validate-l-types-invalid", "register-internal-shutdown", "limit-2")
	lambdaTelemetryMarkers(t, r, &actual, f.records(), boot, nativeBoot, "BEFORE", "/t-original", "/t-init-mutated", "/l-original", "/l-init-mutated", "/put-method", "")
	lambdaTelemetryInvoke(t, r, f, "mutation")
	lambdaTelemetryCompareAPIs(t, r, &actual, f.records(), boot, nativeBoot, "telemetry-exact-duplicate", "telemetry-changed-destination-types", "logs-exact-duplicate", "logs-changed-destination-types")
	warm := lambdaTelemetryInvoke(t, r, f, "warm-control")
	if lambdaTelemetryBoot(warm) != boot {
		t.Fatal("warm mutation replaced the extension environment")
	}
	lambdaTelemetryMarkers(t, r, &actual, f.records(), boot, nativeBoot, "WARM_AFTER_MUTATION", "/t-original", "/t-init-mutated", "/put-method", "")
	lambdaTelemetryInvoke(t, r, f, "runtime-timeout")
	reset := lambdaTelemetryInvoke(t, r, f, "reset-changed-subscription")
	resetBoot, nativeResetBoot := lambdaTelemetryBoot(reset), lambdaTelemetryBoot(f.row(t, "reset-changed-subscription").FunctionPayload)
	if resetBoot == boot {
		t.Fatal("timeout retained the old extension process")
	}
	lambdaTelemetryCompareAPIs(t, r, &actual, f.records(), resetBoot, nativeResetBoot, "stale-id-main", "stale-id-logs", "stale-id-next", "telemetry-initial-reset", "logs-initial", "init-telemetry-changed-destination-types", "init-logs-changed-destination-types")
	lambdaTelemetryMarkers(t, r, &actual, f.records(), resetBoot, nativeResetBoot, "AFTER_RESET", "/t-original", "/t-reset", "/l-original", "/put-method", "/put-reset", "")
}

func TestLambdaExtensionStreamsNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for native stdout/stderr framing replay")
	}
	f := lambdaFixture[lambdaTelemetryFixture](t, "extensions_streams")
	r := newLambdaExtensionLifecycleReplay(t, "memory", "extensions_streams")
	var nativeLines []string
	for _, delivery := range f.records() {
		for _, event := range lambdaTelemetryEvents(t, delivery) {
			if event["type"] == "function" {
				nativeLines = append(nativeLines, strings.TrimSuffix(event["record"].(string), "\n"))
			}
		}
	}
	var boot string
	for _, row := range f.Observations {
		if row.Operation != "invoke" {
			continue
		}
		out, payload := r.invoke(t, row.Label)
		boot = lambdaTelemetryBoot(payload)
		nativeTail, err := base64.StdEncoding.DecodeString(stringValue(row.Result.Output["LogResult"]))
		if err != nil {
			t.Fatal(err)
		}
		localTail, err := base64.StdEncoding.DecodeString(aws.ToString(out.LogResult))
		if err != nil {
			t.Fatal(err)
		}
		wantedTailLines, actualTailLines := strings.Split(string(nativeTail), "\n"), strings.Split(string(localTail), "\n")
		for _, line := range nativeLines {
			if slices.Contains(wantedTailLines, line) && !slices.Contains(actualTailLines, line) {
				t.Fatalf("%s Tail lost native function line %q: %s", row.Label, line, localTail)
			}
		}
	}
	// Partial stdout must not absorb an intervening stderr line, or vice versa.
	// Compare native records without imposing cross-stream delivery ordering.
	var actual []lambdaTelemetryRecord
	for _, delivery := range f.records() {
		for _, event := range lambdaTelemetryEvents(t, delivery) {
			if event["type"] == "function" {
				lambdaTelemetryMarkers(t, r, &actual, f.records(), boot, delivery.Boot, event["record"].(string), delivery.Path)
			}
		}
	}
}

func TestLambdaExtensionBufferingNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for native extension buffering replay")
	}
	f := lambdaFixture[lambdaTelemetryFixture](t, "extensions_buffering")
	r := newLambdaExtensionLifecycleReplay(t, "memory", "extensions_buffering")
	lambdaTelemetryInvoke(t, r, f, "batch-threshold")
	lambdaTelemetryInvoke(t, r, f, "warm-flush")
	// Actual captured payloads distinguish 10000-item omitted/explicit limits
	// from 1000-item limits. No total delivery count or no-drop claim is made.
	wanted := map[string]int{}
	for _, record := range f.records() {
		if record.Kind == "delivery" {
			if count := len(lambdaTelemetryEvents(t, record)); count > wanted[record.Path] {
				wanted[record.Path] = count
			}
		}
	}
	var actual []lambdaTelemetryRecord
	lambdaTelemetryAwait(t, r, &actual, func(records []lambdaTelemetryRecord) bool {
		found := map[string]bool{}
		for _, record := range records {
			if record.Kind != "delivery" {
				continue
			}
			events := lambdaTelemetryEvents(t, record)
			limit, ok := wanted[record.Path]
			if !ok {
				continue
			}
			if len(events) > limit {
				t.Fatalf("%s delivered %d records, native threshold %d", record.Path, len(events), limit)
			}
			if len(events) == limit && events[len(events)-1]["record"] == "m\n" {
				found[record.Path] = true
			}
		}
		return len(found) == len(wanted)
	})
}

func lambdaTelemetryRequestID(payload map[string]any) string {
	for _, key := range []string{"request_id", "requestId"} {
		if id, ok := payload[key].(string); ok {
			return id
		}
	}
	if message, ok := payload["errorMessage"].(string); ok {
		fields := strings.Fields(message)
		if len(fields) > 1 && fields[0] == "RequestId:" {
			return fields[1]
		}
	}
	return ""
}

func lambdaTelemetryPlatform(t *testing.T, records []lambdaTelemetryRecord, request string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, delivery := range records {
		for _, event := range lambdaTelemetryEvents(t, delivery) {
			record, ok := event["record"].(map[string]any)
			if !ok || record["requestId"] != request {
				continue
			}
			kind, _ := event["type"].(string)
			if kind == "platform.report" || kind == "platform.runtimeDone" {
				out[delivery.Path+"/"+kind] = record
			}
		}
	}
	return out
}

func lambdaTelemetrySubscriptionStates(t *testing.T, deliveries []lambdaTelemetryRecord) map[[3]string]bool {
	t.Helper()
	states := map[[3]string]bool{}
	for _, delivery := range deliveries {
		for _, event := range lambdaTelemetryEvents(t, delivery) {
			kind := stringValue(event["type"])
			if kind != "platform.logsSubscription" && kind != "platform.telemetrySubscription" {
				continue
			}
			record := event["record"].(map[string]any)
			states[[3]string{kind, stringValue(record["name"]), stringValue(record["state"])}] = true
		}
	}
	return states
}

func lambdaTelemetryMetricSnapshot(t *testing.T, r *lambdaExtensionLifecycleReplay, template cloudwatch.GetMetricDataInput, start, end time.Time) *cloudwatch.GetMetricDataOutput {
	t.Helper()
	template.StartTime, template.EndTime = &start, &end
	if _, err := r.r.c.cloud.RunDueJobs(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
	out, err := metricsClient(cloudClients{r.r.c.server}, "test").GetMetricData(t.Context(), &template)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func lambdaTelemetryMetricTotals(out *cloudwatch.GetMetricDataOutput) map[string]float64 {
	totals := map[string]float64{}
	for _, result := range out.MetricDataResults {
		for _, value := range result.Values {
			totals[aws.ToString(result.Id)] += value
		}
	}
	return totals
}

func TestLambdaExtensionPlatformNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for native platform delivery and metrics replay")
	}
	f := lambdaFixture[lambdaTelemetryFixture](t, "extensions_platform")
	metrics := lambdaFixture[struct {
		Input  cloudwatch.GetMetricDataInput
		Output cloudwatch.GetMetricDataOutput
	}](t, "extensions_platform_metrics")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newLambdaExtensionLifecycleReplay(t, backend, "extensions_platform")
			start := r.r.clock.Now().Add(-time.Minute)
			var actual []lambdaTelemetryRecord
			requests := map[string]string{}
			for _, label := range []string{"normal", "function-error", "runtime-timeout", "reset-recovery"} {
				payload := lambdaTelemetryInvoke(t, r, f, label)
				requests[label] = lambdaTelemetryRequestID(payload)
				if requests[label] == "" {
					t.Fatalf("%s omitted request correlation: %+v", label, payload)
				}
				if label == "normal" {
					lambdaTelemetryCompareAPIs(t, r, &actual, f.records(), lambdaTelemetryBoot(payload), lambdaTelemetryBoot(f.row(t, label).FunctionPayload), "subscribe-logs-2020", "subscribe-logs-2021", "subscribe-telemetry-202207", "subscribe-telemetry-202212", "subscribe-telemetry-2025", "subscribe-individual")
				}
			}
			wantedStates := lambdaTelemetrySubscriptionStates(t, f.records())
			lambdaTelemetryAwait(t, r, &actual, func(records []lambdaTelemetryRecord) bool {
				got := lambdaTelemetrySubscriptionStates(t, records)
				for state := range wantedStates {
					if !got[state] {
						return false
					}
				}
				return true
			})
			// Timeout reports may be delivered after the next Init. Correlate by
			// request ID rather than requiring a particular batch or process boot.
			for _, label := range []string{"normal", "function-error", "runtime-timeout"} {
				wanted := lambdaTelemetryPlatform(t, f.records(), lambdaTelemetryRequestID(f.row(t, label).FunctionPayload))
				lambdaTelemetryAwait(t, r, &actual, func(records []lambdaTelemetryRecord) bool {
					got := lambdaTelemetryPlatform(t, records, requests[label])
					for key := range wanted {
						if got[key] == nil {
							return false
						}
					}
					return true
				})
				got := lambdaTelemetryPlatform(t, actual, requests[label])
				for key, want := range wanted {
					record := got[key]
					if record["status"] != want["status"] {
						t.Fatalf("%s %s status %v, native %v", label, key, record["status"], want["status"])
					}
					// Historical Logs projections omit telemetry metrics/spans on
					// runtimeDone and omit lifecycle status on report.
					for _, field := range []string{"metrics", "spans"} {
						_, have := record[field]
						_, expected := want[field]
						if have != expected {
							t.Fatalf("%s %s %s presence %v, native %v", label, key, field, have, expected)
						}
					}
				}
				if _, leaked := got["/logs-2020/platform.runtimeDone"]; leaked {
					t.Fatal("2020 Logs schema leaked runtimeDone")
				}
			}
			// Tail waits for committed phase metrics. Publish their completed
			// minute before placing the no-extension control in the next one.
			advanceClock(t, r.r.clock, time.Minute)
			before := lambdaTelemetryMetricTotals(lambdaTelemetryMetricSnapshot(t, r, metrics.Input, start, r.r.clock.Now().Add(time.Minute)))
			if before["m21"] != 4 || before["m31"] != 4 {
				t.Fatalf("extension phase metric samples: %+v", before)
			}
			r.apply(t, "no-extension-configuration")
			name := r.row(t, "create-function").Input["FunctionName"].(string)
			noExtensionStart := r.r.clock.Now()
			for _, label := range []string{"no-extension", "no-extension-warm"} {
				payload := lambdaTelemetryInvoke(t, r, f, label)
				if payload["extension"] != nil {
					t.Fatalf("removed extension still visible to handler: %+v", payload)
				}
			}
			wantedTotals := lambdaTelemetryMetricTotals(&metrics.Output)
			advanceClock(t, r.r.clock, time.Minute)
			snapshot := lambdaTelemetryMetricSnapshot(t, r, metrics.Input, start, r.r.clock.Now().Add(time.Minute))
			gotTotals := lambdaTelemetryMetricTotals(snapshot)
			// Counts are native contracts; real runtime durations are not an
			// equality comparison between different hosts and CPU schedules.
			for _, id := range []string{"m00", "m01", "m10", "m11", "m21", "m31"} {
				if gotTotals[id] != wantedTotals[id] {
					t.Fatalf("metric %s: %v, native %v", id, gotTotals[id], wantedTotals[id])
				}
			}
			control := lambdaTelemetryMetricSnapshot(t, r, metrics.Input, noExtensionStart, r.r.clock.Now().Add(time.Minute))
			for _, result := range control.MetricDataResults {
				if (aws.ToString(result.Id) == "m30" || aws.ToString(result.Id) == "m31") && len(result.Values) != 0 {
					t.Fatalf("no-extension control emitted a sample, not absence: %+v", result)
				}
			}
			if gotTotals["m20"] <= 0 {
				t.Fatal("real runtime Duration was lost")
			}
			if backend == "sqlite" {
				r.r.reopen(t, name)
				after := lambdaTelemetryMetricTotals(lambdaTelemetryMetricSnapshot(t, r, metrics.Input, start, r.r.clock.Now().Add(time.Minute)))
				// Preserve the actual floating-point Duration, including its
				// fractional part, rather than substituting an integer fixture.
				if !reflect.DeepEqual(after, gotTotals) {
					t.Fatalf("metric values changed across SQLite reopen: before %+v, after %+v", gotTotals, after)
				}
			}
		})
	}
}
