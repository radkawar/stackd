package stackd_test

import (
	"fmt"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/xray"

	"stackd/internal/awstest"
)

type stepFunctionsTraceControlReplay struct {
	*stepFunctionsTaskReplay
	starts       map[string]stepFunctionsNativeObservation
	roots        map[string]bool
	segmentTimes map[string]float64
}

// Replay admission and explicit context decisions, not regional sampling-rule
// selection. The fixture's admitted scoped rules reported RequestCount=0, so
// neither their rate-one positives nor their zero-rate draws establish matching.
// Autonomous decisions may differ; their public header and documents must agree.
func TestStepFunctionsNativeTracingControl(t *testing.T) {
	var fixture stepFunctionsNativeFixture
	awsReadFixture(t, "stepfunctions/tracing_control.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			if len(fixture.Observations) <= 270 || fixture.Observations[165].Label != "disabled-window-round-00-batch-00" || fixture.Observations[169].Label != "disabled-window-round-02-batch-00" {
				t.Fatal("control fixture no longer contains the selected open/closed observation boundaries")
			}
			r := &stepFunctionsTraceControlReplay{
				stepFunctionsTaskReplay: stepFunctionsTaskCloud(t, backend, fixture, time.UnixMilli(fixture.Observations[1].Started)),
				starts:                  map[string]stepFunctionsNativeObservation{}, roots: map[string]bool{}, segmentTimes: map[string]float64{},
			}
			for index, row := range fixture.Observations {
				// Keep exact setup/errors, all context cases, and terminal histories.
				// No-permission absence is read at the last captured pre-grant bound
				// (114s), not six equivalent publication-latency samples. Authorized
				// positives use the first settled batch. Disabled Wait samples retain
				// open -> open -> closed; all other disabled publication is checked at
				// the final known-root bound, after public headers have been observed.
				selected := index >= 1 && index <= 12 || index >= 14 && index <= 17 || index == 23 ||
					index >= 28 && index <= 62 || index >= 145 && index <= 165 || index == 167 || index == 169 ||
					index >= 175 && index <= 186 || index >= 209 && index <= 220 || index >= 261 && index <= 270
				if !selected {
					continue
				}
				if !t.Run(fmt.Sprintf("%03d-%s", index, row.Label), func(t *testing.T) {
					r.replayControl(t, row)
					if index == 165 && backend == "sqlite" {
						// This is local persistence evidence, not an AWS restart claim.
						// The next captured open read and then the terminal read must
						// retain the same source/Wait IDs and original start times.
						r.clients = r.reopen()
						r.drain(t)
						r.replayControl(t, fixture.Observations[154])
					}
				}) {
					return
				}
			}
			t.Log("coverage: both machine types, role-gated real publication, explicit/automatic headers, HTTP precedence, disabled upstream tracing, pinned Wait revision and SQLite open-trace retention")
			t.Log("not replayed: scoped-rule admission/readback/statistics or selection claims, sampling-rate draws, query discovery/pagination, cleanup, duplicate publication polls; final batch expectations project only roots from replayed requests")
		})
	}
}

func (r *stepFunctionsTraceControlReplay) replayControl(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	output := r.stepFunctionsNativeReplay.call(t, row)
	if output == nil {
		// call retains native service error classes, including both rejected
		// overlength sampling-rule names; a native failure is never success.
		return
	}
	r.drain(t)
	switch actual := output.(type) {
	case *iam.CreateRoleOutput:
		var native struct {
			Role struct {
				Arn                      string
				AssumeRolePolicyDocument any
			}
		}
		awsDecodeJSON(t, row.Result.Output, &native)
		if actual.Role == nil || aws.ToString(actual.Role.Arn) != native.Role.Arn {
			t.Fatalf("execution role differs: %+v", actual.Role)
		}
		policy, err := url.QueryUnescape(aws.ToString(actual.Role.AssumeRolePolicyDocument))
		if err != nil {
			t.Fatal(err)
		}
		var got any
		awsDecodeJSON(t, []byte(policy), &got)
		r.compare(t, ".trust(JSON)", native.Role.AssumeRolePolicyDocument, got)
		return
	case *iam.GetRolePolicyOutput:
		var native struct {
			RoleName, PolicyName string
			PolicyDocument       any
		}
		awsDecodeJSON(t, row.Result.Output, &native)
		r.compare(t, ".RoleName", native.RoleName, aws.ToString(actual.RoleName))
		r.compare(t, ".PolicyName", native.PolicyName, aws.ToString(actual.PolicyName))
		policy, err := url.QueryUnescape(aws.ToString(actual.PolicyDocument))
		if err != nil {
			t.Fatal(err)
		}
		var got any
		awsDecodeJSON(t, []byte(policy), &got)
		r.compare(t, ".policy(JSON)", native.PolicyDocument, got)
		return
	case *xray.BatchGetTracesOutput:
		r.batchControl(t, row, actual)
		return
	}
	r.compareControlSDK(t, row, output)
}

func (r *stepFunctionsTraceControlReplay) compareControlSDK(t *testing.T, row stepFunctionsNativeObservation, output any) {
	t.Helper()
	native := reflect.New(reflect.TypeOf(output).Elem()).Interface()
	if err := awstest.DecodeSDK(row.Result.Output, native); err != nil {
		t.Fatal(err)
	}
	want, got := stepFunctionsSDKObject(t, native), stepFunctionsSDKObject(t, output)
	operation := stepFunctionsOperation(row.Operation)
	if operation == "startexecution" || operation == "startsyncexecution" {
		arn, ok := want["ExecutionArn"].(string)
		if !ok {
			t.Fatal("native start has no execution ARN")
		}
		r.starts[arn] = row
		// StartExecution itself has no public traceHeader output. Explicit
		// roots are still queryable before the first DescribeExecution.
		request := stepFunctionsTraceControlRequest(t, row)
		parts := stepFunctionsTraceControlParts(request)
		if stepFunctionsTraceControlRoot.MatchString(parts["Root"]) && (parts["Sampled"] == "0" || parts["Sampled"] == "1") {
			r.roots[parts["Root"]] = parts["Sampled"] == "1"
		}
	}
	if operation == "describeexecution" || operation == "startsyncexecution" {
		arn, _ := want["ExecutionArn"].(string)
		start, ok := r.starts[arn]
		if !ok {
			t.Fatalf("no replayed admission for %s", arn)
		}
		r.headerControl(t, start, want["TraceHeader"], got["TraceHeader"])
		// Header decisions and identity were checked above, independently of
		// the rest of the SDK output (status, revision output and field presence).
		want["TraceHeader"] = got["TraceHeader"]
	}
	if operation == "getexecutionhistory" {
		r.compareHistory(t, want, got)
	} else {
		r.compare(t, "", want, got)
	}
}

var stepFunctionsTraceControlRoot = regexp.MustCompile(`^1-[0-9a-f]{8}-[0-9a-f]{24}$`)
var stepFunctionsTraceControlID = regexp.MustCompile(`^[0-9a-f]{16}$`)
var stepFunctionsTraceControlHeader = regexp.MustCompile(`^Root=(1-[0-9a-f]{8}-[0-9a-f]{24})(;Parent=[0-9a-f]{16})?;Sampled=([01])$`)

func stepFunctionsTraceControlRequest(t *testing.T, row stepFunctionsNativeObservation) string {
	t.Helper()
	var input struct{ TraceHeader string }
	awsDecodeJSON(t, row.Input, &input)
	for key, value := range row.HTTPHeaders {
		if strings.EqualFold(key, "X-Amzn-Trace-Id") {
			return value
		}
	}
	return input.TraceHeader
}

func stepFunctionsTraceControlParts(header string) map[string]string {
	parts := map[string]string{}
	for _, field := range strings.Split(header, ";") {
		if key, value, ok := strings.Cut(field, "="); ok {
			parts[key] = value
		}
	}
	return parts
}

func (r *stepFunctionsTraceControlReplay) headerControl(t *testing.T, start stepFunctionsNativeObservation, want, got any) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("omitted disabled traceHeader became %v", got)
		}
		return
	}
	native, nativeOK := want.(string)
	local, localOK := got.(string)
	if !nativeOK || !localOK || !stepFunctionsTraceControlHeader.MatchString(native) || !stepFunctionsTraceControlHeader.MatchString(local) {
		t.Fatalf("public traceHeader is not canonical: native %v, local %v", want, got)
	}
	original := stepFunctionsTraceControlParts(stepFunctionsTraceControlRequest(t, start))
	a, b := stepFunctionsTraceControlParts(native), stepFunctionsTraceControlParts(local)
	if stepFunctionsTraceControlRoot.MatchString(original["Root"]) {
		if a["Root"] != original["Root"] || b["Root"] != original["Root"] {
			t.Fatalf("valid supplied root was not preserved: input %v, native %v, local %v", original, a, b)
		}
	}
	if a["Parent"] != b["Parent"] {
		t.Fatalf("trace parent differs: native %q, local %q", a["Parent"], b["Parent"])
	}
	if decision := original["Sampled"]; decision == "0" || decision == "1" {
		if b["Sampled"] != decision || a["Sampled"] != decision {
			t.Fatalf("explicit sampling decision changed: input %s, native %s, local %s", decision, a["Sampled"], b["Sampled"])
		}
	}
	// A native autonomous draw is not a fixed probability contract. Bind the
	// generated root/header consistently and require publication to follow the
	// local draw; supplied decisions above never receive this relaxation.
	r.bind(t, r.bindings, a["Root"], b["Root"], true)
	r.bind(t, r.bindings, native, local, true)
	if prior, ok := r.roots[a["Root"]]; ok && prior != (b["Sampled"] == "1") {
		t.Fatalf("sampling decision changed for root %s", a["Root"])
	}
	r.roots[a["Root"]] = b["Sampled"] == "1"
}

func (r *stepFunctionsTraceControlReplay) batchControl(t *testing.T, row stepFunctionsNativeObservation, output *xray.BatchGetTracesOutput) {
	t.Helper()
	var native xray.BatchGetTracesOutput
	if err := awstest.DecodeSDK(row.Result.Output, &native); err != nil {
		t.Fatal(err)
	}
	want, got := stepFunctionsSDKObject(t, &native), stepFunctionsSDKObject(t, output)
	r.compare(t, ".UnprocessedTraceIds", want["UnprocessedTraceIds"], got["UnprocessedTraceIds"])
	r.compare(t, ".NextToken", want["NextToken"], got["NextToken"])
	expected := map[string]map[string]any{}
	traces, _ := want["Traces"].([]any)
	for _, value := range traces {
		trace := value.(map[string]any)
		root := trace["Id"].(string)
		sampled, owned := r.roots[root]
		if !owned || !sampled {
			continue
		}
		if local := r.bindings[root]; local != "" {
			root = local
		}
		expected[root] = trace
	}
	actual, _ := got["Traces"].([]any)
	if len(expected) != len(actual) {
		t.Fatalf("owned trace set differs: expected %v, local %v", expected, actual)
	}
	for _, value := range actual {
		trace := value.(map[string]any)
		root := trace["Id"].(string)
		match, ok := expected[root]
		if !ok {
			t.Fatalf("unexpected/duplicate trace %s", root)
		}
		delete(expected, root)
		r.compare(t, ".Trace.Id", match["Id"], trace["Id"])
		r.compare(t, ".Trace.LimitExceeded", match["LimitExceeded"], trace["LimitExceeded"])
		segments, _ := match["Segments"].([]any)
		localSegments, _ := trace["Segments"].([]any)
		if len(segments) != 1 || len(localSegments) != len(segments) {
			t.Fatalf("control trace must retain its one native source document: native %v, local %v", segments, localSegments)
		}
		a, b := segments[0].(map[string]any), localSegments[0].(map[string]any)
		var nativeDocument, localDocument map[string]any
		awsDecodeJSON(t, []byte(a["Document"].(string)), &nativeDocument)
		awsDecodeJSON(t, []byte(b["Document"].(string)), &localDocument)
		if a["Id"] != nativeDocument["id"] || b["Id"] != localDocument["id"] || localDocument["trace_id"] != root {
			t.Fatalf("trace/segment wrapper identity disagrees with its document: %v", trace)
		}
		r.documentControl(t, ".Document", nativeDocument, localDocument)
		if match["Duration"] == nil {
			if trace["Duration"] != nil {
				t.Fatal("open native trace unexpectedly has a duration")
			}
		} else {
			duration, ok := trace["Duration"].(float64)
			start, startOK := localDocument["start_time"].(float64)
			end, endOK := localDocument["end_time"].(float64)
			if !ok || !startOK || !endOK || math.IsNaN(duration) || math.IsInf(duration, 0) || duration < 0 || math.Abs(duration-(end-start)) > 0.001 {
				t.Fatalf("closed trace duration disagrees with its source interval: %v", trace)
			}
		}
	}
}

// Only independent identifiers and timestamp magnitudes are projected. Object
// keys, parent/root links, ownership, cause, open/closed fields and state nodes
// remain exact. Native Wait closure lists Done before Wait, so subsegment order
// is compared by state name; this control fixture has no repeated state names.
func (r *stepFunctionsTraceControlReplay) documentControl(t *testing.T, path string, want, got any) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok || len(expected) != len(actual) {
			t.Fatalf("%s document fields differ: native %v, local %v", path, expected, got)
		}
		if id, ok := expected["id"].(string); ok {
			local, _ := actual["id"].(string)
			if !stepFunctionsTraceControlID.MatchString(local) {
				t.Fatalf("invalid segment ID %q", local)
			}
			r.bind(t, r.bindings, id, local, true)
			start, startOK := actual["start_time"].(float64)
			if !startOK || math.IsNaN(start) || math.IsInf(start, 0) || start <= 0 || start > float64(r.clock.Now().UnixMilli())/1000+0.001 {
				t.Fatalf("invalid segment start: %v", actual)
			}
			if end, closed := actual["end_time"]; closed {
				value, ok := end.(float64)
				if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < start || value > float64(r.clock.Now().UnixMilli())/1000+0.001 {
					t.Fatalf("invalid segment end: %v", actual)
				}
			} else if actual["in_progress"] != true {
				t.Fatalf("segment is neither open nor closed: %v", actual)
			}
			for _, field := range []string{"start_time", "end_time"} {
				if _, exists := expected[field]; !exists {
					continue
				}
				value, ok := actual[field].(float64)
				if !ok {
					t.Fatalf("missing segment %s: %v", field, actual)
				}
				key := id + "." + field
				if prior, found := r.segmentTimes[key]; found && prior != value {
					t.Fatalf("retained %s changed: %v -> %v", key, prior, value)
				}
				r.segmentTimes[key] = value
			}
		}
		for key, value := range expected {
			other, present := actual[key]
			if !present {
				t.Fatalf("%s missing native field %s", path, key)
			}
			if key == "start_time" || key == "end_time" {
				continue
			}
			r.documentControl(t, path+"."+key, value, other)
		}
	case []any:
		actual, ok := got.([]any)
		if !ok || len(expected) != len(actual) {
			t.Fatalf("%s node cardinality differs: native %v, local %v", path, expected, got)
		}
		if strings.HasSuffix(path, ".subsegments") {
			byName := func(a, b any) int {
				return strings.Compare(a.(map[string]any)["name"].(string), b.(map[string]any)["name"].(string))
			}
			slices.SortFunc(expected, byName)
			slices.SortFunc(actual, byName)
		}
		for i := range expected {
			r.documentControl(t, fmt.Sprintf("%s[%d]", path, i), expected[i], actual[i])
		}
	default:
		r.compare(t, path, want, got)
	}
}
