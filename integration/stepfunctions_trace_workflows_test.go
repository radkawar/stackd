package stackd_test

import (
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	xrtypes "github.com/aws/aws-sdk-go-v2/service/xray/types"

	"stackd/internal/awstest"
)

type stepFunctionsWorkflowTraceReplay struct {
	*stepFunctionsTaskReplay
	rows            map[string]stepFunctionsNativeObservation
	pendingMessages map[string]sqstypes.Message
	traceTimes      map[string]string
	apiSpans        map[string]string
	apiTimes        map[string][2]float64
	prepared        map[string]bool
	mapBound        bool
}

// These are provider-produced documents: the only producers exercised here are
// actual workflows and their real service commands. BatchGetTraces also returns
// X-Ray-owned inferred SQS/QueueTime documents, never fabricated PutTraceSegments.
func TestStepFunctionsNativeTracingWorkflows(t *testing.T) {
	var fixture stepFunctionsNativeFixture
	awsReadFixture(t, "stepfunctions/tracing_workflows.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := &stepFunctionsWorkflowTraceReplay{
				stepFunctionsTaskReplay: stepFunctionsTaskCloud(t, backend, fixture, time.UnixMilli(fixture.Observations[0].Started)),
				rows:                    map[string]stepFunctionsNativeObservation{}, pendingMessages: map[string]sqstypes.Message{},
				traceTimes: map[string]string{}, apiSpans: map[string]string{}, apiTimes: map[string][2]float64{}, prepared: map[string]bool{},
			}
			for _, row := range fixture.Observations {
				r.rows[row.Label] = row
			}
			for _, row := range fixture.Observations {
				operation := stepFunctionsOperation(row.Operation)
				if operation == "getcalleridentity" || strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "independent-absence-") || operation == "gettracegraph" || operation == "gettracesummaries" {
					continue
				}
				switch row.Label {
				case "activity-retry-open-trace-0", "activity-retry-final-trace-0", "fail-final-trace-0", "activity-redrive-original-trace-0":
					// Captured empty/stale publication samples precede retained
					// populated/terminal reads. No publication delay is promised.
					continue
				}
				if operation == "describeexecution" && strings.Contains(row.Label, "-final-describe-") {
					var observed struct{ Status string }
					awsDecodeJSON(t, row.Result.Output, &observed)
					if observed.Status == "RUNNING" {
						continue
					}
				}
				if !t.Run(row.Label, func(t *testing.T) {
					r.advance(t, time.UnixMilli(row.Started))
					if operation == "describeexecution" {
						r.advance(t, time.UnixMilli(row.Finished))
					}
					r.drain(t)
					switch {
					case row.Service == "iam":
						r.stepFunctionsTaskReplay.call(t, stepFunctionsTaskObservation{awsNativeObservation: row.awsNativeObservation})
					case row.Service == "sqs":
						if operation == "receivemessage" {
							group, _, _ := strings.Cut(row.Label, "-receive-")
							if !r.prepared[group] {
								// Read the completed trace to establish real API span
								// identities before correlating the received messages.
								trace := r.rows[group+"-final-trace-0"]
								trace.Started, trace.Finished = 0, 0
								r.traces(t, trace)
								r.prepared[group] = true
							}
							r.receiveMessages(t, row, func(native, local string) {
								r.compareHeader(t, native, local, group == "distributed")
							})
						} else {
							r.stepFunctionsTaskReplay.call(t, stepFunctionsTaskObservation{awsNativeObservation: row.awsNativeObservation})
						}
					case row.Service == "xray":
						r.traces(t, row)
					default:
						if row.Label == "distributed-final-describe-1" {
							r.bindMapChildren(t)
						}
						actual := r.stepFunctionsNativeReplay.call(t, row)
						r.drain(t)
						if actual != nil {
							r.compareSDK(t, row, actual)
						}
					}
					if backend == "sqlite" && row.Label == "activity-retry-open-trace-1" {
						// The real Activity lease and open root/state documents exist
						// before closing the stores. Continue the captured callbacks
						// against the reopened server; identity bindings remain live.
						r.clients = r.reopen()
						r.drain(t)
						r.traces(t, row)
					}
				}) {
					return
				}
			}
			if len(r.pendingMessages) != 0 {
				t.Fatal("uncaptured SQS messages", r.pendingMessages)
			}
			t.Log("not replayed: caller identity, cleanup/absence, trace-graph/summary aggregation, four captured publication-lag samples, terminal RUNNING polling samples, and SQS long-poll latency/batch boundaries; every retained workflow/history, received message and populated/child-empty trace is compared")
			t.Log("clock magnitudes and SDK transport header maps are not portable; document times are positive, nested, and stable per span across reads/reopen/redrive; names, topology, field presence, error/cause, HTTP status/content_length, resource identities and received trace Root/deepest Parent remain exact")
		})
	}
}

func TestStepFunctionsNativeTracingSDKHeaders(t *testing.T) {
	var fixture stepFunctionsNativeFixture
	awsReadFixture(t, "stepfunctions/tracing_sdk_headers.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := &stepFunctionsWorkflowTraceReplay{
				stepFunctionsTaskReplay: stepFunctionsTaskCloud(t, backend, fixture, time.UnixMilli(fixture.Observations[0].Started)),
				pendingMessages:         map[string]sqstypes.Message{},
			}
			for _, row := range fixture.Observations {
				if row.Service == "xray" || strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "independent-absence-") {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					r.advance(t, time.UnixMilli(row.Finished))
					r.drain(t)
					switch {
					case stepFunctionsOperation(row.Operation) == "receivemessage":
						r.receiveMessages(t, row, func(nativeHeader, localHeader string) {
							if nativeHeader == "" {
								if localHeader != "" {
									t.Fatal("disabled tracing injected an SQS trace header", localHeader)
								}
								return
							}
							want, got := stepFunctionsWorkflowTraceHeader(t, nativeHeader), stepFunctionsWorkflowTraceHeader(t, localHeader)
							for _, field := range []string{"Root", "Sampled"} {
								r.compare(t, ".AWSTraceHeader."+field, want[field], got[field])
							}
							r.bind(t, r.bindings, nativeHeader, localHeader, true)
						})
					case row.Service == "iam" || row.Service == "sqs":
						r.stepFunctionsTaskReplay.call(t, stepFunctionsTaskObservation{awsNativeObservation: row.awsNativeObservation})
					default:
						actual := r.stepFunctionsNativeReplay.call(t, row)
						r.drain(t)
						if actual != nil {
							r.compareSDK(t, row, actual)
						}
					}
				}) {
					return
				}
			}
			if len(r.pendingMessages) != 0 {
				t.Fatal("unexpected task messages", r.pendingMessages)
			}
			t.Log("bounded native X-Ray reads lacked a positive control and are not absence assertions; sampled document topology and deepest API Parent are covered by tracing_workflows.json")
		})
	}
}

func (r *stepFunctionsWorkflowTraceReplay) compareSDK(t *testing.T, row stepFunctionsNativeObservation, actual any) {
	t.Helper()
	expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
	if err := awstest.DecodeSDK(row.Result.Output, expected); err != nil {
		t.Fatal(err)
	}
	want, got := stepFunctionsSDKObject(t, expected), stepFunctionsSDKObject(t, actual)
	if _, ok := actual.(*sfn.ListExecutionsOutput); ok {
		for _, object := range []map[string]any{want, got} {
			if entries, ok := object["Executions"].([]any); ok {
				slices.SortFunc(entries, func(a, b any) int {
					name := func(value any) string {
						arn := value.(map[string]any)["ExecutionArn"].(string)
						if bound := r.bindings[arn]; bound != "" {
							return bound
						}
						return arn
					}
					return strings.Compare(name(a), name(b))
				})
			}
		}
	}
	if stepFunctionsOperation(row.Operation) == "getexecutionhistory" {
		r.bindHistoryOutputs(t, want, got)
		r.bindHistoryMetadata(t, want, got)
	} else {
		r.bindValues(t, "", want, got)
	}
	// Retain response metadata while normalizing only transport-specific headers.
	want = r.project(t, "", want).(map[string]any)
	got = r.project(t, "", got).(map[string]any)
	if stepFunctionsOperation(row.Operation) == "getexecutionhistory" {
		r.compareHistory(t, want, got)
	} else {
		r.compare(t, "", want, got)
	}
}

// Bind generated service outputs by their real causal state/iteration, not the
// concurrent event-array position. The existing comparator then checks every
// event and complete predecessor chain, including the failed Activity attempts.
func (r *stepFunctionsWorkflowTraceReplay) bindHistoryOutputs(t *testing.T, want, got map[string]any) {
	t.Helper()
	outputs := func(object map[string]any) map[string]any {
		events, _ := object["Events"].([]any)
		byID := map[float64]map[string]any{}
		for _, raw := range events {
			event := raw.(map[string]any)
			byID[event["Id"].(float64)] = event
		}
		out := map[string]any{}
		for _, raw := range events {
			event := raw.(map[string]any)
			if event["Type"] != "TaskSucceeded" {
				continue
			}
			var names []string
			stateFound := false
			for ancestor := event; ancestor != nil; ancestor = byID[ancestor["PreviousEventId"].(float64)] {
				if details, ok := ancestor["StateEnteredEventDetails"].(map[string]any); ok && !stateFound {
					names = append(names, fmt.Sprint(details["Name"]))
					stateFound = true
				}
				if details, ok := ancestor["MapIterationStartedEventDetails"].(map[string]any); ok {
					names = append(names, fmt.Sprintf("%v[%v]", details["Name"], details["Index"]))
				}
			}
			key := strings.Join(names, "/")
			if out[key] != nil {
				t.Fatal("ambiguous captured task-output ancestry", key)
			}
			out[key] = event["TaskSucceededEventDetails"]
		}
		return out
	}
	a, b := outputs(want), outputs(got)
	if len(a) != len(b) {
		t.Fatalf("native/local successful task populations: %d/%d", len(a), len(b))
	}
	for key, value := range a {
		if b[key] == nil {
			t.Fatal("missing successful task ancestry", key)
		}
		r.bindValues(t, "", value, b[key])
	}
}

func (r *stepFunctionsWorkflowTraceReplay) bindMapChildren(t *testing.T) {
	t.Helper()
	if r.mapBound {
		return
	}
	maps := &stepFunctionsMapReplay{stepFunctionsNativeReplay: r.stepFunctionsNativeReplay, fixture: stepFunctionsMapFixture{Account: r.fixture.Account, Region: r.fixture.Region}}
	row := r.rows["distributed-map-runs"]
	row.Started, row.Finished = 0, 0
	actual := r.stepFunctionsNativeReplay.call(t, row).(*sfn.ListMapRunsOutput)
	var expected sfn.ListMapRunsOutput
	if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected.MapRuns) != 1 || len(actual.MapRuns) != 1 {
		t.Fatalf("native/local Map runs: %+v/%+v", expected.MapRuns, actual.MapRuns)
	}
	maps.bindMap(t, aws.ToString(expected.MapRuns[0].MapRunArn), aws.ToString(actual.MapRuns[0].MapRunArn))
	children, err := maps.sfn().ListExecutions(t.Context(), &sfn.ListExecutionsInput{MapRunArn: actual.MapRuns[0].MapRunArn})
	if err != nil || len(children.Executions) != 2 || children.NextToken != nil {
		t.Fatalf("bounded child listing: %+v %v", children, err)
	}
	byInput := map[string]*sfn.DescribeExecutionOutput{}
	for _, child := range children.Executions {
		described, err := maps.sfn().DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: child.ExecutionArn})
		if err != nil {
			t.Fatal(err)
		}
		if described.TraceHeader != nil {
			t.Fatal("Distributed Map child unexpectedly admitted tracing", described)
		}
		input := aws.ToString(described.Input)
		if byInput[input] != nil {
			t.Fatal("duplicate Map child input", input)
		}
		byInput[input] = described
	}
	for _, label := range []string{"distributed-child-description-0", "distributed-child-description-1"} {
		var native sfn.DescribeExecutionOutput
		if err := awstest.DecodeSDK(r.rows[label].Result.Output, &native); err != nil {
			t.Fatal(err)
		}
		local := byInput[aws.ToString(native.Input)]
		if local == nil {
			t.Fatal("missing real Map child", aws.ToString(native.Input))
		}
		r.bind(t, r.bindings, aws.ToString(native.ExecutionArn), aws.ToString(local.ExecutionArn), true)
		r.bind(t, r.bindings, aws.ToString(native.Name), aws.ToString(local.Name), true)
	}
	r.mapBound = true
}

func (r *stepFunctionsWorkflowTraceReplay) receiveMessages(t *testing.T, row stepFunctionsNativeObservation, compareHeader func(native, local string)) {
	t.Helper()
	client := sqs.New(sqs.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider(r.identity.AccessKeyID, r.identity.SecretAccessKey, r.identity.SessionToken)})
	actual, err := awstest.CallSDK(t.Context(), client, row.Operation, r.input(t, row.Input), func(input any) { input.(*sqs.ReceiveMessageInput).WaitTimeSeconds = 0 })
	awsNativeResult(t, row.awsNativeObservation, err)
	if err != nil {
		return
	}
	for _, message := range actual.(*sqs.ReceiveMessageOutput).Messages {
		id := aws.ToString(message.MessageId)
		if _, duplicate := r.pendingMessages[id]; duplicate {
			t.Fatal("SQS message delivered twice without visibility expiry", id)
		}
		r.pendingMessages[id] = message
	}
	var native sqs.ReceiveMessageOutput
	if err := awstest.DecodeSDK(row.Result.Output, &native); err != nil {
		t.Fatal(err)
	}
	for _, message := range native.Messages {
		id := r.bindings[aws.ToString(message.MessageId)]
		local, ok := r.pendingMessages[id]
		if !ok {
			t.Fatal("captured SQS message absent from actual receives", aws.ToString(message.MessageId), id)
		}
		delete(r.pendingMessages, id)
		compareHeader(message.Attributes["AWSTraceHeader"], local.Attributes["AWSTraceHeader"])
		want := stepFunctionsSDKObject(t, &sqs.ReceiveMessageOutput{Messages: []sqstypes.Message{message}})
		got := stepFunctionsSDKObject(t, &sqs.ReceiveMessageOutput{Messages: []sqstypes.Message{local}})
		r.bindValues(t, "", want, got)
		r.compare(t, "", r.project(t, "", want), r.project(t, "", got))
	}
	if len(native.Messages) == 0 && len(r.pendingMessages) != 0 {
		t.Fatal("native empty drain retained unexpected messages", r.pendingMessages)
	}
}

func stepFunctionsWorkflowTraceHeader(t *testing.T, header string) map[string]string {
	t.Helper()
	parts := map[string]string{}
	for _, field := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(field, "=")
		if !ok || value == "" || parts[key] != "" {
			t.Fatal("invalid SQS trace header", header)
		}
		parts[key] = value
	}
	if len(parts) != 3 || !stepFunctionsWorkflowTraceID(parts["Root"], true) || !stepFunctionsWorkflowTraceID(parts["Parent"], false) || parts["Sampled"] != "0" && parts["Sampled"] != "1" {
		t.Fatal("invalid trace context", header)
	}
	return parts
}

func stepFunctionsWorkflowTraceID(value string, root bool) bool {
	if root {
		if len(value) != 35 || !strings.HasPrefix(value, "1-") || value[10] != '-' {
			return false
		}
		value = value[2:10] + value[11:]
	} else if len(value) != 16 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (r *stepFunctionsWorkflowTraceReplay) compareHeader(t *testing.T, native, local string, child bool) {
	t.Helper()
	want, got := stepFunctionsWorkflowTraceHeader(t, native), stepFunctionsWorkflowTraceHeader(t, local)
	if child {
		if want["Sampled"] != "0" || got["Sampled"] != "0" {
			t.Fatal("Distributed Map child was sampled", want, got)
		}
		for _, row := range r.fixture.Observations {
			if stepFunctionsOperation(row.Operation) != "startexecution" {
				continue
			}
			var request struct{ TraceHeader string }
			awsDecodeJSON(t, row.Input, &request)
			if got["Root"] == stepFunctionsWorkflowTraceHeader(t, request.TraceHeader)["Root"] {
				t.Fatal("child reused a parent execution trace root", got)
			}
		}
		r.bind(t, r.bindings, want["Root"], got["Root"], true)
		r.bind(t, r.bindings, want["Parent"], got["Parent"], true)
	} else {
		if want["Sampled"] != "1" || got["Sampled"] != "1" || r.apiSpans[got["Parent"]] != got["Root"] {
			t.Fatal("sampled message Parent is not a deepest SQS integration span in its root", want, got)
		}
	}
	for _, key := range []string{"Root", "Parent", "Sampled"} {
		r.compare(t, ".AWSTraceHeader."+key, want[key], got[key])
	}
	r.bind(t, r.bindings, native, local, true)
}

func (r *stepFunctionsWorkflowTraceReplay) traces(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	actual := r.stepFunctionsNativeReplay.call(t, row).(*xray.BatchGetTracesOutput)
	var expected xray.BatchGetTracesOutput
	if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected.Traces) != len(actual.Traces) {
		t.Fatalf("native/local trace count: %d/%d", len(expected.Traces), len(actual.Traces))
	}
	if !slices.Equal(expected.UnprocessedTraceIds, actual.UnprocessedTraceIds) {
		t.Fatalf("native/local unprocessed traces differ: %v/%v", expected.UnprocessedTraceIds, actual.UnprocessedTraceIds)
	}
	for _, native := range expected.Traces {
		id := aws.ToString(native.Id)
		if bound := r.bindings[id]; bound != "" {
			id = bound
		}
		index := slices.IndexFunc(actual.Traces, func(trace xrtypes.Trace) bool { return aws.ToString(trace.Id) == id })
		if index < 0 {
			t.Fatal("missing trace", id)
		}
		local := actual.Traces[index]
		if !reflect.DeepEqual(native.LimitExceeded, local.LimitExceeded) || (native.Duration == nil) != (local.Duration == nil) {
			t.Fatalf("trace envelope field presence differs: %+v/%+v", native, local)
		}
		if local.Duration != nil && (math.IsNaN(*local.Duration) || math.IsInf(*local.Duration, 0) || *local.Duration < 0) {
			t.Fatal("invalid trace duration", local.Duration)
		}
		if len(native.Segments) != len(local.Segments) {
			t.Fatalf("native/local segment count for %s: %d/%d", id, len(native.Segments), len(local.Segments))
		}
		decode := func(segments []xrtypes.Segment) []map[string]any {
			documents := make([]map[string]any, 0, len(segments))
			for _, segment := range segments {
				var document map[string]any
				awsDecodeJSON(t, []byte(aws.ToString(segment.Document)), &document)
				if document["id"] != aws.ToString(segment.Id) {
					t.Fatal("segment envelope/document identity differs", segment, document)
				}
				documents = append(documents, document)
			}
			return documents
		}
		want, got := decode(native.Segments), decode(local.Segments)
		// The producer root establishes child identities before inferred SQS
		// documents are paired by their actual causal parent, not array order.
		slices.SortStableFunc(want, func(a, b map[string]any) int {
			if a["origin"] == "AWS::StepFunctions::StateMachine" {
				return -1
			}
			if b["origin"] == "AWS::StepFunctions::StateMachine" {
				return 1
			}
			return 0
		})
		for _, document := range want {
			match := -1
			for i, candidate := range got {
				if candidate == nil || candidate["origin"] != document["origin"] {
					continue
				}
				if document["inferred"] == true {
					if candidate["parent_id"] != r.bindings[document["parent_id"].(string)] {
						continue
					}
				} else if candidate["name"] != document["name"] {
					continue
				}
				if match != -1 {
					t.Fatal("ambiguous trace segment topology", document)
				}
				match = i
			}
			if match == -1 {
				t.Fatal("missing trace segment topology", document)
			}
			r.document(t, "trace/"+id, document, got[match], id, nil)
			got[match] = nil
		}
	}
}

func (r *stepFunctionsWorkflowTraceReplay) document(t *testing.T, path string, want, got map[string]any, root string, parent map[string]any) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s document keys differ: native %v local %v", path, want, got)
	}
	nativeID, nativeOK := want["id"].(string)
	localID, localOK := got["id"].(string)
	if !nativeOK || !localOK || !stepFunctionsWorkflowTraceID(localID, false) {
		t.Fatal("invalid segment identity", want, got)
	}
	r.bind(t, r.bindings, nativeID, localID, true)
	path += "/" + fmt.Sprint(want["name"])
	start, ok := got["start_time"].(float64)
	if !ok || start <= 0 || math.IsNaN(start) || math.IsInf(start, 0) || start > float64(r.clock.Now().UnixMilli())/1000+0.001 {
		t.Fatal("invalid span start", path, got)
	}
	end, closed := got["end_time"].(float64)
	if closed && (math.IsNaN(end) || math.IsInf(end, 0) || end < start || end > float64(r.clock.Now().UnixMilli())/1000+0.001) {
		t.Fatal("invalid span end", path, got)
	}
	if parent != nil {
		if start < parent["start_time"].(float64) {
			t.Fatal("child starts before its parent", path, got, parent)
		}
		if outer, ok := parent["end_time"].(float64); ok && closed && end > outer {
			t.Fatal("child ends after its parent", path, got, parent)
		}
		if got["name"] == "QueueTime" && (start != parent["start_time"] || end != parent["end_time"]) {
			t.Fatal("inferred QueueTime interval differs from its service", got, parent)
		}
	}
	if got["namespace"] == "aws" && got["name"] == "SQS" {
		if _, hasChildren := got["subsegments"]; hasChildren {
			t.Fatal("SQS API span unexpectedly has children", got)
		}
		r.apiSpans[localID] = root
		r.apiTimes[localID] = [2]float64{start, end}
	}
	if got["inferred"] == true {
		parentID, _ := got["parent_id"].(string)
		if r.apiSpans[parentID] != root || r.apiTimes[parentID] != [2]float64{start, end} {
			t.Fatal("inferred SQS document is not correlated to its API span", got)
		}
	}
	for key, expected := range want {
		actual, present := got[key]
		if !present {
			t.Fatal("missing document field", path, key)
		}
		switch key {
		case "id":
		case "start_time", "end_time":
			// Independent spans can share a native millisecond but differ locally.
			// Bind by stable span identity/field, preserving repeated-read identity
			// and the original closed trace across the successful redrive.
			stamp, ok := actual.(float64)
			if !ok {
				t.Fatal("invalid trace timestamp", actual)
			}
			r.bind(t, r.traceTimes, nativeID+"/"+key+"/"+fmt.Sprint(expected), strconv.FormatFloat(stamp, 'g', -1, 64), false)
		case "subsegments":
			native, ok := expected.([]any)
			if !ok {
				t.Fatal("invalid native subsegments", expected)
			}
			local, ok := actual.([]any)
			if !ok || len(native) != len(local) {
				t.Fatal("subsegment populations differ", path, expected, actual)
			}
			byName := map[string]map[string]any{}
			for _, raw := range local {
				node := raw.(map[string]any)
				name := node["name"].(string)
				if byName[name] != nil {
					t.Fatal("duplicate sibling span", path, name)
				}
				byName[name] = node
			}
			for _, raw := range native {
				node := raw.(map[string]any)
				name := node["name"].(string)
				if byName[name] == nil {
					t.Fatal("missing sibling span", path, name)
				}
				r.document(t, path, node, byName[name], root, got)
			}
		case "aws":
			native := expected.(map[string]any)
			local, ok := actual.(map[string]any)
			if !ok || len(native) != len(local) {
				t.Fatal("AWS span metadata keys differ", path, native, actual)
			}
			for field, value := range native {
				if field == "request_id" || field == "message_id" {
					text, ok := local[field].(string)
					if !ok || text == "" {
						t.Fatal("missing service identity", path, field, local)
					}
					r.bind(t, r.bindings, value.(string), text, true)
				}
			}
			r.compare(t, path+".aws(JSON)", r.project(t, path+".aws", native), r.project(t, path+".aws", local))
		default:
			r.compare(t, path+"."+key+"(JSON)", expected, actual)
		}
	}
}
