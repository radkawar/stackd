package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sfn"

	"stackd/internal/awstest"
	sfnstore "stackd/storage/stepfunctions"
)

type stepFunctionsRedriveReplay struct {
	*stepFunctionsTaskReplay
	leases       map[string]*sfn.GetActivityTaskOutput
	leaseWorkers map[string]string
	workers      map[string]string
	polled       map[string]bool
	mapCapture   bool
}

func TestStepFunctionsNativeRedriveExecution(t *testing.T) {
	var fixture stepFunctionsNativeFixture
	awsReadFixture(t, "stepfunctions/redrive_execution.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := &stepFunctionsRedriveReplay{
				stepFunctionsTaskReplay: stepFunctionsTaskCloud(t, backend, fixture, time.UnixMilli(fixture.Observations[0].Started)),
				leases:                  map[string]*sfn.GetActivityTaskOutput{},
				leaseWorkers:            map[string]string{}, workers: map[string]string{}, polled: map[string]bool{},
			}
			for index := 0; index < len(fixture.Observations); index++ {
				row := fixture.Observations[index]
				operation := stepFunctionsOperation(row.Operation)
				if operation == "getcalleridentity" || strings.Contains(row.Label, "cleanup") {
					continue
				}
				if operation == "describeexecution" && row.Result.Code == "Success" {
					var observed struct{ Status string }
					awsDecodeJSON(t, row.Result.Output, &observed)
					if observed.Status == "RUNNING" && strings.Contains(row.Label, "-terminal-describe-") {
						// Native timeout polls establish the terminal observation, not
						// a required count of provider scheduling samples.
						continue
					}
				}
				if !t.Run(row.Label, func(t *testing.T) {
					if row.Service == "cloudwatch" {
						r.metrics(t, row)
						return
					}
					if operation == "redriveexecution" {
						// Reopen both before the first redrive and before every token
						// replay, including while RUNNING and after later completion.
						// No in-process token cache can satisfy these observations.
						r.clients = r.reopen()
						r.drain(t)
					}
					if operation == "getexecutionhistory" && row.Result.Code == "Success" {
						index = r.history(t, fixture.Observations, index)
						return
					}
					var actual any
					if operation == "getactivitytask" && row.Result.Code == "Success" {
						actual = r.lease(t, row)
					} else {
						actual = r.stepFunctionsNativeReplay.call(t, row)
					}
					if actual != nil && row.Service == "stepfunctions" {
						r.compareSDK(t, row.Result.Output, actual)
					}
				}) {
					return
				}
			}
			if len(r.leases) != 0 {
				t.Fatal("captured concurrent Activity leases were not consumed", r.leases)
			}
			t.Log("not replayed: caller identity, native timeout polling latency and cleanup/absence polling; metric duration magnitudes are not compared, but first-attempt sample populations and all transition statistics are")
		})
	}
}

// Concurrent Parallel branches may lease in either order. Buffer only actual SDK
// replies, then apply each recorded callback to its own branch. Every captured
// payload is still compared in full, including preserved predecessor output,
// original revision marker, EnteredTime, RetryCount and redrive context.
func (r *stepFunctionsRedriveReplay) lease(t *testing.T, row stepFunctionsNativeObservation) *sfn.GetActivityTaskOutput {
	t.Helper()
	var expected sfn.GetActivityTaskOutput
	if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
		t.Fatal(err)
	}
	var worker struct{ WorkerName string }
	awsDecodeJSON(t, row.Input, &worker)
	key := stepFunctionsRedriveLeaseKey(t, &expected)
	wave := strings.Join(strings.Split(key, "/")[:2], "/") + "/"
	r.advance(t, time.UnixMilli(row.Started))
	for range 4 {
		if actual := r.leases[key]; actual != nil {
			r.bind(t, r.workers, worker.WorkerName, r.leaseWorkers[key], true)
			delete(r.leases, key)
			delete(r.leaseWorkers, key)
			return actual
		}
		var poll *stepFunctionsNativeObservation
		for _, candidate := range r.fixture.Observations {
			if stepFunctionsOperation(candidate.Operation) != "getactivitytask" || r.polled[candidate.Label] || candidate.Result.Code != "Success" {
				continue
			}
			var lease sfn.GetActivityTaskOutput
			if err := awstest.DecodeSDK(candidate.Result.Output, &lease); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(stepFunctionsRedriveLeaseKey(t, &lease), wave) {
				poll = &candidate
				break
			}
		}
		if poll == nil {
			t.Fatal("no unconsumed captured worker poll for", key)
		}
		// Pull the next captured worker forward only when concurrent branches
		// lease in another order. Each worker request is still used exactly once.
		poll.Started, poll.Finished = row.Started, row.Finished
		actual := r.stepFunctionsNativeReplay.call(t, *poll).(*sfn.GetActivityTaskOutput)
		r.polled[poll.Label] = true
		actualKey := stepFunctionsRedriveLeaseKey(t, actual)
		if r.leases[actualKey] != nil {
			t.Fatal("duplicate concurrent Activity lease", actualKey)
		}
		var localWorker struct{ WorkerName string }
		awsDecodeJSON(t, poll.Input, &localWorker)
		r.leases[actualKey], r.leaseWorkers[actualKey] = actual, localWorker.WorkerName
	}
	t.Fatal("no Activity lease for captured branch", key)
	return nil
}

func stepFunctionsRedriveLeaseKey(t *testing.T, lease *sfn.GetActivityTaskOutput) string {
	t.Helper()
	var payload struct {
		Execution struct {
			ID           string `json:"Id"`
			RedriveCount int64
		}
		State struct {
			Name       string
			RetryCount int64
		}
		Input struct{ Index *int }
	}
	awsDecodeJSON(t, []byte(aws.ToString(lease.Input)), &payload)
	index := -1
	if payload.Input.Index != nil {
		index = *payload.Input.Index
	}
	return fmt.Sprintf("%s/%d/%s/%d/%d", payload.Execution.ID, payload.Execution.RedriveCount, payload.State.Name, payload.State.RetryCount, index)
}

func (r *stepFunctionsRedriveReplay) compareSDK(t *testing.T, raw json.RawMessage, actual any) {
	t.Helper()
	expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
	if err := awstest.DecodeSDK(raw, expected); err != nil {
		t.Fatal(err)
	}
	want := r.projection(t, "", stepFunctionsSDKObject(t, expected)).(map[string]any)
	got := r.projection(t, "", stepFunctionsSDKObject(t, actual)).(map[string]any)
	r.compare(t, "", want, got)
}

// The only user-named timestamp in this fixture is a Pass-state capture of
// $$.State.EnteredTime. Give it the same binding as the real context field;
// do not normalize arbitrary user strings that happen to look like dates.
func (r *stepFunctionsRedriveReplay) projection(t *testing.T, path string, value any) any {
	t.Helper()
	switch object := value.(type) {
	case map[string]any:
		stepFunctionsNormalizeMetadata(t, path, object)
		if object["Error"] == "S3.NoSuchKeyException" {
			if cause, ok := object["Cause"].(string); !ok || cause == "" {
				t.Fatal("missing S3 failure diagnostic", object)
			}
			object["Cause"] = "<S3 missing key diagnostic>"
		}
		if r.mapCapture && (object["Status"] == "ABORTED" || strings.HasSuffix(path, ".ExecutionAbortedEventDetails")) {
			// This Map capture has only service-owned sibling cancellation,
			// never a customer StopExecution Cause. Preserve its presence and
			// every error/status/causal event, without pinning provider prose.
			if cause, ok := object["Cause"].(string); !ok || cause == "" {
				t.Fatal("missing Map cancellation diagnostic", object)
			}
			object["Cause"] = "<Map-owned cancellation diagnostic>"
		}
		if object["marker"] == "original-predecessor" {
			if entered, ok := object["entered"]; ok {
				object["EnteredTime"] = entered
				delete(object, "entered")
			}
		}
		for key, child := range object {
			if key == "StartDate" || key == "StopDate" {
				if millis, ok := child.(float64); ok {
					child = time.UnixMilli(int64(millis)).UTC().Format(time.RFC3339Nano)
				}
			}
			if key == "LastModified" && child != nil {
				text, ok := child.(string)
				if !ok {
					t.Fatal("invalid S3 LastModified", child)
				}
				if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
					t.Fatal(err)
				}
				child = "<S3 object timestamp>"
			}
			object[key] = r.projection(t, path+"."+key, child)
		}
	case []any:
		for index, child := range object {
			object[index] = r.projection(t, path, child)
		}
	case string:
		if !strings.HasSuffix(path, ".Definition") && json.Valid([]byte(object)) {
			var decoded any
			awsDecodeJSON(t, []byte(object), &decoded)
			encoded, err := json.Marshal(r.projection(t, path+"(JSON)", decoded))
			if err != nil {
				t.Fatal(err)
			}
			return string(encoded)
		}
	}
	return value
}

// Replay every native page and bind its cursor, then compare complete causal
// chains. Independent branches may cross page boundaries in different orders;
// concatenating preserves all events instead of projecting away their histories.
func (r *stepFunctionsRedriveReplay) history(t *testing.T, rows []stepFunctionsNativeObservation, first int) int {
	t.Helper()
	var expected, actual sfn.GetExecutionHistoryOutput
	for index := first; index < len(rows); index++ {
		row := rows[index]
		var page sfn.GetExecutionHistoryOutput
		if err := awstest.DecodeSDK(row.Result.Output, &page); err != nil {
			t.Fatal(err)
		}
		got := r.stepFunctionsNativeReplay.call(t, row).(*sfn.GetExecutionHistoryOutput)
		if (page.NextToken == nil) != (got.NextToken == nil) {
			t.Fatal("history page lost its continuation boundary", row.Label)
		}
		if page.NextToken != nil {
			// Repeated snapshots may receive fresh native opaque tokens for
			// the same local cursor. Preserve their use, not random uniqueness.
			r.bind(t, r.bindings, *page.NextToken, *got.NextToken, false)
		}
		expected.Events = append(expected.Events, page.Events...)
		actual.Events = append(actual.Events, got.Events...)
		if page.NextToken == nil {
			want := r.projection(t, "", stepFunctionsSDKObject(t, &expected)).(map[string]any)
			local := r.projection(t, "", stepFunctionsSDKObject(t, &actual)).(map[string]any)
			if events, ok := want["Events"].([]any); ok {
				for _, raw := range events {
					event := raw.(map[string]any)
					if details, ok := event["ActivityStartedEventDetails"].(map[string]any); ok {
						if worker, ok := details["WorkerName"].(string); ok && r.workers[worker] != "" {
							details["WorkerName"] = r.workers[worker]
						}
					}
				}
			}
			r.compareHistory(t, want, local)
			return index
		}
		if index+1 == len(rows) || stepFunctionsOperation(rows[index+1].Operation) != "getexecutionhistory" {
			t.Fatal("native history pagination is incomplete", row.Label)
		}
	}
	t.Fatal("native history lacks final page")
	return first
}

func (r *stepFunctionsRedriveReplay) metrics(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	var query cloudwatch.GetMetricStatisticsInput
	var expected cloudwatch.GetMetricStatisticsOutput
	if err := awstest.DecodeSDK(row.Input, &query); err != nil {
		t.Fatal(err)
	}
	if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
		t.Fatal(err)
	}
	// Every execution above uses this capture's account, region, machine and
	// source clock. The native window therefore selects precisely the replayed
	// seven initial attempts and eight redrives, not an unrelated local window.
	client := cloudwatch.New(cloudwatch.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(r.identity.AccessKeyID, r.identity.SecretAccessKey, ""),
		HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
	actual, err := client.GetMetricStatistics(t.Context(), &query)
	awsNativeResult(t, row.awsNativeObservation, err)
	// This capture requests four statistics. Derive Average only to reuse the
	// existing aggregate comparator; it is not an additional native assertion.
	for _, output := range []*cloudwatch.GetMetricStatisticsOutput{&expected, actual} {
		for index := range output.Datapoints {
			point := &output.Datapoints[index]
			if point.Sum == nil || point.SampleCount == nil || *point.SampleCount <= 0 {
				t.Fatal("metric omitted captured sum/sample count", point)
			}
			point.Average = aws.Float64(*point.Sum / *point.SampleCount)
		}
	}
	got, gotUnit := ebMetricStatistics(t, actual.Datapoints)
	want, wantUnit := ebMetricStatistics(t, expected.Datapoints)
	if aws.ToString(actual.Label) != aws.ToString(expected.Label) || gotUnit != wantUnit || got[1] != want[1] {
		t.Fatalf("redrive metric identity/unit/population differs: native=%+v local=%+v", expected, actual)
	}
	if aws.ToString(query.MetricName) != "ExecutionTime" {
		for index := range got {
			if math.Abs(got[index]-want[index]) > 1e-9 {
				t.Fatalf("redrive metric transition statistics differ: native=%v local=%v", want, got)
			}
		}
	}
}

type stepFunctionsRedriveMapReplay struct {
	*stepFunctionsRedriveReplay
	maps            *stepFunctionsMapReplay
	rows            []stepFunctionsNativeObservation
	raced           map[string]string
	racedGeneration map[string]int64
	objects         map[string][]byte
}

func TestStepFunctionsNativeRedriveMap(t *testing.T) {
	var fixture stepFunctionsNativeFixture
	awsReadFixture(t, "stepfunctions/redrive_map.json", &fixture)
	for _, attempt := range []string{"attempt2:", "attempt3:"} {
		var rows []stepFunctionsNativeObservation
		for _, row := range fixture.Observations {
			if !strings.HasPrefix(row.Label, attempt) || strings.Contains(row.Label, ":cleanup:") ||
				attempt == "attempt2:" && strings.HasPrefix(row.Label, attempt+"express:") {
				continue
			}
			row.Operation = strings.ReplaceAll(row.Operation, "_", "")
			rows = append(rows, row)
		}
		if len(rows) == 0 {
			t.Fatal("missing settled redrive capture", attempt)
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(attempt+backend, func(t *testing.T) {
				base := &stepFunctionsRedriveReplay{stepFunctionsTaskReplay: stepFunctionsTaskCloud(t, backend, fixture, time.UnixMilli(rows[0].Started)), mapCapture: true}
				r := &stepFunctionsRedriveMapReplay{stepFunctionsRedriveReplay: base, rows: rows, raced: map[string]string{}, racedGeneration: map[string]int64{}, objects: map[string][]byte{}}
				r.maps = &stepFunctionsMapReplay{stepFunctionsNativeReplay: base.stepFunctionsNativeReplay,
					fixture: stepFunctionsMapFixture{Account: fixture.Account, Region: fixture.Region}}
				for index := 0; index < len(rows); index++ {
					row := rows[index]
					operation := stepFunctionsOperation(row.Operation)
					if operation == "getcalleridentity" || strings.Contains(row.Label, ":redriven-") {
						// Intermediate Map/child PENDING_REDRIVE samples measure
						// scheduling latency. Settled counts and every final child
						// remain asserted below.
						continue
					}
					if operation == "describeexecution" && row.Result.Code == "Success" {
						var observed struct{ Status string }
						awsDecodeJSON(t, row.Result.Output, &observed)
						if observed.Status == "RUNNING" {
							continue
						}
					}
					if !t.Run(row.Label, func(t *testing.T) {
						r.drain(t)
						if strings.Contains(row.Label, ":child:") {
							var request struct{ ExecutionArn string }
							awsDecodeJSON(t, row.Input, &request)
							if _, raced := r.raced[request.ExecutionArn]; raced {
								if operation == "describeexecution" && strings.Contains(row.Label, ":terminal:") {
									r.racedChild(t, row)
								}
								return
							}
						}
						switch {
						case row.Service == "s3api":
							r.s3Call(t, row)
							return
						case operation == "redriveexecution":
							r.clients = r.reopen()
							r.drain(t)
						case operation == "describeexecution" && !strings.Contains(row.Label, ":child:"):
							var request struct{ ExecutionArn string }
							awsDecodeJSON(t, row.Input, &request)
							r.settle(t, request.ExecutionArn)
						case operation == "getexecutionhistory" && row.Result.Code == "Success":
							index = r.history(t, rows, index)
							return
						case operation == "listexecutions" && row.Result.Code == "Success":
							index = r.children(t, index)
							return
						}
						actual := r.stepFunctionsNativeReplay.call(t, row)
						r.drain(t)
						if actual == nil || row.Service != "stepfunctions" {
							return
						}
						if started, ok := actual.(*sfn.StartExecutionOutput); ok {
							r.bindMaps(t, aws.ToString(started.ExecutionArn))
						}
						if described, ok := actual.(*sfn.DescribeMapRunOutput); ok {
							// The one native extra success may still be pending locally;
							// resolve child membership before comparing Map counters.
							r.discoverRace(t, described)
							var expected sfn.DescribeMapRunOutput
							if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
								t.Fatal(err)
							}
							if expected.Status != "SUCCEEDED" && r.racedForMap(t, aws.ToString(expected.MapRunArn)) {
								expected.ItemCounts.Succeeded--
								expected.ItemCounts.Pending++
								expected.ExecutionCounts.Succeeded--
								expected.ExecutionCounts.Pending++
							}
							r.compare(t, "", stepFunctionsSDKObject(t, &expected), stepFunctionsSDKObject(t, actual))
							return
						}
						if definition, ok := actual.(*sfn.DescribeStateMachineForExecutionOutput); ok {
							var expected sfn.DescribeStateMachineForExecutionOutput
							if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
								t.Fatal(err)
							}
							// Synthesized processor definitions are structurally
							// equivalent JSON, unlike CreateStateMachine identity.
							r.compare(t, ".ProcessorDefinition", aws.ToString(expected.Definition), aws.ToString(definition.Definition))
							expected.Definition, definition.Definition = nil, nil
							r.compare(t, "", stepFunctionsSDKObject(t, &expected), stepFunctionsSDKObject(t, definition))
							return
						}
						r.compareSDK(t, row.Result.Output, actual)
					}) {
						return
					}
				}
				r.clients = r.reopen()
				for key, expected := range r.objects {
					actual := r.getObject(t, key)
					if !bytes.Equal(expected, actual) {
						t.Fatal("redrive result object changed after reopen", key)
					}
				}
				t.Log("not replayed: first/trust-confounded attempts, identity, cleanup and intermediate scheduling samples; child-list pages are compared as complete sets. Only the captured raced extra success may instead remain pending: its native detail history is inapplicable locally, its input/count/file membership is preserved, and its newly started final output is checked against the repaired object. All other parent/child histories and errors are retained; generated transport metadata and S3/Map-owned cancellation diagnostic prose are projected, never error classes or customer StopExecution causes")
			})
		}
	}
}

func (r *stepFunctionsRedriveMapReplay) settle(t *testing.T, arn string) {
	t.Helper()
	for range 1000 {
		r.drain(t)
		execution, err := r.maps.sfn().DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: &arn})
		if err != nil {
			t.Fatal(err)
		}
		if execution.Status != "RUNNING" {
			return
		}
		var work sfnstore.WorkRecord
		err = r.repository.View(t.Context(), func(reader sfnstore.Reader) error {
			var err error
			work, err = reader.NextWork()
			return err
		})
		if err != nil || work.Kind == sfnstore.WorkExecutionExpiry {
			t.Fatalf("running redrive Map has no pending transition: %v", err)
		}
		r.advance(t, work.Due)
	}
	t.Fatal("redrive Map did not settle")
}

func (r *stepFunctionsRedriveMapReplay) bindMaps(t *testing.T, parent string) {
	t.Helper()
	actual, err := r.maps.sfn().ListMapRuns(t.Context(), &sfn.ListMapRunsInput{ExecutionArn: &parent})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range r.rows {
		if stepFunctionsOperation(row.Operation) != "listmapruns" || row.Result.Code != "Success" {
			continue
		}
		var request struct{ ExecutionArn string }
		awsDecodeJSON(t, row.Input, &request)
		if request.ExecutionArn != parent {
			continue
		}
		var expected sfn.ListMapRunsOutput
		if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
			t.Fatal(err)
		}
		if len(expected.MapRuns) == 0 {
			continue
		}
		if len(expected.MapRuns) != 1 || len(actual.MapRuns) != 1 {
			t.Fatalf("native/local Map identities: %+v %+v", expected.MapRuns, actual.MapRuns)
		}
		nativeMap, localMap := aws.ToString(expected.MapRuns[0].MapRunArn), aws.ToString(actual.MapRuns[0].MapRunArn)
		r.maps.bindMap(t, nativeMap, localMap)
		nativeID := nativeMap[strings.LastIndexByte(nativeMap, ':')+1:]
		localID := localMap[strings.LastIndexByte(localMap, ':')+1:]
		for _, object := range r.rows {
			if object.Service != "s3api" {
				continue
			}
			var input struct{ Key string }
			awsDecodeJSON(t, object.Input, &input)
			if strings.Contains(input.Key, "/"+nativeID+"/") {
				r.bind(t, r.bindings, input.Key, strings.Replace(input.Key, "/"+nativeID+"/", "/"+localID+"/", 1), true)
			}
		}
		return
	}
	if len(actual.MapRuns) != 0 {
		t.Fatal("uncaptured MapRun", actual.MapRuns)
	}
}

func (r *stepFunctionsRedriveMapReplay) nativeChild(t *testing.T, arn string) *sfn.DescribeExecutionOutput {
	t.Helper()
	for _, row := range r.rows {
		if stepFunctionsOperation(row.Operation) != "describeexecution" || row.Result.Code != "Success" || !strings.Contains(row.Label, ":child:") {
			continue
		}
		var expected sfn.DescribeExecutionOutput
		if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
			t.Fatal(err)
		}
		if aws.ToString(expected.ExecutionArn) == arn {
			return &expected
		}
	}
	t.Fatal("missing captured child input", arn)
	return nil
}

func (r *stepFunctionsRedriveMapReplay) localChildren(t *testing.T, mapARN string) map[float64]*sfn.DescribeExecutionOutput {
	t.Helper()
	children, err := r.maps.sfn().ListExecutions(t.Context(), &sfn.ListExecutionsInput{MapRunArn: &mapARN, MaxResults: 1000})
	if err != nil || children.NextToken != nil {
		t.Fatalf("bounded Map child listing failed: %+v %v", children, err)
	}
	byItem := map[float64]*sfn.DescribeExecutionOutput{}
	for _, child := range children.Executions {
		actual, err := r.maps.sfn().DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: child.ExecutionArn})
		if err != nil {
			t.Fatal(err)
		}
		item := stepFunctionsMapItem(t, aws.ToString(actual.Input))
		if byItem[item] != nil {
			t.Fatal("duplicate Map child item", item)
		}
		byItem[item] = actual
	}
	return byItem
}

func (r *stepFunctionsRedriveMapReplay) discoverRace(t *testing.T, actual *sfn.DescribeMapRunOutput) {
	t.Helper()
	if actual.Status != "FAILED" {
		return
	}
	local := r.localChildren(t, aws.ToString(actual.MapRunArn))
	for _, row := range r.rows {
		if !strings.Contains(row.Label, ":failed:child:") || stepFunctionsOperation(row.Operation) != "describeexecution" {
			continue
		}
		var expected sfn.DescribeExecutionOutput
		if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
			t.Fatal(err)
		}
		if r.bindings[aws.ToString(expected.MapRunArn)] != aws.ToString(actual.MapRunArn) {
			continue
		}
		index := stepFunctionsMapItem(t, aws.ToString(expected.Input))
		if local[index] == nil && expected.Status == "SUCCEEDED" && index == 3 {
			r.raced[aws.ToString(expected.ExecutionArn)] = aws.ToString(expected.Input)
		}
	}
}

func (r *stepFunctionsRedriveMapReplay) racedForMap(t *testing.T, nativeMap string) bool {
	t.Helper()
	for arn := range r.raced {
		if aws.ToString(r.nativeChild(t, arn).MapRunArn) == nativeMap {
			return true
		}
	}
	return false
}

func (r *stepFunctionsRedriveMapReplay) children(t *testing.T, first int) int {
	t.Helper()
	var expected sfn.ListExecutionsOutput
	index := first
	for ; index < len(r.rows); index++ {
		var page sfn.ListExecutionsOutput
		if err := awstest.DecodeSDK(r.rows[index].Result.Output, &page); err != nil {
			t.Fatal(err)
		}
		expected.Executions = append(expected.Executions, page.Executions...)
		if page.NextToken == nil {
			break
		}
		if index+1 == len(r.rows) || stepFunctionsOperation(r.rows[index+1].Operation) != "listexecutions" {
			t.Fatal("incomplete captured child pages")
		}
	}
	var request sfn.ListExecutionsInput
	if err := awstest.DecodeSDK(r.input(t, r.rows[first].Input), &request); err != nil {
		t.Fatal(err)
	}
	request.MaxResults, request.NextToken = 1000, nil
	actual, err := r.maps.sfn().ListExecutions(t.Context(), &request)
	if err != nil || actual.NextToken != nil {
		t.Fatalf("bounded Map child listing failed: %+v %v", actual, err)
	}
	local := r.localChildren(t, aws.ToString(request.MapRunArn))
	kept := expected.Executions[:0]
	for _, child := range expected.Executions {
		arn := aws.ToString(child.ExecutionArn)
		native := r.nativeChild(t, arn)
		got := local[stepFunctionsMapItem(t, aws.ToString(native.Input))]
		if got == nil {
			if _, raced := r.raced[arn]; raced && child.Status == "SUCCEEDED" {
				continue
			}
			t.Fatal("missing Map child", arn)
		}
		if aws.ToString(got.StateMachineArn) != aws.ToString(native.StateMachineArn) {
			t.Fatal("Map child escaped processor namespace", got)
		}
		if _, raced := r.raced[arn]; raced && r.bindings[arn] == "" {
			run, err := r.maps.sfn().DescribeMapRun(t.Context(), &sfn.DescribeMapRunInput{MapRunArn: request.MapRunArn})
			if err != nil {
				t.Fatal(err)
			}
			r.racedGeneration[arn] = int64(aws.ToInt32(run.RedriveCount))
		}
		r.bind(t, r.bindings, arn, aws.ToString(got.ExecutionArn), true)
		r.bind(t, r.bindings, aws.ToString(native.Name), aws.ToString(got.Name), true)
		if strings.Contains(arn, ":express:") {
			nativeParts, localParts := strings.Split(arn, ":"), strings.Split(aws.ToString(got.ExecutionArn), ":")
			if len(nativeParts) != 9 || len(localParts) != 9 || strings.Join(nativeParts[:7], ":") != strings.Join(localParts[:7], ":") || !stepFunctionsContextUUID.MatchString(localParts[8]) {
				t.Fatal("invalid Express Map child identity", got)
			}
			// DescribeExecution.Name contains name:execution-id, whereas the
			// context's Execution.Name contains only the penultimate segment.
			r.bind(t, r.bindings, nativeParts[7], localParts[7], true)
			r.bind(t, r.bindings, nativeParts[8], localParts[8], true)
		}
		kept = append(kept, child)
	}
	expected.Executions = kept
	r.maps.compareExecutionLists(t, &expected, actual)
	return index
}

func (r *stepFunctionsRedriveMapReplay) racedChild(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	actual := r.stepFunctionsNativeReplay.call(t, row).(*sfn.DescribeExecutionOutput)
	var expected sfn.DescribeExecutionOutput
	if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
		t.Fatal(err)
	}
	r.compare(t, ".Input", aws.ToString(expected.Input), aws.ToString(actual.Input))
	if actual.Status != "SUCCEEDED" || aws.ToInt32(actual.RedriveCount) != 0 {
		t.Fatal("previously pending raced child did not execute once", actual)
	}
	var output struct {
		Object struct{ Body string }
		After  struct{ RedriveCount int64 }
	}
	awsDecodeJSON(t, []byte(aws.ToString(actual.Output)), &output)
	var replacement string
	for _, candidate := range r.rows {
		if strings.Contains(candidate.Label, "replace-successful-input-object") {
			var input struct{ Body struct{ UTF8 string } }
			awsDecodeJSON(t, candidate.Input, &input)
			if strings.Contains(row.Label, ":standard:") == strings.Contains(candidate.Label, ":standard:") {
				replacement = input.Body.UTF8
			}
		}
	}
	if replacement == "" || output.Object.Body != replacement || output.After.RedriveCount != 0 {
		t.Fatalf("newly started raced child did not consume repaired source: %+v", output)
	}
}

func stepFunctionsRedriveBody(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var body struct{ Base64, UTF8, SHA256 string }
	awsDecodeJSON(t, raw, &body)
	decoded, err := base64.StdEncoding.DecodeString(body.Base64)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != body.UTF8 || fmt.Sprintf("%x", sha256.Sum256(decoded)) != body.SHA256 {
		t.Fatal("captured S3 bytes failed integrity checks")
	}
	return decoded
}

func (r *stepFunctionsRedriveMapReplay) bucket(t *testing.T) string {
	t.Helper()
	for _, row := range r.rows {
		if row.Service == "s3api" && stepFunctionsOperation(row.Operation) == "createbucket" {
			var input struct{ Bucket string }
			awsDecodeJSON(t, row.Input, &input)
			return input.Bucket
		}
	}
	t.Fatal("missing captured S3 bucket")
	return ""
}

func (r *stepFunctionsRedriveMapReplay) getObject(t *testing.T, key string) []byte {
	t.Helper()
	actual, err := r.maps.s3().GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(r.bucket(t)), Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	defer actual.Body.Close()
	body, err := io.ReadAll(actual.Body)
	if err != nil || aws.ToInt64(actual.ContentLength) != int64(len(body)) {
		t.Fatalf("S3 body length/bytes: %v", err)
	}
	return body
}

func (r *stepFunctionsRedriveMapReplay) s3Call(t *testing.T, row stepFunctionsNativeObservation) {
	t.Helper()
	r.advance(t, time.UnixMilli(row.Started))
	var input map[string]json.RawMessage
	awsDecodeJSON(t, r.input(t, row.Input), &input)
	var body []byte
	if raw, ok := input["Body"]; ok {
		body = stepFunctionsRedriveBody(t, raw)
		delete(input, "Body")
	}
	request, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := awstest.CallSDK(t.Context(), r.maps.s3(), row.Operation, request, func(value any) {
		switch value := value.(type) {
		case *s3.PutObjectInput:
			value.Body = bytes.NewReader(body)
			// Match the captured S3 request semantics rather than the Go
			// SDK's implicit application/octet-stream request header.
			if value.ContentType == nil {
				value.ContentType = aws.String("binary/octet-stream")
			}
		case *s3.ListObjectsV2Input:
			value.EncodingType = "url"
		}
	})
	if row.Result.Code == "404" {
		var response interface{ HTTPStatusCode() int }
		if !errors.As(err, &response) || response.HTTPStatusCode() != 404 {
			t.Fatalf("expected captured S3 absence, got %v", err)
		}
		return
	}
	awsNativeResult(t, row.awsNativeObservation, err)
	if err != nil {
		return
	}
	switch actual := actual.(type) {
	case *s3.CreateBucketOutput:
		var expected s3.CreateBucketOutput
		if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
			t.Fatal(err)
		}
		r.compare(t, ".BucketArn", aws.ToString(expected.BucketArn), aws.ToString(actual.BucketArn))
	case *s3.PutObjectOutput:
		var expected s3.PutObjectOutput
		if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
			t.Fatal(err)
		}
		r.compare(t, ".ETag", aws.ToString(expected.ETag), aws.ToString(actual.ETag))
	case *s3.GetObjectOutput:
		defer actual.Body.Close()
		local, err := io.ReadAll(actual.Body)
		if err != nil || aws.ToInt64(actual.ContentLength) != int64(len(local)) {
			t.Fatalf("invalid S3 object body: %v", err)
		}
		var response struct{ Body json.RawMessage }
		awsDecodeJSON(t, row.Result.Output, &response)
		native := stepFunctionsRedriveBody(t, response.Body)
		var key string
		awsDecodeJSON(t, input["Key"], &key)
		if !strings.HasPrefix(key, "results/") {
			if !bytes.Equal(native, local) {
				t.Fatalf("repaired S3 source bytes differ: native=%q local=%q", native, local)
			}
			return
		}
		if prior, ok := r.objects[key]; ok && !bytes.Equal(prior, local) {
			t.Fatal("redrive overwrote an earlier result generation", key)
		}
		r.objects[key] = local
		r.result(t, key, native, local)
	case *s3.ListObjectsV2Output:
		var expected s3.ListObjectsV2Output
		if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
			t.Fatal(err)
		}
		if actual.NextContinuationToken != nil || aws.ToBool(actual.IsTruncated) || len(actual.Contents) != len(expected.Contents) {
			t.Fatalf("result membership differs: native=%+v local=%+v", expected.Contents, actual.Contents)
		}
		want := map[string]bool{}
		for _, entry := range expected.Contents {
			key := aws.ToString(entry.Key)
			if bound := r.bindings[key]; bound != "" {
				key = bound
			}
			want[key] = true
		}
		for _, entry := range actual.Contents {
			key := aws.ToString(entry.Key)
			if !want[key] || aws.ToInt64(entry.Size) != int64(len(r.getObject(t, key))) {
				t.Fatal("unexpected result key or object size", key)
			}
			delete(want, key)
		}
	default:
		t.Fatalf("unmapped redrive S3 output %T", actual)
	}
}

func (r *stepFunctionsRedriveMapReplay) result(t *testing.T, key string, native, local []byte) {
	t.Helper()
	want, got := stepFunctionsMapResult(t, key, native), stepFunctionsMapResult(t, key, local)
	if path.Base(key) == "manifest.json" {
		files := want.(map[string]any)["ResultFiles"].(map[string]any)
		for _, raw := range files {
			for _, member := range raw.([]any) {
				entry := member.(map[string]any)
				nativeKey := entry["Key"].(string)
				var nativeSize int
				for _, row := range r.rows {
					if row.Service != "s3api" || stepFunctionsOperation(row.Operation) != "getobject" {
						continue
					}
					var request struct{ Key string }
					awsDecodeJSON(t, row.Input, &request)
					if request.Key == nativeKey {
						var response struct{ Body json.RawMessage }
						awsDecodeJSON(t, row.Result.Output, &response)
						nativeSize = len(stepFunctionsRedriveBody(t, response.Body))
						break
					}
				}
				if nativeSize == 0 || entry["Size"] != float64(nativeSize) {
					t.Fatal("captured manifest size differs from exported bytes", nativeKey)
				}
				entry["Size"] = float64(len(r.getObject(t, r.bindings[nativeKey])))
			}
		}
	} else {
		expected, actual := want.([]any), got.([]any)
		for arn, input := range r.raced {
			nativeMap := aws.ToString(r.nativeChild(t, arn).MapRunArn)
			localMap := r.bindings[nativeMap]
			if !strings.Contains(key, "/"+localMap[strings.LastIndexByte(localMap, ':')+1:]+"/") {
				continue
			}
			var generation int64
			if _, suffix, redriven := strings.Cut(key, "/Redrive-"); redriven {
				if _, err := fmt.Sscanf(suffix, "%d/", &generation); err != nil {
					t.Fatal("invalid result generation", key)
				}
			}
			born, admitted := r.racedGeneration[arn]
			// Compare the immutable file's generation, not the child's current
			// status: later manifests still reference the old pending export.
			if path.Base(key) == "PENDING_0.json" && (!admitted || generation < born) {
				expected = append(expected, map[string]any{"Input": input, "InputDetails": map[string]any{"Included": true}, "Status": "PENDING"})
			}
			if path.Base(key) == "SUCCEEDED_0.json" {
				if admitted && generation == born {
					removed := 0
					actual = slices.DeleteFunc(actual, func(value any) bool {
						if value.(map[string]any)["ExecutionArn"] == r.bindings[arn] {
							removed++
							return true
						}
						return false
					})
					if removed != 1 {
						t.Fatal("new raced child missing from redrive result generation", key)
					}
				} else if !strings.Contains(key, "/Redrive-") {
					expected = slices.DeleteFunc(expected, func(value any) bool { return value.(map[string]any)["ExecutionArn"] == arn })
				}
			}
		}
		for _, values := range [][]any{expected, actual} {
			slices.SortFunc(values, func(a, b any) int {
				left := stepFunctionsMapItem(t, a.(map[string]any)["Input"].(string))
				right := stepFunctionsMapItem(t, b.(map[string]any)["Input"].(string))
				if left < right {
					return -1
				}
				if left > right {
					return 1
				}
				return 0
			})
		}
		want, got = expected, actual
	}
	r.compare(t, ".Result(JSON)", r.projection(t, "", want), r.projection(t, "", got))
}
