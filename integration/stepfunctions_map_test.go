package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	sfnstore "stackd/storage/stepfunctions"
)

type stepFunctionsMapObservation struct {
	Label, Service, Operation string
	At                        time.Time
	Request, Response         json.RawMessage
}

type stepFunctionsMapFixture struct {
	Account      string `json:"caller_account"`
	Region       string
	Started      time.Time `json:"started_at"`
	Observations []stepFunctionsMapObservation
	Runs         map[string]struct {
		ExecutionARN string `json:"executionArn"`
		Terminal     json.RawMessage
	}
}

type stepFunctionsMapReplay struct {
	*stepFunctionsNativeReplay
	fixture                 stepFunctionsMapFixture
	repository              sfnstore.Repository
	metadataDate            float64
	cancelExtraARN          string
	objects                 map[string][]byte
	cancelWithoutExtraChild bool
}

// Replay settled observations, not AWS polling/propagation latency. In the
// cancellation capture one extra child succeeded before threshold propagation.
// The only scheduling projection permits that child to remain never-started:
// its captured input moves from SUCCEEDED to PENDING, with all four inputs,
// failure diagnostics, counts and result-file membership still accounted for.
// Generated labels, child identities, dates and result keys are bound explicitly.
func TestStepFunctionsNativeDistributedMapConsumers(t *testing.T) {
	var fixture stepFunctionsMapFixture
	awsReadFixture(t, "stepfunctions/distributed_map.json", &fixture)
	cases := []string{"cancel_pending", "tolerated_failure", "json_pointer_batch", "csv_pipe_batch", "jsonata_flatten", "s3_metadata", "s3_load_flatten"}
	if len(fixture.Runs) != len(cases) {
		t.Fatal("distributed Map fixture cases changed", len(fixture.Runs))
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := &stepFunctionsReplayClock{Manual: clock.NewManual(fixture.Started), timers: make(chan time.Time, 256)}
			r := &stepFunctionsMapReplay{fixture: fixture, objects: map[string][]byte{}, stepFunctionsNativeReplay: &stepFunctionsNativeReplay{
				fixture: stepFunctionsNativeFixture{Account: fixture.Account, Region: fixture.Region}, clock: source,
				identity: aws.Credentials{AccessKeyID: fixture.Account, SecretAccessKey: "test"}, bindings: map[string]string{}, timestamps: map[string]string{},
			}}
			r.clients, r.reopen = retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				r.repository = config.Storage.StepFunctions
				return startPublicCloud(t, config)
			})
			r.setup(t)
			for _, name := range cases {
				if !t.Run(name, func(t *testing.T) { r.run(t, name) }) {
					return
				}
			}
			// Completed exports must survive a fresh graph/database handle without
			// republishing or changing bytes. All reads use the real S3 frontend.
			r.clients = r.reopen()
			r.drain(t)
			for key, body := range r.objects {
				got := r.getObject(t, key)
				if !bytes.Equal(body, got) {
					t.Fatalf("result object changed across reopen: %s", key)
				}
			}
			r.listObjects(t, r.row(t, "s3_load_flatten:objects"))
			t.Log("not replayed: preflight identity/definition-validation probes, immediate/eventually-consistent empty lists, intermediate poll samples, native delays and cross-service timestamp ordering, multipart ETags/checksum algorithm/HTTP metadata, previous failed capture attempt and cleanup calls; cancellation's single raced extra child is the sole count/payload projection")
		})
	}
}

func (r *stepFunctionsMapReplay) row(t *testing.T, label string) stepFunctionsMapObservation {
	t.Helper()
	for _, row := range r.fixture.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatal("missing distributed Map observation", label)
	return stepFunctionsMapObservation{}
}

func (r *stepFunctionsMapReplay) sfn() *sfn.Client {
	return sfn.New(sfn.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
}

func (r *stepFunctionsMapReplay) s3() *s3.Client {
	return s3.New(s3.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", ""), HTTPClient: r.clients.server.Client(), UsePathStyle: true, RetryMaxAttempts: 1})
}

func (r *stepFunctionsMapReplay) call(t *testing.T, row stepFunctionsMapObservation) any {
	t.Helper()
	out, err := awstest.CallSDK(t.Context(), r.sfn(), strings.ReplaceAll(row.Operation, "_", ""), r.input(t, row.Request))
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	return out
}

func (r *stepFunctionsMapReplay) setup(t *testing.T) {
	t.Helper()
	for _, row := range r.fixture.Observations {
		if !strings.HasPrefix(row.Label, "setup:") {
			continue
		}
		r.advance(t, row.At)
		switch row.Service {
		case "iam", "stepfunctions":
			var native stepFunctionsNativeObservation
			native.Label, native.Service = row.Label, row.Service
			native.Operation, native.Input = strings.ReplaceAll(row.Operation, "_", ""), row.Request
			native.Result.Code, native.Result.Output = "Success", row.Response
			r.replay(t, native)
		case "s3":
			if row.Operation == "create_bucket" {
				var input s3.CreateBucketInput
				awsDecodeJSON(t, row.Request, &input)
				if _, err := r.s3().CreateBucket(t.Context(), &input); err != nil {
					t.Fatal(err)
				}
				continue
			}
			var input struct {
				Bucket, Key string
				Body        struct{ Base64 string }
			}
			awsDecodeJSON(t, row.Request, &input)
			body, err := base64.StdEncoding.DecodeString(input.Body.Base64)
			if err != nil {
				t.Fatal(err)
			}
			put, err := r.s3().PutObject(t.Context(), &s3.PutObjectInput{Bucket: &input.Bucket, Key: &input.Key, Body: bytes.NewReader(body)})
			if err != nil {
				t.Fatal(err)
			}
			var native struct{ ETag string }
			awsDecodeJSON(t, row.Response, &native)
			if aws.ToString(put.ETag) != native.ETag {
				t.Fatalf("captured input bytes differ for %s", input.Key)
			}
		}
	}
	// LastModified is service-generated metadata, not part of the input bytes.
	// Bind its numeric JSON representation to the public S3 listing, never to
	// whatever the workflow happens to return.
	listed, err := r.s3().ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String(r.bucket(t)), Prefix: aws.String("flat/")})
	if err != nil || len(listed.Contents) != 1 || listed.Contents[0].LastModified == nil {
		t.Fatalf("source object metadata unavailable: %+v %v", listed, err)
	}
	r.metadataDate = float64(listed.Contents[0].LastModified.Unix()) + float64(listed.Contents[0].LastModified.Nanosecond())/1e9
}

func (r *stepFunctionsMapReplay) bucket(t *testing.T) string {
	t.Helper()
	var input struct{ Bucket string }
	awsDecodeJSON(t, r.row(t, "setup:bucket").Request, &input)
	return input.Bucket
}

func (r *stepFunctionsMapReplay) drain(t *testing.T) {
	r.stepFunctionsNativeReplay.drainEffects(t, r.repository)
}

func (r *stepFunctionsMapReplay) run(t *testing.T, name string) {
	t.Helper()
	start := r.row(t, name+":start")
	r.advance(t, start.At)
	r.compareSDK(t, start.Response, r.call(t, start))
	r.drain(t)
	parent := r.fixture.Runs[name].ExecutionARN
	maps, err := r.sfn().ListMapRuns(t.Context(), &sfn.ListMapRunsInput{ExecutionArn: &parent})
	if err != nil || len(maps.MapRuns) != 1 {
		terminal, describeErr := r.sfn().DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: &parent})
		t.Fatalf("MapRun admission: %+v %v; parent=%+v describe=%v", maps, err, stepFunctionsSDKObject(t, terminal), describeErr)
	}
	var nativeMap sfn.DescribeMapRunOutput
	if err := awstest.DecodeSDK(r.row(t, name+":settled:map").Response, &nativeMap); err != nil {
		t.Fatal(err)
	}
	localMap := aws.ToString(maps.MapRuns[0].MapRunArn)
	r.bindMap(t, aws.ToString(nativeMap.MapRunArn), localMap)
	if name == "cancel_pending" {
		early := r.row(t, name+":early:map")
		r.compareSDK(t, early.Response, r.call(t, early))
		children := r.row(t, name+":early:children")
		r.compareChildren(t, name, "early", r.call(t, children).(*sfn.ListExecutionsOutput))
		// Close with a real RUNNING child in Wait and three never-started
		// inputs. Recovery must preserve the MapRun and resume the same child.
		r.clients = r.reopen()
		r.drain(t)
		r.compareSDK(t, early.Response, r.call(t, early))
		r.compareChildren(t, name, "early", r.call(t, children).(*sfn.ListExecutionsOutput))
	}
	var terminal *sfn.DescribeExecutionOutput
	for range 1000 {
		r.drain(t)
		terminal, err = r.sfn().DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: &parent})
		if err != nil {
			t.Fatal(err)
		}
		if string(terminal.Status) != "RUNNING" {
			break
		}
		var work sfnstore.WorkRecord
		err = r.repository.View(t.Context(), func(reader sfnstore.Reader) error { var err error; work, err = reader.NextWork(); return err })
		if errors.Is(err, sfnstore.ErrNotFound) || err == nil && work.Kind == sfnstore.WorkExecutionExpiry {
			t.Fatal("running Map has no retained work")
		}
		if err != nil {
			t.Fatal(err)
		}
		r.advance(t, work.Due)
	}
	if terminal == nil || string(terminal.Status) == "RUNNING" {
		t.Fatal("Map did not terminate")
	}
	r.drain(t)
	actualMap := r.call(t, r.row(t, name+":settled:map")).(*sfn.DescribeMapRunOutput)
	if name == "cancel_pending" {
		succeeded := actualMap.ExecutionCounts.Succeeded
		if succeeded != 0 && succeeded != 1 {
			t.Fatalf("unexpected cancellation scheduling: %+v", actualMap.ExecutionCounts)
		}
		r.cancelWithoutExtraChild = succeeded == 0
		if r.cancelWithoutExtraChild {
			nativeMap.ExecutionCounts.Pending++
			nativeMap.ItemCounts.Pending++
			nativeMap.ExecutionCounts.Succeeded--
			nativeMap.ItemCounts.Succeeded--
			t.Log("captured extra index=1 success raced threshold propagation; locally still PENDING; retaining exact failure and four-input accounting")
		}
	}
	r.compare(t, "", stepFunctionsSDKObject(t, &nativeMap), stepFunctionsSDKObject(t, actualMap))
	r.compareChildren(t, name, "terminal", r.call(t, r.row(t, name+":settled:children")).(*sfn.ListExecutionsOutput))
	r.bindResultKeys(t, name, aws.ToString(nativeMap.MapRunArn), localMap)
	r.compareSDK(t, r.fixture.Runs[name].Terminal, terminal)
	r.compareSDK(t, r.row(t, name+":settled:list_maps").Response, r.call(t, r.row(t, name+":settled:list_maps")))
	for _, row := range r.fixture.Observations {
		if !strings.HasPrefix(row.Label, name+":terminal:") {
			continue
		}
		if strings.Contains(row.Label, ":filter_") || strings.HasSuffix(row.Label, ":machine_members") {
			actual := r.call(t, row).(*sfn.ListExecutionsOutput)
			var expected sfn.ListExecutionsOutput
			if err := awstest.DecodeSDK(row.Response, &expected); err != nil {
				t.Fatal(err)
			}
			r.projectChildren(&expected)
			r.compareExecutionLists(t, &expected, actual)
		}
		if strings.HasSuffix(row.Label, ":parent_history") {
			r.compareSDK(t, row.Response, r.call(t, row))
		}
	}
	r.results(t, name)
	r.listObjects(t, r.row(t, name+":objects"))
}

func (r *stepFunctionsMapReplay) bindMap(t *testing.T, native, local string) {
	t.Helper()
	nativePrefix, nativeID := native[:strings.LastIndexByte(native, ':')], native[strings.LastIndexByte(native, ':')+1:]
	localPrefix, localID := local[:strings.LastIndexByte(local, ':')], local[strings.LastIndexByte(local, ':')+1:]
	nativeMachine, nativeLabel, ok := strings.Cut(nativePrefix, "/")
	localMachine, localLabel, localOK := strings.Cut(localPrefix, "/")
	if !ok || !localOK || nativeMachine != localMachine || !stepFunctionsContextUUID.MatchString(localID) {
		t.Fatalf("invalid generated MapRun ARN: native=%s local=%s", native, local)
	}
	if !stepFunctionsContextUUID.MatchString(nativeLabel) {
		if localLabel != nativeLabel {
			t.Fatal("explicit Map label changed", localLabel)
		}
	} else if !stepFunctionsContextUUID.MatchString(localLabel) {
		t.Fatal("invalid generated Map label", localLabel)
	}
	r.bind(t, r.bindings, native, local, true)
	r.bind(t, r.bindings, nativeID, localID, true)
	r.bind(t, r.bindings, nativeLabel, localLabel, true)
	r.bind(t, r.bindings, strings.Replace(nativePrefix, ":mapRun:", ":stateMachine:", 1), strings.Replace(localPrefix, ":mapRun:", ":stateMachine:", 1), true)
}

func stepFunctionsMapItem(t *testing.T, input string) float64 {
	t.Helper()
	var value any
	awsDecodeJSON(t, json.RawMessage(input), &value)
	if number, ok := value.(float64); ok {
		return number
	}
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatal("unexpected captured child input", input)
	}
	if items, ok := object["Items"].([]any); ok && len(items) != 0 {
		object = items[0].(map[string]any)
	}
	index, ok := object["index"].(float64)
	if !ok {
		t.Fatal("child input has no item identity", input)
	}
	return index
}

func (r *stepFunctionsMapReplay) compareChildren(t *testing.T, name, phase string, actual *sfn.ListExecutionsOutput) {
	t.Helper()
	byItem := map[float64]*sfn.DescribeExecutionOutput{}
	for _, child := range actual.Executions {
		described, err := r.sfn().DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: child.ExecutionArn})
		if err != nil {
			t.Fatal(err)
		}
		item := stepFunctionsMapItem(t, aws.ToString(described.Input))
		if byItem[item] != nil {
			t.Fatal("duplicate Map child for input", item)
		}
		byItem[item] = described
	}
	for _, row := range r.fixture.Observations {
		if row.Label != name+":"+phase+":child_describe" {
			continue
		}
		var expected sfn.DescribeExecutionOutput
		if err := awstest.DecodeSDK(row.Response, &expected); err != nil {
			t.Fatal(err)
		}
		item := stepFunctionsMapItem(t, aws.ToString(expected.Input))
		if name == "cancel_pending" && phase == "terminal" && r.cancelWithoutExtraChild && item == 1 {
			r.cancelExtraARN = aws.ToString(expected.ExecutionArn)
			continue
		}
		got := byItem[item]
		if got == nil {
			t.Fatalf("missing child for captured item %v", item)
		}
		delete(byItem, item)
		expectedMachine := aws.ToString(expected.StateMachineArn)
		localMachine := r.bindings[expectedMachine]
		if aws.ToString(got.StateMachineArn) != localMachine || aws.ToString(got.ExecutionArn) != strings.Replace(localMachine, ":stateMachine:", ":execution:", 1)+":"+aws.ToString(got.Name) {
			t.Fatalf("child is not in bound MapRun namespace: %+v", got)
		}
		r.bind(t, r.bindings, aws.ToString(expected.ExecutionArn), aws.ToString(got.ExecutionArn), true)
		r.bind(t, r.bindings, aws.ToString(expected.Name), aws.ToString(got.Name), true)
		r.compareSDK(t, row.Response, got)
		for _, detail := range r.fixture.Observations {
			if detail.Label != name+":"+phase+":child_history" && detail.Label != name+":"+phase+":child_definition" {
				continue
			}
			var request struct{ ExecutionArn string }
			awsDecodeJSON(t, detail.Request, &request)
			if request.ExecutionArn == aws.ToString(expected.ExecutionArn) {
				r.compareSDK(t, detail.Response, r.call(t, detail))
			}
		}
	}
	if len(byItem) != 0 {
		t.Fatal("unexpected Map children", byItem)
	}
	label := name + ":" + phase + ":children"
	if phase == "terminal" {
		label = name + ":settled:children"
	}
	var expected sfn.ListExecutionsOutput
	if err := awstest.DecodeSDK(r.row(t, label).Response, &expected); err != nil {
		t.Fatal(err)
	}
	r.projectChildren(&expected)
	r.compareExecutionLists(t, &expected, actual)
}

func (r *stepFunctionsMapReplay) projectChildren(expected *sfn.ListExecutionsOutput) {
	if !r.cancelWithoutExtraChild {
		return
	}
	expected.Executions = slices.DeleteFunc(expected.Executions, func(child sfntypes.ExecutionListItem) bool {
		return aws.ToString(child.ExecutionArn) == r.cancelExtraARN
	})
}

func (r *stepFunctionsMapReplay) compareExecutionLists(t *testing.T, expected, actual *sfn.ListExecutionsOutput) {
	t.Helper()
	// Start-date ties may reorder independent children. Bind by their complete
	// captured input first, then compare every listed member and status.
	want, got := stepFunctionsSDKObject(t, expected), stepFunctionsSDKObject(t, actual)
	for _, object := range []map[string]any{want, got} {
		entries, _ := object["Executions"].([]any)
		slices.SortFunc(entries, func(a, b any) int {
			key := func(v any) string {
				arn := v.(map[string]any)["ExecutionArn"].(string)
				if bound, ok := r.bindings[arn]; ok {
					return bound
				}
				return arn
			}
			return strings.Compare(key(a), key(b))
		})
	}
	r.compare(t, "", want, got)
}

func (r *stepFunctionsMapReplay) compareSDK(t *testing.T, raw json.RawMessage, actual any) {
	t.Helper()
	expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
	if err := awstest.DecodeSDK(raw, expected); err != nil {
		t.Fatal(err)
	}
	want, got := stepFunctionsSDKObject(t, expected), stepFunctionsSDKObject(t, actual)
	want = r.metadata(t, want).(map[string]any)
	if _, ok := actual.(*sfn.GetExecutionHistoryOutput); ok {
		r.compareHistory(t, want, got)
		return
	}
	// A child DescribeStateMachineForExecution returns a synthesized processor
	// definition, not CreateStateMachine's byte-sensitive idempotency input.
	if definition, ok := want["Definition"].(string); ok {
		r.compare(t, ".ProcessorDefinition", definition, got["Definition"])
		delete(want, "Definition")
		delete(got, "Definition")
	}
	if want["Error"] != nil {
		r.compare(t, ".FailureCause", want["Cause"], got["Cause"])
	}
	r.compare(t, "", want, got)
}

func (r *stepFunctionsMapReplay) metadata(t *testing.T, value any) any {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		if v["Key"] == "flat/data.jsonl" && v["LastModified"] != nil {
			v["LastModified"] = r.metadataDate
		}
		for key, child := range v {
			if key != "Definition" {
				v[key] = r.metadata(t, child)
			}
		}
	case []any:
		for index, child := range v {
			v[index] = r.metadata(t, child)
		}
	case string:
		if json.Valid([]byte(v)) {
			var decoded any
			awsDecodeJSON(t, json.RawMessage(v), &decoded)
			encoded, err := json.Marshal(r.metadata(t, decoded))
			if err != nil {
				t.Fatal(err)
			}
			return string(encoded)
		}
	}
	return value
}

func (r *stepFunctionsMapReplay) bindResultKeys(t *testing.T, name, nativeMap, localMap string) {
	t.Helper()
	nativeID, localID := nativeMap[strings.LastIndexByte(nativeMap, ':')+1:], localMap[strings.LastIndexByte(localMap, ':')+1:]
	for _, row := range r.fixture.Observations {
		if row.Label != name+":download" {
			continue
		}
		var input struct{ Key string }
		awsDecodeJSON(t, row.Request, &input)
		if !strings.Contains(input.Key, "/"+nativeID+"/") {
			t.Fatal("result key does not belong to captured MapRun", input.Key)
		}
		r.bind(t, r.bindings, input.Key, strings.Replace(input.Key, "/"+nativeID+"/", "/"+localID+"/", 1), true)
	}
}

func stepFunctionsMapCapturedBody(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var response struct {
		Body struct {
			Base64, UTF8, SHA256 string
			Size                 int
		}
	}
	awsDecodeJSON(t, raw, &response)
	body, err := base64.StdEncoding.DecodeString(response.Body.Base64)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != response.Body.Size || string(body) != response.Body.UTF8 || fmt.Sprintf("%x", sha256.Sum256(body)) != response.Body.SHA256 {
		t.Fatal("captured writer bytes failed integrity checks")
	}
	return body
}

func (r *stepFunctionsMapReplay) getObject(t *testing.T, key string) []byte {
	t.Helper()
	out, err := r.s3().GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(r.bucket(t)), Key: &key})
	if err != nil {
		t.Fatalf("get result %s: %v", key, err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToInt64(out.ContentLength) != int64(len(body)) {
		t.Fatal("S3 content length differs from returned result bytes", key)
	}
	return body
}

func stepFunctionsMapResult(t *testing.T, key string, body []byte) any {
	t.Helper()
	var value any
	if strings.HasSuffix(key, ".jsonl") {
		if len(body) == 0 || body[len(body)-1] != '\n' {
			t.Fatal("JSONL result lacks final record delimiter", key)
		}
		var entries []any
		for _, line := range bytes.Split(body[:len(body)-1], []byte{'\n'}) {
			awsDecodeJSON(t, line, &value)
			entries = append(entries, value)
		}
		return entries
	}
	awsDecodeJSON(t, body, &value)
	return value
}

func (r *stepFunctionsMapReplay) results(t *testing.T, name string) {
	t.Helper()
	var pendingExtra map[string]any
	if name == "cancel_pending" && r.cancelWithoutExtraChild {
		for _, row := range r.fixture.Observations {
			if row.Label != name+":terminal:child_describe" {
				continue
			}
			var child sfn.DescribeExecutionOutput
			if err := awstest.DecodeSDK(row.Response, &child); err != nil {
				t.Fatal(err)
			}
			if stepFunctionsMapItem(t, aws.ToString(child.Input)) == 1 {
				pendingExtra = map[string]any{"Input": aws.ToString(child.Input), "InputDetails": map[string]any{"Included": true}, "Status": "PENDING"}
			}
		}
		if pendingExtra == nil {
			t.Fatal("missing captured raced child input")
		}
	}
	var manifestRow stepFunctionsMapObservation
	nativeSizes := map[string]int{}
	for _, row := range r.fixture.Observations {
		if row.Label != name+":download" {
			continue
		}
		var input struct{ Key string }
		awsDecodeJSON(t, row.Request, &input)
		captured := stepFunctionsMapCapturedBody(t, row.Response)
		nativeSizes[input.Key] = len(captured)
		if path.Base(input.Key) == "manifest.json" {
			manifestRow = row
			continue
		}
		if pendingExtra != nil && path.Base(input.Key) == "SUCCEEDED_0.json" {
			continue
		}
		want := stepFunctionsMapResult(t, input.Key, captured)
		if pendingExtra != nil && path.Base(input.Key) == "PENDING_0.json" {
			want = append([]any{pendingExtra}, want.([]any)...)
		}
		key := r.bindings[input.Key]
		body := r.getObject(t, key)
		r.objects[key] = body
		r.compare(t, ".Result(JSON)", want, stepFunctionsMapResult(t, key, body))
	}
	if manifestRow.Label == "" {
		return
	}
	var request struct{ Key string }
	awsDecodeJSON(t, manifestRow.Request, &request)
	want := stepFunctionsMapResult(t, request.Key, stepFunctionsMapCapturedBody(t, manifestRow.Response)).(map[string]any)
	files := want["ResultFiles"].(map[string]any)
	if pendingExtra != nil {
		files["SUCCEEDED"] = []any{}
	}
	for _, entries := range files {
		for _, raw := range entries.([]any) {
			entry := raw.(map[string]any)
			nativeKey := entry["Key"].(string)
			if entry["Size"] != float64(nativeSizes[nativeKey]) {
				t.Fatal("captured manifest size differs from captured object bytes", nativeKey)
			}
			body, exists := r.objects[r.bindings[nativeKey]]
			if !exists {
				t.Fatal("manifest references unread result", nativeKey)
			}
			// Sizes are byte counts, so bind to real exported bytes after checking
			// payload structure; generated names/date spelling change lengths.
			entry["Size"] = float64(len(body))
		}
	}
	key := r.bindings[request.Key]
	body := r.getObject(t, key)
	r.objects[key] = body
	r.compare(t, ".Manifest(JSON)", want, stepFunctionsMapResult(t, key, body))
}

func (r *stepFunctionsMapReplay) listObjects(t *testing.T, row stepFunctionsMapObservation) {
	t.Helper()
	var input s3.ListObjectsV2Input
	awsDecodeJSON(t, row.Request, &input)
	actual, err := r.s3().ListObjectsV2(t.Context(), &input)
	if err != nil {
		t.Fatal(err)
	}
	var native s3.ListObjectsV2Output
	if err := awstest.DecodeSDK(row.Response, &native); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, object := range native.Contents {
		key := aws.ToString(object.Key)
		if r.cancelWithoutExtraChild && strings.Contains(key, "results/cancel/") && path.Base(key) == "SUCCEEDED_0.json" {
			continue
		}
		bound, ok := r.bindings[key]
		if !ok {
			t.Fatal("unbound captured writer key", key)
		}
		want[bound] = true
	}
	if aws.ToBool(actual.IsTruncated) || len(actual.Contents) != len(want) || int(aws.ToInt32(actual.KeyCount)) != len(want) {
		t.Fatalf("result object membership differs: native=%v local=%+v", want, actual)
	}
	for _, object := range actual.Contents {
		key := aws.ToString(object.Key)
		if !want[key] {
			t.Fatal("unexpected result object", key)
		}
		if body, ok := r.objects[key]; !ok || aws.ToInt64(object.Size) != int64(len(body)) {
			t.Fatal("listed result size differs from public GetObject", key)
		}
		if object.LastModified == nil || object.LastModified.After(r.clock.Now()) {
			t.Fatal("invalid result LastModified", key)
		}
		delete(want, key)
	}
}
