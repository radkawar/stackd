package stackd_test

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	sfnstore "stackd/storage/stepfunctions"
)

type stepFunctionsTaskObservation struct {
	awsNativeObservation
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	BodyBytes  *struct {
		Base64 string
		Length int
	} `json:"body_bytes"`
}

type stepFunctionsTaskReplay struct {
	*stepFunctionsNativeReplay
	messages   []sqstypes.Message
	repository sfnstore.Repository
}

// Replay the recorded requests in order, including the interrupted cleanup and
// subsequent recreation. This fixture's "recovery" is native machine recreation,
// not evidence of AWS process/crash recovery. The local reopen below separately
// checks retained IAM/rule/revision state before a new execution is admitted.
func TestStepFunctionsNativeTaskIntegrations(t *testing.T) {
	var fixture struct {
		Account, Region string
		Observations    []stepFunctionsTaskObservation
	}
	awsReadFixture(t, "stepfunctions/task_integrations.json", &fixture)
	if len(fixture.Observations) < 164 {
		t.Fatal("native task fixture is missing the no-polling nested completion")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := stepFunctionsTaskCloud(t, backend, stepFunctionsNativeFixture{Account: fixture.Account, Region: fixture.Region}, fixture.Observations[0].StartedAt)
			for index, row := range fixture.Observations[:164] {
				operation := stepFunctionsOperation(row.Operation)
				if operation == "getcalleridentity" || row.Result.Code == "CLIError" {
					// CLI get-object failures contain no retained service result;
					// observations 105-107 retain actual bytes and replace no errors.
					continue
				}
				if index == 4 {
					// The just-created primary principal was not propagated to IAM.
					// The identical request succeeds at observation 6 after 30s.
					t.Log("omitting measured IAM principal propagation failure at observation 4; replaying identical settled create at 6")
					continue
				}
				var observed struct{ Status string }
				if row.Result.Code == "Success" && len(row.Result.Output) != 0 {
					awsDecodeJSON(t, row.Result.Output, &observed)
				}
				if observed.Status == "DELETING" || observed.Status == "RUNNING" && operation == "describeexecution" {
					// Keep the exact subsequent terminal/absence observation, not
					// native deletion or one-second child scheduling latency.
					continue
				}
				if !t.Run(fmt.Sprintf("%03d-%s", index, row.Label), func(t *testing.T) {
					r.call(t, row)
					if index == 156 {
						// All earlier executions are terminal. Reopen the real stores
						// after BOTH polling and EventBridge grants have been removed.
						// The next captured .sync:2 must use the retained managed rule
						// and its real EventBridge delivery, not a producer-side wakeup.
						r.clients = r.reopen()
						r.retainedPolicy(t, row)
						r.call(t, fixture.Observations[143])
						r.call(t, fixture.Observations[144])
					}
				}) {
					return
				}
			}
			t.Log("native coverage ends at observation 163; final resource cleanup/deletion polling (164 onward) is outside this task contract")
			t.Log("native .sync and .sync:2 pair retains polling grants (146-154); BOTH grants removed (156-163) captures .sync:2 only, not a second .sync probe")
			t.Log("projections: AWS gateway-only headers and representation-dependent encoded lengths, service-owned diagnostics for six named failure probes, generated IDs/tokens/receipts/session names, timestamp magnitudes and SQS receive batch boundaries/long-poll latency; SDK metadata status, modeled headers and request-ID relationships, payload types, service error classes, destination bytes, message attributes, causal history and managed rule/targets remain checked; this fixture has no Catch probe")
		})
	}
}

func stepFunctionsTaskCloud(t *testing.T, backend string, fixture stepFunctionsNativeFixture, start time.Time) *stepFunctionsTaskReplay {
	t.Helper()
	source := &stepFunctionsReplayClock{Manual: clock.NewManual(start.Truncate(time.Millisecond)), timers: make(chan time.Time, 256)}
	r := &stepFunctionsTaskReplay{stepFunctionsNativeReplay: &stepFunctionsNativeReplay{
		fixture: fixture, clock: source,
		identity: aws.Credentials{AccessKeyID: fixture.Account, SecretAccessKey: "test"},
		bindings: map[string]string{}, timestamps: map[string]string{},
	}}
	r.clients, r.reopen = retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		r.repository = config.Storage.StepFunctions
		return startPublicCloud(t, config)
	})
	return r
}

func (r *stepFunctionsTaskReplay) drain(t *testing.T) {
	r.stepFunctionsNativeReplay.drainEffects(t, r.repository)
}

func (r *stepFunctionsTaskReplay) call(t *testing.T, row stepFunctionsTaskObservation) any {
	t.Helper()
	r.advance(t, row.StartedAt.Truncate(time.Millisecond))
	if stepFunctionsOperation(row.Operation) == "describeexecution" {
		r.advance(t, row.FinishedAt.Truncate(time.Millisecond))
	}
	config := aws.Config{Region: r.fixture.Region, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenSupported,
		Credentials:                credentials.NewStaticCredentialsProvider(r.identity.AccessKeyID, r.identity.SecretAccessKey, r.identity.SessionToken)}
	endpoint := aws.String(r.clients.server.URL)
	var client any
	switch row.Service {
	case "iam":
		client = iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
	case "s3api":
		client = s3.NewFromConfig(config, func(o *s3.Options) { o.BaseEndpoint = endpoint; o.UsePathStyle = true })
	case "sqs":
		client = sqs.NewFromConfig(config, func(o *sqs.Options) { o.BaseEndpoint = endpoint })
	case "events":
		client = eventbridge.NewFromConfig(config, func(o *eventbridge.Options) { o.BaseEndpoint = endpoint })
	case "stepfunctions":
		client = sfn.NewFromConfig(config, func(o *sfn.Options) {
			o.BaseEndpoint = endpoint
			o.APIOptions = append(o.APIOptions, stepFunctionsLocalEndpoint)
		})
	default:
		t.Fatal("unmapped task fixture service", row.Service)
	}
	input := r.input(t, row.Input)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	type reply struct {
		output any
		err    error
	}
	done := make(chan reply, 1)
	for len(r.clock.timers) != 0 {
		<-r.clock.timers
	}
	go func() {
		output, err := awstest.CallSDK(ctx, client, row.Operation, input, func(request any) {
			switch request := request.(type) {
			case *sqs.ReceiveMessageInput:
				// Effects are already drained. As in the SQS metric fixture
				// replay, inspect destination messages without replaying
				// native long-poll latency or advancing unrelated timers.
				request.WaitTimeSeconds = 0
			case *s3.ListObjectsV2Input:
				// Botocore supplies this request customization implicitly.
				request.EncodingType = "url"
			}
		})
		done <- reply{output, err}
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	var result reply
wait:
	for {
		select {
		case result = <-done:
			break wait
		case <-ticker.C:
			r.drain(t)
		case <-ctx.Done():
			t.Fatal("task SDK request did not finish", ctx.Err())
		}
	}
	if execution, ok := result.output.(*sfn.DescribeExecutionOutput); ok {
		var native struct{ Status string }
		awsDecodeJSON(t, row.Result.Output, &native)
		for result.err == nil && execution.Status == "RUNNING" && native.Status != "RUNNING" {
			select {
			case <-ticker.C:
				r.drain(t)
				result.output, result.err = awstest.CallSDK(ctx, client, row.Operation, input)
				if result.err == nil {
					execution = result.output.(*sfn.DescribeExecutionOutput)
				}
			case <-ctx.Done():
				t.Fatal("native terminal execution did not settle", ctx.Err())
			}
		}
	}
	awsNativeResult(t, row.awsNativeObservation, result.err)
	if result.err != nil {
		return nil
	}
	r.drain(t)
	// IAM setup requests remain real SDK calls. Their generated role IDs bind
	// SQS SenderId to the actual role rather than accepting an arbitrary sender.
	if row.Service == "iam" {
		if created, ok := result.output.(*iam.CreateRoleOutput); ok {
			var native struct{ Role struct{ Arn, RoleId string } }
			awsDecodeJSON(t, row.Result.Output, &native)
			if created.Role == nil || aws.ToString(created.Role.Arn) != native.Role.Arn {
				t.Fatalf("native role identity differs: %+v", created)
			}
			r.bind(t, r.bindings, native.Role.RoleId, aws.ToString(created.Role.RoleId), true)
		}
		return result.output
	}
	if queue, ok := result.output.(*sqs.CreateQueueOutput); ok {
		var native sqs.CreateQueueOutput
		if err := awstest.DecodeSDK(row.Result.Output, &native); err != nil {
			t.Fatal(err)
		}
		r.bind(t, r.bindings, aws.ToString(native.QueueUrl), aws.ToString(queue.QueueUrl), true)
		return result.output
	}
	if bucket, ok := result.output.(*s3.CreateBucketOutput); ok {
		// Native Location uses AWS's origin; destination content is read below.
		var native s3.CreateBucketOutput
		if err := awstest.DecodeSDK(row.Result.Output, &native); err != nil {
			t.Fatal(err)
		}
		r.compare(t, ".BucketArn", aws.ToString(native.BucketArn), aws.ToString(bucket.BucketArn))
		return result.output
	}
	if object, ok := result.output.(*s3.GetObjectOutput); ok {
		body, err := io.ReadAll(object.Body)
		object.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if row.BodyBytes == nil {
			t.Fatal("native get-object has no retained body bytes")
		}
		expected, err := base64.StdEncoding.DecodeString(row.BodyBytes.Base64)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string(expected) || len(body) != row.BodyBytes.Length {
			t.Fatalf("destination object bytes differ: native %q, local %q", expected, body)
		}
		object.Body = nil
	}
	native := reflect.New(reflect.TypeOf(result.output).Elem()).Interface()
	if err := awstest.DecodeSDK(row.Result.Output, native); err != nil {
		t.Fatal(err)
	}
	if object, ok := native.(*s3.GetObjectOutput); ok && len(object.Metadata) == 0 {
		// The CLI materializes {}; Go leaves an absent HTTP prefix-header
		// map nil. No S3 response header can express an empty metadata map.
		object.Metadata = nil
	}
	if received, ok := result.output.(*sqs.ReceiveMessageOutput); ok {
		r.receive(t, row, native.(*sqs.ReceiveMessageOutput), received)
		return result.output
	}
	for _, output := range []any{native, result.output} {
		stepFunctionsTaskProjectFailure(t, row.Label, output)
	}
	want, got := stepFunctionsSDKObject(t, native), stepFunctionsSDKObject(t, result.output)
	if _, ok := result.output.(*sfn.ListExecutionsOutput); ok {
		// Parallel child start times may tie locally. Identity, cardinality and
		// child outputs are exact; native reverse start-time order is not.
		for _, object := range []map[string]any{want, got} {
			if executions, ok := object["Executions"].([]any); ok {
				slices.SortFunc(executions, func(a, b any) int {
					name := func(value any) string {
						arn, _ := value.(map[string]any)["ExecutionArn"].(string)
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
	if stepFunctionsOperation(row.Operation) != "getexecutionhistory" {
		r.bindValues(t, "", want, got)
	} else {
		r.bindHistoryMetadata(t, want, got)
	}
	want = r.project(t, "", want).(map[string]any)
	got = r.project(t, "", got).(map[string]any)
	if stepFunctionsOperation(row.Operation) == "getexecutionhistory" {
		r.compareHistory(t, want, got)
	} else {
		r.compare(t, "", want, got)
	}
	return result.output
}

// Native ReceiveMessage may return fewer than MaxNumberOfMessages. Preserve the
// actual calls, accumulate only the three contiguous credential-drain receives,
// and require exactly their captured message set; all other receives are exact.
func (r *stepFunctionsTaskReplay) receive(t *testing.T, row stepFunctionsTaskObservation, want, got *sqs.ReceiveMessageOutput) {
	t.Helper()
	if strings.HasPrefix(row.Label, "credentials-drain-receive-") {
		r.messages = append(r.messages, got.Messages...)
		matched := make([]sqstypes.Message, 0, len(want.Messages))
		for _, expected := range want.Messages {
			id := r.bindings[aws.ToString(expected.MessageId)]
			index := slices.IndexFunc(r.messages, func(message sqstypes.Message) bool { return aws.ToString(message.MessageId) == id })
			if index < 0 {
				t.Fatalf("native drained message %s missing from actual receives", id)
			}
			matched = append(matched, r.messages[index])
			r.messages = slices.Delete(r.messages, index, index+1)
		}
		if len(want.Messages) == 0 && len(r.messages) != 0 {
			t.Fatalf("unexpected task messages left after native drain: %+v", r.messages)
		}
		got.Messages = matched
	}
	if len(want.Messages) != len(got.Messages) {
		t.Fatalf("native message count %d, actual %d", len(want.Messages), len(got.Messages))
	}
	expected, actual := stepFunctionsSDKObject(t, want), stepFunctionsSDKObject(t, got)
	r.bindValues(t, "", expected, actual)
	r.compare(t, "", r.project(t, "", expected), r.project(t, "", actual))
}

func (r *stepFunctionsTaskReplay) bindValues(t *testing.T, path string, want, got any) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok {
			return
		} // Shared comparator reports the type mismatch.
		if nativeMetadata, ok := expected["SdkResponseMetadata"].(map[string]any); ok {
			localMetadata, _ := actual["SdkResponseMetadata"].(map[string]any)
			nativeID, _ := nativeMetadata["RequestId"].(string)
			localID, _ := localMetadata["RequestId"].(string)
			r.bind(t, r.bindings, nativeID, localID, true)
		}
		if body, present := actual["Body"].(string); present {
			digest := md5.Sum([]byte(body))
			for _, key := range []string{"MD5OfBody", "Md5OfBody"} {
				if checksum, present := actual[key]; present && checksum != hex.EncodeToString(digest[:]) {
					t.Fatal("actual SQS body does not match its MD5", actual)
				}
			}
		}
		for key, value := range expected {
			r.bindValues(t, path+"."+key, value, actual[key])
		}
	case []any:
		actual, ok := got.([]any)
		if !ok || len(expected) != len(actual) {
			return
		}
		for i := range expected {
			r.bindValues(t, path, expected[i], actual[i])
		}
	case string:
		actual, ok := got.(string)
		if !ok || expected == "" {
			return
		}
		if _, bound := r.bindings[expected]; bound {
			r.bind(t, r.bindings, expected, actual, false)
			return
		}
		if json.Valid([]byte(expected)) && !strings.HasSuffix(path, ".Definition") {
			var a, b any
			awsDecodeJSON(t, []byte(expected), &a)
			awsDecodeJSON(t, []byte(actual), &b)
			r.bindValues(t, path+"(JSON)", a, b)
			return
		}
		if strings.HasSuffix(path, ".MessageId") || strings.HasSuffix(path, ".ReceiptHandle") || strings.HasSuffix(path, ".TaskToken") || strings.HasSuffix(path, ".Token") && strings.HasPrefix(expected, "<redacted-") {
			r.bind(t, r.bindings, expected, actual, true)
		}
		if strings.HasSuffix(path, ".MD5OfMessageBody") || strings.HasSuffix(path, ".Md5OfMessageBody") || strings.HasSuffix(path, ".MD5OfBody") || strings.HasSuffix(path, ".Md5OfBody") {
			// Object key ordering and task tokens change serialized JSON bytes.
			// Bind send/receive digests consistently; every actual body is hashed
			// above and its complete decoded payload is compared separately.
			digest, err := hex.DecodeString(actual)
			if err != nil || len(digest) != md5.Size {
				t.Fatalf("invalid SQS body checksum: %q", actual)
			}
			r.bind(t, r.bindings, expected, actual, true)
		}
		if strings.HasSuffix(path, ".ExecutionArn") {
			nativeParts, actualParts := strings.Split(expected, ":"), strings.Split(actual, ":")
			if len(nativeParts) == 8 && stepFunctionsContextUUID.MatchString(nativeParts[7]) {
				if len(actualParts) != 8 || strings.Join(nativeParts[:7], ":") != strings.Join(actualParts[:7], ":") || !stepFunctionsContextUUID.MatchString(actualParts[7]) {
					t.Fatalf("invalid generated child identity: native %s local %s", expected, actual)
				}
				r.bind(t, r.bindings, expected, actual, true)
				r.bind(t, r.bindings, nativeParts[7], actualParts[7], true)
			}
		}
	}
}

// These probes have service/SDK-owned diagnostics, not customer Fail-state
// Causes. Keep exact status/error classes, causal failure events and destination
// effects; English diagnostics and HTTP request IDs are not a modeled contract.
// No captured probe here uses Catch, so this fixture makes no Catch claim.
func stepFunctionsTaskProjectFailure(t *testing.T, label string, output any) {
	t.Helper()
	selected := false
	for _, prefix := range []string{
		"s3-no-such-key-", "sqs-sdk-target-error-", "execution-role-no-states-trust-",
		"execution-role-missing-", "execution-role-no-target-permissions-", "credentials-denied-",
		"conflicting-algorithm", "invalid-sha256",
	} {
		selected = selected || strings.HasPrefix(label, prefix)
	}
	if !selected {
		return
	}
	project := func(cause **string) {
		if *cause == nil || strings.TrimSpace(**cause) == "" {
			t.Fatal("service-owned failure is missing its diagnostic")
		}
		*cause = aws.String("<service-owned diagnostic>")
	}
	switch output := output.(type) {
	case *sfn.TestStateOutput:
		project(&output.Cause)
	case *sfn.DescribeExecutionOutput:
		project(&output.Cause)
	case *sfn.GetExecutionHistoryOutput:
		for i := range output.Events {
			event := &output.Events[i]
			if details := event.TaskFailedEventDetails; details != nil {
				project(&details.Cause)
			}
			if details := event.ExecutionFailedEventDetails; details != nil {
				project(&details.Cause)
			}
		}
	}
}

// Project only independently generated values. Crucially, JSON-bearing strings
// remain strings: .sync Input/Output must not silently become .sync:2 objects.
// SDK metadata retains status, modeled headers and consistent command IDs.
// Service prose is projected only by the explicitly scoped helper above.
func (r *stepFunctionsTaskReplay) project(t *testing.T, path string, value any) any {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		stepFunctionsNormalizeMetadata(t, path, value)
		for key, child := range value {
			if key == "LastModified" || key == "SentTimestamp" || key == "ApproximateFirstReceiveTimestamp" {
				// S3 service timestamps are second-granularity; SQS timestamps
				// are decimal milliseconds. Preserve presence and validate them,
				// but do not require native network/worker latency magnitudes.
				if child != nil {
					text, ok := child.(string)
					if !ok || text == "" {
						t.Fatalf("invalid %s timestamp: %v", key, child)
					}
					if key == "LastModified" {
						if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
							t.Fatal(err)
						}
					} else {
						var millis json.Number = json.Number(text)
						if n, err := millis.Int64(); err != nil || n <= 0 {
							t.Fatalf("invalid %s: %s", key, text)
						}
					}
					value[key] = "<service-timestamp>"
				}
				continue
			}
			if key == "SenderId" {
				text, ok := child.(string)
				if !ok {
					t.Fatalf("invalid SQS sender: %v", child)
				}
				role, session, ok := strings.Cut(text, ":")
				if !ok || role == "" || session == "" {
					t.Fatalf("SQS task sender is not a role session: %s", text)
				}
				if bound := r.bindings[role]; bound != "" {
					role = bound
				}
				value[key] = role + ":<session>"
				continue
			}
			if key == "StartDate" || key == "StopDate" {
				if millis, ok := child.(float64); ok {
					child = time.UnixMilli(int64(millis)).UTC().Format(time.RFC3339Nano)
				}
			}
			value[key] = r.project(t, path+"."+key, child)
		}
		if name, _ := value["Error"].(string); strings.HasPrefix(name, "States.") {
			// Do not inherit the shared blanket States.* cause projection:
			// customer Causes remain compared outside the six service probes.
			value["TaskCause"] = value["Cause"]
			delete(value, "Cause")
		}
		return value
	case []any:
		for i := range value {
			value[i] = r.project(t, path, value[i])
		}
		return value
	case string:
		if bound := r.bindings[value]; bound != "" {
			return bound
		}
		if !strings.HasSuffix(path, ".Definition") && json.Valid([]byte(value)) {
			var document any
			awsDecodeJSON(t, []byte(value), &document)
			data, err := json.Marshal(r.project(t, path+"(JSON)", document))
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}
	}
	return value
}

func (r *stepFunctionsTaskReplay) retainedPolicy(t *testing.T, row stepFunctionsTaskObservation) {
	t.Helper()
	var request iam.PutRolePolicyInput
	if err := awstest.DecodeSDK(row.Input, &request); err != nil {
		t.Fatal(err)
	}
	client := r.clients.iam(r.identity.AccessKeyID, r.identity.SecretAccessKey, r.identity.SessionToken)
	actual, err := client.GetRolePolicy(t.Context(), &iam.GetRolePolicyInput{RoleName: request.RoleName, PolicyName: request.PolicyName})
	if err != nil {
		t.Fatal(err)
	}
	document, err := url.QueryUnescape(aws.ToString(actual.PolicyDocument))
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	awsDecodeJSON(t, []byte(aws.ToString(request.PolicyDocument)), &want)
	awsDecodeJSON(t, []byte(document), &got)
	r.compare(t, ".retained-policy(JSON)", want, got)
}
