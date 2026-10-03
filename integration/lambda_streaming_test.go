package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"stackd"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd/storage"
)

type lambdaStreamingFixture struct {
	Prefix, Account, Runtime string
	Artifact                 struct {
		Source string `json:"source_utf8"`
		ZIP    string `json:"zip_base64"`
	}
	Observations []lambdaStreamingRow
	Custom       *lambdaStreamingFixture `json:"custom_runtime"`
	Timeout      *lambdaStreamingFixture `json:"timeout_runtime"`
}

type lambdaStreamingRow struct {
	Label, Operation string
	Input            json.RawMessage
	LogTail          string `json:"log_tail_utf8"`
	Result           struct {
		Code   string
		Output struct {
			StatusCode                                                           int32
			ExecutedVersion, ResponseStreamContentType, FunctionError, LogResult string
			ResponseMetadata                                                     struct{ HTTPHeaders map[string]string }
		}
	}
	Events []struct {
		Event struct {
			Complete *lambdatypes.InvokeWithResponseStreamCompleteEvent `json:"InvokeComplete"`
		}
	}
	Payload *string `json:"concatenated_payload_base64"`
	Length  int64   `json:"payload_length"`
	SHA256  string  `json:"payload_sha256"`
}

// x86 exercises persistence on both backends; arm64 checks the runtime binaries,
// not another Cartesian copy of API admission, publication and large responses.
func TestLambdaStreamingDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise real Docker Lambda streaming")
	}
	fixture := lambdaFixture[lambdaStreamingFixture](t, "streaming")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			architectures := []string{"x86_64"}
			if backend == "memory" {
				architectures = append(architectures, "arm64")
			}
			for _, architecture := range architectures {
				t.Run(architecture, func(t *testing.T) {
					for _, group := range []struct {
						name    string
						fixture *lambdaStreamingFixture
					}{{"node", &fixture}, {"custom_runtime", fixture.Custom}, {"timeout_runtime", fixture.Timeout}} {
						if group.fixture == nil || architecture == "arm64" && group.name == "timeout_runtime" {
							continue
						}
						t.Run(group.name, func(t *testing.T) {
							testLambdaStreamingReplay(t, backend, architecture, group.fixture)
						})
					}
				})
			}
		})
	}
}

func testLambdaStreamingReplay(t *testing.T, backend, architecture string, fixture *lambdaStreamingFixture) {
	ctx := t.Context()
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "streaming.sqlite"))
	}
	cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: nil}, nil)
	c := cloudClients{server}
	client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	name := "stream-replay-" + architecture
	normalize := strings.NewReplacer(fixture.Prefix, name, fixture.Account, "000000000000")
	code := lambdaStreamingCode(t, fixture, architecture)
	var created bool
	var previousBoot int64
	var reset bool
	for _, row := range fixture.Observations {
		if row.Result.Code != "Success" {
			continue
		}
		switch row.Operation {
		case "create_role":
			input := lambdaStreamingInput[iam.CreateRoleInput](t, row.Input, normalize)
			if _, err := c.iam("test", "test", "").CreateRole(ctx, &input); err != nil {
				t.Fatal(err)
			}
		case "put_role_policy":
			input := lambdaStreamingInput[iam.PutRolePolicyInput](t, row.Input, normalize)
			if _, err := c.iam("test", "test", "").PutRolePolicy(ctx, &input); err != nil {
				t.Fatal(err)
			}
		case "create_function":
			input := lambdaStreamingInput[awslambda.CreateFunctionInput](t, row.Input, normalize)
			input.Code = &lambdatypes.FunctionCode{ZipFile: code}
			input.Architectures = []lambdatypes.Architecture{lambdatypes.Architecture(architecture)}
			if _, err := client.CreateFunction(ctx, &input); err != nil {
				t.Fatal(err)
			}
			created = true
			if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
				t.Fatal(err)
			}
		case "publish_version":
			input := lambdaStreamingInput[awslambda.PublishVersionInput](t, row.Input, normalize)
			if _, err := client.PublishVersion(ctx, &input); err != nil {
				t.Fatal(err)
			}
		case "update_function_configuration":
			input := lambdaStreamingInput[awslambda.UpdateFunctionConfigurationInput](t, row.Input, normalize)
			if _, err := client.UpdateFunctionConfiguration(ctx, &input); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(client, fastLambdaUpdatedWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
				t.Fatal(err)
			}
		case "create_alias":
			input := lambdaStreamingInput[awslambda.CreateAliasInput](t, row.Input, normalize)
			if _, err := client.CreateAlias(ctx, &input); err != nil {
				t.Fatal(err)
			}
		case "invoke", "invoke_with_response_stream":
			if architecture == "arm64" && row.Label != "success" && row.Label != "explicit_trailer_streaming" && row.Label != "explicit_error_before_streaming" {
				continue
			}
			t.Run(row.Label, func(t *testing.T) {
				// This native capture transfers 201 MiB and takes over a minute.
				// Keep it out of the ordinary matrix; the large-boundary smoke is separate.
				if row.Label == "over_200_mib_streaming" {
					t.Skip("201 MiB native boundary belongs to the separate large-boundary smoke")
				}
				if row.Label == "disconnect" {
					lambdaStreamingDisconnect(t, client, logsClient(c, "test"), row, normalize)
					return
				}
				log := lambdaStreamingInvoke(t, client, row, normalize)
				timedOut := lambdaStreamingTimedOut(row.LogTail)
				if lambdaStreamingTimedOut(string(log)) != timedOut {
					t.Fatalf("timeout report differs from native: %s", log)
				}
				if strings.Contains(row.LogTail, `"boot_id":`) {
					boot := lambdaStreamingBootID(t, log)
					if reset && boot == previousBoot {
						t.Fatal("timed-out runtime process was reused")
					}
					previousBoot, reset = boot, timedOut
				}
			})
		}
	}
	if !created {
		t.Fatal("fixture has no successful function creation")
	}
	if architecture == "x86_64" && fixture.Runtime == "nodejs22.x" {
		t.Run("admission", func(t *testing.T) {
			_, key, secret := c.user(t, "test", "stream-caller")
			options := client.Options()
			options.Credentials = credentials.NewStaticCredentialsProvider(key, secret, "")
			caller := awslambda.New(options)
			arn := "arn:aws:lambda:us-east-1:000000000000:function:" + name
			putUserPolicy(t, c.iam("test", "test", ""), "stream-caller", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":%q},{"Effect":"Deny","Action":"lambda:InvokeFunction","Resource":%q}]}`, arn, arn))
			_, err := caller.InvokeWithResponseStream(t.Context(), &awslambda.InvokeWithResponseStreamInput{FunctionName: &name, Payload: []byte(`{}`)})
			assertAPIError(t, err, "AccessDeniedException")
			_, err = client.InvokeWithResponseStream(t.Context(), &awslambda.InvokeWithResponseStreamInput{FunctionName: aws.String(name + "-missing"), Payload: []byte(`{}`)})
			assertAPIError(t, err, "ResourceNotFoundException")
		})
		if backend == "memory" {
			t.Run("shutdown_unread_stream", func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				// The captured version retains the streaming handler after the
				// fixture changes $LATEST to its ordinary handler.
				out, err := client.InvokeWithResponseStream(ctx, &awslambda.InvokeWithResponseStreamInput{FunctionName: &name, Qualifier: aws.String("1"), Payload: []byte(`{"mode":"large","bytes":210763776,"token":"shutdown"}`)})
				if err != nil {
					t.Fatal(err)
				}
				stream := out.GetStream()
				defer stream.Close()
				if event := <-stream.Events(); event == nil {
					t.Fatalf("no initial response: %v", stream.Err())
				}
				// Leave the socket unread long enough for its bounded buffers to fill.
				time.Sleep(time.Second)
				closed := make(chan error, 1)
				go func() { closed <- cloud.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					cancel()
					stream.Close()
					<-closed
					t.Fatal("stack shutdown blocked on an unread response")
				}
			})
		}
	}
}

func lambdaStreamingCode(t *testing.T, fixture *lambdaStreamingFixture, architecture string) []byte {
	t.Helper()
	if fixture.Artifact.ZIP != "" {
		code, err := base64.StdEncoding.DecodeString(fixture.Artifact.ZIP)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	if fixture.Artifact.Source == "" {
		t.Fatal("custom runtime fixture has no customer source")
	}
	directory := t.TempDir()
	source, binary := filepath.Join(directory, "main.go"), filepath.Join(directory, "bootstrap")
	if err := os.WriteFile(source, []byte(fixture.Artifact.Source), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", binary, source)
	command.Dir = directory
	goarch := "amd64"
	if architecture == "arm64" {
		goarch = "arm64"
	}
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0", "GO111MODULE=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile customer bootstrap: %v\n%s", err, output)
	}
	code, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	return lambdaZIP(t, map[string]string{"bootstrap": string(code)}, "bootstrap")
}

// Boto3's captured blobs differ from encoding/json's []byte representation.
// Adapt them once, including identities inside decoded customer payloads; ZIP
// blobs remain binary, and digest-only ZIP captures are replaced by the build.
func lambdaStreamingInput[T any](t *testing.T, raw json.RawMessage, normalize *strings.Replacer) T {
	t.Helper()
	var input any
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	var adapt func(any, string) any
	adapt = func(value any, key string) any {
		switch value := value.(type) {
		case map[string]any:
			if encoded, ok := value["base64"].(string); ok {
				blob, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				if key == "Payload" {
					blob = []byte(normalize.Replace(string(blob)))
				}
				return blob
			}
			if key == "ZipFile" {
				return nil
			}
			for k, v := range value {
				value[k] = adapt(v, k)
			}
		case []any:
			for i, v := range value {
				value[i] = adapt(v, key)
			}
		case string:
			return normalize.Replace(value)
		}
		return value
	}
	data, err := json.Marshal(adapt(input, ""))
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func lambdaStreamingInvoke(t *testing.T, client *awslambda.Client, row lambdaStreamingRow, normalize *strings.Replacer) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	want := row.Result.Output
	if row.Operation == "invoke" {
		input := lambdaStreamingInput[awslambda.InvokeInput](t, row.Input, normalize)
		out, err := client.Invoke(ctx, &input)
		if err != nil {
			t.Fatal(err)
		}
		if out.StatusCode != want.StatusCode || aws.ToString(out.ExecutedVersion) != want.ExecutedVersion || aws.ToString(out.FunctionError) != want.FunctionError {
			t.Fatalf("ordinary response status/version/function error = %d/%q/%q, native = %d/%q/%q", out.StatusCode, aws.ToString(out.ExecutedVersion), aws.ToString(out.FunctionError), want.StatusCode, want.ExecutedVersion, want.FunctionError)
		}
		lambdaStreamingHTTP(t, out.ResultMetadata, want.ResponseMetadata.HTTPHeaders)
		log := lambdaStreamingLog(t, out.LogResult, want.LogResult != "", input.Payload)
		lambdaStreamingPayload(t, out.Payload, row, normalize)
		return log
	}
	input := lambdaStreamingInput[awslambda.InvokeWithResponseStreamInput](t, row.Input, normalize)
	out, err := client.InvokeWithResponseStream(ctx, &input)
	if err != nil {
		t.Fatal(err)
	}
	stream := out.GetStream()
	defer stream.Close()
	if out.StatusCode != want.StatusCode || aws.ToString(out.ExecutedVersion) != want.ExecutedVersion || aws.ToString(out.ResponseStreamContentType) != want.ResponseStreamContentType {
		t.Fatalf("stream response status/version/content type = %d/%q/%q, native = %d/%q/%q", out.StatusCode, aws.ToString(out.ExecutedVersion), aws.ToString(out.ResponseStreamContentType), want.StatusCode, want.ExecutedVersion, want.ResponseStreamContentType)
	}
	lambdaStreamingHTTP(t, out.ResultMetadata, want.ResponseMetadata.HTTPHeaders)
	var payload bytes.Buffer
	digest := sha256.New()
	var length int64
	var complete *lambdatypes.InvokeWithResponseStreamCompleteEvent
	for event := range stream.Events() {
		switch event := event.(type) {
		case *lambdatypes.InvokeWithResponseStreamResponseEventMemberPayloadChunk:
			if complete != nil {
				t.Fatal("payload arrived after InvokeComplete")
			}
			chunk := event.Value.Payload
			length += int64(len(chunk))
			digest.Write(chunk)
			if row.Payload != nil {
				if length > 1<<20 {
					t.Fatal("small native payload exceeded 1 MiB")
				}
				payload.Write(chunk)
			}
		case *lambdatypes.InvokeWithResponseStreamResponseEventMemberInvokeComplete:
			if complete != nil {
				t.Fatal("duplicate InvokeComplete")
			}
			complete = &event.Value
		default:
			t.Fatalf("unexpected SDK stream event %T", event)
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	var expected *lambdatypes.InvokeWithResponseStreamCompleteEvent
	for _, event := range row.Events {
		if event.Event.Complete != nil {
			expected = event.Event.Complete
		}
	}
	if complete == nil || expected == nil {
		t.Fatal("missing actual or native InvokeComplete")
	}
	if aws.ToString(complete.ErrorCode) != aws.ToString(expected.ErrorCode) || aws.ToString(complete.ErrorDetails) != aws.ToString(expected.ErrorDetails) {
		t.Fatalf("InvokeComplete error = %q/%q, native = %q/%q", aws.ToString(complete.ErrorCode), aws.ToString(complete.ErrorDetails), aws.ToString(expected.ErrorCode), aws.ToString(expected.ErrorDetails))
	}
	log := lambdaStreamingLog(t, complete.LogResult, aws.ToString(expected.LogResult) != "", input.Payload)
	if row.Payload == nil {
		if length != row.Length || hex.EncodeToString(digest.Sum(nil)) != row.SHA256 {
			t.Fatalf("payload length/hash = %d/%x, native = %d/%s", length, digest.Sum(nil), row.Length, row.SHA256)
		}
	} else {
		lambdaStreamingPayload(t, payload.Bytes(), row, normalize)
	}
	return log
}

func lambdaStreamingHTTP(t *testing.T, metadata middleware.Metadata, headers map[string]string) {
	t.Helper()
	response, ok := awsmiddleware.GetRawResponse(metadata).(*smithyhttp.Response)
	if !ok {
		t.Fatal("missing HTTP response metadata")
	}
	for _, name := range []string{"content-type", "x-amzn-remapped-content-type"} {
		if got := response.Header.Get(name); got != headers[name] {
			t.Fatalf("HTTP %s = %q, native = %q", name, got, headers[name])
		}
	}
}

func lambdaStreamingLog(t *testing.T, result *string, present bool, payload []byte) []byte {
	t.Helper()
	if (aws.ToString(result) != "") != present {
		t.Fatalf("LogResult presence = %t, native = %t", aws.ToString(result) != "", present)
	}
	if !present {
		return nil
	}
	log, err := base64.StdEncoding.DecodeString(aws.ToString(result))
	if err != nil {
		t.Fatalf("invalid base64 LogResult: %v", err)
	}
	var event struct{ Token string }
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.Token == "" || !bytes.Contains(log, []byte(event.Token)) {
		t.Fatalf("LogResult lacks this invocation's customer token %q: %s", event.Token, log)
	}
	return log
}

func lambdaStreamingTimedOut(log string) bool {
	for line := range strings.SplitSeq(log, "\n") {
		if strings.HasPrefix(line, "REPORT RequestId:") {
			return strings.Contains(line, "Status: timeout")
		}
	}
	return false
}

func lambdaStreamingBootID(t *testing.T, log []byte) int64 {
	t.Helper()
	for line := range strings.SplitSeq(string(log), "\n") {
		if !strings.HasPrefix(line, "PROBE_RUNTIME_REQUEST ") {
			continue
		}
		_, body, _ := strings.Cut(line, "{")
		var request struct {
			BootID int64 `json:"boot_id"`
		}
		if err := json.Unmarshal([]byte("{"+body), &request); err != nil {
			t.Fatal(err)
		}
		if request.BootID != 0 {
			return request.BootID
		}
	}
	t.Fatalf("missing customer runtime boot identity: %s", log)
	return 0
}

func lambdaStreamingPayload(t *testing.T, got []byte, row lambdaStreamingRow, normalize *strings.Replacer) {
	t.Helper()
	if row.Payload == nil {
		t.Fatal("ordinary/small response missing native payload")
	}
	want, err := base64.StdEncoding.DecodeString(*row.Payload)
	if err != nil {
		t.Fatal(err)
	}
	want = []byte(normalize.Replace(string(want)))
	// JSON formatting/key order is not a Lambda contract. Binary prefixes and
	// partial failure payloads still compare byte-for-byte.
	if bytes.Equal(got, want) {
		return
	}
	var actualJSON, nativeJSON any
	if json.Unmarshal(got, &actualJSON) == nil && json.Unmarshal(want, &nativeJSON) == nil && reflect.DeepEqual(actualJSON, nativeJSON) {
		return
	}
	if prefix := bytes.IndexByte(want, '{'); prefix > 0 && len(got) >= prefix && bytes.Equal(got[:prefix], want[:prefix]) {
		if json.Unmarshal(got[prefix:], &actualJSON) == nil && json.Unmarshal(want[prefix:], &nativeJSON) == nil && reflect.DeepEqual(actualJSON, nativeJSON) {
			return
		}
	}
	t.Fatalf("payload = %q, native = %q", got, want)
}

func lambdaStreamingDisconnect(t *testing.T, client *awslambda.Client, logs *cloudwatchlogs.Client, row lambdaStreamingRow, normalize *strings.Replacer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	input := lambdaStreamingInput[awslambda.InvokeWithResponseStreamInput](t, row.Input, normalize)
	if _, err := client.PutFunctionConcurrency(ctx, &awslambda.PutFunctionConcurrencyInput{FunctionName: input.FunctionName, ReservedConcurrentExecutions: aws.Int32(1)}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := client.DeleteFunctionConcurrency(ctx, &awslambda.DeleteFunctionConcurrencyInput{FunctionName: input.FunctionName}); err != nil {
			t.Error(err)
		}
	}()
	out, err := client.InvokeWithResponseStream(ctx, &input)
	if err != nil {
		t.Fatal(err)
	}
	stream := out.GetStream()
	defer stream.Close()
	var first []byte
	for event := range stream.Events() {
		if chunk, ok := event.(*lambdatypes.InvokeWithResponseStreamResponseEventMemberPayloadChunk); ok && len(chunk.Value.Payload) != 0 {
			first = chunk.Value.Payload
			break
		}
	}
	if len(first) == 0 {
		t.Fatalf("no bytes before disconnect: %v", stream.Err())
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	// A second invocation is attempted before waiting for any completion log.
	// It must not steal the execution slot released by closing only delivery.
	probe := &awslambda.InvokeWithResponseStreamInput{FunctionName: input.FunctionName, Payload: []byte(`{"mode":"empty","token":"after-disconnect"}`)}
	second, err := client.InvokeWithResponseStream(ctx, probe)
	if second != nil {
		second.GetStream().Close()
	}
	assertAPIError(t, err, "TooManyRequestsException")
	var event struct{ Token string }
	if err := json.Unmarshal(input.Payload, &event); err != nil {
		t.Fatal(err)
	}
	completion := "PROBE_COMPLETE " + event.Token
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	finished := false
	for !finished {
		query := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + aws.ToString(input.FunctionName))}
		for {
			out, err := logs.FilterLogEvents(ctx, query)
			if err != nil {
				var apiErr smithy.APIError
				if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ResourceNotFoundException" {
					t.Fatal(err)
				}
				break
			}
			for _, entry := range out.Events {
				if strings.Contains(aws.ToString(entry.Message), completion) {
					finished = true
				}
			}
			if finished || out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(query.NextToken) {
				break
			}
			query.NextToken = out.NextToken
		}
		if finished {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("disconnected execution never logged completion for %q: %v", event.Token, ctx.Err())
		case <-ticker.C:
		}
	}
	// Logging precedes the runtime response acknowledgment; wait for the slot
	// release, accepting only throttling during that transition.
	for {
		out, err := client.InvokeWithResponseStream(ctx, probe)
		if err == nil {
			stream := out.GetStream()
			defer stream.Close()
			complete := false
			for event := range stream.Events() {
				switch event := event.(type) {
				case *lambdatypes.InvokeWithResponseStreamResponseEventMemberInvokeComplete:
					if complete || aws.ToString(event.Value.ErrorCode) != "" || aws.ToString(event.Value.ErrorDetails) != "" {
						t.Fatalf("post-disconnect completion: %+v", event.Value)
					}
					complete = true
				case *lambdatypes.InvokeWithResponseStreamResponseEventMemberPayloadChunk:
					if len(event.Value.Payload) != 0 {
						t.Fatal("post-disconnect empty invocation returned payload")
					}
				default:
					t.Fatalf("unexpected post-disconnect event %T", event)
				}
			}
			if err := stream.Err(); err != nil {
				t.Fatal(err)
			}
			if !complete {
				t.Fatal("post-disconnect invocation never completed")
			}
			return
		}
		assertAPIError(t, err, "TooManyRequestsException")
		select {
		case <-ctx.Done():
			t.Fatal("execution slot not released after customer completion")
		case <-ticker.C:
		}
	}
}
