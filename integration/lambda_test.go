package stackd_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/compute/docker"
	computelambda "stackd/compute/lambda"
	"stackd/storage"
)

// Keep the SDK's state predicates and caller deadlines without five-second
// polling floors between local container readiness observations.
func fastLambdaActiveWaiter(options *awslambda.FunctionActiveWaiterOptions) {
	options.MinDelay = 50 * time.Millisecond
	options.MaxDelay = 500 * time.Millisecond
}

func fastLambdaUpdatedWaiter(options *awslambda.FunctionUpdatedWaiterOptions) {
	options.MinDelay = 50 * time.Millisecond
	options.MaxDelay = 500 * time.Millisecond
}

// Opt in only with STACKD_LAMBDA_DOCKER=1. This uses the local Linux Docker
// daemon and CLI, with the pinned Python 3.12 images already pulled; it never pulls an image.
func TestLambdaDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { testLambdaDockerSDK(t, backend) })
	}
}

type lambdaAWSObservation struct {
	Request struct {
		InvocationType string
		Payload        string
	}
	Response struct {
		StatusCode       int
		FunctionError    string
		ExecutedVersion  string
		PayloadJSON      map[string]any
		ResponseMetadata struct{ HTTPHeaders map[string]string }
	}
	Error struct{ Error struct{ Code string } }
}

func testLambdaDockerSDK(t *testing.T, backend string) {
	ctx := t.Context()
	var fixture struct {
		HandlerSources map[string]string `json:"handler_sources"`
		Observations   map[string]lambdaAWSObservation
	}
	data, err := os.ReadFile("../testdata/aws/lambda/container_execution.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	entry, err := os.ReadFile("testdata/lambda/entry.py")
	if err != nil {
		t.Fatal(err)
	}
	code := func(version string) []byte {
		t.Helper()
		source := fixture.HandlerSources[version]
		if source == "" {
			t.Fatalf("native fixture has no handler source %s", version)
		}
		return lambdaZIP(t, map[string]string{"handler.py": source, "entry.py": string(entry)})
	}
	// Keep CLI inspection on the exact daemon used by the executor, independent
	// of DOCKER_HOST/context. No name-prefix cleanup or global pruning is used.
	const dockerHost = "unix:///var/run/docker.sock"
	docker := func(args ...string) string {
		t.Helper()
		commandCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		output, err := exec.CommandContext(commandCtx, "docker", append([]string{"--host", dockerHost}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("Docker inspection %v: %v\n%s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "lambda.sqlite"))
	}
	owners := map[string]bool{}
	assertDisposed := func() {
		t.Helper()
		for owner := range owners {
			filter := "label=io.stackd.owner=" + owner
			if got := docker("container", "ls", "--all", "--quiet", "--filter", filter); got != "" {
				t.Errorf("owned Lambda containers survived disposal (%s): %s", owner, got)
			}
			if got := docker("volume", "ls", "--quiet", "--filter", filter); got != "" {
				t.Errorf("owned Lambda volumes survived disposal (%s): %s", owner, got)
			}
		}
	}
	t.Cleanup(assertDisposed)
	_, server := newLambdaDockerStack(t, stackd.Config{Storage: backends}, nil)
	callbackEndpoint := strings.Replace(server.URL, "127.0.0.1", "host.docker.internal", 1)
	c := cloudClients{server}
	root := c.iam("test", "test", "")
	clientFor := func(key, secret string) *awslambda.Client {
		return awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	}
	client := clientFor("test", "test")
	name := fmt.Sprintf("docker-sdk-%s-%d", backend, time.Now().UnixNano())
	arn := "arn:aws:lambda:us-east-1:000000000000:function:" + name
	trust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	createRole := func(roleName string) string {
		t.Helper()
		out, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(trust)})
		if err != nil {
			t.Fatal(err)
		}
		return aws.ToString(out.Role.Arn)
	}
	roleName := name + "-execution"
	roleARN := createRole(roleName)
	otherRoleName := name + "-other"
	otherRoleARN := createRole(otherRoleName)
	_, deployKey, deploySecret := c.user(t, "test", name+"-deployer")
	deployer := clientFor(deployKey, deploySecret)
	putUserPolicy(t, root, name+"-deployer", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":%q},{"Effect":"Allow","Action":"iam:PassRole","Resource":%q,"Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}`, arn, roleARN))
	input := &awslambda.CreateFunctionInput{FunctionName: aws.String(name), Role: aws.String(otherRoleARN), Runtime: lambdatypes.RuntimePython312, Handler: aws.String("entry.invoke"), Code: &lambdatypes.FunctionCode{ZipFile: code("v1")}, Timeout: aws.Int32(2), MemorySize: aws.Int32(128), Environment: &lambdatypes.Environment{Variables: map[string]string{"PROBE_VERSION": "v1"}}}
	_, err = deployer.CreateFunction(ctx, input)
	assertAPIError(t, err, "AccessDeniedException")
	_, err = client.GetFunctionConfiguration(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
	assertAPIError(t, err, "ResourceNotFoundException")
	input.Role = aws.String(roleARN)
	created, err := deployer.CreateFunction(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(created.FunctionArn) != arn {
		t.Fatalf("function ARN = %s, want %s", aws.ToString(created.FunctionArn), arn)
	}
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := client.DeleteFunction(cleanupCtx, &awslambda.DeleteFunctionInput{FunctionName: aws.String(name)}); err != nil {
				t.Error(err)
			}
		}
	})
	configuration := &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}
	active, err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).WaitForOutput(ctx, configuration, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != lambdatypes.StateActive || aws.ToString(active.Role) != roleARN || aws.ToString(active.Handler) != "entry.invoke" {
		t.Fatalf("active configuration: %#v", active)
	}
	regionalOptions := client.Options()
	regionalOptions.Region = "us-west-2"
	_, err = awslambda.New(regionalOptions).GetFunctionConfiguration(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: new(arn)})
	assertAPIError(t, err, "ResourceNotFoundException")
	updated := func() {
		t.Helper()
		if err := awslambda.NewFunctionUpdatedWaiter(client, fastLambdaUpdatedWaiter).Wait(ctx, configuration, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	rememberOwner := func(payload map[string]any) string {
		t.Helper()
		stream, _ := payload["runtime_owner"].(string)
		observed := strings.Fields(docker("container", "ls", "--filter", "label=io.stackd.function="+arn, "--format", `{{.Label "io.stackd.owner"}}`))
		if len(observed) == 0 {
			t.Fatal("invocation did not use a live Docker environment")
		}
		for _, owner := range observed {
			owners[owner] = true
		}
		return stream
	}
	requestIDs := map[string]bool{}
	replay := func(label string) {
		t.Helper()
		row, ok := fixture.Observations[label]
		if !ok {
			t.Fatalf("missing AWS observation %s", label)
		}
		response, body := lambdaRawInvoke(t, server, name, row.Request.InvocationType, []byte(row.Request.Payload))
		if label == "invoke_malformed_json" {
			if response.StatusCode != http.StatusBadRequest || response.Header.Get("X-Amzn-Errortype") != row.Error.Error.Code {
				t.Fatalf("%s: status/headers %d %v, body %s", label, response.StatusCode, response.Header, body)
			}
			return
		}
		if response.StatusCode != row.Response.StatusCode {
			t.Fatalf("%s: HTTP %d, want %d: %s", label, response.StatusCode, row.Response.StatusCode, body)
		}
		for _, header := range []string{"content-type", "x-amz-function-error", "x-amz-executed-version"} {
			if got, want := response.Header.Get(header), row.Response.ResponseMetadata.HTTPHeaders[header]; got != want {
				t.Fatalf("%s: %s = %q, want %q; body: %s", label, header, got, want, body)
			}
		}
		if row.Response.StatusCode == http.StatusNoContent {
			if len(body) != 0 {
				t.Fatalf("DryRun executed or returned a payload: %s", body)
			}
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("%s did not return raw JSON: %s: %v", label, body, err)
		}
		if row.Response.FunctionError != "" {
			if payload["errorType"] != row.Response.PayloadJSON["errorType"] {
				t.Fatalf("%s error = %s, want %v", label, body, row.Response.PayloadJSON)
			}
			if label == "invoke_handler_exception" && payload["errorMessage"] != row.Response.PayloadJSON["errorMessage"] {
				t.Fatalf("handler exception was not propagated: %s", body)
			}
			return
		}
		rememberOwner(payload)
		for _, field := range []string{"event", "global_counter", "tmp_counter", "code_version", "environment", "function_version", "memory_limit_in_mb"} {
			if !reflect.DeepEqual(payload[field], row.Response.PayloadJSON[field]) {
				t.Fatalf("%s: %s = %#v, native AWS = %#v", label, field, payload[field], row.Response.PayloadJSON[field])
			}
		}
		if payload["function_name"] != name || payload["invoked_function_arn"] != arn {
			t.Fatalf("incorrect RIC invocation context: %s", body)
		}
		id, _ := payload["aws_request_id"].(string)
		if id == "" || requestIDs[id] {
			t.Fatalf("missing/reused invocation request ID: %q", id)
		}
		requestIDs[id] = true
	}
	for _, label := range []string{"invoke_first", "invoke_warm", "invoke_dry_run", "invoke_malformed_json", "invoke_handler_exception", "invoke_after_exception"} {
		replay(label)
	}
	_, err = client.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(name), Environment: &lambdatypes.Environment{Variables: map[string]string{"PROBE_VERSION": "v2"}}})
	if err != nil {
		t.Fatal(err)
	}
	updated()
	replay("invoke_after_configuration_update")
	replay("invoke_warm_after_configuration_update")
	_, err = client.UpdateFunctionCode(ctx, &awslambda.UpdateFunctionCodeInput{FunctionName: aws.String(name), ZipFile: code("v2")})
	if err != nil {
		t.Fatal(err)
	}
	updated()
	for _, label := range []string{"invoke_after_code_update", "invoke_warm_after_code_update", "invoke_timeout", "invoke_after_timeout"} {
		replay(label)
	}
	qualified, err := client.Invoke(ctx, &awslambda.InvokeInput{FunctionName: new(name), Qualifier: new("$LATEST"), Payload: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	var qualifiedPayload map[string]any
	if err := json.Unmarshal(qualified.Payload, &qualifiedPayload); err != nil {
		t.Fatal(err)
	}
	if qualifiedPayload["invoked_function_arn"] != arn+":$LATEST" {
		t.Fatalf("qualified invocation lost its ARN: %s", qualified.Payload)
	}

	// Customer boto3 signs real outbound requests using the injected execution
	// role session. Policy changes must affect even an already-warm runtime.
	queue, err := c.sqs("test", "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	queueARN := "arn:aws:sqs:us-east-1:000000000000:" + name
	policy := func(sourceARN string) string {
		return fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"lambda:SourceFunctionArn":%q}}}}`, queueARN, sourceARN)
	}
	putRolePolicy(t, root, roleName, policy(arn))
	putRolePolicy(t, root, otherRoleName, policy(arn+"-wrong"))
	_, err = client.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(name), Handler: aws.String("entry.send"), Timeout: aws.Int32(10)})
	if err != nil {
		t.Fatal(err)
	}
	updated()
	send := func(body string, allowed bool) string {
		t.Helper()
		payload, err := json.Marshal(map[string]string{"queue_url": strings.Replace(aws.ToString(queue.QueueUrl), server.URL, callbackEndpoint, 1), "body": body})
		if err != nil {
			t.Fatal(err)
		}
		out, err := client.Invoke(ctx, &awslambda.InvokeInput{FunctionName: aws.String(name), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		if out.StatusCode != 200 || out.FunctionError != nil || aws.ToString(out.ExecutedVersion) != "$LATEST" {
			t.Fatalf("customer invocation: %#v, %s", out, out.Payload)
		}
		var result map[string]any
		if err := json.Unmarshal(out.Payload, &result); err != nil {
			t.Fatal(err)
		}
		if allowed {
			if id, _ := result["message_id"].(string); id == "" || result["error_code"] != nil {
				t.Fatalf("execution role SDK call denied: %s", out.Payload)
			}
		} else if result["error_code"] != "AccessDenied" || result["message_id"] != nil {
			t.Fatalf("execution role SDK call escaped policy: %s", out.Payload)
		}
		return rememberOwner(result)
	}
	warmOwner := send("allowed-first", true)
	putRolePolicy(t, root, roleName, `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)
	if owner := send("denied-current-policy", false); owner != warmOwner {
		t.Fatal("policy change test did not exercise the existing warm runtime")
	}
	putRolePolicy(t, root, roleName, policy(arn))
	if owner := send("allowed-restored", true); owner != warmOwner {
		t.Fatal("restored policy was not observed by the warm runtime")
	}
	_, err = deployer.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(name), Role: aws.String(otherRoleARN)})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = client.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(name), Role: aws.String(otherRoleARN)})
	if err != nil {
		t.Fatal(err)
	}
	updated()
	otherOwner := send("denied-source-function", false)
	if otherOwner == warmOwner {
		t.Fatal("role update reused the previous execution environment")
	}
	putRolePolicy(t, root, otherRoleName, policy(arn))
	if owner := send("allowed-new-role", true); owner != otherOwner {
		t.Fatal("new role policy did not apply to the same warm runtime")
	}
	messages, err := c.sqs("test", "test", "").ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil {
		t.Fatal(err)
	}
	gotMessages := map[string]int{}
	for _, message := range messages.Messages {
		gotMessages[aws.ToString(message.Body)]++
	}
	if want := (map[string]int{"allowed-first": 1, "allowed-restored": 1, "allowed-new-role": 1}); !reflect.DeepEqual(gotMessages, want) {
		t.Fatalf("SQS side effects = %v, want %v", gotMessages, want)
	}
	if _, err := client.DeleteFunction(ctx, &awslambda.DeleteFunctionInput{FunctionName: aws.String(name)}); err != nil {
		t.Fatal(err)
	}
	deleted = true
	_, err = client.GetFunctionConfiguration(ctx, configuration)
	assertAPIError(t, err, "ResourceNotFoundException")
	assertDisposed()
}

// lambdaZIP owns deterministic fixture packaging and explicit executable modes.
func lambdaZIP(t *testing.T, files map[string]string, executables ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		header := &zip.FileHeader{Name: path, Method: zip.Deflate}
		header.SetMode(0o644)
		if slices.Contains(executables, path) {
			header.SetMode(0o755)
		}
		writer, err := archive.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, files[path]); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func lambdaFixture[T any](t *testing.T, name string) T {
	t.Helper()
	var fixture T
	data, err := os.ReadFile("../testdata/aws/lambda/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func lambdaTelemetryHelpers(t *testing.T) map[string]string {
	t.Helper()
	helpers := make(map[string]string, 2)
	for architecture, suffix := range map[string]string{"x86_64": "amd64", "arm64": "arm64"} {
		filename := os.Getenv("STACKD_LAMBDA_TELEMETRY_HELPER_" + strings.ToUpper(suffix))
		if filename == "" {
			filename = filepath.Join("..", "bin", "lambda-telemetry-"+suffix)
		}
		filename, err := filepath.Abs(filename)
		if err != nil {
			t.Fatal(err)
		}
		helpers[architecture] = filename
	}
	return helpers
}

func newLambdaDockerStack(t *testing.T, config stackd.Config, runtime *computelambda.DockerConfig) (*stackd.Stack, *httptest.Server) {
	t.Helper()
	var runtimeConfig computelambda.DockerConfig
	if runtime != nil {
		runtimeConfig = *runtime
	}
	if runtimeConfig.Client == nil {
		engine, err := docker.New(t.Context(), docker.Config{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(engine.Close)
		runtimeConfig.Client = engine
	}
	if runtimeConfig.TelemetryHelpers == nil {
		runtimeConfig.TelemetryHelpers = lambdaTelemetryHelpers(t)
	}
	if runtimeConfig.Namespace == "" {
		runtimeConfig.Namespace = "lambda-test-" + rand.Text()
	}
	executor, err := computelambda.NewDockerExecutor(t.Context(), runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := executor.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	endpoint := fmt.Sprintf("http://host.docker.internal:%d", port)
	config.LambdaExecutor = executor
	config.LambdaKeepAlive = 5 * time.Minute
	config.ComputeEndpoint, config.PublicEndpoint = endpoint, endpoint
	cloud, err := stackd.New(config)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(cloud)
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	server.URL = fmt.Sprintf("http://127.0.0.1:%d", port)
	t.Cleanup(func() {
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
		server.Close()
	})
	return cloud, server
}

func lambdaRawInvoke(t *testing.T, server *httptest.Server, name, invocationType string, payload []byte) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/2015-03-31/functions/"+name+"/invocations", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Amz-Invocation-Type", invocationType)
	return lambdaRawRequest(t, server, request, payload, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
}

func lambdaRawRequest(t *testing.T, server *httptest.Server, request *http.Request, payload []byte, credential aws.Credentials) (*http.Response, []byte) {
	t.Helper()
	digest := sha256.Sum256(payload)
	if err := v4.NewSigner().SignHTTP(t.Context(), credential, request, hex.EncodeToString(digest[:]), "lambda", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}
