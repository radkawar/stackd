package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/uuid"
	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	runtime "stackd/compute/lambda"
	"stackd/storage"
)

// This is local execution evidence, not a native AWS provenance fixture. The
// official image's RIC talks to stackd's Runtime API; no RIE or host handler runs.
func TestLambdaLocalImageDockerExecutionAndHotSwap(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to execute real image functions")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("image smoke requires the Docker CLI: ", err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			tag := "stackd-lambda-image-smoke:" + uuid.NewString()
			built := false
			t.Cleanup(func() {
				if !built {
					return
				}
				// Delete only the test-owned mutable source tag. Deployment
				// aliases belong to Lambda, and an old config ID need not remain
				// independently addressable in Docker's containerd image store.
				command := exec.Command("docker", "image", "rm", tag)
				if output, err := command.CombinedOutput(); err != nil {
					t.Errorf("removing smoke source tag: %v %s", err, output)
				}
			})
			build := func(marker string) {
				t.Helper()
				directory := t.TempDir()
				dockerfile := fmt.Sprintf("FROM %s\nCOPY index.py /var/task/index.py\nCMD [\"index.handler\"]\n", runtime.Python312X8664Image)
				source := fmt.Sprintf("import boto3,json,os\ndef handler(event,context):\n marker=%q\n if event.get('Records'):\n  boto3.client('sqs',endpoint_url=os.environ['AWS_ENDPOINT_URL']).send_message(QueueUrl=os.environ['OUTPUT_QUEUE_URL'],MessageBody=json.dumps({'marker':marker,'event':event}))\n return {'marker':marker,'event':event,'version':context.function_version}\n", marker)
				for name, body := range map[string]string{"Dockerfile": dockerfile, "index.py": source} {
					if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0644); err != nil {
						t.Fatal(err)
					}
				}
				command := exec.CommandContext(t.Context(), "docker", "build", "--platform=linux/amd64", "--pull=false", "--network=none", "-t", tag, directory)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("building installed official RIC image: %v\n%s", err, output)
				}
				built = true
			}
			build("first")
			replay := &lambdaQualifiedReplay{backend: backend, path: filepath.Join(t.TempDir(), "images.sqlite"), clock: clock.NewManual(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))}
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, replay.closeDatabase = openSQLiteBackends(t, replay.path)
			}
			engine, err := docker.New(t.Context(), docker.Config{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(engine.Close)
			config := runtime.DockerConfig{Client: engine, Namespace: "lambda-image-test-" + uuid.NewString(), CallbackHost: os.Getenv("STACKD_LAMBDA_CALLBACK_HOST"), TelemetryHelpers: lambdaTelemetryHelpers(t)}
			openExecutor := func() *runtime.DockerExecutor {
				t.Helper()
				executor, err := runtime.NewDockerExecutor(t.Context(), config)
				if err != nil {
					t.Fatal(err)
				}
				return executor
			}
			executor := openExecutor()
			fenced := &imageAdmissionFence{DockerExecutor: executor}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := executor.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
			connect := func(backends *storage.Backends) {
				t.Helper()
				cloud, server := newLambdaDockerStackWithExecutor(t, stackd.Config{Storage: backends, Clock: replay.clock}, fenced)
				clients := cloudClients{server}
				replay.c = &lambdaEventsCloud{repository: backends.Lambda, cloud: cloud, server: server, queues: clients.sqs("test", "test", ""), lambda: awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})}
			}
			connect(backends)
			c := replay.c
			role, err := (cloudClients{c.server}).iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("image-runtime"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			imagePins := func() []byte {
				t.Helper()
				command := exec.Command("docker", "container", "ls", "--all", "--filter", "label=io.stackd.lambda.instance="+config.Namespace, "--filter", "label=io.stackd.kind=lambda-image-pin", "--format", "{{.ID}}")
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("listing native image retention ownership: %v %s", err, output)
				}
				artifacts := exec.Command("docker", "image", "ls", "--all", "--filter", "label=io.stackd.lambda.instance="+config.Namespace, "--filter", "label=io.stackd.kind=lambda-image-pin", "--format", "{{.ID}}")
				images, err := artifacts.CombinedOutput()
				if err != nil {
					t.Fatalf("listing native owned image artifacts: %v %s", err, images)
				}
				output = append(output, images...)
				return output
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.lambda.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: aws.String("image-rollback"), Role: role.Role.Arn, PackageType: lambdatypes.PackageTypeImage, Code: &lambdatypes.FunctionCode{ImageUri: aws.String(tag)}, ImageConfig: &lambdatypes.ImageConfig{WorkingDirectory: aws.String("relative")}})
			assertAPIError(t, err, "InvalidParameterValueException")
			if pins := imagePins(); len(pins) != 0 {
				t.Fatalf("rejected image admission leaked native retention ownership: %s", pins)
			}
			name := aws.String("image-hot-swap")
			created, err := c.lambda.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: name, Role: role.Role.Arn, PackageType: lambdatypes.PackageTypeImage, Code: &lambdatypes.FunctionCode{ImageUri: aws.String(tag)}, Timeout: aws.Int32(20), Publish: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if _, err := replay.c.lambda.DeleteFunction(cleanup, &awslambda.DeleteFunctionInput{FunctionName: name}); err != nil {
					t.Errorf("deleting deployed smoke image function: %v", err)
				}
				// The output queue message is sent inside the guest before its
				// Runtime API response and extension phase complete. Deletion
				// retires accepted work, not its lifetime; join the real service
				// shutdown before asserting that every execution root is gone.
				if err := replay.c.cloud.Close(); err != nil {
					t.Errorf("joining accepted image execution cleanup: %v", err)
				}
				command := exec.CommandContext(cleanup, "docker", "image", "inspect", tag)
				if output, err := command.CombinedOutput(); err != nil {
					t.Errorf("Lambda cleanup removed the caller's source image tag: %v %s", err, output)
				}
				if pins := imagePins(); len(pins) != 0 {
					t.Errorf("deleting the final deployment left native image retention ownership: %s", pins)
				}
			}()
			if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			invoke := func(qualifier, marker string) {
				t.Helper()
				input := &awslambda.InvokeInput{FunctionName: name, Payload: []byte(`{"route":"image-smoke"}`)}
				if qualifier != "" {
					input.Qualifier = aws.String(qualifier)
				}
				result, err := replay.c.lambda.Invoke(t.Context(), input)
				if err != nil {
					t.Fatalf("invoking real image function qualifier %q expecting %q: %v", qualifier, marker, err)
				}
				if result.FunctionError != nil {
					t.Fatalf("RIC execution error: %s %s", aws.ToString(result.FunctionError), result.Payload)
				}
				var output struct {
					Marker string            `json:"marker"`
					Event  map[string]string `json:"event"`
				}
				if err := json.Unmarshal(result.Payload, &output); err != nil {
					t.Fatal(err)
				}
				if output.Marker != marker || output.Event["route"] != "image-smoke" {
					t.Fatalf("unexpected actual function result: %s", result.Payload)
				}
			}
			invoke("", "first")
			// Stop an accepted cold call before Docker acquires any image-consuming
			// container. Hot-swap/deletion must not collect this admission's image.
			raceName := aws.String("image-accepted-lease")
			if _, err := c.lambda.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: raceName, Role: role.Role.Arn, PackageType: lambdatypes.PackageTypeImage, Code: &lambdatypes.FunctionCode{ImageUri: aws.String(tag)}, Timeout: aws.Int32(20)}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: raceName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			type acceptedResult struct {
				output *awslambda.InvokeOutput
				err    error
			}
			pauseInvocation := func() (<-chan acceptedResult, func()) {
				t.Helper()
				entered, release := fenced.pauseNext(aws.ToString(raceName))
				t.Cleanup(release)
				result := make(chan acceptedResult, 1)
				go func() {
					output, err := c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: raceName, Payload: []byte(`{"route":"image-lease"}`)})
					result <- acceptedResult{output, err}
				}()
				select {
				case <-entered:
				case <-time.After(time.Minute):
					t.Fatal("accepted image invocation never reached native preparation fence")
				}
				return result, release
			}
			finishInvocation := func(result <-chan acceptedResult, release func(), marker string) {
				t.Helper()
				release()
				select {
				case response := <-result:
					if response.err != nil {
						t.Fatal("accepted image execution lost retention: ", response.err)
					}
					var actual struct{ Marker string }
					if err := json.Unmarshal(response.output.Payload, &actual); err != nil {
						t.Fatal(err)
					}
					if response.output.FunctionError != nil || actual.Marker != marker {
						t.Fatalf("actual admitted image response = %+v %s", response.output.FunctionError, response.output.Payload)
					}
				case <-time.After(time.Minute):
					t.Fatal("accepted image invocation did not finish after native preparation fence")
				}
			}
			accepted, release := pauseInvocation()
			build("second")
			if _, err := c.lambda.UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: raceName, ImageUri: aws.String(tag)}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: raceName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			finishInvocation(accepted, release, "first")
			accepted, release = pauseInvocation()
			if _, err := c.lambda.DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: raceName}); err != nil {
				t.Fatal(err)
			}
			finishInvocation(accepted, release, "second")
			invoke("", "first") // Retagging alone must never alter a deployed function.
			if _, err := c.lambda.UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: name, ImageUri: aws.String(tag)}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			invoke("", "second")
			invoke(aws.ToString(created.Version), "first")
			if backend == "sqlite" {
				if err := replay.c.cloud.Close(); err != nil {
					t.Fatal(err)
				}
				replay.c.server.Close()
				if err := executor.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
				replay.closeDatabase()
				backends, closeDatabase := openSQLiteBackends(t, replay.path)
				replay.closeDatabase = closeDatabase
				executor = openExecutor()
				fenced.DockerExecutor = executor
				connect(backends)
				invoke("", "second")
				invoke(aws.ToString(created.Version), "first")
			}
			c = replay.c
			root := (cloudClients{c.server}).iam("test", "test", "")
			if _, err := root.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: aws.String("image-runtime"), PolicyName: aws.String("queue-delivery"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage","sqs:ChangeMessageVisibility","sqs:GetQueueAttributes"],"Resource":"*"}]}`)}); err != nil {
				t.Fatal(err)
			}
			inputQueue, err := c.queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("image-source")})
			if err != nil {
				t.Fatal(err)
			}
			outputQueue, err := c.queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("image-output")})
			if err != nil {
				t.Fatal(err)
			}
			attributes, err := c.queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: inputQueue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeName("QueueArn")}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.lambda.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: name, Environment: &lambdatypes.Environment{Variables: map[string]string{"OUTPUT_QUEUE_URL": aws.ToString(outputQueue.QueueUrl)}}}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			mapping, err := c.lambda.CreateEventSourceMapping(t.Context(), &awslambda.CreateEventSourceMappingInput{FunctionName: name, EventSourceArn: aws.String(attributes.Attributes["QueueArn"]), BatchSize: aws.Int32(1), Enabled: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if _, err := replay.c.lambda.DeleteEventSourceMapping(cleanup, &awslambda.DeleteEventSourceMappingInput{UUID: mapping.UUID}); err != nil {
					t.Errorf("deleting image smoke SQS mapping: %v", err)
				}
			}()
			if _, err := c.queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: inputQueue.QueueUrl, MessageBody: aws.String("real-source-message")}); err != nil {
				t.Fatal(err)
			}
			delivered := false
			deadline := time.Now().Add(time.Minute)
			for time.Now().Before(deadline) {
				if err := replay.clock.Advance(100 * time.Millisecond); err != nil {
					t.Fatal(err)
				}
				messages, err := c.queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: outputQueue.QueueUrl, MaxNumberOfMessages: 1})
				if err != nil {
					t.Fatal(err)
				}
				if len(messages.Messages) > 0 {
					var response struct {
						Marker string
						Event  struct{ Records []struct{ Body string } }
					}
					if err := json.Unmarshal([]byte(aws.ToString(messages.Messages[0].Body)), &response); err != nil {
						t.Fatal(err)
					}
					if response.Marker != "second" || len(response.Event.Records) != 1 || response.Event.Records[0].Body != "real-source-message" {
						t.Fatalf("actual source-to-image-to-SQS event: %s", aws.ToString(messages.Messages[0].Body))
					}
					delivered = true
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !delivered {
				t.Fatal("real SQS source never reached image RIC and output queue")
			}
		})
	}
}

// This fence only delays real native preparation; it never substitutes an
// environment, engine response, credentials, or customer invocation result.
type imageAdmissionFence struct {
	*runtime.DockerExecutor
	mu              sync.Mutex
	function        string
	entered, resume chan struct{}
}

func (f *imageAdmissionFence) pauseNext(function string) (<-chan struct{}, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.function, f.entered, f.resume = function, make(chan struct{}), make(chan struct{})
	resume := f.resume
	var once sync.Once
	return f.entered, func() { once.Do(func() { close(resume) }) }
}

func (f *imageAdmissionFence) Prepare(ctx context.Context, spec runtime.Specification) (runtime.Environment, error) {
	f.mu.Lock()
	var entered, resume chan struct{}
	if f.function == spec.FunctionName {
		entered, resume = f.entered, f.resume
		f.function = ""
	}
	f.mu.Unlock()
	if entered != nil {
		close(entered)
		select {
		case <-resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.DockerExecutor.Prepare(ctx, spec)
}
