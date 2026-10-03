package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"stackd"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd/clock"
	"stackd/storage"
)

func TestLambdaRuntimeLogDeliverySDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real runtime log delivery")
	}
	var fixture struct {
		Handler     string `json:"handler_source"`
		Invocations []struct {
			Prefix, Text, Partial string
			Repeat                int
		}
		Cases []struct {
			Name         string
			SourceSuffix string `json:"source_suffix"`
			Delivered    bool
		}
	}
	data, err := os.ReadFile("testdata/lambda/log_delivery.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("handler.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(entry, fixture.Handler); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "logs.sqlite"))
			}
			epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
			cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: clock.NewManual(epoch)}, nil)
			c := cloudClients{server}
			root := c.iam("test", "test", "")
			client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			logClient := logsClient(c, "test")
			for _, scenario := range fixture.Cases {
				t.Run(scenario.Name, func(t *testing.T) {
					name := "runtime-logs-" + scenario.Name
					functionARN := "arn:aws:lambda:us-east-1:000000000000:function:" + name
					role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
					if err != nil {
						t.Fatal(err)
					}
					putRolePolicy(t, root, name, fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/%s:*","Condition":{"ArnEquals":{"lambda:SourceFunctionArn":%q}}}}`, name, functionARN+scenario.SourceSuffix))
					_, err = client.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: aws.String(name), Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"), Code: &lambdatypes.FunctionCode{ZipFile: archive.Bytes()}, Timeout: aws.Int32(10)})
					if err != nil {
						t.Fatal(err)
					}
					if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}, time.Minute); err != nil {
						t.Fatal(err)
					}
					var destination struct{ Group, Stream string }
					var expected strings.Builder
					expected.WriteString("cold initialization\n")
					for _, invocation := range fixture.Invocations {
						payload, err := json.Marshal(map[string]any{"prefix": invocation.Prefix, "text": invocation.Text, "repeat": invocation.Repeat, "partial": invocation.Partial})
						if err != nil {
							t.Fatal(err)
						}
						out, err := client.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: aws.String(name), Payload: payload, LogType: lambdatypes.LogTypeTail})
						if err != nil || out.FunctionError != nil {
							t.Fatalf("logging changed invocation outcome: %v %v", out, err)
						}
						var current struct{ Group, Stream string }
						if err := json.Unmarshal(out.Payload, &current); err != nil {
							t.Fatal(err)
						}
						if current.Group != "/aws/lambda/"+name || current.Stream == "" {
							t.Fatalf("runtime log destination: %+v", current)
						}
						if destination.Stream != "" && destination != current {
							t.Fatalf("warm runtime changed log stream: %+v -> %+v", destination, current)
						}
						destination = current
						tail, err := base64.StdEncoding.DecodeString(aws.ToString(out.LogResult))
						if err != nil || !utf8.Valid(tail) {
							t.Fatalf("invalid Invoke log tail: %d bytes, %v", len(tail), err)
						}
						expected.WriteString(invocation.Prefix + strings.Repeat(invocation.Text, invocation.Repeat) + "\n")
						expected.WriteString("stderr:" + invocation.Prefix + "\n" + invocation.Partial)
					}
					// Deletion drains the native stream, including its unterminated final
					// line. Log groups outlive function deletion.
					if _, err := client.DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: aws.String(name)}); err != nil {
						t.Fatal(err)
					}
					if !scenario.Delivered {
						_, err := logClient.DescribeLogStreams(t.Context(), &cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: aws.String(destination.Group)})
						assertAPIError(t, err, "ResourceNotFoundException")
						return
					}
					var captured strings.Builder
					var token *string
					for range 30 {
						out, err := logClient.GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: aws.String(destination.Group), LogStreamName: aws.String(destination.Stream), StartFromHead: aws.Bool(true), NextToken: token})
						if err != nil {
							t.Fatal(err)
						}
						for _, event := range out.Events {
							if aws.ToInt64(event.Timestamp) != epoch.UnixMilli() {
								t.Fatalf("log timestamp escaped service-time edge: %v", event.Timestamp)
							}
							captured.WriteString(aws.ToString(event.Message))
						}
						if token != nil && aws.ToString(out.NextForwardToken) == *token {
							break
						}
						token = out.NextForwardToken
					}
					// stdout/stderr are independent native pipes. Platform lifecycle
					// records add bytes, so compare each customer message separately.
					actual := captured.String()
					for _, message := range strings.Split(expected.String(), "\n") {
						if message != "" && strings.Count(actual, message) != 1 {
							t.Fatalf("runtime message missing or duplicated (%d bytes); captured %d bytes", len(message), len(actual))
						}
					}
				})
			}
			if err := cloud.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
