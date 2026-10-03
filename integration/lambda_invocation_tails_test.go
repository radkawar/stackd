package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd"
)

// Replays output from actual official RICs. Do not normalize log timestamps into
// a fixed order: AWS's stdout, native frames and platform streams can interleave.
func TestLambdaInvocationTailsNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real invocation tail ownership")
	}
	fixture := lambdaFixture[struct {
		Sources map[string]string
		Cases   []struct {
			Label          string
			Event          json.RawMessage
			LogType        string
			InvocationType string
			Stream         bool
			FunctionError  string
			Decoded        string `json:"decoded_utf8"`
		}
	}](t, "invocation_tails")
	_, server := newLambdaDockerStack(t, stackd.Config{}, nil)
	c := cloudClients{server}
	client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	root := c.iam("test", "test", "")
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("invocation-tails"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "invocation-tails", `{"Statement":{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/invocation-tails-*:*"}}`)
	for _, runtime := range []struct{ name, source, file string }{{"python3.12", "python", "entry.py"}, {"nodejs22.x", "node", "entry.js"}} {
		t.Run(runtime.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			entry, err := writer.Create(runtime.file)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte(fixture.Sources[runtime.source])); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			name := "invocation-tails-" + runtime.source
			_, err = client.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: &name, Role: role.Role.Arn, Runtime: lambdatypes.Runtime(runtime.name), Handler: aws.String("entry.handler"), Code: &lambdatypes.FunctionCode{ZipFile: archive.Bytes()}, Timeout: aws.Int32(2)})
			if err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			configuration := ""
			var previous []string
			for _, row := range fixture.Cases {
				if !strings.HasPrefix(row.Label, runtime.name+"-") && !(runtime.source == "node" && row.Stream) {
					continue
				}
				// The same tail behavior is covered with backend thresholds enabled;
				// avoid another identical JSON matrix without those thresholds.
				if strings.Contains(row.Label, "-JSON-DEBUG-") || row.InvocationType == "Event" {
					continue
				}
				next := "Text"
				if strings.Contains(row.Label, "-JSON-") {
					next = "JSON"
				}
				if row.Stream {
					next = "stream"
				}
				if next != configuration {
					logging := &lambdatypes.LoggingConfig{LogFormat: lambdatypes.LogFormatText}
					handler := "entry.handler"
					if next == "JSON" {
						logging.LogFormat = lambdatypes.LogFormatJson
						logging.ApplicationLogLevel = lambdatypes.ApplicationLogLevelError
						logging.SystemLogLevel = lambdatypes.SystemLogLevelWarn
					}
					if row.Stream {
						handler = "entry.streaming"
					}
					if _, err := client.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: &name, Handler: &handler, LoggingConfig: logging}); err != nil {
						t.Fatal(err)
					}
					if err := awslambda.NewFunctionUpdatedWaiter(client, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
						t.Fatal(err)
					}
					configuration = next
					previous = nil
				}
				t.Run(row.Label, func(t *testing.T) {
					var encoded *string
					if row.Stream {
						out, err := client.InvokeWithResponseStream(t.Context(), &awslambda.InvokeWithResponseStreamInput{FunctionName: &name, Payload: row.Event, LogType: lambdatypes.LogType(row.LogType)})
						if err != nil {
							t.Fatal(err)
						}
						stream := out.GetStream()
						defer stream.Close()
						complete := false
						for event := range stream.Events() {
							if terminal, ok := event.(*lambdatypes.InvokeWithResponseStreamResponseEventMemberInvokeComplete); ok {
								encoded, complete = terminal.Value.LogResult, true
							}
						}
						if err := stream.Err(); err != nil || !complete {
							t.Fatalf("stream did not complete: %v", err)
						}
					} else {
						out, err := client.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: &name, Payload: row.Event, LogType: lambdatypes.LogType(row.LogType)})
						if err != nil {
							t.Fatal(err)
						}
						if aws.ToString(out.FunctionError) != row.FunctionError {
							t.Fatalf("function error = %q, want %q", aws.ToString(out.FunctionError), row.FunctionError)
						}
						encoded = out.LogResult
					}
					if row.LogType == "None" {
						if encoded != nil {
							t.Fatal("None returned LogResult")
						}
						return
					}
					tail, err := base64.StdEncoding.DecodeString(aws.ToString(encoded))
					if err != nil || !utf8.Valid(tail) || len(tail) > 4102 {
						t.Fatalf("invalid tail: %d bytes, %v", len(tail), err)
					}
					for _, marker := range []string{"TAIL_INIT", "TAIL_BEGIN " + row.Label, "TAIL_DEBUG " + row.Label, "TAIL_WARN " + row.Label, "TAIL_ERROR " + row.Label, "TAIL_LAST " + row.Label, "TAIL_PARTIAL " + row.Label, "TAIL_AFTER_STREAM " + row.Label, "REPORT RequestId:", "platform.runtimeDone", "platform.report"} {
						// Independent native streams can interleave around an
						// overflowing record; do not pin which earlier app
						// records happen to survive that ordering.
						if strings.Contains(row.Label, "-unicode") && strings.HasPrefix(marker, "TAIL_") && !strings.HasPrefix(marker, "TAIL_LAST ") && !strings.HasPrefix(marker, "TAIL_AFTER_STREAM ") {
							continue
						}
						if strings.Contains(string(tail), marker) != strings.Contains(row.Decoded, marker) {
							t.Fatalf("native marker %q differs: %s", marker, tail)
						}
					}
					for _, prior := range previous {
						if !strings.Contains(row.Decoded, prior) && bytes.Contains(tail, []byte(prior)) {
							t.Fatalf("previous invocation %q leaked into %s", prior, tail)
						}
					}
					if strings.Contains(row.Label, "-unicode") && configuration != "JSON" && len(tail) < 4096 {
						t.Fatalf("Text tail did not retain byte suffix: %d", len(tail))
					}
					if configuration == "JSON" && strings.Contains(row.Label, "-unicode") && bytes.Contains(tail, []byte("😀")) {
						t.Fatal("oversized JSON record was returned partially")
					}
					previous = append(previous, row.Label)
				})
			}
			if _, err := client.DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: &name}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
