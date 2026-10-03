package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"stackd"
	"stackd/storage"
)

// Execute the exact captured native handlers through official images, not local
// handler substitutes. Configuration changes and SQLite restart must select the
// deployment's immutable logging controls, including published invocations.
func TestLambdaStructuredLoggingDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for official runtime logging")
	}
	data, err := os.ReadFile("../testdata/aws/lambda_structured_logging.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Handlers map[string]string `json:"handlers"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, language := range []string{"python", "node"} {
			t.Run(backend+"/"+language, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "logging.sqlite")
				backends := storage.NewMemory()
				var closeDatabase func()
				if backend == "sqlite" {
					backends, closeDatabase = openSQLiteBackends(t, path)
				}
				cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends}, nil)
				client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
				root := (cloudClients{server}).iam("test", "test", "")
				logs := logsClient(cloudClients{server}, "test")
				const name = "structured-logs"
				const group = "application/structured-logs"
				role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
				if err != nil {
					t.Fatal(err)
				}
				putRolePolicy(t, root, name, fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:us-east-1:000000000000:log-group:%s:*"}}`, group))
				var archive bytes.Buffer
				writer := zip.NewWriter(&archive)
				filename, runtime := "handler.py", lambdatypes.RuntimePython312
				if language == "node" {
					filename, runtime = "handler.js", lambdatypes.RuntimeNodejs22x
				}
				entry, err := writer.Create(filename)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte(fixture.Handlers[language])); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				created, err := client.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: aws.String(name), Role: role.Role.Arn, Runtime: runtime, Handler: aws.String("handler.handler"), Code: &lambdatypes.FunctionCode{ZipFile: archive.Bytes()}, LoggingConfig: &lambdatypes.LoggingConfig{LogFormat: lambdatypes.LogFormatJson, LogGroup: aws.String(group)}})
				if err != nil {
					t.Fatal(err)
				}
				if created.LoggingConfig.ApplicationLogLevel != lambdatypes.ApplicationLogLevelInfo || created.LoggingConfig.SystemLogLevel != lambdatypes.SystemLogLevelInfo {
					t.Fatalf("JSON defaults: %+v", created.LoggingConfig)
				}
				if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}, time.Minute); err != nil {
					t.Fatal(err)
				}
				published, err := client.PublishVersion(t.Context(), &awslambda.PublishVersionInput{FunctionName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				invoke := func(marker, qualifier string) {
					t.Helper()
					input := &awslambda.InvokeInput{FunctionName: aws.String(name), Payload: []byte(fmt.Sprintf(`{"marker":%q}`, marker))}
					if qualifier != "" {
						input.Qualifier = aws.String(qualifier)
					}
					out, err := client.Invoke(t.Context(), input)
					if err != nil || out.FunctionError != nil {
						t.Fatalf("invoke: %+v %v", out, err)
					}
				}
				invoke("initial", "")
				updated, err := client.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(name), LoggingConfig: &lambdatypes.LoggingConfig{LogFormat: lambdatypes.LogFormatJson, ApplicationLogLevel: lambdatypes.ApplicationLogLevelError, SystemLogLevel: lambdatypes.SystemLogLevelWarn, LogGroup: aws.String(group)}})
				if err != nil {
					t.Fatal(err)
				}
				if updated.LoggingConfig.ApplicationLogLevel != lambdatypes.ApplicationLogLevelError {
					t.Fatalf("update: %+v", updated.LoggingConfig)
				}
				if err := awslambda.NewFunctionUpdatedWaiter(client, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}, time.Minute); err != nil {
					t.Fatal(err)
				}
				invoke("filtered", "")
				invoke("published", aws.ToString(published.Version))
				if backend == "sqlite" {
					if err := cloud.Close(); err != nil {
						t.Fatal(err)
					}
					server.Close()
					closeDatabase()
					backends, _ = openSQLiteBackends(t, path)
					cloud, server = newLambdaDockerStack(t, stackd.Config{Storage: backends}, nil)
					client = awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
					logs = logsClient(cloudClients{server}, "test")
					invoke("reopened-filtered", "")
					invoke("reopened-published", aws.ToString(published.Version))
				}
				// Closing drains both customer output and the dedicated runtime log FD
				// before negative assertions, avoiding timing-based absence checks.
				if err := cloud.Close(); err != nil {
					t.Fatal(err)
				}
				out, err := logs.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String(group)})
				if err != nil {
					t.Fatal(err)
				}
				messages := make(map[string]bool)
				types := make(map[string]bool)
				requests := make(map[string]string)
				systemRequests := make(map[string]bool)
				for _, event := range out.Events {
					var record struct {
						Message   json.RawMessage `json:"message"`
						Type      string          `json:"type"`
						Level     string          `json:"level"`
						Timestamp string          `json:"timestamp"`
						RequestID string          `json:"requestId"`
						Record    struct {
							RequestID string `json:"requestId"`
						} `json:"record"`
					}
					if json.Unmarshal([]byte(aws.ToString(event.Message)), &record) != nil {
						continue
					}
					types[record.Type] = true
					if record.Type == "platform.start" || record.Type == "platform.report" {
						systemRequests[record.Record.RequestID] = true
					}
					var message string
					if json.Unmarshal(record.Message, &message) == nil {
						messages[message] = true
						requests[message] = record.RequestID
						if strings.HasPrefix(message, "library-") && (record.Timestamp == "" || record.RequestID == "") {
							t.Fatalf("missing managed fields: %s", aws.ToString(event.Message))
						}
					}
				}
				info, errorLevel := "INFO", "ERROR"
				if language == "node" {
					info, errorLevel = "info", "error"
				}
				markers := []string{"initial", "filtered", "published"}
				if backend == "sqlite" {
					markers = append(markers, "reopened-filtered", "reopened-published")
				}
				for _, marker := range markers {
					if !messages["library-"+marker+"-"+errorLevel] {
						t.Fatalf("missing ERROR for %s: %v", marker, messages)
					}
					wantInfo := !strings.Contains(marker, "filtered")
					if messages["library-"+marker+"-"+info] != wantInfo {
						t.Fatalf("application threshold leaked for %s: %v", marker, messages)
					}
					if systemRequests[requests["library-"+marker+"-"+errorLevel]] != wantInfo {
						t.Fatalf("system threshold leaked for %s", marker)
					}
					if language == "python" && !messages["missing-time-"+marker] {
						t.Fatalf("raw JSON severity lost without timestamp for %s", marker)
					}
				}
				if !types["platform.start"] || !types["platform.report"] || types["platform.runtimeDone"] || types["platform.end"] {
					t.Fatalf("INFO system events: %v", types)
				}
			})
		}
	}
}
