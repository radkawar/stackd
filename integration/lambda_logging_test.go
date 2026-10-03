package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"stackd"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd/clock"
	"stackd/storage"
)

// Custom stream naming and execution-role requirements follow
// https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-loggroups.html.
// Logging configuration is versioned according to
// https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html.
func TestLambdaLoggingConfigurationDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real logging configuration and delivery")
	}
	var fixture struct {
		Handler string `json:"handler_source"`
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
			path := filepath.Join(t.TempDir(), "logging.sqlite")
			backends := storage.NewMemory()
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			sourceClock := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: sourceClock}, nil)
			c := cloudClients{server}
			root := c.iam("test", "test", "")
			client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			logs := logsClient(c, "test")
			const name = "logging-config"
			const firstGroup = "/application/shared.first_#-logs"
			const secondGroup = "application-replacement"
			defaultGroup := "/aws/lambda/" + name
			role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, root, name, fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":["arn:aws:logs:us-east-1:000000000000:log-group:%s:*","arn:aws:logs:us-east-1:000000000000:log-group:%s:*","arn:aws:logs:us-east-1:000000000000:log-group:%s:*"],"Condition":{"ArnEquals":{"lambda:SourceFunctionArn":"arn:aws:lambda:us-east-1:000000000000:function:%s"}}}}`, firstGroup, secondGroup, defaultGroup, name))
			created, err := client.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: aws.String(name), Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"), Code: &lambdatypes.FunctionCode{ZipFile: archive.Bytes()}, LoggingConfig: &lambdatypes.LoggingConfig{LogFormat: lambdatypes.LogFormatText, LogGroup: aws.String(firstGroup)}})
			if err != nil {
				t.Fatal(err)
			}
			assertConfiguration := func(configuration *lambdatypes.LoggingConfig, group string) {
				t.Helper()
				if configuration == nil || configuration.LogFormat != lambdatypes.LogFormatText || aws.ToString(configuration.LogGroup) != group {
					t.Fatalf("logging configuration = %+v, want Text to %q", configuration, group)
				}
			}
			assertConfiguration(created.LoggingConfig, firstGroup)
			if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}, time.Minute); err != nil {
				t.Fatal(err)
			}
			type destination struct{ Group, Stream string }
			invoke := func(function, qualifier, group, marker string) destination {
				t.Helper()
				payload, err := json.Marshal(map[string]any{"prefix": marker, "text": "", "repeat": 0})
				if err != nil {
					t.Fatal(err)
				}
				in := &awslambda.InvokeInput{FunctionName: aws.String(function), Payload: payload}
				if qualifier != "" {
					in.Qualifier = aws.String(qualifier)
				}
				out, err := client.Invoke(t.Context(), in)
				if err != nil || out.FunctionError != nil {
					t.Fatalf("logging changed invocation outcome: %+v, %v", out, err)
				}
				var result destination
				if err := json.Unmarshal(out.Payload, &result); err != nil {
					t.Fatal(err)
				}
				if result.Group != group {
					t.Fatalf("runtime destination = %+v, want group %q", result, group)
				}
				version := qualifier
				if version == "" {
					version = "$LATEST"
				}
				pattern := `^2031/02/03/\[` + regexp.QuoteMeta(version) + `\][0-9a-f]{32}$`
				if group != "/aws/lambda/"+function {
					pattern = `^2031/02/03/` + regexp.QuoteMeta(function) + `\[` + regexp.QuoteMeta(version) + `\]\[[0-9a-f]{32}\]$`
				}
				if !regexp.MustCompile(pattern).MatchString(result.Stream) {
					t.Fatalf("runtime stream %q does not identify function/version in selected group", result.Stream)
				}
				return result
			}
			awaitLog := func(destination destination, marker string) {
				t.Helper()
				deadline := time.Now().Add(10 * time.Second)
				for {
					out, err := logs.GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: aws.String(destination.Group), LogStreamName: aws.String(destination.Stream), StartFromHead: aws.Bool(true)})
					if err == nil {
						for _, event := range out.Events {
							if aws.ToString(event.Message) == marker+"\n" {
								return
							}
						}
					}
					if time.Now().After(deadline) {
						t.Fatalf("runtime log %q missing from %+v: %+v, %v", marker, destination, out, err)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			first := invoke(name, "", firstGroup, "custom-created")
			awaitLog(first, "custom-created")
			warm := invoke(name, "", firstGroup, "custom-warm")
			awaitLog(warm, "custom-warm")
			if first != warm {
				t.Fatalf("warm runtime changed destination: %+v -> %+v", first, warm)
			}
			published, err := client.PublishVersion(t.Context(), &awslambda.PublishVersionInput{FunctionName: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			version := aws.ToString(published.Version)
			update := func(in *awslambda.UpdateFunctionConfigurationInput, group string) {
				t.Helper()
				in.FunctionName = aws.String(name)
				out, err := client.UpdateFunctionConfiguration(t.Context(), in)
				if err != nil {
					t.Fatal(err)
				}
				assertConfiguration(out.LoggingConfig, group)
				if err := awslambda.NewFunctionUpdatedWaiter(client, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}, time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			for i, configuration := range []*lambdatypes.LoggingConfig{nil, {}, {LogFormat: lambdatypes.LogFormatText}} {
				group := firstGroup
				if configuration != nil {
					group = defaultGroup
				}
				update(&awslambda.UpdateFunctionConfigurationInput{Description: aws.String(fmt.Sprintf("omitted group %d", i)), LoggingConfig: configuration}, group)
				marker := fmt.Sprintf("preserved-%d", i)
				awaitLog(invoke(name, "", group, marker), marker)
			}
			update(&awslambda.UpdateFunctionConfigurationInput{LoggingConfig: &lambdatypes.LoggingConfig{LogGroup: aws.String(secondGroup)}}, secondGroup)
			awaitLog(invoke(name, "", secondGroup, "replacement"), "replacement")
			awaitLog(invoke(name, version, firstGroup, "published-retained"), "published-retained")
			_, err = client.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(name + ":" + version), LoggingConfig: &lambdatypes.LoggingConfig{LogGroup: aws.String(secondGroup)}})
			assertAPIError(t, err, "InvalidParameterValueException")
			for _, scenario := range []struct {
				name          string
				configuration lambdatypes.LoggingConfig
				code          string
			}{
				{"application-level", lambdatypes.LoggingConfig{ApplicationLogLevel: lambdatypes.ApplicationLogLevelInfo}, "InvalidParameterValueException"},
				{"system-level", lambdatypes.LoggingConfig{SystemLogLevel: lambdatypes.SystemLogLevelInfo}, "InvalidParameterValueException"},
				{"empty-group", lambdatypes.LoggingConfig{LogGroup: aws.String("")}, "ValidationException"},
				{"invalid-group", lambdatypes.LoggingConfig{LogGroup: aws.String("invalid:group")}, "ValidationException"},
				{"oversized-group", lambdatypes.LoggingConfig{LogGroup: aws.String(strings.Repeat("g", 513))}, "ValidationException"},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					_, err := client.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(name), LoggingConfig: &scenario.configuration})
					assertAPIError(t, err, scenario.code)
					out, err := client.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
					if err != nil {
						t.Fatal(err)
					}
					assertConfiguration(out.LoggingConfig, secondGroup)
				})
			}
			if backend == "sqlite" {
				if err := cloud.Close(); err != nil {
					t.Fatal(err)
				}
				server.Close()
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
				cloud, server = newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: sourceClock}, nil)
				c = cloudClients{server}
				root = c.iam("test", "test", "")
				client = awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
				logs = logsClient(c, "test")
				awaitLog(invoke(name, "", secondGroup, "reopened-latest"), "reopened-latest")
				awaitLog(invoke(name, version, firstGroup, "reopened-published"), "reopened-published")
				awaitLog(first, "custom-created")
			}
			// Explicitly selecting the function's own default resets custom routing.
			update(&awslambda.UpdateFunctionConfigurationInput{LoggingConfig: &lambdatypes.LoggingConfig{LogFormat: lambdatypes.LogFormatText, LogGroup: aws.String(defaultGroup)}}, defaultGroup)
			awaitLog(invoke(name, "", defaultGroup, "reset-default"), "reset-default")
			if _, err := client.DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
			for _, scenario := range []struct {
				denied              string
				existing, delivered bool
			}{
				{"CreateLogGroup", false, false},
				{"CreateLogGroup", true, true},
				{"CreateLogStream", true, false},
				{"PutLogEvents", true, false},
			} {
				t.Run(fmt.Sprintf("deny-%s-existing-%t", scenario.denied, scenario.existing), func(t *testing.T) {
					function := fmt.Sprintf("deny-%s-%t", scenario.denied, scenario.existing)
					group := "application/" + function
					role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(function), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
					if err != nil {
						t.Fatal(err)
					}
					putRolePolicy(t, root, function, fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:us-east-1:000000000000:log-group:%s:*"},{"Effect":"Deny","Action":"logs:%s","Resource":"*"}]}`, group, scenario.denied))
					if scenario.existing {
						if _, err := logs.CreateLogGroup(t.Context(), &cloudwatchlogs.CreateLogGroupInput{LogGroupName: aws.String(group)}); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := client.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: aws.String(function), Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"), Code: &lambdatypes.FunctionCode{ZipFile: archive.Bytes()}, LoggingConfig: &lambdatypes.LoggingConfig{LogGroup: aws.String(group)}}); err != nil {
						t.Fatal(err)
					}
					if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(function)}, time.Minute); err != nil {
						t.Fatal(err)
					}
					location := invoke(function, "", group, function)
					// Deletion drains real Docker output before negative delivery checks.
					if _, err := client.DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: aws.String(function)}); err != nil {
						t.Fatal(err)
					}
					if scenario.delivered {
						awaitLog(location, function)
						return
					}
					streams, err := logs.DescribeLogStreams(t.Context(), &cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: aws.String(group)})
					if !scenario.existing {
						assertAPIError(t, err, "ResourceNotFoundException")
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if scenario.denied == "CreateLogStream" {
						if len(streams.LogStreams) != 0 {
							t.Fatalf("denied stream creation left streams: %+v", streams.LogStreams)
						}
						return
					}
					if len(streams.LogStreams) != 1 || aws.ToString(streams.LogStreams[0].LogStreamName) != location.Stream {
						t.Fatalf("successful stream creation was lost after denied event delivery: %+v", streams.LogStreams)
					}
					out, err := logs.GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: aws.String(group), LogStreamName: aws.String(location.Stream), StartFromHead: aws.Bool(true)})
					if err != nil || len(out.Events) != 0 {
						t.Fatalf("denied event delivery wrote logs: %+v, %v", out, err)
					}
				})
			}
			if err := cloud.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
