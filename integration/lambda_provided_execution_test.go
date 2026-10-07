package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// A custom runtime executable uses the documented Runtime API inside the
// official provided.al2023 OS image. No controller-side customer handler runs.
const providedSmokeRuntime = `package main
import ("encoding/json";"fmt";"io";"net/http";"os";"strings")
func main(){
 endpoint:="http://"+os.Getenv("AWS_LAMBDA_RUNTIME_API")+"/2018-06-01/runtime/invocation/"
 for {
  next,err:=http.Get(endpoint+"next");if err!=nil {panic(err)}
  event,err:=io.ReadAll(next.Body);next.Body.Close();if err!=nil || next.StatusCode!=200 {panic(fmt.Sprint("next invocation: ",err,next.StatusCode))}
  payload,err:=json.Marshal(map[string]any{"marker":%q,"handler":os.Getenv("_HANDLER"),"event":json.RawMessage(event)});if err!=nil {panic(err)}
  response,err:=http.Post(endpoint+next.Header.Get("Lambda-Runtime-Aws-Request-Id")+"/response","application/json",strings.NewReader(string(payload)));if err!=nil {panic(err)}
  io.Copy(io.Discard,response.Body);response.Body.Close();if response.StatusCode!=202 {panic(fmt.Sprint("response: ",response.StatusCode))}
 }
}
`

func providedSmokeZIP(t *testing.T, marker string) []byte {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "main.go")
	if err := os.WriteFile(source, []byte(fmt.Sprintf(providedSmokeRuntime, marker)), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "bootstrap")
	command := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", binary, source)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("building custom runtime executable: %v\n%s", err, output)
	}
	code, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: "bootstrap", Method: zip.Deflate}
	header.SetMode(0755)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(code); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func TestLambdaProvidedAL2023DockerBootstrapAndHotSwap(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to run real provided.al2023 ZIPs")
	}
	first, second := providedSmokeZIP(t, "first"), providedSmokeZIP(t, "second")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			replay := newLambdaQualifiedReplay(t, backend)
			c := replay.c
			role, err := (cloudClients{c.server}).iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("provided-runtime"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			name := aws.String("provided-hot-swap")
			created, err := c.lambda.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: name, Role: role.Role.Arn, Runtime: lambdatypes.Runtime("provided.al2023"), Handler: aws.String("custom.handler.setting"), Code: &lambdatypes.FunctionCode{ZipFile: first}, Architectures: []lambdatypes.Architecture{lambdatypes.Architecture("x86_64")}, Timeout: aws.Int32(20), Publish: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			invoke := func(qualifier, marker string) {
				t.Helper()
				input := &awslambda.InvokeInput{FunctionName: name, Payload: []byte(`{"route":"provided-smoke"}`)}
				if qualifier != "" {
					input.Qualifier = aws.String(qualifier)
				}
				result, err := c.lambda.Invoke(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				if result.FunctionError != nil {
					t.Fatalf("custom runtime error: %s %s", aws.ToString(result.FunctionError), result.Payload)
				}
				var response struct {
					Marker, Handler string
					Event           map[string]string
				}
				if err := json.Unmarshal(result.Payload, &response); err != nil {
					t.Fatal(err)
				}
				if response.Marker != marker || response.Handler != "custom.handler.setting" || response.Event["route"] != "provided-smoke" {
					t.Fatalf("custom runtime response: %s", result.Payload)
				}
			}
			invoke("", "first")
			if _, err := c.lambda.UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: name, ZipFile: second}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			invoke("", "second")
			invoke(aws.ToString(created.Version), "first")
			invalidName := aws.String("provided-invalid-bootstrap")
			if _, err := c.lambda.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{FunctionName: invalidName, Role: role.Role.Arn, Runtime: lambdatypes.Runtime("provided.al2023"), Handler: aws.String("bootstrap"), Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"bootstrap": "#!/bin/sh\nexit 1\n"})}, Timeout: aws.Int32(20)}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: invalidName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			failed, err := c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: invalidName, Payload: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			var failure struct {
				ErrorType string `json:"errorType"`
			}
			if err := json.Unmarshal(failed.Payload, &failure); err != nil {
				t.Fatal(err)
			}
			if failed.FunctionError == nil || failure.ErrorType != "Runtime.InvalidEntrypoint" {
				t.Fatalf("non-executable bootstrap did not return the real runtime error: %s %+v", failed.Payload, failed.FunctionError)
			}
		})
	}
}
