package stackd_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	computelambda "stackd/compute/lambda"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

func lambdaDynamoDBDocker(t *testing.T) {
	t.Helper()
	lambdaURLDocker(t)
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 for real DynamoDB stream delivery")
	}
}

func lambdaDynamoDBCloud(t *testing.T, backend string, source *clock.Manual) (cloudClients, func() cloudClients) {
	t.Helper()
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	observed := &dynamoReplayRuntime{Runtime: runtime}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		for _, spec := range observed.specifications() {
			if err := runtime.Remove(ctx, spec); err != nil {
				t.Error(err)
			}
		}
	})
	return retainedCloud(t, backend, stackd.Config{Clock: source, DynamoDBRuntime: observed},
		func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
			return newLambdaDockerStack(t, config, &computelambda.DockerConfig{Client: engine})
		})
}

func lambdaDynamoDBClient(clients cloudClients) *awslambda.Client {
	return awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
}

func lambdaDynamoDBCall(t *testing.T, clients cloudClients, row lambdaURLRow, replace *strings.Replacer) any {
	t.Helper()
	raw := json.RawMessage(replace.Replace(string(row.Input)))
	var output any
	var err error
	switch row.Service {
	case "dynamodb":
		output, err = awstest.CallSDK(t.Context(), dynamoClient(clients, "test", "test", clients.server.Client()), row.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, raw) })
	case "iam":
		output, err = awstest.CallSDK(t.Context(), clients.iam("test", "test", ""), row.Operation, raw)
	case "logs":
		output, err = awstest.CallSDK(t.Context(), logsClient(clients, "test"), row.Operation, raw)
	case "sqs":
		output, err = awstest.CallSDK(t.Context(), clients.sqs("test", "test", ""), row.Operation, raw)
	case "s3api":
		output, err = awstest.CallSDK(t.Context(), s3NativeClient(clients, "test", "test"), row.Operation, raw)
	case "lambda":
		input := lambdaSQSNativeInput[map[string]any](t, raw, strings.NewReplacer())
		operation := lambdaSQSControlOperations(lambdaDynamoDBClient(clients))[row.Operation]
		if operation == nil {
			t.Fatalf("missing Lambda replay operation %s", row.Operation)
		}
		output, err = operation(t.Context(), input)
	default:
		t.Fatalf("unexpected prerequisite service %s", row.Service)
	}
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	return output
}
