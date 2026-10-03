package stackd_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd/clock"
	"stackd/internal/awstest"
)

func TestLambdaConcurrencyHistoricalSQLiteUpgrade(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	f := lambdaConcurrencyLocal(t, lambdaFixture[lambdaConcurrencyFixture](t, "concurrency_admission"))
	source := clock.NewManual(time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC))
	current := filepath.Join(t.TempDir(), "current.sqlite")
	backends, closeDatabase := openSQLiteBackends(t, current)
	c := lambdaEventsConnect(t, backends, source)
	role := lambdaAdmissionInput[iam.CreateRoleInput](t, f.row(t, "create_execution_role").Input)
	if _, err := (cloudClients{c.server}).iam("test", "test", "").CreateRole(t.Context(), role); err != nil {
		t.Fatal(err)
	}
	input := lambdaAdmissionInput[awslambda.CreateFunctionInput](t, f.row(t, "create_function_2").Input)
	input.Publish = false
	if _, err := c.lambda.CreateFunction(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute); err != nil {
		t.Fatal(err)
	}
	invoke := &awslambda.InvokeInput{FunctionName: input.FunctionName, Payload: []byte(`{"upgrade":"retained-code"}`)}
	before, err := c.lambda.Invoke(t.Context(), invoke)
	if err != nil || before.FunctionError != nil {
		t.Fatalf("historical source runtime: %+v %v", before, err)
	}
	configuration, err := c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.cloud.Close(); err != nil {
		t.Fatal(err)
	}
	c.server.Close()
	path := filepath.Join(t.TempDir(), "version44.sqlite")
	historical := awstest.HistoricalSQLite(t, path, "../storage/sqlite/schema", 44, current, map[string]string{
		"lambda_functions": historicalLambdaFunctions,
	})
	closeDatabase()
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	backends, _ = openSQLiteBackends(t, path)
	c = lambdaEventsConnect(t, backends, source)
	upgraded, err := c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(upgraded.RevisionId) != aws.ToString(configuration.RevisionId) || aws.ToString(upgraded.CodeSha256) != aws.ToString(configuration.CodeSha256) {
		t.Fatal("upgrade changed public revision or retained code")
	}
	if _, err := c.lambda.PutFunctionConcurrency(t.Context(), &awslambda.PutFunctionConcurrencyInput{FunctionName: input.FunctionName, ReservedConcurrentExecutions: aws.Int32(0)}); err != nil {
		t.Fatal(err)
	}
	_, err = c.lambda.Invoke(t.Context(), invoke)
	execution := lambdaFixture[lambdaConcurrencyFixture](t, "concurrency_execution")
	assertAPIError(t, err, execution.row(t, "sync-zero-settled").Result.Code)
	if _, err := c.lambda.DeleteFunctionConcurrency(t.Context(), &awslambda.DeleteFunctionConcurrencyInput{FunctionName: input.FunctionName}); err != nil {
		t.Fatal(err)
	}
	after, err := c.lambda.Invoke(t.Context(), invoke)
	if err != nil || after.FunctionError != nil {
		t.Fatalf("upgraded real runtime: %+v %v", after, err)
	}
	if !reflect.DeepEqual(lambdaQueueObject(t, string(before.Payload)), lambdaQueueObject(t, string(after.Payload))) {
		t.Fatalf("upgrade/reservation metadata replaced retained deployment: before=%s after=%s", before.Payload, after.Payload)
	}
}
