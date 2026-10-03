package stackd_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd/clock"
	"stackd/internal/awstest"
)

const historicalLambdaFunctions = `SELECT f.*, a.code FROM fixture.lambda_functions AS f
JOIN fixture.lambda_code_archives AS a ON a.partition=f.partition AND a.account=f.account AND a.region=f.region AND a.code_sha256=f.code_sha256`

func lambdaArchiveUpgradeZIP(t *testing.T, version string) []byte {
	t.Helper()
	return lambdaZIP(t, map[string]string{"entry.py": fmt.Sprintf("def invoke(event, context):\n    return {\"version\": %q}\n", version)})
}

func TestLambdaCodeArchivesHistoricalSQLiteUpgrade(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	f := lambdaConcurrencyLocal(t, lambdaFixture[lambdaConcurrencyFixture](t, "concurrency_admission"))
	now := time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC)
	source := clock.NewManual(now)
	current := filepath.Join(t.TempDir(), "current.sqlite")
	backends, closeDatabase := openSQLiteBackends(t, current)
	c := lambdaEventsConnect(t, backends, source)
	role := lambdaAdmissionInput[iam.CreateRoleInput](t, f.row(t, "create_execution_role").Input)
	if _, err := (cloudClients{c.server}).iam("test", "test", "").CreateRole(t.Context(), role); err != nil {
		t.Fatal(err)
	}
	input := lambdaAdmissionInput[awslambda.CreateFunctionInput](t, f.row(t, "create_function_2").Input)
	input.Publish = false
	input.Runtime, input.Handler = lambdatypes.RuntimePython312, aws.String("entry.invoke")
	original := lambdaArchiveUpgradeZIP(t, "current")
	candidate := lambdaArchiveUpgradeZIP(t, "pending")
	input.Code = &lambdatypes.FunctionCode{ZipFile: original}
	names := []string{aws.ToString(input.FunctionName) + "-current", aws.ToString(input.FunctionName) + "-pending"}
	configurations := make([]*awslambda.GetFunctionConfigurationOutput, len(names))
	for i, name := range names {
		input.FunctionName = aws.String(name)
		if _, err := c.lambda.CreateFunction(t.Context(), input); err != nil {
			t.Fatal(err)
		}
		if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
			t.Fatal(err)
		}
		configuration, err := c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name})
		if err != nil {
			t.Fatal(err)
		}
		configurations[i] = configuration
	}
	if err := c.cloud.Close(); err != nil {
		t.Fatal(err)
	}
	c.server.Close()
	path := filepath.Join(t.TempDir(), "version45.sqlite")
	historical := awstest.HistoricalSQLite(t, path, "../storage/sqlite/schema", 45, current, map[string]string{"lambda_functions": historicalLambdaFunctions})
	closeDatabase()
	// Stage a historical candidate while the service is stopped, so recovery
	// must actually use migrated pending ZIP bytes rather than a warmed runtime.
	digest := sha256.Sum256(candidate)
	candidateHash := base64.StdEncoding.EncodeToString(digest[:])
	modified := now.Add(time.Second)
	if _, err := historical.ExecContext(t.Context(), `INSERT INTO lambda_functions
(partition,account,region,name,pending,runtime,handler,role,description,architecture,code,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason,dead_letter_arn,deployment_revision)
SELECT partition,account,region,name,true,runtime,handler,role,description,architecture,?,?,timeout,memory_mb,ephemeral_mb,?,?,state,state_reason,state_reason_code,'InProgress',update_reason,dead_letter_arn,?
FROM lambda_functions WHERE name=? AND pending=false`, candidate, candidateHash, "historical-candidate", modified, "historical-deployment", names[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := historical.ExecContext(t.Context(), "UPDATE lambda_functions SET update_status='InProgress' WHERE name=? AND pending=false", names[1]); err != nil {
		t.Fatal(err)
	}
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	backends, _ = openSQLiteBackends(t, path)
	c = lambdaEventsConnect(t, backends, source)
	for i, name := range names {
		if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
			t.Fatal(err)
		}
		configuration, err := c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name})
		if err != nil {
			t.Fatal(err)
		}
		// Recovery completes the pending update and rotates its public revision.
		// The retained deployment is observable through its hash and runtime.
		wantVersion, wantHash := "current", aws.ToString(configurations[i].CodeSha256)
		if i == 1 {
			wantVersion, wantHash = "pending", candidateHash
		}
		if aws.ToString(configuration.CodeSha256) != wantHash {
			t.Fatalf("upgrade recovered wrong code: got %s want %s", aws.ToString(configuration.CodeSha256), wantHash)
		}
		result, err := c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: &name, Payload: []byte(`{}`)})
		if err != nil || result.FunctionError != nil {
			t.Fatalf("upgraded real runtime: %+v %v", result, err)
		}
		var payload struct{ Version string }
		if err := json.Unmarshal(result.Payload, &payload); err != nil || payload.Version != wantVersion {
			t.Fatalf("upgraded runtime used wrong ZIP: %s %v", result.Payload, err)
		}
	}
}
