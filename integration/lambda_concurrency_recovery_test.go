package stackd_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd/clock"
	"stackd/storage"
)

// Reservations survive repository reopening, but account accounting counts each
// active function once, not its replacement deployment. Concurrent writers share
// the account boundary instead of independently observing spare capacity.
func TestLambdaConcurrencyAccountReservationRecovery(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaConcurrencyLocal(t, lambdaFixture[lambdaConcurrencyFixture](t, "concurrency_admission"))
			usage := lambdaFixture[struct {
				lambdaConcurrencyFixture
				ZIPBytes int64 `json:"zip_bytes"`
			}](t, "concurrency_usage")
			nativeBefore := lambdaAdmissionInput[awslambda.GetAccountSettingsOutput](t, usage.row(t, "before_create").Result.Output)
			nativeAfter := lambdaAdmissionInput[awslambda.GetAccountSettingsOutput](t, usage.row(t, "after_create_settled").Result.Output)
			source := clock.NewManual(time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "reservations.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			c := lambdaEventsConnect(t, backends, source)
			root := (cloudClients{c.server}).iam("test", "test", "")
			role := lambdaAdmissionInput[iam.CreateRoleInput](t, f.row(t, "create_execution_role").Input)
			if _, err := root.CreateRole(t.Context(), role); err != nil {
				t.Fatal(err)
			}
			template := lambdaAdmissionInput[awslambda.CreateFunctionInput](t, f.row(t, "create_function_2").Input)
			template.Publish = false
			settings := func(client *awslambda.Client) *awslambda.GetAccountSettingsOutput {
				t.Helper()
				out, err := client.GetAccountSettings(t.Context(), &awslambda.GetAccountSettingsInput{})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			baseline := settings(c.lambda)
			names := []string{aws.ToString(template.FunctionName), aws.ToString(template.FunctionName) + "-peer"}
			// The accounting capture has no deployable artifact. Apply its observed
			// storage-per-ZIP-byte relationship to the admission capture's real ZIP;
			// never derive the expectation from the emulator's own CodeSize response.
			codeSize := int64(len(template.Code.ZipFile)*len(names)) * (nativeAfter.AccountUsage.TotalCodeSize - nativeBefore.AccountUsage.TotalCodeSize) / usage.ZIPBytes
			functionCount := int64(len(names)) * (nativeAfter.AccountUsage.FunctionCount - nativeBefore.AccountUsage.FunctionCount)
			for _, name := range names {
				template.FunctionName = aws.String(name)
				_, err := c.lambda.CreateFunction(t.Context(), template)
				if err != nil {
					t.Fatal(err)
				}
				if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			active := settings(c.lambda)
			if active.AccountUsage.FunctionCount-baseline.AccountUsage.FunctionCount != functionCount || active.AccountUsage.TotalCodeSize-baseline.AccountUsage.TotalCodeSize != codeSize {
				t.Fatalf("account usage failed to count committed ZIP deployments: before=%+v after=%+v code=%d", baseline.AccountUsage, active.AccountUsage, codeSize)
			}
			// Default quota values are not pinned. This requests competing shares of the
			// advertised unreserved pool; both cannot preserve the native 100 floor.
			share := aws.ToInt32(active.AccountLimit.UnreservedConcurrentExecutions) / 2
			results := make(chan error, 2)
			start := make(chan struct{})
			for _, name := range names {
				go func() {
					<-start
					_, err := c.lambda.PutFunctionConcurrency(t.Context(), &awslambda.PutFunctionConcurrencyInput{FunctionName: &name, ReservedConcurrentExecutions: &share})
					results <- err
				}()
			}
			close(start)
			successes := 0
			for range names {
				if err := <-results; err == nil {
					successes++
				} else {
					assertAPIError(t, err, f.row(t, "invalid_excessive").Result.Code)
				}
			}
			if successes != 1 {
				t.Fatalf("competing reservations committed %d successes", successes)
			}
			var reservedName string
			for _, name := range names {
				out, err := c.lambda.GetFunctionConcurrency(t.Context(), &awslambda.GetFunctionConcurrencyInput{FunctionName: &name})
				if err != nil {
					t.Fatal(err)
				}
				if out.ReservedConcurrentExecutions != nil {
					reservedName = name
				}
			}
			reserved := settings(c.lambda)
			if aws.ToInt32(active.AccountLimit.UnreservedConcurrentExecutions)-aws.ToInt32(reserved.AccountLimit.UnreservedConcurrentExecutions) != share || !reflect.DeepEqual(active.AccountUsage, reserved.AccountUsage) {
				t.Fatalf("reservation double-counted usage or capacity: active=%+v reserved=%+v", active, reserved)
			}
			for _, scope := range []struct{ account, region string }{{"222222222222", "us-east-1"}, {"test", "us-west-2"}} {
				options := c.lambda.Options()
				options.Region = scope.region
				options.Credentials = credentials.NewStaticCredentialsProvider(scope.account, "test", "")
				other := awslambda.New(options)
				isolated := settings(other)
				if isolated.AccountUsage.FunctionCount != baseline.AccountUsage.FunctionCount || isolated.AccountUsage.TotalCodeSize != baseline.AccountUsage.TotalCodeSize || aws.ToInt32(isolated.AccountLimit.UnreservedConcurrentExecutions) != aws.ToInt32(baseline.AccountLimit.UnreservedConcurrentExecutions) {
					t.Fatalf("reservation/usage leaked into %s/%s: %+v", scope.account, scope.region, isolated)
				}
				_, err := other.GetFunctionConcurrency(t.Context(), &awslambda.GetFunctionConcurrencyInput{FunctionName: &reservedName})
				assertAPIError(t, err, f.row(t, "missing_get").Result.Code)
			}
			configuration, err := c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &reservedName})
			if err != nil {
				t.Fatal(err)
			}
			// Same-clock code replacement must neither duplicate usage nor reset the
			// independent reservation when the candidate replaces the active slot.
			_, err = c.lambda.UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: &reservedName, ZipFile: template.Code.ZipFile, RevisionId: configuration.RevisionId})
			if err != nil {
				t.Fatal(err)
			}
			pending := settings(c.lambda)
			if !reflect.DeepEqual(pending.AccountUsage, reserved.AccountUsage) {
				t.Fatal("candidate deployment counted as another function")
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &reservedName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			beforeClose := settings(c.lambda)
			if err := c.cloud.Close(); err != nil {
				t.Fatal(err)
			}
			c.server.Close()
			if backend == "sqlite" {
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
			}
			c = lambdaEventsConnect(t, backends, source)
			afterOpen := settings(c.lambda)
			if !reflect.DeepEqual(beforeClose.AccountUsage, afterOpen.AccountUsage) || !reflect.DeepEqual(beforeClose.AccountLimit, afterOpen.AccountLimit) {
				t.Fatalf("reopen lost account reservations: before=%+v after=%+v", beforeClose, afterOpen)
			}
			retained, err := c.lambda.GetFunctionConcurrency(t.Context(), &awslambda.GetFunctionConcurrencyInput{FunctionName: &reservedName})
			if err != nil || aws.ToInt32(retained.ReservedConcurrentExecutions) != share {
				t.Fatalf("reopen lost reservation: %+v %v", retained, err)
			}
			if _, err := c.lambda.DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: &reservedName}); err != nil {
				t.Fatal(err)
			}
			reclaimed := settings(c.lambda)
			if aws.ToInt32(reclaimed.AccountLimit.UnreservedConcurrentExecutions) != aws.ToInt32(active.AccountLimit.UnreservedConcurrentExecutions) || reclaimed.AccountUsage.FunctionCount != active.AccountUsage.FunctionCount-1 || reclaimed.AccountUsage.TotalCodeSize != active.AccountUsage.TotalCodeSize-codeSize/int64(len(names)) {
				t.Fatalf("delete failed to reclaim function usage and reservation: %+v", reclaimed)
			}
		})
	}
}

func TestLambdaConcurrencySameClockDeploymentAndZeroRecovery(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "zero-recovery.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			r := lambdaConcurrencyProvision(t, backends, source)
			r.command(t, "reserve_one")
			r.invoke(t, "permission-success-control")
			lambdaEventsReceive(t, r.c, r.audit, 2)
			input := r.functions[aws.ToString(r.name)]
			variables := map[string]string{}
			for key, value := range input.Environment.Variables {
				variables[key] = value
			}
			variables["AUDIT_QUEUE_URL"] = aws.ToString(r.destination)
			stamp := source.Now()
			if _, err := r.c.lambda.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: r.name, Environment: &lambdatypes.Environment{Variables: variables}}); err != nil {
				t.Fatal(err)
			}
			// Reservation metadata changes while candidate preparation is asynchronous.
			r.command(t, "zero_settled")
			r.command(t, "restore_capacity")
			if err := awslambda.NewFunctionUpdatedWaiter(r.c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: r.name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			if !source.Now().Equal(stamp) {
				t.Fatal("test requires same-clock deployment replacement")
			}
			r.invoke(t, "recovery-sync")
			lambdaEventsReceive(t, r.c, r.destination, 2)
			lambdaEventsQuiet(t, r.c, r.audit)
			// Restore captured routes before persisting zero capacity and its terminal
			// discarded events. Reopening may recreate environments, never old work.
			if _, err := r.c.lambda.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: r.name, Environment: input.Environment}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(r.c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: r.name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			r.command(t, "zero_settled")
			r.command(t, "both_routes")
			r.command(t, "both_routes_dlq")
			r.discard(t, []string{"zero-both-a"}, true, true)
			if err := r.c.cloud.Close(); err != nil {
				t.Fatal(err)
			}
			r.c.server.Close()
			if backend == "sqlite" {
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
			}
			r.c = lambdaEventsConnect(t, backends, source)
			reservation, err := r.c.lambda.GetFunctionConcurrency(t.Context(), &awslambda.GetFunctionConcurrencyInput{FunctionName: r.name})
			if err != nil || reservation.ReservedConcurrentExecutions == nil || *reservation.ReservedConcurrentExecutions != 0 {
				t.Fatalf("reopen confused explicit zero with absent reservation: %+v %v", reservation, err)
			}
			r.invoke(t, "sync-zero-settled")
			r.invoke(t, "dryrun-zero-settled")
			r.command(t, "restore_capacity")
			// Rebind only the endpoint after reopening the actual HTTP server.
			input.Environment.Variables["AWS_ENDPOINT_URL"] = strings.Replace(r.c.server.URL, "127.0.0.1", "host.docker.internal", 1)
			if _, err := r.c.lambda.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: r.name, Environment: input.Environment}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(r.c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: r.name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			r.invoke(t, "recovery-sync")
			lambdaEventsReceive(t, r.c, r.audit, 2)
			advanceClock(t, source, 2*time.Hour)
			lambdaEventsQuiet(t, r.c, r.audit, r.destination, r.dlq)
		})
	}
}
