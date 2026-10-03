package stackd_test

import (
	"bytes"
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
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"stackd/clock"
	"stackd/storage"
)

// The guide specifies periodic ownership checks, not their frequency. This test
// exercises the LOCAL one-hour schedule using native ZIPs and real Docker/SDKs.
func TestLambdaReferenceSourceLifecycleDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[struct {
		Observations []lambdaQualifiedRow
		Packages     map[string]struct{ ZIP struct{ Base64 []byte } }
	}](t, "s3_sources")
	layers := lambdaFixture[lambdaLayerFixture](t, "layers")
	roleRow := lambdaQualifiedObservation(t, lambdaQualifiedFixture{Observations: fixture.Observations}, "create-role-stackd-s3code-a14f509c-exec")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 15, 18, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "source-lifecycle.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			c := lambdaEventsConnect(t, backends, source)
			objects := s3NativeClient(cloudClients{c.server}, "test", "test")
			role, err := (cloudClients{c.server}).iam("test", "test", "").CreateRole(ctx, lambdaAdmissionInput[iam.CreateRoleInput](t, lambdaQualifiedJSON(t, roleRow.Input)))
			if err != nil {
				t.Fatal(err)
			}
			bucket := aws.String("lambda-source-lifecycle")
			if _, err := objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := objects.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: "Enabled"}}); err != nil {
				t.Fatal(err)
			}
			put := func(key string, code []byte) *string {
				t.Helper()
				out, err := objects.PutObject(ctx, &s3.PutObjectInput{Bucket: bucket, Key: aws.String(key), Body: bytes.NewReader(code)})
				if err != nil {
					t.Fatal(err)
				}
				return out.VersionId
			}
			functionVersion := put("function.zip", fixture.Packages["A"].ZIP.Base64)
			layerVersion := put("layer.zip", layers.Artifacts["layer-a"].ZIP.Base64)
			policy := func(resource string) {
				t.Helper()
				document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::%s/%s"}]}`, *bucket, resource)
				if _, err := objects.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: bucket, Policy: &document}); err != nil {
					t.Fatal(err)
				}
			}
			policy("*")
			layer, err := c.lambda.PublishLayerVersion(ctx, &awslambda.PublishLayerVersionInput{LayerName: aws.String("source-lifecycle"), Content: &lambdatypes.LayerVersionContentInput{S3Bucket: bucket, S3Key: aws.String("layer.zip"), S3ObjectVersion: layerVersion, S3ObjectStorageMode: "REFERENCE"}})
			if err != nil {
				t.Fatal(err)
			}
			name := aws.String("source-lifecycle-reference")
			created, err := c.lambda.CreateFunction(ctx, &awslambda.CreateFunctionInput{FunctionName: name, Runtime: "python3.12", Handler: aws.String("lambda_function.handler"), Role: role.Role.Arn, Code: &lambdatypes.FunctionCode{S3Bucket: bucket, S3Key: aws.String("function.zip"), S3ObjectVersion: functionVersion, S3ObjectStorageMode: "REFERENCE"}, Publish: true})
			if err != nil {
				t.Fatal(err)
			}
			layerName := aws.String("source-lifecycle-layer-only")
			if _, err := c.lambda.CreateFunction(ctx, &awslambda.CreateFunctionInput{FunctionName: layerName, Runtime: "python3.12", Handler: aws.String("lambda_function.handler"), Role: role.Role.Arn, Code: &lambdatypes.FunctionCode{ZipFile: fixture.Packages["A"].ZIP.Base64}, Layers: []string{*layer.LayerVersionArn}}); err != nil {
				t.Fatal(err)
			}
			for _, function := range []*string{name, layerName} {
				if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: function}, time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			state := func(function, qualifier *string, want lambdatypes.State) {
				t.Helper()
				out, err := c.lambda.GetFunctionConfiguration(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: function, Qualifier: qualifier})
				if err != nil {
					t.Fatal(err)
				}
				if out.State != want {
					t.Fatalf("%s/%s state=%s, want %s", *function, aws.ToString(qualifier), out.State, want)
				}
			}
			invoke := func(function *string) {
				t.Helper()
				out, err := c.lambda.Invoke(ctx, &awslambda.InvokeInput{FunctionName: function, Payload: []byte(`{}`)})
				if err != nil {
					t.Fatal(err)
				}
				var result struct{ Marker string }
				if err := json.Unmarshal(out.Payload, &result); err != nil {
					t.Fatal(err)
				}
				if out.FunctionError != nil || result.Marker != "A" {
					t.Fatalf("runtime failed: %+v payload=%s", out, out.Payload)
				}
			}
			update := func(function *string) {
				t.Helper()
				if _, err := c.lambda.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: function, Description: aws.String(source.Now().String())}); err != nil {
					t.Fatal(err)
				}
				if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: function}, time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			drain := func() {
				t.Helper()
				if _, err := c.cloud.RunDueJobs(ctx, 100); err != nil {
					t.Fatal(err)
				}
			}
			advanceClock(t, source, 30*time.Minute)
			update(name)           // Unrelated configuration must not postpone the first check.
			policy("function.zip") // Only layer service access is now missing.
			advanceClock(t, source, 30*time.Minute)
			drain() // Successful own-source checks must persist the next deadline.
			state(name, nil, "Active")
			state(layerName, nil, "Active")
			update(layerName) // Omitted layers neither refetch nor reauthorize.
			invoke(layerName)
			_, err = c.lambda.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: layerName, Layers: []string{*layer.LayerVersionArn}})
			assertAPIError(t, err, "InvalidParameterValueException")
			advanceClock(t, source, 30*time.Minute)
			if _, err := objects.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: bucket}); err != nil {
				t.Fatal(err)
			}
			if err := c.cloud.Close(); err != nil {
				t.Fatal(err)
			}
			c.server.Close()
			if backend == "sqlite" {
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
			}
			c = lambdaEventsConnect(t, backends, source)
			objects = s3NativeClient(cloudClients{c.server}, "test", "test")
			advanceClock(t, source, 30*time.Minute-time.Second)
			drain()
			state(name, nil, "Active") // Successful check survived the reopen.
			advanceClock(t, source, time.Second)
			drain()
			state(name, nil, "Inactive")             // Reopen did not postpone the due work.
			state(name, created.Version, "Inactive") // Published references retain ownership too.
			state(layerName, nil, "Active")
			_, err = c.lambda.Invoke(ctx, &awslambda.InvokeInput{FunctionName: name, Payload: []byte(`{}`)})
			assertAPIError(t, err, "ResourceConflictException")
			_, err = c.lambda.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: name, Description: aws.String("must not commit")})
			assertAPIError(t, err, "InvalidParameterValueException")
			state(name, nil, "Inactive")
			policy("function.zip")
			state(name, nil, "Inactive") // Restoring access alone is not activation.
			update(name)                 // Real preparation and readiness, not a synthetic Active flag.
			drain()
			state(name, nil, "Active")
			invoke(name)
			state(name, created.Version, "Inactive") // Latest recovery cannot rewrite an older deployment.
			if _, err := c.lambda.UpdateFunctionCode(ctx, &awslambda.UpdateFunctionCodeInput{FunctionName: name, ZipFile: fixture.Packages["A"].ZIP.Base64}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: name}, time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := objects.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: bucket, Key: aws.String("function.zip"), VersionId: functionVersion}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Hour)
			drain()
			state(name, nil, "Active") // COPY clears the periodic source obligation.
			invoke(name)
		})
	}
}
