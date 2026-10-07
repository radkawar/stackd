package stackd_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"stackd"
	"stackd/clock"
	computelambda "stackd/compute/lambda"
	"stackd/storage"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

func lambdaKinesisCloud(t *testing.T, backend string, source *clock.Manual, observe ...func(*storage.Backends)) (cloudClients, func() cloudClients) {
	t.Helper()
	lambdaURLDocker(t)
	runtime := newKinesisReplayRuntime(t)
	// Observed image replays reconstruct both controller and native executor.
	// Root deployment pins outlive Close and belong to one stable namespace.
	namespace := "lambda-kinesis-" + rand.Text()
	var executor *computelambda.DockerExecutor
	return retainedCloud(t, backend, stackd.Config{Clock: source, KinesisRuntime: runtime},
		func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
			if len(observe) == 0 {
				return newLambdaDockerStack(t, config, &computelambda.DockerConfig{Client: runtime.client})
			}
			if executor != nil {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				err := executor.Close(ctx)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, observer := range observe {
				observer(config.Storage)
			}
			callback := os.Getenv("STACKD_LAMBDA_CALLBACK_HOST")
			if callback == "" && goruntime.GOOS == "darwin" {
				callback = "host.docker.internal"
			}
			var err error
			executor, err = computelambda.NewDockerExecutor(t.Context(), computelambda.DockerConfig{Client: runtime.client, Namespace: namespace, CallbackHost: callback, TelemetryHelpers: lambdaTelemetryHelpers(t)})
			if err != nil {
				t.Fatal(err)
			}
			current := executor
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := current.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			return newLambdaDockerStackWithExecutor(t, config, executor)
		})
}

func lambdaKinesisNativeSetup(t *testing.T, fixture lambdaKinesisFixture, clients cloudClients, source *clock.Manual) (*strings.Replacer, string) {
	t.Helper()
	account := fixture.row(t, "identity_before_writes").Result.Output["Account"].(string)
	replace := strings.NewReplacer(account, "000000000000")
	call := func(row lambdaURLRow) any { return lambdaKinesisCall(t, clients, row, replace) }
	call(fixture.row(t, "create_log_group"))
	call(fixture.row(t, "create_role"))
	call(fixture.row(t, "create_stream"))
	streamARN := aws.ToString(awaitKinesisActive(t, source, clients.kinesis("test", "test", ""), fixture.Prefix).StreamDescriptionSummary.StreamARN)
	consumerARN := lambdaKinesisConsumer(t, clients, source, streamARN)
	nativeConsumer := fixture.row(t, "register_consumer").Result.Output["Consumer"].(map[string]any)["ConsumerARN"].(string)
	replace = strings.NewReplacer(nativeConsumer, consumerARN, account, "000000000000")
	for _, policy := range []string{"policy_owned-logs", "policy_owned-source"} {
		call(fixture.row(t, policy))
	}
	for _, row := range fixture.Observations {
		if row.Operation == "create-function" && row.Result.Code == "Success" {
			call(row)
			break
		}
	}
	if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &fixture.Prefix}, time.Minute); err != nil {
		t.Fatal(err)
	}
	call(fixture.row(t, "publish_handler"))
	return replace, streamARN
}

func lambdaKinesisMappingState(t *testing.T, clients cloudClients, source *clock.Manual, id, state string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		advanceClock(t, source, 250*time.Millisecond)
		out, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToString(out.State) == state {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("mapping %s did not become %s", id, state)
}

func lambdaKinesisConsumer(t *testing.T, clients cloudClients, source *clock.Manual, streamARN string) string {
	t.Helper()
	client := clients.kinesis("test", "test", "")
	out, err := client.RegisterStreamConsumer(t.Context(), &kinesis.RegisterStreamConsumerInput{StreamARN: &streamARN, ConsumerName: aws.String("lambda-reader")})
	if err != nil {
		t.Fatal(err)
	}
	awaitKinesisConsumerActive(t, source, client, aws.ToString(out.Consumer.ConsumerARN))
	return aws.ToString(out.Consumer.ConsumerARN)
}

func lambdaKinesisInvocations(t *testing.T, clients cloudClients, source *clock.Manual, name, marker string, count int) []lambdaDynamoDBInvocation {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var got []lambdaDynamoDBInvocation
	for time.Now().Before(deadline) {
		advanceClock(t, source, 250*time.Millisecond)
		got = lambdaDynamoDBLogInvocations(t, clients, name, marker)
		if len(got) >= count {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Kinesis runtime invocations=%d want at least %d: %+v", len(got), count, got)
	return nil
}

func lambdaKinesisRecordData(t *testing.T, record map[string]any) map[string]any {
	t.Helper()
	data := record["kinesis"].(map[string]any)
	decoded, err := base64.StdEncoding.DecodeString(data["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(decoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
