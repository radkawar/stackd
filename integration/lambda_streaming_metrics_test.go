package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"stackd"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd/clock"
	"stackd/storage"
)

// Each native function was invoked exactly once: an explicit Errors=0 sample
// is distinct from no datapoints, and a successful InvokeComplete is distinct
// from successful execution. Keep those two public contracts in the same replay.
func TestLambdaStreamingMetricsDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise real Docker Lambda streaming metrics")
	}
	fixture := lambdaFixture[struct {
		Prefix, Account string
		StartedAt       time.Time `json:"started_at"`
		Artifact        struct {
			Fixture string
		}
		Observations []lambdaStreamingRow
		Cases        map[string]struct {
			Invocation struct {
				lambdaStreamingRow
				Response json.RawMessage
				Payload  struct{ Base64 string }
			}
			Metrics map[string]struct {
				Datapoints []metrictypes.Datapoint
				LastPoll   int `json:"last_poll"`
			}
		}
	}](t, "streaming_metrics")
	if len(fixture.Cases) == 0 {
		t.Fatal("fixture has no captured metric invocations")
	}
	artifact := lambdaFixture[lambdaStreamingFixture](t, strings.TrimSuffix(strings.TrimPrefix(fixture.Artifact.Fixture, "testdata/aws/lambda/"), ".json"))
	code := lambdaStreamingCode(t, &artifact, "x86_64")
	source := clock.NewManual(fixture.StartedAt)
	start := source.Now().Add(-time.Minute)
	cloud, server := newLambdaDockerStack(t, stackd.Config{Storage: storage.NewMemory(), Clock: source}, nil)
	clients := cloudClients{server}
	client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	metrics := metricsClient(clients, "test")
	normalize := strings.NewReplacer(fixture.Prefix, "stream-metrics-replay", fixture.Account, "000000000000")
	observations := make(map[string]lambdaStreamingRow, len(fixture.Observations))
	for _, row := range fixture.Observations {
		observations[row.Label] = row
		// The capture includes IAM-propagation retries; replay only accepted
		// setup calls, not those transient native admission failures.
		if row.Result.Code != "Success" {
			continue
		}
		switch row.Operation {
		case "create_role":
			input := lambdaStreamingInput[iam.CreateRoleInput](t, row.Input, normalize)
			if _, err := clients.iam("test", "test", "").CreateRole(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
		case "put_role_policy":
			input := lambdaStreamingInput[iam.PutRolePolicyInput](t, row.Input, normalize)
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
		case "create_function":
			input := lambdaStreamingInput[awslambda.CreateFunctionInput](t, row.Input, normalize)
			input.Code = &lambdatypes.FunctionCode{ZipFile: code}
			input.Architectures = []lambdatypes.Architecture{lambdatypes.Architecture("x86_64")}
			if _, err := client.CreateFunction(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, label := range slices.Sorted(maps.Keys(fixture.Cases)) {
		t.Run(label, func(t *testing.T) {
			captured := fixture.Cases[label]
			row := captured.Invocation.lambdaStreamingRow
			if err := json.Unmarshal(captured.Invocation.Response, &row.Result.Output); err != nil {
				t.Fatal(err)
			}
			row.Payload = &captured.Invocation.Payload.Base64
			// The shared SDK consumer exhausts and closes the stream, rejects
			// duplicate completion, bounds retained chunks to 1 MiB, and compares
			// native completion errors, ordinary FunctionError, and payloads.
			lambdaStreamingInvoke(t, client, row, normalize)
			advanceClock(t, source, time.Minute)
			if _, err := cloud.RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			for _, name := range slices.Sorted(maps.Keys(captured.Metrics)) {
				t.Run(name, func(t *testing.T) {
					want := captured.Metrics[name]
					if len(want.Datapoints) != 1 {
						t.Fatal("native isolated invocation lacks an explicit metric datapoint")
					}
					query, ok := observations[fmt.Sprintf("metrics_%s_%s_%d", label, name, want.LastPoll)]
					if !ok || query.Result.Code != "Success" {
						t.Fatal("missing native metric query")
					}
					input := lambdaStreamingInput[cloudwatch.GetMetricStatisticsInput](t, query.Input, normalize)
					input.StartTime, input.EndTime = &start, aws.Time(source.Now().Add(time.Minute))
					out, err := metrics.GetMetricStatistics(t.Context(), &input)
					if err != nil {
						t.Fatal(err)
					}
					if len(out.Datapoints) != len(want.Datapoints) {
						t.Fatalf("datapoints = %+v, native = %+v; absent data is not zero", out.Datapoints, want.Datapoints)
					}
					got, expected := out.Datapoints[0], want.Datapoints[0]
					// FunctionName isolation makes a single sample observable without
					// comparing wall-clock timestamps or inferring zero from absence.
					if !reflect.DeepEqual(got.Sum, expected.Sum) || !reflect.DeepEqual(got.SampleCount, expected.SampleCount) || got.Unit != expected.Unit {
						gotJSON, _ := json.Marshal(got)
						expectedJSON, _ := json.Marshal(expected)
						t.Fatalf("metric datapoint = %s, native = %s", gotJSON, expectedJSON)
					}
				})
			}
		})
	}
}
