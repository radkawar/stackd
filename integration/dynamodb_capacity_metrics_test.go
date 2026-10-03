package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"stackd"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

type dynamoMetricFixture struct {
	aasControlFixture
	Extensions []dynamoMetricFixture
	Windows    map[string]struct {
		Start, End    time.Time
		CallSequences []int
	}
	MetricSeries map[string]struct {
		MetricName string
		Dimensions []metrictypes.Dimension
	}
	Findings struct {
		Windows map[string]struct {
			Metrics map[string]struct{ Sum *float64 }
		}
	}
}

// Replay native operations and observed sums, not exporter sample counts or
// publication latency. An absent native datapoint is not an expected zero.
func TestDynamoDBNativeCapacityMetricsAcrossReopen(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	for _, sourceName := range []string{"capacity_metrics", "transaction_failure_metrics", "partiql_failure_metrics"} {
		var captured dynamoMetricFixture
		dynamoReadJSON(t, sourceName, &captured)
		for index, fixture := range append([]dynamoMetricFixture{captured}, captured.Extensions...) {
			windows := slices.Collect(maps.Keys(fixture.Windows))
			slices.SortFunc(windows, func(a, b string) int { return fixture.Windows[a].Start.Compare(fixture.Windows[b].Start) })
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(fmt.Sprintf("%s/%d/%s", sourceName, index, backend), func(t *testing.T) {
					clients, reopen, source := dynamoScalingCloud(t, runtime, backend, fixture.aasControlFixture)
					for _, name := range windows {
						if !t.Run(name, func(t *testing.T) {
							window := fixture.Windows[name]
							advanceClock(t, source, window.Start.Sub(source.Now()))
							trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
							for _, sequence := range window.CallSequences {
								row := fixture.Calls[sequence-1]
								client := dynamoClient(*clients, "test", "test", clients.server.Client())
								_, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, row.Input) })
								if row.Code != "Success" {
									assertAPIError(t, err, row.Code)
								} else if err != nil {
									t.Fatal(err)
								}
							}
							// Both the unexported minute and token replay charges must survive.
							reopen()
							advanceClock(t, source, window.End.Sub(source.Now()))
							trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
							for series, observed := range fixture.Findings.Windows[name].Metrics {
								if observed.Sum == nil {
									continue
								}
								metric := fixture.MetricSeries[series]
								request := &cloudwatch.GetMetricStatisticsInput{
									Namespace: aws.String("AWS/DynamoDB"), MetricName: &metric.MetricName,
									Dimensions: metric.Dimensions, StartTime: &window.Start, EndTime: &window.End,
									Period: aws.Int32(60), Statistics: []metrictypes.Statistic{metrictypes.StatisticSum},
								}
								dynamoMetricSum(t, metricsClient(*clients, "test"), request, *observed.Sum)
								if metric.MetricName == "ConsumedWriteCapacityUnits" && *observed.Sum > 0 {
									request.Dimensions = append(slices.Clone(metric.Dimensions), metrictypes.Dimension{Name: aws.String("Source"), Value: aws.String("Customer")})
									dynamoMetricSum(t, metricsClient(*clients, "test"), request, *observed.Sum)
								}
							}
						}) {
							return
						}
					}
				})
			}
		}
	}
}

func dynamoMetricSum(t *testing.T, client *cloudwatch.Client, request *cloudwatch.GetMetricStatisticsInput, expected float64) {
	t.Helper()
	out, err := client.GetMetricStatistics(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, point := range out.Datapoints {
		sum += aws.ToFloat64(point.Sum)
	}
	if len(out.Datapoints) == 0 || sum != expected {
		t.Fatalf("%s %v: sum=%g points=%v; native sum=%g", aws.ToString(request.MetricName), request.Dimensions, sum, out.Datapoints, expected)
	}
}
