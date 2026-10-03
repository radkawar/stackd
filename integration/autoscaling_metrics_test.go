package stackd_test

import (
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// Native AWS supplied all 25 enabled metric names and actual zero-valued
// CloudWatch samples for these five gauges, including no-pool warm/combined
// metrics. Replay their value/unit/statistics through the real publisher and
// CloudWatch owner. Native asynchronous ingestion lag is not a timing oracle.
func TestAutoScalingNativeZeroGroupMetricsAcrossReopen(t *testing.T) {
	fixture := asgFixture(t, "lifecycle_native")
	labels := []string{
		"metrics/native-metric-GroupDesiredCapacity-2",
		"metrics/native-metric-GroupInServiceInstances-2",
		"metrics/native-metric-GroupAndWarmPoolDesiredCapacity-2",
		"metrics/native-no-pool-WarmPoolDesiredCapacity",
		"metrics/native-no-pool-WarmPoolTotalCapacity",
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.row(t, "metrics/create-metrics-zero").StartedAt.Add(-time.Minute))
			bindings := map[string]string{}
			var active *stackd.Stack
			clients, reopen := asgRetainedCloud(t, backend, fixture, source, bindings, func(cloud *stackd.Stack) { active = cloud })
			for _, label := range []string{"owned-vpc", "owned-subnet"} {
				asgPrerequisite(t, clients, fixture.Region, fixture.row(t, label), bindings, nil)
			}
			owned := ecsControlBody(t, fixture.row(t, "owned-subnet").Output)["Subnet"].(map[string]any)["SubnetId"].(string)
			borrowed := ecsControlBody(t, fixture.row(t, "metrics/create-metrics-zero").Input)["VPCZoneIdentifier"].(string)
			bindings[borrowed] = bindings[owned]
			asgPrerequisite(t, clients, fixture.Region, fixture.row(t, "metrics/owned-zero-capacity-template"), bindings, nil)
			for _, label := range []string{"metrics/create-metrics-zero", "metrics/enable-all-one-minute-metrics", "metrics/metrics-enabled-group"} {
				row := fixture.row(t, label)
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				if !t.Run(label, func(t *testing.T) {
					asgReplay(t, clients, fixture.Region, row, bindings, asgRoot())
				}) {
					return
				}
				clients = reopen()
			}
			first := source.Now().Truncate(time.Minute).Add(time.Minute)
			var sampled []time.Time
			for _, scenario := range []struct {
				name string
				at   time.Time
			}{{"initial-minute", first}, {"resumed-without-backfill", first.Add(5 * time.Minute)}} {
				if !t.Run(scenario.name, func(t *testing.T) {
					source.Advance(scenario.at.Sub(source.Now()))
					if _, err := active.RunDueJobs(t.Context(), 100); err != nil {
						t.Fatal(err)
					}
					sampled = append(sampled, scenario.at)
					clients = reopen()
					// Running the reopened scheduler at the same instant must not
					// duplicate a retained gauge or inflate its SampleCount.
					if _, err := active.RunDueJobs(t.Context(), 100); err != nil {
						t.Fatal(err)
					}
					for _, label := range labels {
						t.Run(label, func(t *testing.T) {
							row := fixture.row(t, label)
							var request cloudwatch.GetMetricStatisticsInput
							if err := awstest.DecodeSDK(row.Input, &request); err != nil {
								t.Fatal(err)
							}
							request.StartTime, request.EndTime = &first, aws.Time(scenario.at.Add(time.Minute))
							wire := &awstest.WireClient{Client: clients.server.Client()}
							client := cloudwatch.New(cloudwatch.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: wire, RetryMaxAttempts: 1})
							actual, err := client.GetMetricStatistics(t.Context(), &request)
							if err != nil {
								t.Fatal(err)
							}
							if wire.Status != row.HTTPStatus {
								t.Fatalf("HTTP %d, native %d", wire.Status, row.HTTPStatus)
							}
							var expected cloudwatch.GetMetricStatisticsOutput
							if err := awstest.DecodeSDK(row.Output, &expected); err != nil {
								t.Fatal(err)
							}
							if len(expected.Datapoints) == 0 {
								t.Fatal("selected native metric evidence contains no sampled gauge")
							}
							point := expected.Datapoints[0]
							expected.Datapoints = make([]cwtypes.Datapoint, len(sampled))
							for i, at := range sampled {
								expected.Datapoints[i] = point
								expected.Datapoints[i].Timestamp = aws.Time(at)
							}
							for i := range actual.Datapoints {
								if actual.Datapoints[i].Timestamp != nil {
									actual.Datapoints[i].Timestamp = aws.Time(actual.Datapoints[i].Timestamp.UTC())
								}
							}
							slices.SortFunc(actual.Datapoints, func(a, b cwtypes.Datapoint) int { return aws.ToTime(a.Timestamp).Compare(aws.ToTime(b.Timestamp)) })
							asgCompare(t, label, ec2NetworkDocument(t, &expected), ec2NetworkDocument(t, actual), bindings)
						})
					}
				}) {
					return
				}
			}
		})
	}
}
