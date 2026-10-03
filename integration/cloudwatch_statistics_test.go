package stackd_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

func TestCloudWatchNativeExtendedStatisticsSDK(t *testing.T) {
	fixture := loadMetricFixture(t, "statistics")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, source := metricFixtureCloud(t, backend, fixture)
			client := metricsClient(c, "test")
			for _, label := range []string{"publish-independent-distributions", "publish-all-zero-counts"} {
				row := fixture.row(t, label)
				if at := time.UnixMilli(row.Started); at.After(source.Now()) {
					advanceClock(t, source, at.Sub(source.Now()))
				}
				replayMetric(t, client, row)
			}
			// These are actual response values and field-presence observations, not
			// candidate arithmetic. In particular General has unequal
			// endpoints, inconsistent equal endpoints and inconsistent count-one
			// buckets; Fractional crosses the count-one eligibility boundary.
			for _, metric := range []string{"Weighted", "Expanded", "Uniform", "Tight", "Scaled", "Equal", "Eligible", "Fractional", "General", "Mixed"} {
				for _, family := range []string{"percentile", "trimmed", "fixed"} {
					label := "statistics-" + metric + "-" + family
					t.Run(label, func(t *testing.T) {
						row := fixture.row(t, label)
						assertMetricStatistics(t, replayMetric(t, client, row).(*cloudwatch.GetMetricStatisticsOutput), row.Result.Output)
					})
				}
			}
			// Zero count is admitted and retained: Average is NaN, not zero or
			// missing. Zero-count positive endpoints affect basic extrema and p0/p100.
			for _, label := range []string{"statistics-AllZero-percentile", "statistics-AllZero-trimmed", "statistics-AllZero-fixed", "statistics-ZeroEdges-percentile", "statistics-ZeroEdges-trimmed", "statistics-ZeroEdges-fixed"} {
				t.Run(label, func(t *testing.T) {
					row := fixture.row(t, label)
					assertMetricStatistics(t, replayMetric(t, client, row).(*cloudwatch.GetMetricStatisticsOutput), row.Result.Output)
				})
			}
			// Native rejects a negative fixed winsor bound through both APIs.
			for _, label := range []string{"follow-up-empty-fixed-1", "follow-up-empty-fixed-statistics"} {
				t.Run(label, func(t *testing.T) { replayMetric(t, client, fixture.row(t, label)) })
			}
		})
	}
}

func TestCloudWatchNativeZeroValuedDistributionsSDK(t *testing.T) {
	fixture := loadMetricFixture(t, "statistics")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, source := metricFixtureCloud(t, backend, fixture)
			client := metricsClient(c, "test")
			row := fixture.row(t, "follow-up-publish-zero-distributions")
			if at := time.UnixMilli(row.Started); at.After(source.Now()) {
				advanceClock(t, source, at.Sub(source.Now()))
			}
			replayMetric(t, client, row)
			// These later timestamps reuse names, but publish different inputs:
			// positive-weight zeros, zero-weight zeros, all-zero values, fractional
			// weights and negative mixtures. They are not the zero-COUNT-bin matrix.
			for _, label := range []string{"follow-up-zero-statistics-Weighted", "follow-up-zero-statistics-Eligible", "follow-up-zero-statistics-Equal", "follow-up-zero-statistics-Fractional"} {
				t.Run(label, func(t *testing.T) {
					row := fixture.row(t, label)
					assertMetricStatistics(t, replayMetric(t, client, row).(*cloudwatch.GetMetricStatisticsOutput), row.Result.Output)
				})
			}
			for _, label := range []string{"follow-up-zero-distribution-data", "follow-up-zero-terminal"} {
				t.Run(label, func(t *testing.T) {
					row := fixture.row(t, label)
					assertMetricData(t, replayMetric(t, client, row).(*cloudwatch.GetMetricDataOutput), row.Result.Output)
				})
			}
			for _, row := range loadMetricFixture(t, "metric_labels").Observations {
				t.Run(row.Label, func(t *testing.T) {
					out := replayMetric(t, client, row)
					if out != nil {
						assertMetricData(t, out.(*cloudwatch.GetMetricDataOutput), row.Result.Output)
					}
				})
			}
		})
	}
}

func TestCloudWatchNativeRetainedBinsSDK(t *testing.T) {
	for _, name := range []string{"zero_count_boundaries", "exact_bin_boundaries", "extreme_bin_boundaries"} {
		fixture := loadMetricFixture(t, name)
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				c, source := metricFixtureCloud(t, backend, fixture)
				client := metricsClient(c, "test")
				for _, row := range fixture.Observations {
					// Identity capture is provenance, not a metric operation.
					// Later reads cover incomplete native publication visibility.
					if row.Operation == "get-caller-identity" || row.VisibilityIncomplete {
						continue
					}
					t.Run(row.Label, func(t *testing.T) {
						if at := time.UnixMilli(row.Started); at.After(source.Now()) {
							advanceClock(t, source, at.Sub(source.Now()))
						}
						out := replayMetric(t, client, row)
						if result, ok := out.(*cloudwatch.GetMetricDataOutput); ok {
							assertMetricData(t, result, row.Result.Output)
						}
					})
				}
			})
		}
	}
}
