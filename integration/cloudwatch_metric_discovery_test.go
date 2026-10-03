package stackd_test

import (
	"cmp"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http/protocol/awsquery"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type metricDiscoveryFixture struct {
	Account       string `json:"caller_account"`
	Region        string
	Observations  []awsNativeObservation
	Exclusions    map[string]string                 `json:"replay_exclusions"`
	CountRankTies map[string]bool                   `json:"replay_count_rank_ties"`
	Publications  []struct{ Fixture, Label string } `json:"replay_publications"`
}

func TestCloudWatchNativeMetricDiscovery(t *testing.T) {
	for _, filename := range []string{"metric_search.json", "metric_search_order.json", "metric_insights.json", "metric_insights_keywords.json", "metric_search_windows.json"} {
		for _, backend := range []string{"memory", "sqlite"} {
			for _, protocol := range []string{"rpc", "query"} {
				t.Run(filename+"/"+backend+"/"+protocol, func(t *testing.T) { replayMetricDiscovery(t, filename, backend, protocol) })
			}
		}
	}
}

func replayMetricDiscovery(t *testing.T, filename, backend, protocol string) {
	t.Helper()
	var fixture metricDiscoveryFixture
	awsReadFixture(t, "cloudwatch/"+filename, &fixture)
	slices.SortStableFunc(fixture.Observations, func(a, b awsNativeObservation) int { return cmp.Compare(a.Started, b.Started) })
	source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
	client := func() *cloudwatch.Client {
		options := cloudwatch.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1}
		if protocol == "query" {
			options.Protocol = awsquery.New(&smithy.ServiceSchema{Version: "2010-08-01"})
		}
		return cloudwatch.New(options)
	}
	for _, publication := range fixture.Publications {
		var prerequisite metricDiscoveryFixture
		awsReadFixture(t, "cloudwatch/"+publication.Fixture, &prerequisite)
		found := false
		for _, row := range prerequisite.Observations {
			if row.Label != publication.Label {
				continue
			}
			_, err := awstest.CallSDK(t.Context(), client(), row.Operation, row.Input)
			awsNativeResult(t, row, err)
			found = true
			break
		}
		if !found {
			t.Fatalf("missing native publication %s/%s", publication.Fixture, publication.Label)
		}
	}
	if backend == "sqlite" && len(fixture.Publications) > 0 {
		clients = reopen()
	}
	tokens := map[string]*string{}
	for _, row := range fixture.Observations {
		if row.Service != "cloudwatch" || row.Result.Code == "CLIError" {
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			if reason := fixture.Exclusions[row.Label]; reason != "" {
				t.Skip(reason)
			}
			when := time.UnixMilli(row.Started).UTC()
			if when.After(source.Now()) {
				advanceClock(t, source, when.Sub(source.Now()))
			}
			output, err := awstest.CallSDK(t.Context(), client(), row.Operation, row.Input, func(input any) {
				if query, ok := input.(*cloudwatch.GetMetricDataInput); ok && query.NextToken != nil {
					if token, known := tokens[*query.NextToken]; known {
						query.NextToken = token
					}
				}
			})
			awsNativeResult(t, row, err)
			if err != nil {
				return
			}
			switch result := output.(type) {
			case *cloudwatch.PutMetricDataOutput:
				if backend == "sqlite" {
					clients = reopen()
				}
			case *cloudwatch.GetMetricDataOutput:
				var native struct{ NextToken *string }
				if err := json.Unmarshal(row.Result.Output, &native); err != nil {
					t.Fatal(err)
				}
				if native.NextToken != nil {
					tokens[*native.NextToken] = result.NextToken
				}
				expected := row.Result.Output
				if fixture.CountRankTies[row.Label] {
					var native cloudwatch.GetMetricDataOutput
					if err := awstest.DecodeSDK(expected, &native); err != nil {
						t.Fatal(err)
					}
					normalized := *result
					normalized.MetricDataResults = slices.Clone(result.MetricDataResults)
					normalizeDiscoveryCountRanks(t, &normalized)
					normalizeDiscoveryCountRanks(t, &native)
					expected, err = json.Marshal(native)
					if err != nil {
						t.Fatal(err)
					}
					result = &normalized
				}
				assertMetricData(t, result, expected)
			default:
				t.Fatalf("unsupported discovery capture operation %s", row.Operation)
			}
		})
	}
}

// COUNT orders groups by returned datapoint count. Native captures do not
// establish a tie-breaker; retain and validate ranks between unequal counts.
func normalizeDiscoveryCountRanks(t *testing.T, output *cloudwatch.GetMetricDataOutput) {
	t.Helper()
	for start := 0; start < len(output.MetricDataResults); {
		end := start + 1
		for end < len(output.MetricDataResults) && len(output.MetricDataResults[end].Values) == len(output.MetricDataResults[start].Values) {
			end++
		}
		for i := start; i < end; i++ {
			result := &output.MetricDataResults[i]
			prefix := strconv.Itoa(i+1) + " - "
			label := aws.ToString(result.Label)
			if !strings.HasPrefix(label, prefix) {
				t.Fatalf("rank %d: label %q", i+1, label)
			}
			result.Label = aws.String(strconv.Itoa(start+1) + " - " + strings.TrimPrefix(label, prefix))
		}
		start = end
	}
}
