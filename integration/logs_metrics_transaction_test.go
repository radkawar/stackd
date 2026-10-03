package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
	metricstorage "stackd/storage/cloudwatch"
)

// Fail only after the real repository has mutated point storage. A publisher
// mock cannot establish that the enclosing Logs transaction rolls this back.
type logsMetricAppendFailure struct {
	metricstorage.Repository
	fail atomic.Bool
}

type logsMetricFailingTransaction struct {
	metricstorage.Transaction
	owner *logsMetricAppendFailure
}

func (r *logsMetricAppendFailure) Update(ctx context.Context, fn func(metricstorage.Transaction) error) error {
	return r.Repository.Update(ctx, func(tx metricstorage.Transaction) error {
		return fn(&logsMetricFailingTransaction{Transaction: tx, owner: r})
	})
}

func (tx *logsMetricFailingTransaction) AppendPoints(id string, points []metricstorage.Point) error {
	if err := tx.Transaction.AppendPoints(id, points); err != nil {
		return err
	}
	if tx.owner.fail.Swap(false) {
		return errors.New("injected failure after metric points append")
	}
	return nil
}

func TestLogsMetricsAtomicPublicationAuthorizationAndReopen(t *testing.T) {
	fixture := loadLogsMetricFixture(t, "metric_filters")
	requests := map[string]logsMetricObservation{}
	for _, row := range fixture.Observations {
		requests[row.Label] = row
	}
	var nativeBatch cloudwatchlogs.PutLogEventsInput
	if err := json.Unmarshal(requests["publish-basic"].Input, &nativeBatch); err != nil {
		t.Fatal(err)
	}
	var filter cloudwatchlogs.PutMetricFilterInput
	if err := json.Unmarshal(requests["create-number"].Input, &filter); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "logs-metrics.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.UnixMilli(requests["publish-basic"].Started).UTC())
			var cloud *stackd.Stack
			var c cloudClients
			var logs *cloudwatchlogs.Client
			var metrics *cloudwatch.Client
			var fault *logsMetricAppendFailure
			connect := func() {
				t.Helper()
				fault = &logsMetricAppendFailure{Repository: backends.CloudWatch}
				backends.CloudWatch = fault
				var err error
				cloud, err = stackd.New(stackd.Config{Storage: backends, Clock: source, AccountID: fixture.Account})
				if err != nil {
					t.Fatal(err)
				}
				c = cloudClients{httptest.NewServer(cloud)}
				logs, metrics = logsClient(c, "test"), metricsClient(c, "test")
			}
			connect()
			defer func() {
				c.server.Close()
				if err := cloud.Close(); err != nil {
					t.Error(err)
				}
				closeDB()
			}()
			for _, operation := range []struct{ Name, Label string }{{"CreateLogGroup", "create-group"}, {"CreateLogStream", "create-stream-basic"}, {"PutMetricFilter", "create-number"}} {
				if _, err := awstest.CallSDK(t.Context(), logs, operation.Name, requests[operation.Label].Input); err != nil {
					t.Fatal(err)
				}
			}
			configuration := func() logtypes.MetricFilter {
				t.Helper()
				out, err := logs.DescribeMetricFilters(t.Context(), &cloudwatchlogs.DescribeMetricFiltersInput{LogGroupName: filter.LogGroupName, FilterNamePrefix: filter.FilterName})
				if err != nil || len(out.MetricFilters) != 1 {
					t.Fatalf("filter configuration unavailable: %+v, %v", out, err)
				}
				return out.MetricFilters[0]
			}
			original := configuration()
			journalRows := func() []journal.Event {
				t.Helper()
				rows, err := backends.Journal.Read(t.Context(), 0, 1000)
				if err != nil {
					t.Fatal(err)
				}
				var accepted []journal.Event
				for _, row := range rows {
					if row.LogsBatchAccepted.LogGroupARN == "arn:aws:logs:us-east-1:"+fixture.Account+":log-group:"+fixture.Group {
						accepted = append(accepted, row)
					}
				}
				return accepted
			}
			readLogs := func() []logtypes.FilteredLogEvent {
				t.Helper()
				out, err := logs.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: nativeBatch.LogGroupName, LogStreamNames: []string{aws.ToString(nativeBatch.LogStreamName)}})
				if err != nil {
					t.Fatal(err)
				}
				return out.Events
			}
			query := &cloudwatch.GetMetricStatisticsInput{Namespace: filter.MetricTransformations[0].MetricNamespace, MetricName: filter.MetricTransformations[0].MetricName, StartTime: aws.Time(source.Now().Add(-time.Minute)), EndTime: aws.Time(source.Now().Add(time.Hour)), Period: aws.Int32(60), Statistics: []metrictypes.Statistic{metrictypes.StatisticSum, metrictypes.StatisticSampleCount}}
			readMetrics := func(client *cloudwatch.Client) []metrictypes.Datapoint {
				t.Helper()
				out, err := client.GetMetricStatistics(t.Context(), query)
				if err != nil {
					t.Fatal(err)
				}
				return out.Datapoints
			}
			assertTotal := func(wantSum, wantCount float64) {
				t.Helper()
				var sum, count float64
				for _, point := range readMetrics(metrics) {
					sum += aws.ToFloat64(point.Sum)
					count += aws.ToFloat64(point.SampleCount)
				}
				if sum != wantSum || count != wantCount {
					t.Fatalf("published sum/count = %v/%v, want %v/%v", sum, count, wantSum, wantCount)
				}
			}
			input := &cloudwatchlogs.PutLogEventsInput{LogGroupName: nativeBatch.LogGroupName, LogStreamName: nativeBatch.LogStreamName, LogEvents: []logtypes.InputLogEvent{nativeBatch.LogEvents[0]}}
			if _, err := logs.PutLogEvents(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			assertTotal(7, 1)
			beforeLogs, beforeMetrics, beforeJournal := readLogs(), readMetrics(metrics), journalRows()
			advanceClock(t, source, time.Minute)
			input.LogEvents[0].Timestamp = aws.Int64(source.Now().UnixMilli())
			fault.fail.Store(true)
			_, err := logs.PutLogEvents(t.Context(), input)
			assertAPIError(t, err, "ServiceUnavailableException")
			if fault.fail.Load() {
				t.Fatal("real metric append fault was not exercised")
			}
			if !reflect.DeepEqual(readLogs(), beforeLogs) || !reflect.DeepEqual(readMetrics(metrics), beforeMetrics) || !reflect.DeepEqual(journalRows(), beforeJournal) {
				t.Fatal("failed source ingestion leaked Logs records, metric points, or accepted-batch journal events")
			}
			if _, err := logs.PutLogEvents(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			assertTotal(14, 2)
			stored, accepted := readLogs(), journalRows()
			if len(stored) != 2 || aws.ToString(stored[1].Message) != aws.ToString(input.LogEvents[0].Message) || aws.ToInt64(stored[1].Timestamp) != aws.ToInt64(input.LogEvents[0].Timestamp) || aws.ToString(stored[0].EventId) == aws.ToString(stored[1].EventId) {
				t.Fatalf("retry did not commit distinct original source events: %+v", stored)
			}
			if len(accepted) != len(beforeJournal)+1 || accepted[len(accepted)-1].LogsBatchAccepted.EventCount != 1 {
				t.Fatalf("retry did not commit exactly one accepted batch: %+v", accepted)
			}

			// Source authorization belongs to Logs. The configured service publisher
			// must not impersonate the application for cloudwatch:PutMetricData.
			_, key, secret := c.user(t, "test", "logs-only")
			putUserPolicy(t, c.iam("test", "test", ""), "logs-only", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"},{"Effect":"Deny","Action":"cloudwatch:PutMetricData","Resource":"*"}]}`)
			provider := credentials.NewStaticCredentialsProvider(key, secret, "")
			_, err = metricsClient(c, key).PutMetricData(t.Context(), &cloudwatch.PutMetricDataInput{Namespace: query.Namespace, MetricData: []metrictypes.MetricDatum{{MetricName: query.MetricName, Timestamp: aws.Time(source.Now()), Value: aws.Float64(1001)}}}, func(options *cloudwatch.Options) { options.Credentials = provider })
			assertAPIError(t, err, "AccessDenied")
			advanceClock(t, source, time.Minute)
			input.LogEvents[0].Timestamp = aws.Int64(source.Now().UnixMilli())
			if _, err := logsClient(c, key).PutLogEvents(t.Context(), input, func(options *cloudwatchlogs.Options) { options.Credentials = provider }); err != nil {
				t.Fatal(err)
			}
			assertTotal(21, 3)
			if other := readMetrics(metricsClient(c, "999999999999")); len(other) != 0 {
				t.Fatalf("cross-account metric read leaked points: %+v", other)
			}
			otherList, err := metricsClient(c, "999999999999").ListMetrics(t.Context(), &cloudwatch.ListMetricsInput{Namespace: query.Namespace})
			if err != nil || len(otherList.Metrics) != 0 {
				t.Fatalf("cross-account discovery leaked metrics: %+v, %v", otherList, err)
			}

			if backend == "sqlite" {
				c.server.Close()
				if err := cloud.Close(); err != nil {
					t.Fatal(err)
				}
				closeDB()
				backends, closeDB = openSQLiteBackends(t, path)
				connect()
				assertTotal(21, 3)
				if got := configuration(); !reflect.DeepEqual(got, original) {
					t.Fatalf("reopen changed metric filter: %+v, before %+v", got, original)
				}
			}
			advanceClock(t, source, time.Minute)
			input.LogEvents[0].Timestamp = aws.Int64(source.Now().UnixMilli())
			if _, err := logs.PutLogEvents(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			assertTotal(28, 4)
			// Replacement cannot rewrite already published samples; deletion cannot
			// erase them or apply retroactively to an accepted event.
			replacement := filter
			replacement.MetricTransformations = append([]logtypes.MetricTransformation(nil), filter.MetricTransformations...)
			replacement.MetricTransformations[0].MetricValue = aws.String("2")
			if _, err := logs.PutMetricFilter(t.Context(), &replacement); err != nil {
				t.Fatal(err)
			}
			if got := configuration(); aws.ToInt64(got.CreationTime) != aws.ToInt64(original.CreationTime) || aws.ToString(got.MetricTransformations[0].MetricValue) != "2" {
				t.Fatalf("replacement changed creation or lost value: %+v", got)
			}
			assertTotal(28, 4)
			advanceClock(t, source, time.Minute)
			input.LogEvents[0].Timestamp = aws.Int64(source.Now().UnixMilli())
			if _, err := logs.PutLogEvents(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			assertTotal(30, 5)
			if _, err := logs.DeleteMetricFilter(t.Context(), &cloudwatchlogs.DeleteMetricFilterInput{LogGroupName: filter.LogGroupName, FilterName: filter.FilterName}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Minute)
			input.LogEvents[0].Timestamp = aws.Int64(source.Now().UnixMilli())
			if _, err := logs.PutLogEvents(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			assertTotal(30, 5)
			if events := readLogs(); len(events) != 6 || aws.ToInt64(events[5].Timestamp) != aws.ToInt64(input.LogEvents[0].Timestamp) {
				t.Fatalf("filter deletion interfered with source ingestion: %+v", events)
			}
		})
	}
}
