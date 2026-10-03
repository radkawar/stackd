package stackd_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd"
	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type lambdaDynamoDBMetricsFixture struct {
	lambdaURLFixture
	Cases map[string]struct {
		StreamARN            string                              `json:"stream_arn"`
		MappingUUID          string                              `json:"mapping_uuid"`
		QueueURL             string                              `json:"queue_url"`
		HandlerAttempts      map[string]lambdaDynamoDBInvocation `json:"handler_attempts"`
		DestinationDocuments map[string]map[string]any           `json:"destination_documents"`
	} `json:"cases"`
	MetricQueryIndex map[string]struct {
		Case   string `json:"case"`
		Metric string `json:"metric"`
	} `json:"metric_query_index"`
}

type lambdaDynamoDBMetricContract struct {
	Input cloudwatch.GetMetricStatisticsInput
	Sum   float64
}

// Only positive native series are contracts here. In particular, the capture's
// absent no-destination DroppedEventCount is not a promise to publish zero.
func TestLambdaDynamoDBDockerNativeDestinationMetrics(t *testing.T) {
	lambdaDynamoDBDocker(t)
	fixture := lambdaFixture[lambdaDynamoDBMetricsFixture](t, "dynamodb_metrics")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt)
			clients, _ := lambdaDynamoDBCloud(t, backend, source)
			replacements := []string{fixture.row(t, "identity_before_writes").Result.Output["Account"].(string), "000000000000"}
			replace := func() *strings.Replacer { return strings.NewReplacer(replacements...) }
			call := func(row lambdaURLRow) any { return lambdaDynamoDBCall(t, clients, row, replace()) }
			step := func(d time.Duration) {
				advanceClock(t, source, d)
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			}
			call(fixture.row(t, "create_logs"))
			call(fixture.row(t, "create_role"))
			queues := map[string]*string{}
			for _, label := range []string{"delivered", "denied"} {
				native := fixture.Cases[label]
				row := fixture.row(t, label+"_create_table")
				input := lambdaStreamingInput[dynamodb.CreateTableInput](t, row.Input, replace())
				call(row)
				ddb := dynamoClient(clients, "test", "test", clients.server.Client())
				if err := dynamoWaitActive(t.Context(), ddb, aws.ToString(input.TableName)); err != nil {
					t.Fatal(err)
				}
				table, err := ddb.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: input.TableName})
				if err != nil {
					t.Fatal(err)
				}
				replacements = append([]string{native.StreamARN, aws.ToString(table.Table.LatestStreamArn)}, replacements...)
				queue := call(fixture.row(t, label+"_create_queue")).(*sqs.CreateQueueOutput)
				queues[label] = queue.QueueUrl
				replacements = append([]string{native.QueueURL, aws.ToString(queue.QueueUrl)}, replacements...)
			}
			for _, row := range fixture.Observations {
				if strings.HasPrefix(row.Label, "policy_owned-") && row.Result.Code == "Success" {
					call(row)
				}
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
			for _, label := range []string{"delivered", "denied"} {
				call(fixture.row(t, label+"_create_alias"))
				mapping := call(fixture.row(t, label+"_create_mapping")).(map[string]any)
				replacements = append([]string{fixture.Cases[label].MappingUUID, mapping["UUID"].(string)}, replacements...)
			}
			// The native capture waited for disabled creation before updating.
			step(time.Second)
			// Admission succeeds first. The destination's current queue policy,
			// rather than the policy seen at mapping creation, rejects delivery.
			call(fixture.row(t, "deny_admitted_destination"))
			for _, label := range []string{"delivered", "denied"} {
				for _, row := range fixture.Observations {
					if strings.HasPrefix(row.Label, label+"_put_") && row.Operation == "put-item" {
						var input struct {
							Item map[string]map[string]string
						}
						if err := json.Unmarshal(row.Input, &input); err != nil {
							t.Fatal(err)
						}
						if input.Item["phase"]["S"] == "initial" {
							call(row)
						}
					}
				}
				call(fixture.row(t, label+"_enable"))
			}
			contracts := lambdaDynamoDBMetricContracts(t, fixture, replace())
			metricClient := metricsClient(clients, "test")
			query := func(contract lambdaDynamoDBMetricContract) cloudwatch.GetMetricStatisticsInput {
				input := contract.Input
				input.StartTime = aws.Time(fixture.StartedAt.Add(-time.Minute))
				input.EndTime = aws.Time(source.Now().Add(time.Minute))
				return input
			}
			failure := contracts["function"]["DestinationDeliveryFailures"]
			deadline := time.Now().Add(90 * time.Second)
			observedFailure := false
			for time.Now().Before(deadline) {
				step(time.Second)
				input := query(failure)
				out, err := metricClient.GetMetricStatistics(t.Context(), &input)
				if err != nil {
					t.Fatal(err)
				}
				for _, point := range out.Datapoints {
					observedFailure = observedFailure || aws.ToFloat64(point.Sum) > 0
				}
				if observedFailure {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !observedFailure {
				t.Fatal("admitted destination rejection did not publish a positive failure datapoint")
			}
			lambdaSQSMetricSum(t, metricClient, query(failure), failure.Sum)
			lambdaDynamoDBMetricDestination(t, clients, fixture, "delivered", queues["delivered"], replace(), step)
			call(fixture.row(t, "restore_destination_policy"))
			call(fixture.row(t, "denied_put_4"))
			lambdaDynamoDBMetricDestination(t, clients, fixture, "denied", queues["denied"], replace(), step)
			lambdaDynamoDBMetricRecords(t, clients, fixture, replace())
			// Flush service-time metric deadlines, not AWS's observed publication
			// latency. No assertions are made about empty series or future retries.
			step(time.Minute)
			for _, metrics := range contracts {
				for _, contract := range metrics {
					lambdaSQSMetricSum(t, metricClient, query(contract), contract.Sum)
				}
			}
		})
	}
}

func lambdaDynamoDBMetricContracts(t *testing.T, fixture lambdaDynamoDBMetricsFixture, replace *strings.Replacer) map[string]map[string]lambdaDynamoDBMetricContract {
	t.Helper()
	row := fixture.row(t, "final_metrics")
	input := lambdaStreamingInput[cloudwatch.GetMetricDataInput](t, row.Input, replace)
	var output struct {
		MetricDataResults []metrictypes.MetricDataResult
	}
	if err := json.Unmarshal(lambdaQualifiedJSON(t, row.Result.Output), &output); err != nil {
		t.Fatal(err)
	}
	totals := map[string]float64{}
	for _, result := range output.MetricDataResults {
		for _, value := range result.Values {
			totals[aws.ToString(result.Id)] += value
		}
	}
	contracts := map[string]map[string]lambdaDynamoDBMetricContract{}
	for _, q := range input.MetricDataQueries {
		id := aws.ToString(q.Id)
		identity := fixture.MetricQueryIndex[id]
		if identity.Case != "delivered" && identity.Case != "denied" && !(identity.Case == "function" && identity.Metric == "DestinationDeliveryFailures") {
			continue
		}
		if q.MetricStat == nil || totals[id] <= 0 {
			continue
		}
		if contracts[identity.Case] == nil {
			contracts[identity.Case] = map[string]lambdaDynamoDBMetricContract{}
		}
		metric := q.MetricStat.Metric
		contracts[identity.Case][identity.Metric] = lambdaDynamoDBMetricContract{
			Input: cloudwatch.GetMetricStatisticsInput{Namespace: metric.Namespace, MetricName: metric.MetricName, Dimensions: metric.Dimensions,
				Period: q.MetricStat.Period, Statistics: []metrictypes.Statistic{metrictypes.Statistic(aws.ToString(q.MetricStat.Stat))}},
			Sum: totals[id],
		}
	}
	for label, names := range map[string][]string{
		"delivered": {"InvokedEventCount", "FailedInvokeEventCount", "OnFailureDestinationDeliveredEventCount"},
		"denied":    {"DroppedEventCount", "OnFailureDestinationDeliveredEventCount"},
		"function":  {"DestinationDeliveryFailures"},
	} {
		for _, name := range names {
			if contracts[label][name].Sum <= 0 {
				t.Fatalf("native fixture lacks positive %s/%s evidence", label, name)
			}
		}
	}
	return contracts
}

func lambdaDynamoDBMetricDestination(t *testing.T, clients cloudClients, fixture lambdaDynamoDBMetricsFixture, label string, queue *string, replace *strings.Replacer, step func(time.Duration)) {
	t.Helper()
	var expected map[string]any
	for _, document := range fixture.Cases[label].DestinationDocuments {
		expected = lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, document), replace)
		break
	}
	if expected == nil {
		t.Fatalf("native fixture lacks %s destination evidence", label)
	}
	var actual map[string]any
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		step(time.Second)
		out, err := clients.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue, MaxNumberOfMessages: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) > 0 {
			if err := json.Unmarshal([]byte(aws.ToString(out.Messages[0].Body)), &actual); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if actual == nil {
		t.Fatalf("%s destination did not accept a failure document", label)
	}
	context := actual["requestContext"].(map[string]any)
	info := actual["DDBStreamBatchInfo"].(map[string]any)
	linked := false
	for _, invocation := range lambdaDynamoDBLogInvocations(t, clients, fixture.Prefix, "DDB_METRICS ") {
		if invocation.RequestID != context["requestId"] || invocation.InvokedARN != context["functionArn"] {
			continue
		}
		records := invocation.Event["Records"].([]any)
		first := records[0].(map[string]any)["dynamodb"].(map[string]any)
		last := records[len(records)-1].(map[string]any)["dynamodb"].(map[string]any)
		if info["startSequenceNumber"] != first["SequenceNumber"] || info["endSequenceNumber"] != last["SequenceNumber"] || info["batchSize"] != float64(len(records)) {
			t.Fatalf("destination sequence range does not identify its real invocation: %s", lambdaQualifiedJSON(t, actual))
		}
		if label == "denied" && first["NewImage"].(map[string]any)["phase"].(map[string]any)["S"] != "restored_control" {
			t.Fatal("restored destination document did not identify the new control record")
		}
		linked = true
		break
	}
	if !linked {
		t.Fatalf("%s destination document has no matching real runtime invocation", label)
	}
	for _, document := range []map[string]any{actual, expected} {
		delete(document, "timestamp")
		delete(document["requestContext"].(map[string]any), "requestId")
		batch := document["DDBStreamBatchInfo"].(map[string]any)
		for _, name := range []string{"shardId", "startSequenceNumber", "endSequenceNumber", "approximateArrivalOfFirstRecord", "approximateArrivalOfLastRecord"} {
			delete(batch, name)
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s destination\ngot %s\nwant %s", label, lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
	}
}

func lambdaDynamoDBMetricRecords(t *testing.T, clients cloudClients, fixture lambdaDynamoDBMetricsFixture, replace *strings.Replacer) {
	t.Helper()
	// Compare record contents as a set, not invocation count or runtime timing.
	// Positive native metric totals separately distinguish events from batches.
	keys := func(invocation lambdaDynamoDBInvocation) []string {
		var result []string
		for _, record := range invocation.Event["Records"].([]any) {
			event := lambdaDynamoDBComparableEvent(t, map[string]any{"Records": []any{record}})
			result = append(result, invocation.InvokedARN+" "+string(lambdaQualifiedJSON(t, event)))
		}
		return result
	}
	want := map[string]bool{}
	for _, label := range []string{"delivered", "denied"} {
		for _, invocation := range fixture.Cases[label].HandlerAttempts {
			normalized := lambdaStreamingInput[lambdaDynamoDBInvocation](t, lambdaQualifiedJSON(t, invocation), replace)
			for _, key := range keys(normalized) {
				want[key] = true
			}
		}
	}
	got := map[string]bool{}
	for _, invocation := range lambdaDynamoDBLogInvocations(t, clients, fixture.Prefix, "DDB_METRICS ") {
		for _, key := range keys(invocation) {
			got[key] = true
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("real runtime record contents differ\ngot %v\nwant %v", got, want)
	}
}
