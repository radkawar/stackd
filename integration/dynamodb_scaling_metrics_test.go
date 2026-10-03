package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aastypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

// Native fixtures own the alarm configurations and maintenance transitions.
// The workload additionally exercises the source-to-alarm-to-capacity path; its
// service-clock deadlines do not assert AWS publication latency or empty series.
func TestDynamoDBScalingMetricsAcrossReopen(t *testing.T) {
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
	maintenance := aasFixture(t, "dynamodb_maintenance")
	metrics := aasFixture(t, "dynamodb_metrics")
	var capacity aasControlFixture
	dynamoReadJSON(t, "capacity_metrics", &capacity)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, fixture := range []struct {
				name                                       string
				data                                       aasControlFixture
				register, policy, initial, update, changed string
				kinds                                      []string
			}{
				{"maintenance", maintenance, "register-", "initial-policy-", "initial-alarms", "explicit-capacity-update", "after-capacity-update-before-synthetic-alarms", []string{"tableRead", "tableWrite", "indexRead", "indexWrite"}},
				{"disable-scale-in", metrics, "register-", "put-", "alarms-before-capacity-change", "change-owned-table-capacity", "alarms-after-capacity-change-0", []string{"table-read", "table-write", "index-read", "index-write"}},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					clients, reopen, _ := dynamoScalingCloud(t, runtime, backend, fixture.data)
					bindings, times := map[string]string{}, map[float64]float64{}
					for _, kind := range fixture.kinds {
						dynamoScalingCall(t, *clients, fixture.data.row(t, fixture.register+kind), bindings)
						label := fixture.policy + kind
						if fixture.name == "disable-scale-in" {
							label += "-policy"
						}
						dynamoScalingCall(t, *clients, fixture.data.row(t, label), bindings)
					}
					dynamoScalingAlarms(t, *clients, fixture.data.row(t, fixture.initial), bindings, times)
					reopen()
					dynamoScalingAlarms(t, *clients, fixture.data.row(t, fixture.initial), bindings, times)
					dynamoScalingCall(t, *clients, fixture.data.row(t, fixture.update), bindings)
					table := ecsControlBody(t, fixture.data.row(t, "create-owned-table").Input)["TableName"].(string)
					if err := dynamoWaitActive(t.Context(), dynamoClient(*clients, "test", "test", clients.server.Client()), table); err != nil {
						t.Fatal(err)
					}
					reopen()
					// A direct capacity update alone must not churn any alarm family.
					dynamoScalingAlarms(t, *clients, fixture.data.row(t, fixture.changed), bindings, times)
					if fixture.name != "maintenance" {
						return
					}
					for _, label := range []string{"synthetic-maintenance-reset", "synthetic-maintenance-alarm"} {
						dynamoScalingCall(t, *clients, fixture.data.row(t, label), bindings)
					}
					trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
					reopen()
					refreshed := fixture.data.row(t, "after-synthetic-delivery-alarms")
					dynamoScalingAlarms(t, *clients, refreshed, bindings, times)
					for _, kind := range fixture.kinds {
						aasReplay(t, *clients, fixture.data.row(t, "after-synthetic-delivery-activities-"+kind), bindings, times)
						// Identical PutScalingPolicy is not a refresh request, including
						// for the three families still carrying their old thresholds.
						dynamoScalingCall(t, *clients, fixture.data.row(t, "initial-policy-"+kind), bindings)
					}
					reopen()
					dynamoScalingAlarms(t, *clients, refreshed, bindings, times)
					// Redeliver to the replacement alarm at its already-matching
					// capacity. Preserve its IDs, policy action ARN and empty history.
					var alarms cloudwatch.DescribeAlarmsOutput
					if err := json.Unmarshal(refreshed.Output, &alarms); err != nil {
						t.Fatal(err)
					}
					for _, alarm := range alarms.MetricAlarms {
						if aws.ToString(alarm.MetricName) != "ProvisionedReadCapacityUnits" || len(alarm.Dimensions) != 1 || alarm.ComparisonOperator != metrictypes.ComparisonOperatorGreaterThanThreshold {
							continue
						}
						for _, label := range []string{"synthetic-maintenance-reset", "synthetic-maintenance-alarm"} {
							r := fixture.data.row(t, label)
							input := ecsControlBody(t, r.Input)
							input["AlarmName"] = aws.ToString(alarm.AlarmName)
							if text, ok := input["StateReasonData"].(string); ok {
								reason := ecsControlBody(t, []byte(text))
								reason["threshold"] = aws.ToFloat64(alarm.Threshold)
								input["StateReasonData"] = string(dynamoScalingJSON(t, reason))
							}
							r.Input = dynamoScalingJSON(t, input)
							dynamoScalingCall(t, *clients, r, bindings)
						}
					}
					trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
					reopen()
					dynamoScalingAlarms(t, *clients, refreshed, bindings, times)
					aasReplay(t, *clients, fixture.data.row(t, "after-synthetic-delivery-activities-tableRead"), bindings, times)
				})
			}
			t.Run("source-workload", func(t *testing.T) {
				clients, reopen, source := dynamoScalingCloud(t, runtime, backend, maintenance)
				bindings, times := map[string]string{}, map[float64]float64{}
				table := ecsControlBody(t, maintenance.row(t, "create-owned-table").Input)["TableName"].(string)
				for _, label := range []string{"register-tableRead", "initial-policy-tableRead"} {
					dynamoScalingCall(t, *clients, maintenance.row(t, label), bindings)
				}
				initial := dynamoScalingReadFamily(t, maintenance.row(t, "initial-alarms"), 1)
				dynamoScalingAlarms(t, *clients, initial, bindings, times)
				_, key, secret := clients.user(t, "test", "dynamodb-only")
				putUserPolicy(t, clients.iam("test", "test", ""), "dynamodb-only", allow(`"dynamodb:*"`, "*"))
				denied := cloudwatch.New(cloudwatch.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				_, err := denied.PutMetricData(t.Context(), &cloudwatch.PutMetricDataInput{Namespace: aws.String("AWS/DynamoDB"), MetricData: []metrictypes.MetricDatum{{MetricName: aws.String("ConsumedReadCapacityUnits"), Value: aws.Float64(1)}}})
				assertAPIError(t, err, "AccessDenied")
				// Use the observed metric identity/statistics, not the capture's
				// mixed transaction totals or its absent provisioned datapoints.
				queryRow := capacity.row(t, "publication-0-tableRead")
				input := ecsControlBody(t, queryRow.Input)
				nativeTable := input["Dimensions"].([]any)[0].(map[string]any)["Value"].(string)
				var query cloudwatch.GetMetricStatisticsInput
				if err := json.Unmarshal(aasInput(t, queryRow, map[string]string{nativeTable: table}), &query); err != nil {
					t.Fatal(err)
				}
				start := source.Now()
				for minute := range 2 {
					for batch := range 4 {
						keys := make([]map[string]dynamotypes.AttributeValue, 100)
						for i := range keys {
							keys[i] = map[string]dynamotypes.AttributeValue{"pk": &dynamotypes.AttributeValueMemberS{Value: fmt.Sprintf("missing-%d-%d-%d", minute, batch, i)}}
						}
						wire := &awstest.WireClient{Client: clients.server.Client()}
						out, err := dynamoClient(*clients, key, secret, wire).BatchGetItem(t.Context(), &dynamodb.BatchGetItemInput{RequestItems: map[string]dynamotypes.KeysAndAttributes{table: {Keys: keys}}, ReturnConsumedCapacity: dynamotypes.ReturnConsumedCapacityNone})
						if err != nil {
							t.Fatal(err)
						}
						if len(out.UnprocessedKeys) != 0 || len(out.Responses[table]) != 0 {
							t.Fatalf("missing-key read was not fully processed: %+v", out)
						}
						if _, leaked := ecsControlBody(t, wire.Body)["ConsumedCapacity"]; leaked {
							t.Fatal("private consumed capacity leaked into ReturnConsumedCapacity=NONE response")
						}
						if minute == 0 && batch == 1 {
							// Half the first completed-minute total must survive reopen
							// before it has ever been visible through CloudWatch.
							reopen()
						}
					}
					advanceClock(t, source, time.Minute)
					trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
					query.StartTime = aws.Time(start.Add(time.Duration(minute) * time.Minute))
					query.EndTime = aws.Time(query.StartTime.Add(time.Minute))
					out, err := metricsClient(*clients, "test").GetMetricStatistics(t.Context(), &query)
					if err != nil {
						t.Fatal(err)
					}
					if len(out.Datapoints) != 1 || aws.ToFloat64(out.Datapoints[0].Sum) != 200 || !aws.ToTime(out.Datapoints[0].Timestamp).Equal(*query.StartTime) || out.Datapoints[0].Unit != metrictypes.StandardUnitCount {
						t.Fatalf("completed minute %d: want 200 read units at %s, got %+v", minute, query.StartTime, out.Datapoints)
					}
				}
				reopen()
				// Scalar alarms intentionally evaluate one tick behind metric-query
				// visibility. No synthetic consumed alarm is injected here.
				advanceClock(t, source, time.Minute)
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
				resource := "table/" + table
				activityInput := &applicationautoscaling.DescribeScalingActivitiesInput{ServiceNamespace: aastypes.ServiceNamespaceDynamodb, ResourceId: &resource, ScalableDimension: aastypes.ScalableDimensionDynamoDBTableReadCapacityUnits, IncludeNotScaledActivities: aws.Bool(true)}
				deadline := time.Now().Add(30 * time.Second)
				var activityID string
				for {
					trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
					out, err := aasClient(*clients, "us-east-1", "test", "test", clients.server.Client()).DescribeScalingActivities(t.Context(), activityInput)
					if err != nil {
						t.Fatal(err)
					}
					if len(out.ScalingActivities) == 1 && out.ScalingActivities[0].StatusCode == aastypes.ScalingActivityStatusCodeSuccessful {
						activityID = aws.ToString(out.ScalingActivities[0].ActivityId)
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("source workload did not complete exactly one scaling activity: %+v", out.ScalingActivities)
					}
					time.Sleep(10 * time.Millisecond)
				}
				description, err := dynamoClient(*clients, "test", "test", clients.server.Client()).DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: &table})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToInt64(description.Table.ProvisionedThroughput.ReadCapacityUnits) != 5 || description.Table.TableStatus != dynamotypes.TableStatusActive {
					t.Fatalf("successful scaling did not reach native ACTIVE read capacity 5: %+v", description.Table)
				}
				// Reuse the observed replacement-family configuration, scaled from
				// native capacity 4 to the workload's capacity 5 (210/150/5/5).
				refreshed := dynamoScalingReadFamily(t, maintenance.row(t, "after-synthetic-delivery-alarms"), 5.0/4)
				dynamoScalingAlarms(t, *clients, refreshed, bindings, times)
				reopen()
				dynamoScalingAlarms(t, *clients, refreshed, bindings, times)
				out, err := aasClient(*clients, "us-east-1", "test", "test", clients.server.Client()).DescribeScalingActivities(t.Context(), activityInput)
				if err != nil {
					t.Fatal(err)
				}
				if len(out.ScalingActivities) != 1 || aws.ToString(out.ScalingActivities[0].ActivityId) != activityID || out.ScalingActivities[0].StatusCode != aastypes.ScalingActivityStatusCodeSuccessful {
					t.Fatalf("successful activity did not survive reopen: %+v", out.ScalingActivities)
				}
			})
		})
	}
}

func dynamoScalingCloud(t *testing.T, runtime dynamoengine.Runtime, backend string, fixture aasControlFixture) (*cloudClients, func(), *clock.Manual) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	observed := &dynamoReplayRuntime{Runtime: runtime}
	// Register first: retained workers/storage close before their native volumes.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		for _, spec := range observed.specifications() {
			if err := runtime.Remove(ctx, spec); err != nil {
				t.Errorf("remove owned DynamoDB database %s: %v", spec.ID, err)
			}
		}
	})
	clients, open := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source, DynamoDBRuntime: observed})
	row := fixture.row(t, "create-owned-table")
	table := ecsControlBody(t, row.Input)["TableName"].(string)
	dynamoScalingCall(t, clients, row, nil)
	if err := dynamoWaitActive(t.Context(), dynamoClient(clients, "test", "test", clients.server.Client()), table); err != nil {
		t.Fatal(err)
	}
	return &clients, func() { clients = open() }, source
}

func dynamoScalingCall(t *testing.T, clients cloudClients, row aasControlRow, bindings map[string]string) any {
	t.Helper()
	var client any
	switch row.Service {
	case "dynamodb":
		client = dynamoClient(clients, "test", "test", clients.server.Client())
	case "application-autoscaling":
		client = aasClient(clients, "us-east-1", "test", "test", clients.server.Client())
	case "cloudwatch":
		client = metricsClient(clients, "test")
	default:
		t.Fatalf("unselected fixture service %s", row.Service)
	}
	input := aasInput(t, row, bindings)
	out, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(`{}`), func(target any) {
		if row.Service == "dynamodb" {
			dynamoSDKInput(t, target, input)
		} else if err := json.Unmarshal(input, target); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	return out
}

func dynamoScalingJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func dynamoScalingReadFamily(t *testing.T, row aasControlRow, thresholdRatio float64) aasControlRow {
	t.Helper()
	var output cloudwatch.DescribeAlarmsOutput
	if err := json.Unmarshal(row.Output, &output); err != nil {
		t.Fatal(err)
	}
	output.MetricAlarms = slices.DeleteFunc(output.MetricAlarms, func(alarm metrictypes.MetricAlarm) bool {
		return len(alarm.Dimensions) != 1 || !strings.Contains(aws.ToString(alarm.MetricName), "ReadCapacityUnits")
	})
	for i := range output.MetricAlarms {
		output.MetricAlarms[i].Threshold = aws.Float64(aws.ToFloat64(output.MetricAlarms[i].Threshold) * thresholdRatio)
	}
	row.Output = dynamoScalingJSON(t, output)
	return row
}

func dynamoScalingAlarms(t *testing.T, clients cloudClients, row aasControlRow, bindings map[string]string, times map[float64]float64) {
	t.Helper()
	if row.Region == "" {
		row.Region = "us-east-1"
	}
	var native cloudwatch.DescribeAlarmsOutput
	if err := json.Unmarshal(row.Output, &native); err != nil {
		t.Fatal(err)
	}
	actual := dynamoScalingCall(t, clients, row, bindings).(*cloudwatch.DescribeAlarmsOutput)
	// aasAlarms sorts by already-bound names. Multiple policies share the same
	// name prefix, so first bind by metric/dimensions/operator, never UUID order.
	key := func(alarm metrictypes.MetricAlarm) string {
		parts := []string{aws.ToString(alarm.Namespace), aws.ToString(alarm.MetricName), string(alarm.ComparisonOperator)}
		for _, dimension := range alarm.Dimensions {
			parts = append(parts, aws.ToString(dimension.Name)+"="+aws.ToString(dimension.Value))
		}
		slices.Sort(parts)
		return strings.Join(parts, "|")
	}
	for _, want := range native.MetricAlarms {
		for _, got := range actual.MetricAlarms {
			if key(want) == key(got) {
				aasCompare(t, row.Label+".AlarmName", aws.ToString(want.AlarmName), aws.ToString(got.AlarmName), bindings, times)
				break
			}
		}
	}
	aasAlarms(t, clients, row, bindings, times)
}
