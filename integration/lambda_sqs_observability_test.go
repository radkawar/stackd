package stackd_test

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"stackd/internal/awstest"
	logstore "stackd/internal/services/logs"
	"stackd/journal"
	"stackd/storage"
)

// The capture queried GetMetricData. Sum is independent of the reader API and
// minute placement, so replay its positive totals through GetMetricStatistics.
// Missing native samples are not a provider-wide promise to publish no sample.
type lambdaSQSObservationFixture struct {
	lambdaSQSDeliveryFixture
	SliceMetadata struct {
		Audit struct {
			Records []map[string]any `json:"selected_records"`
		} `json:"audit"`
	} `json:"slice_metadata"`
}

func lambdaSQSObservationRow(t *testing.T, f lambdaSQSDeliveryFixture, label string) lambdaSQSDeliveryObservation {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native observation %s", label)
	return lambdaSQSDeliveryObservation{}
}

func lambdaSQSMetricSum(t *testing.T, client *cloudwatch.Client, input cloudwatch.GetMetricStatisticsInput, want float64) {
	t.Helper()
	out, err := client.GetMetricStatistics(t.Context(), &input)
	if err != nil {
		t.Fatal(err)
	}
	var got float64
	for _, point := range out.Datapoints {
		got += aws.ToFloat64(point.Sum)
	}
	if got != want {
		t.Fatalf("%s dimensions=%v: sum=%v native=%v", aws.ToString(input.MetricName), input.Dimensions, got, want)
	}
}

func TestLambdaSQSMappingDockerNativeMetricsAndCausality(t *testing.T) {
	lambdaURLDocker(t)
	f := lambdaFixture[lambdaSQSObservationFixture](t, "sqs_mapping_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, label := range []string{"isolated_partial", "isolated_filter", "fifo_groups_order", "ordinary_error_redelivery"} {
			t.Run(backend+"/"+label, func(t *testing.T) {
				selected := lambdaSQSDeliveryCase(t, f.lambdaSQSDeliveryFixture, label)
				r := lambdaSQSDeliverySetup(t, backend, selected)
				start := r.clock.Now().Add(-time.Minute)
				runtime := r.run(t)
				advanceClock(t, r.clock, time.Minute)
				trailNativeDrain(t, r.c.cloud)
				client := metricsClient(cloudClients{r.c.server}, "test")
				row := lambdaSQSObservationRow(t, f.lambdaSQSDeliveryFixture, "bounded_correct_dimension_metrics")
				var query cloudwatch.GetMetricDataInput
				if err := json.Unmarshal(row.Input, &query); err != nil {
					t.Fatal(err)
				}
				var results struct {
					MetricDataResults []metrictypes.MetricDataResult
				}
				if err := json.Unmarshal(lambdaQualifiedJSON(t, row.Result.Output), &results); err != nil {
					t.Fatal(err)
				}
				totals := map[string]float64{}
				positive := map[string]bool{}
				for _, result := range results.MetricDataResults {
					for _, value := range result.Values {
						totals[aws.ToString(result.Id)] += value
					}
					positive[aws.ToString(result.Id)] = totals[aws.ToString(result.Id)] > 0
				}
				metricLabel := label
				if label == "fifo_groups_order" {
					metricLabel = "main_fifo"
				}
				for _, q := range query.MetricDataQueries {
					if q.MetricStat == nil || !positive[aws.ToString(q.Id)] || !strings.HasPrefix(aws.ToString(q.Label), metricLabel+":") {
						continue
					}
					metric := q.MetricStat.Metric
					input := cloudwatch.GetMetricStatisticsInput{Namespace: metric.Namespace, MetricName: metric.MetricName,
						Dimensions: []metrictypes.Dimension{{Name: aws.String("EventSourceMappingUUID"), Value: r.mapping.UUID}},
						StartTime:  &start, EndTime: aws.Time(r.clock.Now().Add(time.Minute)), Period: q.MetricStat.Period, Statistics: []metrictypes.Statistic{metrictypes.StatisticSum}}
					lambdaSQSMetricSum(t, client, input, totals[aws.ToString(q.Id)])
					// The original native two-dimension queries returned no series;
					// the corrected inventory proves UUID is the complete identity.
					input.Dimensions = append(input.Dimensions, metrictypes.Dimension{Name: aws.String("FunctionName"), Value: aws.String(f.Prefix)})
					out, err := client.GetMetricStatistics(t.Context(), &input)
					if err != nil {
						t.Fatal(err)
					}
					if len(out.Datapoints) != 0 {
						t.Fatalf("fabricated FunctionName+UUID series for %s: %v", aws.ToString(metric.MetricName), out.Datapoints)
					}
				}
				if label != "ordinary_error_redelivery" {
					inventory := lambdaSQSObservationRow(t, f.lambdaSQSDeliveryFixture, "metric_inventory_"+metricLabel)
					var native struct{ Metrics []metrictypes.Metric }
					if err := json.Unmarshal(lambdaQualifiedJSON(t, inventory.Result.Output), &native); err != nil {
						t.Fatal(err)
					}
					listed, err := client.ListMetrics(t.Context(), &cloudwatch.ListMetricsInput{Namespace: aws.String("AWS/Lambda"), Dimensions: []metrictypes.DimensionFilter{{Name: aws.String("EventSourceMappingUUID"), Value: r.mapping.UUID}}})
					if err != nil {
						t.Fatal(err)
					}
					found := map[string]bool{}
					for _, metric := range listed.Metrics {
						if len(metric.Dimensions) != 1 || aws.ToString(metric.Dimensions[0].Name) != "EventSourceMappingUUID" || aws.ToString(metric.Dimensions[0].Value) != aws.ToString(r.mapping.UUID) {
							t.Fatalf("non-native ESM dimensions: %v", metric)
						}
						found[aws.ToString(metric.MetricName)] = true
					}
					for _, metric := range native.Metrics {
						if !found[aws.ToString(metric.MetricName)] {
							t.Fatalf("native published metric missing: %s", aws.ToString(metric.MetricName))
						}
					}
				}
				// Native bounded function totals corroborate runtime ESM_EVENT and
				// ESM_THROW records. Isolate those same outcomes locally rather than
				// attributing the capture's all-scenario total to one mapping.
				for _, q := range query.MetricDataQueries {
					if q.MetricStat == nil || !positive[aws.ToString(q.Id)] {
						continue
					}
					name := aws.ToString(q.MetricStat.Metric.MetricName)
					if name != "Invocations" && name != "Errors" {
						continue
					}
					var want float64
					for _, evidence := range runtime {
						if name == "Invocations" || evidence.Kind == "ESM_THROW" {
							want++
						}
					}
					if want == 0 {
						continue
					}
					lambdaSQSMetricSum(t, client, cloudwatch.GetMetricStatisticsInput{Namespace: q.MetricStat.Metric.Namespace, MetricName: &name,
						Dimensions: []metrictypes.Dimension{{Name: aws.String("FunctionName"), Value: aws.String(f.Prefix)}}, StartTime: &start,
						EndTime: aws.Time(r.clock.Now().Add(time.Minute)), Period: q.MetricStat.Period, Statistics: []metrictypes.Statistic{metrictypes.StatisticSum}}, want)
				}
				lambdaSQSObservationCausality(t, r, runtime)
				lambdaSQSObservationAudit(t, f, r, runtime)
			})
		}
	}
}

// Read only the committed journal produced by real SendMessageBatch and the
// real Docker runtime. The public request ID joins runtime output to Invoke;
// the typed link supplies the batch-to-source relationship, not a receipt ledger.
func lambdaSQSObservationCausality(t *testing.T, r *lambdaSQSDeliveryReplay, runtime []lambdaSQSRuntimeEvidence) {
	t.Helper()
	var rows []journal.Event
	for after := int64(0); ; {
		page, err := r.backends.Journal.Read(t.Context(), after, 1000)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, page...)
		if len(page) < 1000 {
			break
		}
		after = page[len(page)-1].Sequence
	}
	invokes := map[string]journal.Event{}
	links := map[string]journal.Event{}
	messages := map[string]journal.Event{}
	for _, row := range rows {
		if call := row.APICallCompleted; call != nil && call.EventSource == "lambda.amazonaws.com" && call.EventName == "Invoke" {
			invokes[row.RequestID] = row
		}
		if id := row.LambdaSourceBatchAccepted.InvocationEventID; id != "" {
			if _, exists := links[id]; exists {
				t.Fatalf("duplicate batch link for %s", id)
			}
			links[id] = row
		}
		if id := row.SQSMessageAccepted.MessageID; id != "" {
			messages[id] = row
		}
	}
	if len(links) != len(runtime) {
		t.Fatalf("source batch links=%d executed requests=%d", len(links), len(runtime))
	}
	for _, evidence := range runtime {
		invoke, ok := invokes[evidence.RequestID]
		if !ok {
			t.Fatalf("runtime request %s has no native Invoke", evidence.RequestID)
		}
		eventID := invoke.APICallCompleted.EventID
		link, ok := links[eventID]
		if !ok {
			t.Fatalf("Invoke %s has no typed source batch", eventID)
		}
		batch := link.LambdaSourceBatchAccepted
		if batch.MappingARN != aws.ToString(r.mapping.EventSourceMappingArn) || batch.SourceARN != aws.ToString(r.mapping.EventSourceArn) {
			t.Fatalf("batch source identity: %+v", batch)
		}
		var delivered []string
		for _, record := range evidence.Event["Records"].([]any) {
			delivered = append(delivered, record.(map[string]any)["messageId"].(string))
		}
		actual := slices.Clone(batch.RecordIDs)
		slices.Sort(actual)
		slices.Sort(delivered)
		if !slices.Equal(actual, delivered) {
			t.Fatalf("Invoke %s linked messages=%v delivered=%v", eventID, actual, delivered)
		}
		for _, id := range actual {
			source, exists := messages[id]
			if !exists || source.Sequence >= invoke.Sequence || source.SQSMessageAccepted.QueueARN != batch.SourceARN {
				t.Fatalf("message %s lacks committed source before Invoke acceptance", id)
			}
		}
		if invoke.Sequence >= link.Sequence {
			t.Fatalf("batch %d precedes its accepted Invoke %d", link.Sequence, invoke.Sequence)
		}
	}
	// A log group's retained events and its committed ingestion batches are both
	// append-ordered. Join each actual ESM_EVENT to its batch, not wall time:
	// manual service time may be identical before and after Docker execution.
	var logEvents []logstore.EventRecord
	if err := r.backends.Logs.View(t.Context(), func(reader logstore.Reader) error {
		group, err := reader.Group(logstore.GroupKey{Scope: logstore.Scope{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"}, Name: "/aws/lambda/" + r.caseData.fixture.Prefix})
		if err != nil {
			return err
		}
		logEvents, err = reader.Events(logstore.EventQuery{GroupID: group.ID, End: r.clock.Now().UnixMilli() + 1, Limit: 10000})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var logSequence int64
	observed := map[string]bool{}
	for _, row := range rows {
		batch := row.LogsBatchAccepted
		if batch.LogGroupARN != "arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/"+r.caseData.fixture.Prefix {
			continue
		}
		end := logSequence + batch.EventCount
		for _, event := range logEvents {
			if event.Sequence <= logSequence || event.Sequence > end {
				continue
			}
			at := strings.Index(event.Message, "ESM_EVENT ")
			if at < 0 {
				continue
			}
			var evidence lambdaSQSRuntimeEvidence
			if err := json.Unmarshal([]byte(strings.TrimSpace(event.Message[at+len("ESM_EVENT "):])), &evidence); err != nil {
				t.Fatal(err)
			}
			invoke, ok := invokes[evidence.RequestID]
			if !ok {
				t.Fatalf("runtime log %s has no accepted Invoke", evidence.RequestID)
			}
			link := links[invoke.APICallCompleted.EventID]
			if link.Sequence == 0 || link.Sequence >= row.Sequence {
				t.Fatalf("runtime output %s committed before its source batch", evidence.RequestID)
			}
			observed[evidence.RequestID] = true
		}
		logSequence = end
	}
	for _, evidence := range runtime {
		if !observed[evidence.RequestID] {
			t.Fatalf("runtime request %s has no causally ordered log ingestion", evidence.RequestID)
		}
	}
}

func lambdaSQSObservationAudit(t *testing.T, f lambdaSQSObservationFixture, r *lambdaSQSDeliveryReplay, runtime []lambdaSQSRuntimeEvidence) {
	t.Helper()
	// Native delivery is deliberately a positive subset, not a demand for every
	// event to arrive within AWS's bounded capture. Match the delivered message
	// identities and receive counts before normalizing the native request ID.
	byRequest := map[string]journal.Event{}
	for _, row := range lambdaAuditRows(t, r.backends.Journal) {
		byRequest[row.RequestID] = row
	}
	checked := 0
	for _, native := range f.SliceMetadata.Audit.Records {
		var captured *lambdaSQSRuntimeEvidence
		for i := range f.Runtime {
			if f.Runtime[i].Kind == "ESM_EVENT" && f.Runtime[i].RequestID == native["requestID"] {
				captured = &f.Runtime[i]
				break
			}
		}
		if captured == nil {
			t.Fatalf("selected native audit has no exact runtime request ID join: %v", native["requestID"])
		}
		for _, local := range runtime {
			if !lambdaSQSObservationSameDelivery(captured.Event, local.Event, r.ids) {
				continue
			}
			row, ok := byRequest[local.RequestID]
			if !ok {
				t.Fatalf("local runtime request %s missing Invoke projection", local.RequestID)
			}
			params := native["requestParameters"].(map[string]any)
			normalize := strings.NewReplacer(params["sourceArn"].(string), aws.ToString(r.mapping.EventSourceMappingArn), f.Account, "000000000000")
			want := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, native), normalize)
			got := lambdaAuditDocument(t, row)
			lambdaQualifiedAuditProjection(t, got, want)
			for _, field := range []string{"userIdentity", "sourceIPAddress", "userAgent", "awsRegion", "recipientAccountId"} {
				if !reflect.DeepEqual(got[field], want[field]) {
					t.Fatalf("Invoke %s got=%v native=%v", field, got[field], want[field])
				}
			}
			if got["requestID"] != local.RequestID || got["eventID"] != row.APICallCompleted.EventID {
				t.Fatalf("Invoke lost runtime/journal identity: %v", got)
			}
			if _, present := native["sharedEventID"]; present && (got["sharedEventID"] == nil || got["sharedEventID"] == got["eventID"]) {
				t.Fatal("service Invoke lost distinct shared event identity")
			}
			checked++
		}
	}
	if (r.caseData.scenario.Label == "isolated_partial" || r.caseData.scenario.Label == "isolated_filter") && checked == 0 {
		t.Fatal("isolated scenario lost its positive native runtime/audit relationship")
	}
}

func lambdaSQSObservationSameDelivery(native, local map[string]any, ids map[string]string) bool {
	// Native does not promise identical batch packing. One exact source ID and
	// receive count associates a selected native execution with the local batch;
	// the causal test independently verifies every local batch member.
	counts := map[string]any{}
	for _, value := range native["Records"].([]any) {
		record := value.(map[string]any)
		if id := ids[record["messageId"].(string)]; id != "" {
			counts[id] = record["attributes"].(map[string]any)["ApproximateReceiveCount"]
		}
	}
	for _, value := range local["Records"].([]any) {
		record := value.(map[string]any)
		if count, ok := counts[record["messageId"].(string)]; ok && count == record["attributes"].(map[string]any)["ApproximateReceiveCount"] {
			return true
		}
	}
	return false
}

// The existing journal-to-CloudTrail consumer is also used for management;
// capture only five positive SDK calls, not IAM propagation or pagination timing.
func TestLambdaSQSMappingDockerNativeManagementAudit(t *testing.T) {
	lambdaURLDocker(t)
	f := lambdaFixture[struct {
		Runs []struct {
			lambdaSQSControlRun
			CloudTrail struct {
				Events []struct {
					Record      map[string]any         `json:"cloudtrail_event"`
					Observation struct{ Label string } `json:"sdk_observation"`
				}
			} `json:"cloudtrail"`
		}
	}](t, "sqs_mapping_controls")
	run := f.Runs[0]
	native := map[string]map[string]any{}
	for _, event := range run.CloudTrail.Events {
		native[event.Observation.Label] = event.Record
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sqs-management.sqlite"))
			}
			r := newLambdaSQSControlReplay(run.lambdaSQSControlRun)
			r.connect(t, backends)
			for _, row := range run.Observations {
				if row.Label == "create_standard_defaults_visibility_equals_timeout" {
					break
				}
				if row.Operation == "get_caller_identity" || row.Operation == "get_function_configuration" || row.Operation == "get_role_policy" || row.Operation == "invoke" || (row.Operation == "create_function" && row.Result.Code != "Success") {
					continue
				}
				r.command(t, row)
			}
			// Both captured functions are prepared. Rebind the first mapping's
			// read/no-op requests to the independently created second function's
			// mapping; its captured deletion has precisely this default state.
			for _, label := range []string{"same_source_second_function", "create_standard_defaults_visibility_equals_timeout_settle_0", "list_function", "noop_update", "remove_second_function_mapping_before_retarget"} {
				var selected lambdaSQSControlRow
				for _, row := range run.Observations {
					if row.Label == label {
						selected = row
						break
					}
				}
				if selected.Label == "" || native[label] == nil {
					t.Fatalf("missing positive management capture %s", label)
				}
				input := lambdaStreamingInput[map[string]any](t, selected.Input, r.normalize())
				out, err := awstest.CallSDK(t.Context(), r.c.lambda, lambdaURLObservationOperation(selected.Operation), lambdaQualifiedJSON(t, input))
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				if created, ok := out.(*awslambda.CreateEventSourceMappingOutput); ok {
					nativeID := selected.Result.Output["UUID"].(string)
					r.replacements = append(r.replacements, nativeID, aws.ToString(created.UUID))
					for _, row := range run.Observations {
						if row.Label == "create_standard_defaults_visibility_equals_timeout" {
							r.replacements = append(r.replacements, row.Result.Output["UUID"].(string), aws.ToString(created.UUID))
						}
					}
					r.replacements = append(r.replacements, run.Prefix+"-a", run.Prefix+"-b")
				}
				id := nativeAuditRequestID(t, out, nil)
				var got map[string]any
				for _, row := range lambdaAuditRows(t, backends.Journal) {
					if row.RequestID == id {
						got = lambdaAuditDocument(t, row)
						break
					}
				}
				if got == nil {
					t.Fatalf("%s SDK request %s missing management record", label, id)
				}
				want := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, native[label]), r.normalize())
				// The mapping clock is local. Retain timestamp field presence but
				// normalize its value, never diagnostic English or optional fields.
				if response, ok := want["responseElements"].(map[string]any); ok {
					actual, ok := got["responseElements"].(map[string]any)
					if !ok {
						t.Fatalf("%s missing response projection", label)
					}
					if _, present := actual["lastModified"]; !present {
						t.Fatalf("%s missing modification time", label)
					}
					response["lastModified"] = actual["lastModified"]
				}
				lambdaQualifiedAuditProjection(t, got, want)
				advanceClock(t, r.clock, time.Second)
			}
		})
	}
}
