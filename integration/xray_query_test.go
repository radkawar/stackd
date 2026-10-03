package stackd_test

import (
	"encoding/json"
	"math"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/xray"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

// Local selections supplement the native wire oracle with documented grammar
// and durability transitions. They assert membership, not a second projection.
type xrayQueryObservation struct {
	xrayNativeObservation
	TraceIDs      *[]string                 `json:"trace_ids"`
	SummaryFields map[string]map[string]any `json:"summary_fields"`
}

type xrayQueryStream struct {
	Name, Region, Prefix  string
	Observations, Cleanup []xrayQueryObservation
}

type xrayQueryPlan struct {
	Exclusions    map[string]string
	RestartBefore []string `json:"restart_before"`
	After         map[string][]xrayQueryObservation
	Scenarios     []xrayQueryStream
	// Compare handles native approximation or unordered-choice contracts. Exact
	// responses continue through the shared canonical wire comparison.
	Compare func(*testing.T, xrayQueryObservation, map[string]any, map[string]any) bool `json:"-"`
}

func TestXRayNativeQueriesAndGroups(t *testing.T) {
	var queries xrayQueryStream
	awsReadFixture(t, "xray/trace_queries.json", &queries)
	queries.Name = "native-queries"
	var projection xrayProjectionCapture
	awsReadFixture(t, "xray/trace_projection_edges.json", &projection)
	causes := projection.stream(t, "native-root-causes", nil)
	var plan xrayQueryPlan
	awsReadFixture(t, "xray/query_transitions.json", &plan)
	var receiptCapture struct{ Observations []xrayQueryObservation }
	awsReadFixture(t, "xray/query_time_edges.json", &receiptCapture)
	for _, row := range receiptCapture.Observations {
		// These later CLI reads reuse the already-converged trace projection.
		// Keep their native windows/membership and revision while moving the
		// read into this replay's post-completion, pre-delete phase.
		row.Service, row.Account, row.Result.HTTPStatus = "xray", queries.Observations[0].Account, 200
		row.Started = queries.Observations[len(queries.Observations)-1].Started
		var captured struct{ TraceSummaries []map[string]any }
		awsDecodeJSON(t, row.Result.Output, &captured)
		ids := []string{}
		row.SummaryFields = map[string]map[string]any{}
		for _, summary := range captured.TraceSummaries {
			id := summary["Id"].(string)
			ids = append(ids, id)
			fields := map[string]any{}
			for _, field := range []string{"Revision", "IsPartial", "Duration", "ResponseTime", "MatchedEventTime"} {
				fields[field] = summary[field]
			}
			row.SummaryFields[id] = fields
		}
		row.TraceIDs = &ids
		queries.Observations = append(queries.Observations, row)
	}
	var groups xrayQueryStream
	awsReadFixture(t, "xray/group_edges.json", &groups)
	groups.Name = "native-group-edges"
	var aggregate struct {
		xrayProjectionCapture
		MetricReadback struct {
			Observations []xrayProjectionObservation
		} `json:"metric_readback"`
	}
	awsReadFixture(t, "xray/trace_aggregate_edges.json", &aggregate)
	var metrics []xrayQueryObservation
	for _, captured := range aggregate.MetricReadback.Observations {
		row := xrayQueryObservation{}
		row.Label, row.Service, row.Operation = "metrics-"+captured.Label, "cloudwatch", "get-metric-statistics"
		row.Input, row.RawResponse = captured.Input, captured.RawResponse
		row.Account, row.Region = queries.Observations[0].Account, queries.Region
		at, err := http.ParseTime(captured.Headers["Date"])
		if err != nil {
			t.Fatal(err)
		}
		row.Started = at.UnixMilli()
		row.Result.Code, row.Result.HTTPStatus, row.Result.Output = "Success", captured.Status, captured.Output
		metrics = append(metrics, row)
		plan.RestartBefore = append(plan.RestartBefore, row.Label)
	}
	pending := xrayQueryPendingMetrics(t, queries, metrics, &plan)
	queries.Cleanup = append(queries.Cleanup, metrics...)
	streams := append([]xrayQueryStream{queries, causes, groups, pending}, plan.Scenarios...)
	for index, name := range []string{"native-arrival-clocks", "native-group-admission", "native-converged-deletion"} {
		streams = append(streams, aggregate.Supplemental[index+4].stream(t, name, nil))
	}
	plan.Compare = xrayQueryClockCompare
	for _, backend := range []string{"memory", "sqlite"} {
		for _, stream := range streams {
			t.Run(backend+"/"+stream.Name, func(t *testing.T) {
				replayXRayQueries(t, backend, stream, plan)
			})
		}
	}
}

// Replay the retained mutations within one unpublished minute, including
// identical segment revisions, then delete the group before restarting. The
// native metric totals remain the oracle; neither deletion nor revisions may
// lose or multiply the first memberships awaiting publication.
func xrayQueryPendingMetrics(t *testing.T, queries xrayQueryStream, metrics []xrayQueryObservation, plan *xrayQueryPlan) xrayQueryStream {
	t.Helper()
	stream := xrayQueryStream{Name: "pending-group-metrics", Region: queries.Region, Prefix: queries.Prefix}
	var latest int64
	for _, row := range queries.Observations {
		if row.Operation == "put-trace-segments" {
			latest = row.Started
		}
	}
	minute := time.UnixMilli(latest).UTC().Truncate(time.Minute).Add(time.Minute)
	for _, row := range append(slices.Clone(queries.Observations), queries.Cleanup...) {
		if row.Service != "xray" || row.Result.Code != "Success" {
			continue
		}
		switch row.Operation {
		case "create-group", "update-group", "put-trace-segments", "delete-group":
		default:
			continue
		}
		row.Label = "pending-" + row.Label
		row.Started = minute.Add(time.Duration(len(stream.Observations)+1) * time.Second).UnixMilli()
		stream.Observations = append(stream.Observations, row)
		if row.Operation == "put-trace-segments" {
			row.Label += "-identical-revision"
			stream.Observations = append(stream.Observations, row)
		}
	}
	if len(stream.Observations) >= 60 {
		t.Fatal("pending metric mutations must fit in one minute")
	}
	for _, row := range metrics {
		row.Label = "pending-" + row.Label
		row.Started = minute.Add(2 * time.Minute).UnixMilli()
		stream.Observations = append(stream.Observations, row)
		plan.RestartBefore = append(plan.RestartBefore, row.Label)
	}
	return stream
}

func xrayQueryMetricSum(t *testing.T, client *cloudwatch.Client, row xrayQueryObservation) {
	t.Helper()
	var input cloudwatch.GetMetricStatisticsInput
	awsDecodeJSON(t, row.Input, &input)
	raw := row.Result.Output
	if row.RawResponse != "" {
		raw = []byte(row.RawResponse)
	}
	var native struct {
		Label      string
		Datapoints []struct {
			Sum  float64
			Unit string
		}
	}
	awsDecodeJSON(t, raw, &native)
	var want float64
	var unit string
	for _, point := range native.Datapoints {
		want += point.Sum
		if unit != "" && unit != point.Unit {
			t.Fatal("native metric mixes units")
		}
		unit = point.Unit
	}
	out, err := client.GetMetricStatistics(t.Context(), &input)
	awsNativeResult(t, row.awsNativeObservation, err)
	if err != nil {
		return
	}
	if aws.ToString(out.Label) != native.Label {
		t.Fatalf("metric label: native %q, local %q", native.Label, aws.ToString(out.Label))
	}
	var got float64
	for _, point := range out.Datapoints {
		if string(point.Unit) != unit {
			t.Errorf("metric unit: native %q, local %q", unit, point.Unit)
		}
		if point.Timestamp == nil || point.Timestamp.Before(input.StartTime.Truncate(time.Minute)) || !point.Timestamp.Before(*input.EndTime) {
			t.Errorf("metric timestamp %v outside requested window", point.Timestamp)
		}
		if point.Sum == nil || *point.Sum < 0 || *point.Sum != math.Trunc(*point.Sum) {
			t.Fatalf("invalid first-membership count %v", point.Sum)
		}
		got += *point.Sum
	}
	// AWS's distributed zero samples change SampleCount/Minimum/Average and
	// publication latency can move minute buckets. Their sum is the membership
	// contract, not the publisher's cadence or number of participating workers.
	if got != want {
		t.Fatalf("first-membership metric sum: native %v, local %v", want, got)
	}
}

func xrayQueryClockCompare(t *testing.T, row xrayQueryObservation, actual, expected map[string]any) bool {
	if row.Label != "ungrouped-new-window-2" {
		return false
	}
	// This account-wide native window also contains the concurrent cause-branch
	// probe. Keep every owned service/edge and compare the entire local graph;
	// only the demonstrably unrelated native service namespace is excluded.
	expected["Services"] = slices.DeleteFunc(expected["Services"].([]any), func(raw any) bool {
		return !strings.HasPrefix(raw.(map[string]any)["Name"].(string), "stackd-xaggregate-1d8033f7da")
	})
	// The envelope also spans those unrelated native services. Its complete
	// clock contract is checked by the owned-window captures above.
	delete(actual, "StartTime")
	delete(actual, "EndTime")
	delete(expected, "StartTime")
	delete(expected, "EndTime")
	if !reflect.DeepEqual(actual, expected) {
		got, _ := json.Marshal(actual)
		want, _ := json.Marshal(expected)
		t.Fatalf("owned native arrival graph differs\nnative: %s\nlocal:  %s", want, got)
	}
	return true
}

func replayXRayQueries(t *testing.T, backend string, stream xrayQueryStream, plan xrayQueryPlan) {
	t.Helper()
	var rows []xrayQueryObservation
	for _, row := range append(slices.Clone(stream.Observations), stream.Cleanup...) {
		if row.Service != "xray" && row.Service != "cloudwatch" {
			continue // Native trail/bucket teardown is owned by audit replay.
		}
		rows = append(rows, row)
		for _, extra := range plan.After[row.Label] {
			if extra.Started == 0 {
				extra.Started = row.Started
			}
			if extra.Account == "" {
				extra.Account = row.Account
			}
			rows = append(rows, extra)
		}
	}
	if len(rows) == 0 {
		t.Fatal("query scenario has no operations")
	}
	path := filepath.Join(t.TempDir(), "xray-queries.sqlite")
	backends, closeDB := storage.NewMemory(), func() {}
	if backend == "sqlite" {
		backends, closeDB = openSQLiteBackends(t, path)
	}
	source := clock.NewManual(time.UnixMilli(rows[0].Started).UTC())
	owner := t
	cloud, clients, closeStack := startEventDeliveryCloud(t, backends, source)
	groupARNs := map[string]string{}
	receipts := map[string]float64{}
	for _, row := range rows {
		if reason, transient := plan.Exclusions[row.Label]; transient {
			t.Run(row.Label, func(t *testing.T) { t.Skip(reason) })
			continue
		}
		if !t.Run(row.Label, func(t *testing.T) {
			// Restart before advancing: pending minute publication must survive
			// closing SQLite, rather than being flushed by the old process.
			if slices.Contains(plan.RestartBefore, row.Label) {
				closeStack()
				if backend == "sqlite" {
					closeDB()
					backends, closeDB = openSQLiteBackends(owner, path)
				}
				cloud, clients, closeStack = startEventDeliveryCloud(owner, backends, source)
			}
			when := time.UnixMilli(row.Started).UTC()
			if when.After(source.Now()) {
				advanceClock(t, source, when.Sub(source.Now()))
			}
			region := row.Region
			if region == "" {
				region = stream.Region
			}
			account := row.Account
			if account == "" {
				account = rows[0].Account
			}
			if row.Service == "cloudwatch" {
				trailNativeDrain(t, cloud)
				options := metricsClient(clients, account).Options()
				options.Region = region
				xrayQueryMetricSum(t, cloudwatch.New(options), row)
				return
			}
			input := string(row.Input)
			for native, local := range groupARNs {
				input = strings.ReplaceAll(input, native, local)
			}
			wire := &awstest.WireClient{Client: clients.server.Client()}
			options := clients.xrayRegion(region, account, "test", "").Options()
			options.HTTPClient = wire
			options.APIOptions = append(options.APIOptions, awstest.JSONBody(json.RawMessage(input)))
			// Preserve literal numeric timestamps and malformed native inputs at
			// the frontend, bypassing only SDK required-field validation.
			seed := json.RawMessage(`{"TraceSegmentDocuments":[],"TraceIds":[],"StartTime":"2026-09-23T00:00:00Z","EndTime":"2026-09-23T00:01:00Z","GroupName":"request","ResourceARN":"request","Tags":[],"TagKeys":[]}`)
			_, err := awstest.CallSDK(t.Context(), xray.New(options), row.Operation, seed)
			awsNativeResult(t, row.awsNativeObservation, err)
			if err != nil {
				return
			}
			if wire.Status != row.Result.HTTPStatus {
				t.Fatalf("HTTP status: native %d, local %d", row.Result.HTTPStatus, wire.Status)
			}
			actual := xrayNativeReply(t, wire.Body, stream.Prefix)
			if row.Operation == "put-trace-segments" {
				var batch struct{ TraceSegmentDocuments []string }
				awsDecodeJSON(t, row.Input, &batch)
				for _, document := range batch.TraceSegmentDocuments {
					var segment struct {
						TraceID string `json:"trace_id"`
					}
					awsDecodeJSON(t, []byte(document), &segment)
					receipts[segment.TraceID] = float64(source.Now().Unix())
				}
			}
			if row.Operation == "get-trace-summaries" {
				count, ok := actual["TracesProcessedCount"].(float64)
				summaries, present := actual["TraceSummaries"].([]any)
				// Native index work is not a cross-implementation count oracle.
				// It must still honestly bound the returned and ingested traces.
				if !ok || !present || count != math.Trunc(count) || count < float64(len(summaries)) || count > float64(len(receipts)) {
					t.Fatalf("invalid processed count %v for %d returned / %d ingested traces", actual["TracesProcessedCount"], len(summaries), len(receipts))
				}
				var query struct{ StartTime, EndTime float64 }
				awsDecodeJSON(t, row.Input, &query)
				pageStart, ok := actual["ApproximateTime"].(float64)
				// This is a page/index boundary, not a trace event timestamp.
				// Native Service scans include a preceding one-minute bucket.
				if !ok || pageStart < math.Floor(query.StartTime)-60 || pageStart > query.EndTime {
					t.Fatalf("page start %v outside query candidate range [%v, %v]", actual["ApproximateTime"], math.Floor(query.StartTime)-60, query.EndTime)
				}
			}
			if row.TraceIDs != nil {
				var ids []string
				collection := "TraceSummaries"
				if row.Operation == "batch-get-traces" {
					collection = "Traces"
				}
				for _, raw := range actual[collection].([]any) {
					summary := raw.(map[string]any)
					id := summary["Id"].(string)
					ids = append(ids, id)
					for field, want := range row.SummaryFields[id] {
						if field == "MatchedEventTime" && want != nil {
							want = receipts[id]
						}
						if !reflect.DeepEqual(summary[field], want) {
							t.Errorf("trace %s %s: want %#v, got %#v", id, field, want, summary[field])
						}
					}
				}
				slices.Sort(ids)
				want := slices.Clone(*row.TraceIDs)
				slices.Sort(want)
				if !slices.Equal(ids, want) {
					t.Fatalf("filtered trace IDs: want %v, got %v", want, ids)
				}
				return
			}
			want := string(row.Result.Output)
			if row.RawResponse != "" {
				want = row.RawResponse
			}
			if row.Operation == "create-group" {
				expected := xrayNativeReply(t, []byte(want), stream.Prefix)
				nativeARN := awsFixtureField(expected, "Group.GroupARN").(string)
				localARN, ok := awsFixtureField(actual, "Group.GroupARN").(string)
				prefix := nativeARN[:strings.LastIndex(nativeARN, "/")+1]
				if !ok || !strings.HasPrefix(localARN, prefix) || len(localARN) <= len(prefix) {
					t.Fatalf("group ARN lost scope/name: want prefix %q, got %q", prefix, localARN)
				}
				groupARNs[nativeARN] = localARN
			}
			for native, local := range groupARNs {
				want = strings.ReplaceAll(want, native, local)
			}
			expected := xrayNativeReply(t, []byte(want), stream.Prefix)
			if row.Operation == "get-trace-summaries" {
				delete(actual, "TracesProcessedCount")
				delete(expected, "TracesProcessedCount")
				delete(actual, "ApproximateTime")
				delete(expected, "ApproximateTime")
			}
			// Native indexing receipt is asynchronous. Bind that timestamp to
			// the replay's service clock, preserving the field and all selection
			// windows rather than pretending AWS's indexing lag is contractual.
			if summaries, ok := expected["TraceSummaries"].([]any); ok {
				for _, raw := range summaries {
					summary := raw.(map[string]any)
					if summary["MatchedEventTime"] != nil {
						at, found := receipts[summary["Id"].(string)]
						if !found {
							t.Fatalf("no receipt binding for trace %s", summary["Id"])
						}
						summary["MatchedEventTime"] = at
					}
				}
			}
			xrayQueryCanonical(t, actual)
			xrayQueryCanonical(t, expected)
			if plan.Compare != nil && plan.Compare(t, row, actual, expected) {
				return
			}
			if !reflect.DeepEqual(actual, expected) {
				actualJSON, _ := json.Marshal(actual)
				expectedJSON, _ := json.Marshal(expected)
				t.Fatalf("native query response differs\nnative: %s\nlocal:  %s", expectedJSON, actualJSON)
			}
		}) {
			return // Later observations depend on successful earlier mutations.
		}
	}
}

func xrayQueryCanonical(t *testing.T, response map[string]any) {
	t.Helper()
	if traces, ok := response["Traces"].([]any); ok {
		for _, rawTrace := range traces {
			for _, rawSegment := range rawTrace.(map[string]any)["Segments"].([]any) {
				segment := rawSegment.(map[string]any)
				document := segment["Document"].(map[string]any)
				if document["inferred"] != true {
					continue
				}
				if segment["Id"] != document["id"] {
					t.Fatalf("inferred segment envelope and document disagree: %#v", segment)
				}
				identity := "inferred:" + document["parent_id"].(string)
				segment["Id"], document["id"] = identity, identity
				if children, ok := document["subsegments"].([]any); ok {
					for _, rawChild := range children {
						child := rawChild.(map[string]any)
						child["id"] = identity + ":" + child["name"].(string)
					}
				}
			}
		}
	}
	if services, ok := response["Services"].([]any); ok {
		identities := map[any]string{}
		seen := map[string]bool{}
		for _, raw := range services {
			service := raw.(map[string]any)
			identity, _ := json.Marshal([]any{service["Name"], service["Type"], service["AccountId"]})
			key := string(identity)
			if seen[key] {
				t.Fatalf("duplicate service identity %s", key)
			}
			if _, exists := identities[service["ReferenceId"]]; exists {
				t.Fatalf("duplicate graph reference ID %v", service["ReferenceId"])
			}
			seen[key] = true
			identities[service["ReferenceId"]] = key
		}
		for _, raw := range services {
			service := raw.(map[string]any)
			service["ReferenceId"] = identities[service["ReferenceId"]]
			for _, rawEdge := range service["Edges"].([]any) {
				edge := rawEdge.(map[string]any)
				identity, found := identities[edge["ReferenceId"]]
				if !found {
					t.Fatalf("dangling graph edge %v", edge["ReferenceId"])
				}
				edge["ReferenceId"] = identity
			}
		}
	}
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for field, child := range value {
				visit(child)
				items, ok := child.([]any)
				if !ok {
					continue
				}
				switch field {
				case "Traces", "Segments", "subsegments", "TraceSummaries", "Groups", "Tags", "ServiceIds", "AvailabilityZones", "InstanceIds", "ResourceARNs", "Users", "Names", "Aliases", "Edges", "DurationHistogram", "ResponseTimeHistogram", "ErrorRootCauses", "FaultRootCauses", "ResponseTimeRootCauses":
					// Histogram bins are compared as (Value, Count) observations;
					// no merging, rounding, or dropping empty/null distinctions.
					xrayQuerySort(items)
				}
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	// Services within root causes and EntityPath are ordered causal paths, not
	// sets. Sort only the graph's top-level Services after their child sets.
	visit(response)
	if services, ok := response["Services"].([]any); ok {
		xrayQuerySort(services)
	}
}

func xrayQuerySort(values []any) {
	slices.SortFunc(values, func(a, b any) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return strings.Compare(string(left), string(right))
	})
}
