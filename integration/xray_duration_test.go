package stackd_test

import (
	"fmt"
	"math"
	"slices"
	"testing"
)

// Keep the request clock in addition to the common capture's server Date. The
// former drives SDK replay; the latter remains the native receipt evidence.
// No query windows are rebased to the present or to segment event timestamps.
type xrayDurationCapture struct {
	xrayProjectionCapture
	Observations []struct {
		xrayProjectionObservation
		Started  float64 `json:"request_started"`
		Observed float64 `json:"response_observed"`
	}
	Supplemental []xrayDurationCapture `json:"supplemental_captures"`
}

func (capture xrayDurationCapture) stream(t *testing.T, name string) xrayQueryStream {
	t.Helper()
	stream := xrayQueryStream{Name: name, Region: capture.Region, Prefix: capture.Prefix}
	for _, observation := range capture.Observations {
		projection := capture.xrayProjectionCapture
		projection.Observations = []xrayProjectionObservation{observation.xrayProjectionObservation}
		row := projection.stream(t, name, nil).Observations[0]
		if observation.Started <= 0 || observation.Observed < observation.Started {
			t.Fatalf("invalid native request/receipt interval for %s", observation.Label)
		}
		row.Started = int64(observation.Started * 1000)
		stream.Observations = append(stream.Observations, row)
	}
	return stream
}

func TestXRayNativeDurationHistory(t *testing.T) {
	var capture xrayDurationCapture
	awsReadFixture(t, "xray/duration_edges.json", &capture)
	if len(capture.Supplemental) < 6 {
		t.Fatal("duration history requires the completed discriminator and its retained-trace continuation")
	}

	original := capture.stream(t, "original")
	originalPlan := xrayQueryPlan{
		Exclusions: map[string]string{
			"retained-fault-trace":                   "cross-capture readback: this trace predates this stream's recorded inputs; new transition-a reproduces its history below",
			"retained-fault-trace-graph":             "cross-capture readback lacks predecessor ingestion in this capture; transition-a is the owned positive control",
			"retained-fault-original-receipt-window": "cross-capture window contains unrelated predecessor traces absent from this stream, not an empty-graph oracle",
			"completed-group-poll-0":                 "native group index has no completed roots yet; poll 2 and both converged reads contain all three",
			"completed-group-poll-1":                 "native group index has only transition-b; poll 2 and both converged reads contain all three",
		},
		RestartBefore: []string{"completed-trace-graph-transition-a", "converged-group-combined-window"},
		Compare:       xrayDurationCompare(""),
	}

	// The aborted supplemental[0:4] probes have different owned trace IDs.
	// Supplemental[5], in contrast, reads and extends precisely the traces from
	// supplemental[4]. Replay their actual writes, reads and group deletion in
	// recorded order; seeding only the final documents destroys the experiment.
	history := capture.Supplemental[4].stream(t, "progressive-and-retained")
	continuation := capture.Supplemental[5].stream(t, "retained-continuation")
	if history.Prefix != continuation.Prefix || history.Region != continuation.Region {
		t.Fatal("retained continuation changed capture scope")
	}
	history.Observations = append(history.Observations, continuation.Observations...)
	historyPlan := xrayQueryPlan{
		Exclusions: map[string]string{
			"initial-partial-growth-trace-graph-0":    "native trace is not indexed yet (400); subsequent successful empty partial graphs are retained",
			"initial-complete-revision-trace-graph-0": "native trace is not indexed yet (400); subsequent complete-root reads converge",
			"initial-late-extension-trace-graph-0":    "native trace is not indexed yet (400); subsequent complete-root reads converge",
			"initial-traces-0":                        "native returns no traces immediately after ingestion; reads 1-3 retain all three",
			"second-late-extension-trace-graph-0":     "native still returns the pre-child duration 7; reads 1-3 converge to duration 11",
			"second-traces-0":                         "native still returns the initial documents; reads 1-3 retain the new children",
			"final-partial-growth-trace-graph-0":      "native still returns the in-progress empty graph; reads 1-3 converge to completed duration 10.5",
			"final-traces-0":                          "native still returns the in-progress root; reads 1-3 retain its completion",
			"after-partial-growth-trace-graph-0":      "native still returns duration 10.5 without the final child; reads 1-3 converge to duration 7",
			"after-late-extension-trace-graph-0":      "native still returns duration 11 without the final child; reads 1-3 converge to duration 13",
			"after-traces-0":                          "native still returns pre-transition documents; reads 1-3 retain both final children",
		},
		RestartBefore: []string{
			"second-late-extension-trace-graph-1",
			"final-partial-growth-trace-graph-1",
			"before-partial-growth-trace-graph",
			"settled-ungrouped-service-graph-0",
		},
		Compare: xrayDurationCompare(history.Prefix + "-late-extension"),
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			t.Run(original.Name, func(t *testing.T) { replayXRayQueries(t, backend, original, originalPlan) })
			t.Run(history.Name, func(t *testing.T) { replayXRayQueries(t, backend, history, historyPlan) })
		})
	}
}

func xrayDurationCompare(coldGroupRoot string) func(*testing.T, xrayQueryObservation, map[string]any, map[string]any) bool {
	return func(t *testing.T, row xrayQueryObservation, actual, expected map[string]any) bool {
		if row.Operation != "get-trace-graph" && row.Operation != "get-service-graph" {
			return false
		}
		var query struct{ GroupARN, GroupName string }
		awsDecodeJSON(t, row.Input, &query)
		if coldGroupRoot != "" && row.Operation == "get-service-graph" && (query.GroupARN != "" || query.GroupName != "") {
			// supplemental[4].findings: this newly created native group lost the
			// initial late-extension root admission and never backfilled it. Its
			// later root is only an edge source (count 0). Do not emulate native
			// group-creation propagation loss as deterministic admission behavior.
			// Exclude only that root/client projection, retaining the inferred
			// receiver and ALL partial-growth/complete-revision group statistics.
			// Ungrouped and per-trace late-extension remain fully compared.
			t.Log("excluding cold-group late-extension root/client: native missed initial admission; duration_edges.json supplemental_captures[4].findings")
			for _, response := range []map[string]any{actual, expected} {
				response["Services"] = slices.DeleteFunc(response["Services"].([]any), func(raw any) bool {
					return raw.(map[string]any)["Name"] == coldGroupRoot
				})
			}
		}
		local := xrayDurationHistogramObjects(actual)
		for identity, native := range xrayDurationHistogramObjects(expected) {
			object, ok := local[identity]
			if !ok {
				continue // Full semantic comparison below reports missing services/edges.
			}
			for _, field := range []string{"DurationHistogram", "ResponseTimeHistogram"} {
				want, nativeBins := native[field].([]any)
				got, localBins := object[field].([]any)
				if !nativeBins || !localBins || len(want) == 0 || len(got) == 0 {
					continue // Absent, null, empty and populated remain distinct.
				}
				wantCount, wantMoment := xrayDurationHistogramMoment(t, identity+"/"+field, want)
				gotCount, gotMoment := xrayDurationHistogramMoment(t, identity+"/"+field, got)
				if wantCount == 1 {
					continue // A single observation has no merge ambiguity.
				}
				// T-digest centroid merging is not a bin-shape contract. Both
				// millisecond-rounded distributions can differ by half a
				// millisecond per observation, hence their combined envelope.
				if gotCount != wantCount || math.Abs(gotMoment-wantMoment) > 0.001*wantCount+1e-8 {
					t.Fatalf("%s %s: native count/moment %g/%g, local %g/%g", identity, field, wantCount, wantMoment, gotCount, gotMoment)
				}
				object[field] = native[field]
			}
		}
		xrayProjectionEqual(t, actual, expected)
		return true
	}
}

func xrayDurationHistogramObjects(response map[string]any) map[string]map[string]any {
	objects := map[string]map[string]any{}
	for _, raw := range response["Services"].([]any) {
		service := raw.(map[string]any)
		// replayXRayQueries has already canonicalized opaque reference IDs to
		// semantic service identities, including client/root distinctions.
		identity := fmt.Sprint(service["ReferenceId"])
		objects[identity] = service
		for _, rawEdge := range service["Edges"].([]any) {
			edge := rawEdge.(map[string]any)
			objects[identity+"/edge/"+fmt.Sprint(edge["ReferenceId"])] = edge
		}
	}
	return objects
}

func xrayDurationHistogramMoment(t *testing.T, identity string, bins []any) (count, moment float64) {
	t.Helper()
	for _, raw := range bins {
		bin, ok := raw.(map[string]any)
		if !ok || len(bin) != 2 {
			t.Fatalf("%s invalid histogram bin %v", identity, raw)
		}
		n, countOK := bin["Count"].(float64)
		value, valueOK := bin["Value"].(float64)
		if !countOK || !valueOK || n <= 0 || n != math.Trunc(n) || math.IsInf(n, 0) || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			t.Fatalf("%s invalid histogram bin %v", identity, bin)
		}
		count += n
		moment += n * value
	}
	return count, moment
}
