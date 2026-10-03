package stackd_test

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// These captures retain the signed wire operations, rather than a second set of
// hand-authored projections. The query replay owns ingestion, SDK calls, clocks,
// account scoping, normalization and both storage backends.
type xrayProjectionObservation struct {
	Label, Path   string
	Input, Output json.RawMessage
	Status        int
	RawResponse   string            `json:"raw_response_body"`
	Headers       map[string]string `json:"response_headers"`
}

type xrayProjectionCapture struct {
	Prefix, Region string
	Account        string `json:"caller_account"`
	Observations   []xrayProjectionObservation
	Supplemental   []xrayProjectionCapture `json:"supplemental_captures"`
	Choices        []xrayProjectionChoice  `json:"equal_priority_selections"`
}

type xrayProjectionChoice struct {
	TraceID         string   `json:"trace_id"`
	Category        string   `json:"category"`
	ClientImpacting bool     `json:"client_impacting"`
	Count           int      `json:"expected_count"`
	Names           []string `json:"allowed_terminal_entity_names"`
}

func (capture xrayProjectionCapture) stream(t *testing.T, name string, keep func(xrayProjectionObservation) bool) xrayQueryStream {
	t.Helper()
	stream := xrayQueryStream{Name: name, Region: capture.Region, Prefix: capture.Prefix}
	routes := map[string]string{
		"TraceSegments": "put-trace-segments", "TraceSummaries": "get-trace-summaries",
		"Traces":     "batch-get-traces",
		"TraceGraph": "get-trace-graph", "ServiceGraph": "get-service-graph",
		"CreateGroup": "create-group", "GetGroup": "get-group", "GetGroups": "get-groups",
		"UpdateGroup": "update-group", "DeleteGroup": "delete-group",
	}
	for _, captured := range capture.Observations {
		if keep != nil && !keep(captured) {
			continue
		}
		row := xrayQueryObservation{}
		row.Label, row.Input, row.Service = captured.Label, captured.Input, "xray"
		row.Account, row.Region, row.RawResponse = capture.Account, capture.Region, captured.RawResponse
		row.Operation = routes[captured.Path]
		if row.Operation == "" {
			t.Fatalf("unknown native projection route %q", captured.Path)
		}
		at, err := http.ParseTime(captured.Headers["Date"])
		if err != nil {
			t.Fatal(err)
		}
		row.Started = at.UnixMilli()
		row.Result.Code, row.Result.HTTPStatus, row.Result.Output = "Success", captured.Status, captured.Output
		if captured.Status >= 400 {
			for key, value := range captured.Headers {
				if strings.EqualFold(key, "x-amzn-errortype") {
					row.Result.Code = strings.Split(value, ":")[0]
				}
			}
			if row.Result.Code == "Success" {
				t.Fatalf("native error %s has no error type", captured.Label)
			}
		}
		stream.Observations = append(stream.Observations, row)
	}
	return stream
}

func TestXRayNativeInferredDocuments(t *testing.T) {
	var capture struct {
		Region        string
		CapturedAt    time.Time         `json:"captured_at"`
		Documents     []json.RawMessage `json:"seed_documents"`
		Input, Output json.RawMessage
	}
	awsReadFixture(t, "xray/inferred_documents.json", &capture)
	documents := make([]string, len(capture.Documents))
	for i, document := range capture.Documents {
		documents[i] = string(document)
	}
	input, err := json.Marshal(map[string]any{"TraceSegmentDocuments": documents})
	if err != nil {
		t.Fatal(err)
	}
	seed := xrayQueryObservation{}
	seed.Label, seed.Service, seed.Operation = "seed-captured-documents", "xray", "put-trace-segments"
	seed.Account, seed.Input, seed.Started = eventDeliveryAccount, input, capture.CapturedAt.UnixMilli()
	seed.Result.Code, seed.Result.HTTPStatus = "Success", 200
	seed.Result.Output = json.RawMessage(`{"UnprocessedTraceSegments":[]}`)
	read := seed
	read.Operation, read.Input, read.Result.Output = "batch-get-traces", capture.Input, capture.Output
	read.Label = "inferred-before-restart"
	restored := read
	restored.Label = "inferred-after-restart"
	stream := xrayQueryStream{Name: "inferred-documents", Region: capture.Region, Observations: []xrayQueryObservation{seed, read, restored}}
	plan := xrayQueryPlan{
		RestartBefore: []string{restored.Label},
		Compare: func(t *testing.T, row xrayQueryObservation, actual, expected map[string]any) bool {
			if row.Operation != "batch-get-traces" {
				return false
			}
			// The AWS CLI strips null modeled members. Compare the complete
			// document result, not its absent-versus-null continuation field.
			delete(actual, "NextToken")
			delete(expected, "NextToken")
			xrayProjectionEqual(t, actual, expected)
			return true
		},
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { replayXRayQueries(t, backend, stream, plan) })
	}
}

func TestXRayNativeHistogramProjection(t *testing.T) {
	var capture xrayProjectionCapture
	awsReadFixture(t, "xray/histogram_edges.json", &capture)
	stream := capture.stream(t, "native-histograms", nil)
	samples := map[string][]float64{}
	for _, document := range xrayProjectionDocuments(t, stream) {
		name := document["name"].(string)
		samples[name] = append(samples[name], document["end_time"].(float64)-document["start_time"].(float64))
	}
	plan := xrayQueryPlan{
		Exclusions: map[string]string{
			"service-graph-0": "native index is incomplete: linear1024 has 132/1024 requests; weighted256 is absent",
			"service-graph-1": "native index is incomplete: linear1024 has 383/1024 and weighted256 has 47/256 requests; reads 2–4 converge",
		},
		Compare: func(t *testing.T, row xrayQueryObservation, actual, expected map[string]any) bool {
			if row.Operation != "get-service-graph" {
				return false
			}
			// AWS documents t-digest, not a centroid count cap or exact merge
			// order. Complete repeated reads even disagree on the number of bins:
			// https://aws.amazon.com/blogs/aws/latency-distribution-graph-in-aws-x-ray/
			localHistograms := map[string]any{}
			for side, response := range []map[string]any{actual, expected} {
				for _, raw := range response["Services"].([]any) {
					service := raw.(map[string]any)
					name := service["Name"].(string)
					values, ok := samples[name]
					if !ok {
						t.Fatalf("unexpected histogram service %q", name)
					}
					objects := []map[string]any{service}
					for _, edge := range service["Edges"].([]any) {
						objects = append(objects, edge.(map[string]any))
					}
					for _, object := range objects {
						if stats, ok := object["SummaryStatistics"].(map[string]any); ok {
							var sum float64
							for _, value := range values {
								sum += value
							}
							if stats["TotalCount"] != float64(len(values)) || stats["TotalResponseTime"] != math.Round(sum*1000)/1000 {
								t.Fatalf("%s lost raw observations: %v", name, stats)
							}
						}
						for _, field := range []string{"DurationHistogram", "ResponseTimeHistogram"} {
							if bins, ok := object[field].([]any); ok {
								xrayProjectionHistogram(t, name, bins, values)
								if side == 0 && object["Root"] == true {
									localHistograms[name+"/"+field] = slices.Clone(bins)
								}
								// Only the validated approximation is substituted. Null,
								// absent and empty histograms remain distinguishable.
								object[field] = []any{}
							}
						}
					}
				}
			}
			for _, field := range []string{"DurationHistogram", "ResponseTimeHistogram"} {
				// Reversal invariance is an emulator determinism contract, not
				// a claim that AWS emits identical centroids for permutations.
				left := localHistograms[capture.Prefix+"-linear256/"+field]
				right := localHistograms[capture.Prefix+"-reverse256/"+field]
				if left == nil || !reflect.DeepEqual(left, right) {
					t.Errorf("local %s depends on insertion order", field)
				}
			}
			xrayProjectionEqual(t, actual, expected)
			return true
		},
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { replayXRayQueries(t, backend, stream, plan) })
	}
}

func xrayProjectionHistogram(t *testing.T, name string, bins []any, samples []float64) {
	t.Helper()
	// Native bins are a wire set (and arrive unsorted). Check the numeric
	// centroid order, not JSON/count sort order imposed by shared canonicalization.
	bins = slices.Clone(bins)
	slices.SortFunc(bins, func(a, b any) int {
		left, right := a.(map[string]any)["Value"].(float64), b.(map[string]any)["Value"].(float64)
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
		return 0
	})
	counts := map[float64]float64{}
	var roundedSum float64
	for _, sample := range samples {
		value := math.Round(sample*1000) / 1000
		counts[value]++
		roundedSum += value
	}
	var count, weighted float64
	previous := math.Inf(-1)
	for _, raw := range bins {
		bin := raw.(map[string]any)
		value, n := bin["Value"].(float64), bin["Count"].(float64)
		if len(bin) != 2 || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value <= previous || n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
			t.Fatalf("%s invalid centroid %v after %g", name, bin, previous)
		}
		previous = value
		count += n
		weighted += value * n
	}
	// Each millisecond-rounded weighted centroid contributes at most half a
	// millisecond per observation. This is an arithmetic envelope, not an AWS
	// t-digest accuracy guarantee, and deliberately differs from raw-sum latency.
	if count != float64(len(samples)) || math.Abs(weighted-roundedSum) > 0.0005*count+1e-8 {
		t.Fatalf("%s histogram loses mass: count=%g/%d weighted=%g rounded inputs=%g", name, count, len(samples), weighted, roundedSum)
	}
	minimum, maximum := math.Inf(1), math.Inf(-1)
	for value := range counts {
		minimum, maximum = math.Min(minimum, value), math.Max(maximum, value)
	}
	if len(bins) == 0 || bins[0].(map[string]any)["Value"] != minimum || bins[len(bins)-1].(map[string]any)["Value"] != maximum {
		t.Fatalf("%s loses distribution tails", name)
	}
	for value, n := range counts {
		if n <= 1 {
			continue
		}
		var retained float64
		for _, bin := range bins {
			if bin.(map[string]any)["Value"] == value {
				retained += bin.(map[string]any)["Count"].(float64)
			}
		}
		if retained != n {
			t.Errorf("%s repeated latency %g: want %g observations, got %g", name, value, n, retained)
		}
	}
	if len(counts) > 100 && len(bins) >= len(counts) {
		t.Errorf("%s high-cardinality histogram did not aggregate observations", name)
	}
}

func TestXRayNativeCauseProjection(t *testing.T) {
	var capture xrayProjectionCapture
	awsReadFixture(t, "xray/cause_branch_edges.json", &capture)
	for _, backend := range []string{"memory", "sqlite"} {
		for i, captured := range append([]xrayProjectionCapture{capture}, capture.Supplemental...) {
			t.Run(fmt.Sprintf("%s/branches-%d", backend, i), func(t *testing.T) {
				stream := captured.stream(t, "native-branches", nil)
				plan := xrayQueryPlan{Exclusions: map[string]string{
					"summaries-0-page-0": "native index is empty immediately after ingestion; summaries-2-page-0 contains every owned trace",
					"summaries-1-page-0": "native asynchronous index is incomplete (27/39, 19/32, 6/8 or 6/14); the next retained read converges",
				}}
				documents := xrayProjectionDocuments(t, stream)
				choices := map[string]xrayProjectionChoice{}
				for _, choice := range captured.Choices {
					choices[choice.TraceID] = choice
				}
				selectors := xrayProjectionSelectors(t, &stream, documents)
				var baseline []any
				plan.Compare = func(t *testing.T, row xrayQueryObservation, actual, expected map[string]any) bool {
					if row.Operation != "get-trace-summaries" {
						return false
					}
					if predicate, ok := selectors[row.Label]; ok {
						selected := []any{}
						for _, raw := range baseline {
							if predicate(raw.(map[string]any)) {
								selected = append(selected, raw)
							}
						}
						expected["TraceSummaries"] = selected
					} else {
						wantByID := map[string]map[string]any{}
						for _, raw := range expected["TraceSummaries"].([]any) {
							summary := raw.(map[string]any)
							wantByID[summary["Id"].(string)] = summary
						}
						for _, raw := range actual["TraceSummaries"].([]any) {
							summary := raw.(map[string]any)
							id := summary["Id"].(string)
							if choice, ok := choices[id]; ok {
								xrayProjectionRebindChoice(t, choice, documents[id], summary, wantByID[id])
							}
						}
						baseline = actual["TraceSummaries"].([]any)
					}
					xrayProjectionEqual(t, actual, expected)
					return true
				}
				replayXRayQueries(t, backend, stream, plan)
			})
		}
	}
}

// The 51 retained descriptors admit an opaque native tie winner, not extra
// branches. Rebind only that terminal in the native path to the selected input
// entity. Every other field, service boundary, impact flag and exception owner
// remains subject to canonical wire equality.
func xrayProjectionRebindChoice(t *testing.T, choice xrayProjectionChoice, document, actual, expected map[string]any) {
	t.Helper()
	field := "FaultRootCauses"
	if choice.Category == "error" {
		field = "ErrorRootCauses"
	}
	causes := actual[field].([]any)
	if len(causes) != choice.Count || choice.Count != 1 || expected == nil {
		t.Fatalf("%s: expected %d causal traversal, got %v", choice.TraceID, choice.Count, causes)
	}
	cause := causes[0].(map[string]any)
	services := cause["Services"].([]any)
	if cause["ClientImpacting"] != choice.ClientImpacting || len(services) == 0 {
		t.Fatalf("%s: incorrect impact or missing source service: %v", choice.TraceID, cause)
	}
	path := services[0].(map[string]any)["EntityPath"].([]any)
	if len(path) != 2 {
		t.Fatalf("%s: choice must retain root and one child: %v", choice.TraceID, path)
	}
	terminal := path[1].(map[string]any)["Name"].(string)
	if !slices.Contains(choice.Names, terminal) {
		t.Fatalf("%s: ineligible terminal %q", choice.TraceID, terminal)
	}
	var chosen map[string]any
	for _, raw := range document["subsegments"].([]any) {
		child := raw.(map[string]any)
		if child["name"] == terminal {
			chosen = child
		}
	}
	if chosen == nil {
		t.Fatalf("%s: terminal is not an actual child", choice.TraceID)
	}
	owned := []any{}
	if cause, ok := chosen["cause"].(map[string]any); ok {
		if exceptions, ok := cause["exceptions"].([]any); ok {
			for _, raw := range exceptions {
				exception := raw.(map[string]any)
				owned = append(owned, map[string]any{"Name": exception["type"], "Message": exception["message"]})
			}
		}
	}
	wantCause := expected[field].([]any)[0].(map[string]any)
	wantServices := wantCause["Services"].([]any)
	wantPath := wantServices[0].(map[string]any)["EntityPath"].([]any)
	wantTerminal := wantPath[len(wantPath)-1].(map[string]any)
	wantTerminal["Name"], wantTerminal["Exceptions"] = terminal, owned
	wantTerminal["Remote"] = chosen["namespace"] == "remote"
	if len(wantServices) == 2 {
		inferred := wantServices[1].(map[string]any)
		inferred["Name"], inferred["Names"] = terminal, []any{terminal}
		inferred["EntityPath"].([]any)[0].(map[string]any)["Name"] = terminal
		// Its native empty Exceptions and Remote=false are intentionally not
		// rebound to the caller's exception/Remote fields.
	}
}

func xrayProjectionDocuments(t *testing.T, stream xrayQueryStream) map[string]map[string]any {
	t.Helper()
	documents := map[string]map[string]any{}
	for _, row := range stream.Observations {
		if row.Operation != "put-trace-segments" {
			continue
		}
		var batch struct{ TraceSegmentDocuments []string }
		awsDecodeJSON(t, row.Input, &batch)
		for _, raw := range batch.TraceSegmentDocuments {
			var document map[string]any
			awsDecodeJSON(t, []byte(raw), &document)
			documents[document["trace_id"].(string)] = document
		}
	}
	return documents
}

func xrayProjectionEqual(t *testing.T, actual, expected map[string]any) {
	t.Helper()
	xrayQueryCanonical(t, actual)
	xrayQueryCanonical(t, expected)
	if !reflect.DeepEqual(actual, expected) {
		left, _ := json.Marshal(actual)
		right, _ := json.Marshal(expected)
		t.Fatalf("native projection differs\nnative: %s\nlocal:  %s", right, left)
	}
}

// These are explicitly local consistency queries derived from retained input
// names. They compare selector membership with the validated returned paths,
// never with AWS's opaque equal-priority winner.
func xrayProjectionSelectors(t *testing.T, stream *xrayQueryStream, documents map[string]map[string]any) map[string]func(map[string]any) bool {
	t.Helper()
	names, exceptions := map[string]bool{}, map[string]bool{}
	var visit func(map[string]any)
	visit = func(document map[string]any) {
		names[document["name"].(string)] = true
		if cause, ok := document["cause"].(map[string]any); ok {
			if entries, ok := cause["exceptions"].([]any); ok {
				for _, raw := range entries {
					if exception, ok := raw.(map[string]any); ok {
						if name, ok := exception["type"].(string); ok {
							exceptions[name] = true
						}
					}
				}
			}
		}
		if children, ok := document["subsegments"].([]any); ok {
			for _, raw := range children {
				visit(raw.(map[string]any))
			}
		}
	}
	for _, document := range documents {
		visit(document)
	}
	baseline := stream.Observations[len(stream.Observations)-1]
	selectors := map[string]func(map[string]any) bool{}
	for _, category := range []string{"fault", "error"} {
		field := "FaultRootCauses"
		if category == "error" {
			field = "ErrorRootCauses"
		}
		for _, level := range []string{"entity", "service", "exception"} {
			candidates := names
			if level == "exception" {
				candidates = exceptions
			}
			ordered := make([]string, 0, len(candidates))
			for name := range candidates {
				ordered = append(ordered, name)
			}
			slices.Sort(ordered)
			for _, name := range ordered {
				flags := []string{""}
				if level == "entity" {
					flags = []string{"Remote"}
				}
				if level == "service" {
					flags = []string{"Inferred"}
				}
				for _, flag := range flags {
					for _, value := range []bool{false, true} {
						if flag == "" && value {
							continue
						}
						condition := fmt.Sprintf("name = %q", name)
						if flag != "" {
							condition += fmt.Sprintf(" AND %s = %t", strings.ToLower(flag), value)
						}
						var input map[string]any
						awsDecodeJSON(t, baseline.Input, &input)
						input["FilterExpression"] = fmt.Sprintf("(%s) AND rootcause.%s.%s { %s }", input["FilterExpression"], category, level, condition)
						row := baseline
						row.Label = fmt.Sprintf("local-selector-%d-%s-%s", len(selectors), category, level)
						var err error
						row.Input, err = json.Marshal(input)
						if err != nil {
							t.Fatal(err)
						}
						stream.Observations = append(stream.Observations, row)
						selectors[row.Label] = func(summary map[string]any) bool {
							for _, raw := range summary[field].([]any) {
								for _, rawService := range raw.(map[string]any)["Services"].([]any) {
									service := rawService.(map[string]any)
									items := []any{service}
									if level != "service" {
										items = service["EntityPath"].([]any)
									}
									for _, rawItem := range items {
										item := rawItem.(map[string]any)
										matches := []any{item}
										if level == "exception" {
											matches = item["Exceptions"].([]any)
										}
										for _, rawMatch := range matches {
											match := rawMatch.(map[string]any)
											if match["Name"] == name && (flag == "" || match[flag] == value) {
												return true
											}
										}
									}
								}
							}
							return false
						}
					}
				}
			}
		}
	}
	return selectors
}

func TestXRayNativeIdentityProjection(t *testing.T) {
	var capture xrayProjectionCapture
	awsReadFixture(t, "xray/trace_aggregate_edges.json", &capture)
	// Initial origin/generic AWS identity graphs and operation/resource-key
	// graphs are exact native oracles, independent of histogram approximation
	// and branch ties. Clock/group supplemental captures belong to query replay.
	for i, captured := range []xrayProjectionCapture{capture, capture.Supplemental[2]} {
		stream := captured.stream(t, fmt.Sprintf("native-identities-%d", i), func(row xrayProjectionObservation) bool {
			return row.Path == "TraceSegments" || row.Path == "TraceGraph"
		})
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(backend+"/"+stream.Name, func(t *testing.T) {
				replayXRayQueries(t, backend, stream, xrayQueryPlan{})
			})
		}
	}
}
