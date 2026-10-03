package xray

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/xray"
)

// These are local work bounds, not replicas of AWS's unpublished index pages.
// PartialScan visits at most ten pages; small collections are scanned in full.
const traceQueryPageSize = 1000
const tracePartialScanLimit = 10 * traceQueryPageSize

type traceQueryCursor struct {
	Query   string  `json:"q"`
	Time    float64 `json:"t"`
	ID      string  `json:"id"`
	Scanned int     `json:"n"`
}

func queryWindow(start, end *api.Timestamp) (traceWindow, error) {
	if start == nil || end == nil {
		return traceWindow{}, failure("ValidationException", "StartTime and EndTime are required")
	}
	if end.Before(*start) {
		return traceWindow{}, failure("InvalidRequestException", "End time cannot be earlier than start time")
	}
	return traceWindow{Start: start.UTC(), End: end.UTC()}, nil
}

// Native accepts but ignores SamplingStrategy unless Sampling is explicitly
// true. FixedRate is supported only for the Event clock. PartialScan's Value
// does not represent a probability (even values outside [0,1] are accepted).
func querySampling(in *api.GetTraceSummariesRequest, kind api.TimeRangeType) (partial bool, rate float64, err error) {
	if in.Sampling == nil || !bool(*in.Sampling) {
		return false, 1, nil
	}
	if in.SamplingStrategy == nil || in.SamplingStrategy.Name == nil || *in.SamplingStrategy.Name == api.SamplingStrategyNamePartialScan {
		return true, 1, nil
	}
	if *in.SamplingStrategy.Name != api.SamplingStrategyNameFixedRate {
		return false, 0, failure("ValidationException", "Invalid sampling strategy name")
	}
	v := in.SamplingStrategy.Value
	if v == nil || math.IsNaN(float64(*v)) || *v < 0 || *v > 1 {
		return false, 0, failure("InvalidRequestException", "sampling rate must be specified and its value must be between [0, 1]")
	}
	if kind != api.TimeRangeTypeEvent {
		return false, 0, failure("InvalidRequestException", "Cannot use FixedRate with input time range type: "+string(kind)+". Please try using time range type: Event")
	}
	return false, float64(*v), nil
}

func queryTraceTime(record TraceRecord, kind api.TimeRangeType) float64 {
	switch kind {
	case api.TimeRangeTypeEvent:
		return float64(record.Updated.Unix())
	case api.TimeRangeTypeService:
		return record.End
	default:
		return record.Start
	}
}

func querySampled(id string, rate float64) bool {
	if rate == 1 {
		return true
	}
	if rate == 0 {
		return false
	}
	// Stable uniform sampling makes continuation/retries deterministic without
	// storing a second query result collection or consuming shared random state.
	hash := sha256.Sum256([]byte(id))
	return float64(binary.BigEndian.Uint64(hash[:8])>>11)/float64(uint64(1)<<53) < rate
}

func (s *Service) getTraceSummaries(tx Transaction, in *api.GetTraceSummariesRequest) (*api.GetTraceSummariesResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetTraceSummaries", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	window, err := queryWindow(in.StartTime, in.EndTime)
	if err != nil {
		return nil, err
	}
	kind := api.TimeRangeTypeTraceId
	if in.TimeRangeType != nil {
		kind = *in.TimeRangeType
	}
	if kind != api.TimeRangeTypeTraceId && kind != api.TimeRangeTypeEvent && kind != api.TimeRangeTypeService {
		return nil, failure("ValidationException", "Invalid time range type")
	}
	partial, rate, err := querySampling(in, kind)
	if err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	request := *in
	request.NextToken = nil
	identity, err := json.Marshal(struct {
		Scope   Scope
		Request api.GetTraceSummariesRequest
	}{scope, request})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(identity)
	query := base64.RawURLEncoding.EncodeToString(digest[:])
	cursor := traceQueryCursor{Query: query}
	if in.NextToken != nil {
		data, decodeErr := base64.RawURLEncoding.DecodeString(string(*in.NextToken))
		if decodeErr != nil || json.Unmarshal(data, &cursor) != nil || cursor.Query != query || cursor.ID == "" || cursor.Scanned < 1 || (partial && cursor.Scanned >= tracePartialScanLimit) {
			return nil, failure("InvalidRequestException", "Invalid token "+string(*in.NextToken))
		}
	}
	groups, err := tx.Groups(scope)
	if err != nil {
		return nil, err
	}
	filter, err := compileTraceFilter(value(in.FilterExpression), groupExpressions(append(groups, defaultGroup(scope))))
	if err != nil {
		return nil, err
	}
	selectionKind := TraceStartTime
	switch kind {
	case api.TimeRangeTypeEvent:
		selectionKind = TraceEventTime
	case api.TimeRangeTypeService:
		selectionKind = TraceServiceTime
	}
	rows, err := tx.Traces(TraceSelection{Scope: scope, Start: window.Start, End: window.End, Kind: selectionKind})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b TraceData) int {
		if order := cmp.Compare(queryTraceTime(b.Record, kind), queryTraceTime(a.Record, kind)); order != 0 {
			return order
		}
		return cmp.Compare(a.Record.Key.ID, b.Record.Key.ID)
	})
	approximate := window.Start.Truncate(time.Second)
	var serviceWindow *traceWindow
	if kind == api.TimeRangeTypeService {
		serviceWindow = &window
		approximate = approximate.Add(-time.Minute)
	}
	out := &api.GetTraceSummariesResult{TraceSummaries: api.TraceSummaryList{}}
	now := s.clock.Now()
	processed := 0
	limit := traceQueryPageSize
	if partial {
		limit = min(limit, tracePartialScanLimit-cursor.Scanned)
	}
	last := cursor
	for _, row := range rows {
		stamp := queryTraceTime(row.Record, kind)
		if cursor.ID != "" && (stamp > cursor.Time || stamp == cursor.Time && row.Record.Key.ID <= cursor.ID) {
			continue
		}
		segments := liveTraceSegments(row.Segments, now)
		if len(segments) == 0 {
			continue
		}
		if processed == limit {
			if !partial || last.Scanned < tracePartialScanLimit {
				data, err := json.Marshal(last)
				if err != nil {
					return nil, err
				}
				out.NextToken = new(api.String(base64.RawURLEncoding.EncodeToString(data)))
			}
			approximate = time.Time(*traceTimestamp(last.Time)).Truncate(time.Second)
			break
		}
		processed++
		last = traceQueryCursor{Query: query, Time: stamp, ID: row.Record.Key.ID, Scanned: cursor.Scanned + processed}
		if !querySampled(row.Record.Key.ID, rate) {
			continue
		}
		view, err := projectTrace(row.Record.Key, segments)
		if err != nil {
			return nil, err
		}
		summary := view.Summary
		summary.Revision = new(api.Integer(row.Record.Revision))
		if kind != api.TimeRangeTypeTraceId {
			summary.MatchedEventTime = new(api.Timestamp(row.Record.Updated))
		}
		if filter.match(view, serviceWindow, &summary) {
			out.TraceSummaries = append(out.TraceSummaries, summary)
		}
	}
	out.ApproximateTime = new(api.Timestamp(approximate))
	out.TracesProcessedCount = new(api.NullableLong(processed))
	return out, nil
}

func (s *Service) getTraceGraph(tx Transaction, in *api.GetTraceGraphRequest) (*api.GetTraceGraphResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetTraceGraph", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	if in.NextToken != nil {
		return nil, failure("InvalidRequestException", "NextToken is currently not supported")
	}
	if len(in.TraceIds) == 0 {
		return nil, failure("InvalidRequestException", "Zero trace ids provided")
	}
	if len(in.TraceIds) != 1 {
		return nil, failure("InvalidRequestException", "Currently only one trace Id is supported")
	}
	id := string(in.TraceIds[0])
	if !traceIDPattern.MatchString(id) {
		return nil, failure("InvalidRequestException", "Invalid traceId. ErrorCode: InvalidId")
	}
	key := TraceKey{Scope: scopeFor(tx.Context()), ID: id}
	rows, err := tx.TraceSegments(key)
	if err != nil {
		return nil, err
	}
	rows = liveTraceSegments(rows, s.clock.Now())
	if len(rows) == 0 {
		return nil, failure("InvalidRequestException", "Trace id not found")
	}
	view, err := projectTrace(key, rows)
	if err != nil {
		return nil, err
	}
	return &api.GetTraceGraphResult{Services: view.Services}, nil
}

func (s *Service) getServiceGraph(tx Transaction, in *api.GetServiceGraphRequest) (*api.GetServiceGraphResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetServiceGraph", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	if in.NextToken != nil {
		return nil, failure("InvalidRequestException", "NextToken is currently not supported")
	}
	window, err := queryWindow(in.StartTime, in.EndTime)
	if err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	group := defaultGroup(scope)
	if in.GroupName != nil || in.GroupARN != nil {
		group, err = resolveGroup(tx, value(in.GroupName), value(in.GroupARN))
		if errors.Is(err, ErrNotFound) {
			return nil, failure("InvalidRequestException", "Group not found.")
		}
		if err != nil {
			return nil, err
		}
	}
	views, oldVersions, err := s.serviceGraphViews(tx, group, window)
	if err != nil {
		return nil, err
	}
	out := &api.GetServiceGraphResult{Services: aggregateTraceGraphs(views), ContainsOldGroupVersions: new(api.Boolean(oldVersions))}
	// Report the observations actually aggregated, not request bounds or a
	// fabricated AWS index bucket. Empty graphs retain null temporal bounds.
	include := func(start, end *api.Timestamp) {
		if start != nil && (out.StartTime == nil || start.Before(*out.StartTime)) {
			out.StartTime = start
		}
		if end != nil {
			// Node bounds enclose the last one-second bucket; the graph envelope
			// reports the timestamp of that last observation instead.
			last := end.Add(-time.Second)
			if out.EndTime == nil || last.After(*out.EndTime) {
				out.EndTime = new(last)
			}
		}
	}
	for _, service := range out.Services {
		include(service.StartTime, service.EndTime)
		for _, edge := range service.Edges {
			include(edge.StartTime, edge.EndTime)
		}
	}
	return out, nil
}

// serviceGraphViews shares receipt selection, historical topology and retained
// group admission between graph and time-series consumers.
func (s *Service) serviceGraphViews(tx Transaction, group GroupRecord, window traceWindow) ([]*traceView, bool, error) {
	now := s.clock.Now()
	selection := TraceSelection{Scope: scopeFor(tx.Context()), Start: window.Start, End: window.End, Kind: TraceCompletionTime}
	if group.Key.Name != "Default" {
		selection.Group = &group.Key
	}
	rows, err := tx.Traces(selection)
	if err != nil {
		return nil, false, err
	}
	views := make([]*traceView, 0, len(rows))
	oldVersions := false
	for _, row := range rows {
		segments := liveTraceSegments(row.Segments, now)
		// Later receipts must not resolve an earlier inferred receiver into a
		// future reported service. Keep old parents, however: a newly received
		// child still needs its historical caller for edge topology.
		segments = slices.DeleteFunc(segments, func(segment SegmentRecord) bool {
			return segment.Received.After(window.End)
		})
		for i := range segments {
			if segments[i].Completed != nil && segments[i].Completed.After(window.End) {
				segments[i].End = nil
				segments[i].Completed = nil
				segments[i].Revision = segments[i].ReceivedRevision
			}
		}
		if len(segments) == 0 {
			continue
		}
		view, err := projectTrace(row.Record.Key, segments)
		if err != nil {
			return nil, false, err
		}
		view.graphWindow = &window
		view.graphMembership = row.Membership
		views = append(views, view)
		oldVersions = oldVersions || selection.Group != nil && row.Membership.Version < group.Version
	}
	return views, oldVersions, nil
}
