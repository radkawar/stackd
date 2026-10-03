package logs

import (
	"math"
	"slices"
	"strings"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
	"stackd/internal/services/logs/filterpattern"
)

func timeBounds(start, end *api.Timestamp) (int64, int64, *awswire.Error) {
	a, b := int64(0), int64(math.MaxInt64)
	if start != nil {
		a = int64(*start)
	}
	if end != nil {
		b = int64(*end)
	}
	if a < 0 || b < 0 || a > b {
		return 0, 0, invalid("The time range is invalid.")
	}
	return a, b, nil
}
func (s *Service) getLogEvents(tx Transaction, in *api.GetLogEventsRequest) (*api.GetLogEventsResponse, *awswire.Error) {
	ref, w := reference(in.LogGroupName, in.LogGroupIdentifier)
	if w != nil {
		return nil, w
	}
	g, w := s.loadGroup(tx, ref, "GetLogEvents", value(in.LogStreamName))
	if w != nil {
		return nil, w
	}
	stream, err := tx.Stream(StreamKey{g.ID, value(in.LogStreamName)})
	if err != nil {
		return nil, wireError(err)
	}
	if enabled(in.Unmask) {
		return nil, unsupported("Unmask requires data-protection policy support, which is not implemented.")
	}
	n, w := pageLimit(in.Limit, MaxBatchEvents, MaxBatchEvents)
	if w != nil {
		return nil, w
	}
	start, end, w := timeBounds(in.StartTime, in.EndTime)
	if w != nil {
		return nil, w
	}
	query := queryIdentity("GetLogEvents", g.ID, stream.ID, start, end)
	token, w := s.decodeToken(value(in.NextToken), query)
	if w != nil {
		return nil, w
	}
	backward := !enabled(in.StartFromHead)
	if in.NextToken != nil {
		if token.Direction != "f" && token.Direction != "b" {
			return nil, invalid("Invalid pagination direction.")
		}
		backward = token.Direction == "b"
		if !backward && !enabled(in.StartFromHead) {
			return nil, invalid("startFromHead must be true when using a forward token.")
		}
	}
	q := EventQuery{GroupID: g.ID, StreamID: stream.ID, Start: max(start, s.retainedAfter(g)), End: end, Cursor: token.Cursor, HasCursor: token.HasCursor, Backward: backward, Limit: min(n, 128)}
	rows := make([]EventRecord, 0, min(n, 128))
	bytes := 0
	done := false
	for !done && len(rows) < n {
		q.Limit = min(128, n-len(rows))
		batch, err := tx.Events(q)
		if err != nil {
			return nil, wireError(err)
		}
		for _, e := range batch {
			size := len(e.Message) + EventOverheadBytes
			if bytes+size > MaxBatchBytes {
				done = true
				break
			}
			bytes += size
			rows = append(rows, e)
			q.Cursor = e.EventCursor
			q.HasCursor = true
		}
		if len(batch) < q.Limit {
			done = true
		}
	}
	if backward {
		slices.Reverse(rows)
	}
	out := &api.GetLogEventsResponse{Events: api.OutputLogEvents{}}
	f, b := token, token
	f.Direction = "f"
	b.Direction = "b"
	for _, e := range rows {
		out.Events = append(out.Events, api.OutputLogEvent{Timestamp: new(api.Timestamp(e.Timestamp)), IngestionTime: new(api.Timestamp(e.Ingestion)), Message: new(api.EventMessage(e.Message))})
	}
	if len(rows) > 0 {
		b.Cursor = rows[0].EventCursor
		b.HasCursor = true
		f.Cursor = rows[len(rows)-1].EventCursor
		f.HasCursor = true
	}
	out.NextBackwardToken = encodeToken(b)
	out.NextForwardToken = encodeToken(f)
	return out, nil
}
func (s *Service) filterLogEvents(tx Transaction, in *api.FilterLogEventsRequest) (*api.FilterLogEventsResponse, *awswire.Error) {
	ref, w := reference(in.LogGroupName, in.LogGroupIdentifier)
	if w != nil {
		return nil, w
	}
	g, w := s.loadGroup(tx, ref, "FilterLogEvents", "")
	if w != nil {
		return nil, w
	}
	if enabled(in.Unmask) {
		return nil, unsupported("Unmask requires data-protection policy support, which is not implemented.")
	}
	if len(in.LogStreamNames) > 0 && in.LogStreamNamePrefix != nil {
		return nil, invalid("logStreamNames and logStreamNamePrefix are mutually exclusive.")
	}
	pattern, err := filterpattern.Compile(value(in.FilterPattern))
	if err != nil {
		return nil, invalid(err.Error())
	}
	n, w := pageLimit(in.Limit, MaxBatchEvents, MaxBatchEvents)
	if w != nil {
		return nil, w
	}
	start, end, w := timeBounds(in.StartTime, in.EndTime)
	if w != nil {
		return nil, w
	}
	// FilterLogEvents includes the end timestamp, unlike GetLogEvents.
	if in.EndTime != nil && end < math.MaxInt64 {
		end++
	}
	names := make([]string, len(in.LogStreamNames))
	for i, name := range in.LogStreamNames {
		names[i] = string(name)
		if _, err := tx.Stream(StreamKey{g.ID, string(name)}); err != nil {
			return nil, wireError(err)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	query := queryIdentity("FilterLogEvents", g.ID, start, end, names, value(in.LogStreamNamePrefix), value(in.FilterPattern))
	token, w := s.decodeToken(value(in.NextToken), query)
	if w != nil {
		return nil, w
	}
	backward := in.StartFromHead != nil && !enabled(in.StartFromHead)
	if in.NextToken != nil {
		if token.Direction != "f" && token.Direction != "b" {
			return nil, invalid("Invalid pagination direction.")
		}
		backward = token.Direction == "b"
	}
	if backward && start < 1704067200000 {
		return nil, invalid("Descending FilterLogEvents requires startTime on or after January 1, 2024.")
	}
	token.Direction = "f"
	if backward {
		token.Direction = "b"
	}
	q := EventQuery{GroupID: g.ID, Start: max(start, s.retainedAfter(g)), End: end, Cursor: token.Cursor, HasCursor: token.HasCursor, Backward: backward, Limit: 128}
	out := &api.FilterLogEventsResponse{Events: api.FilteredLogEvents{}, SearchedLogStreams: api.SearchedLogStreams{}}
	bytes, scanned := 0, 0
	defer func() {
		if backward {
			slices.Reverse(out.Events)
		}
	}()
	for {
		batch, err := tx.Events(q)
		if err != nil {
			return nil, wireError(err)
		}
		for _, e := range batch {
			match := (len(names) == 0 || slices.Contains(names, e.StreamName)) && strings.HasPrefix(e.StreamName, value(in.LogStreamNamePrefix)) && pattern.Match(e.Message)
			if match && (len(out.Events) == n || bytes+len(e.Message)+EventOverheadBytes > MaxBatchBytes) {
				out.NextToken = encodeToken(token)
				return out, nil
			}
			q.Cursor = e.EventCursor
			q.HasCursor = true
			token.Cursor = e.EventCursor
			token.HasCursor = true
			scanned++
			if match {
				bytes += len(e.Message) + EventOverheadBytes
				out.Events = append(out.Events, api.FilteredLogEvent{EventId: new(api.EventId(e.ID)), LogStreamName: new(api.LogStreamName(e.StreamName)), Timestamp: new(api.Timestamp(e.Timestamp)), IngestionTime: new(api.Timestamp(e.Ingestion)), Message: new(api.EventMessage(e.Message))})
			}
		}
		if len(batch) < q.Limit {
			return out, nil
		}
		if scanned >= MaxBatchEvents {
			out.NextToken = encodeToken(token)
			return out, nil
		}
	}
}
