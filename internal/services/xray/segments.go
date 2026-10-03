package xray

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/xray"
)

var (
	traceIDPattern   = regexp.MustCompile(`^1-[0-9a-fA-F]{8}-[0-9a-fA-F]{24}$`)
	segmentIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)
)

// Trace IDs also carry W3C identifiers. Their middle component is not an
// authoritative timestamp; retention follows ingestion time, not that value.
const traceRetention = 30 * 24 * time.Hour

func (s *Service) putTraceSegments(tx Transaction, in *api.PutTraceSegmentsRequest) (*api.PutTraceSegmentsResult, error) {
	if _, err := s.authorizedPolicies(tx, "PutTraceSegments"); err != nil {
		return nil, err
	}
	if len(in.TraceSegmentDocuments) == 0 {
		return nil, failure("InvalidRequestException", "Segments can not be empty")
	}
	out := &api.PutTraceSegmentsResult{UnprocessedTraceSegments: api.UnprocessedTraceSegmentList{}}
	scope, now := scopeFor(tx.Context()), s.clock.Now()
	audit, _ := tx.Context().Value(traceAuditKey{}).(*traceAudit)
	var changed []traceUpdate
	revisions := make(map[TraceKey]int64)
	for _, document := range in.TraceSegmentDocuments {
		records, rejected := decodeSegments(string(document))
		if rejected != nil {
			out.UnprocessedTraceSegments = append(out.UnprocessedTraceSegments, *rejected)
			continue
		}
		if audit != nil {
			audit.TraceIDs = append(audit.TraceIDs, records[0].Key.TraceKey.ID)
		}
		for index, record := range records {
			record.Key.Scope = scope
			record.Received = now
			if !record.InProgress && record.End != nil {
				record.Completed = new(now)
			}
			old, err := tx.Segment(record.Key)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if err == nil && now.Before(old.Received.Add(traceRetention)) {
				// First completion wins regardless of inline or independent
				// submission. A completed parent also freezes its submitted tree.
				if !old.InProgress {
					if index == 0 {
						break
					}
					continue
				}
				record.Received = old.Received
				record.InlineOrder = old.InlineOrder
				record.ReceivedRevision = old.ReceivedRevision
			}
			revision, assigned := revisions[record.Key.TraceKey]
			if !assigned {
				trace, err := tx.Trace(record.Key.TraceKey)
				if err != nil && !errors.Is(err, ErrNotFound) {
					return nil, err
				}
				revision = trace.Revision + 1
				revisions[record.Key.TraceKey] = revision
				changed = append(changed, traceUpdate{Key: record.Key.TraceKey, Revision: revision})
			}
			record.Revision = revision
			if record.ReceivedRevision == 0 {
				record.ReceivedRevision = revision
			}
			if err := tx.PutSegment(record); err != nil {
				return nil, err
			}
		}
	}
	if err := s.indexTraces(tx, changed); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) batchGetTraces(tx Transaction, in *api.BatchGetTracesRequest) (*api.BatchGetTracesResult, error) {
	if _, err := s.authorizedPolicies(tx, "BatchGetTraces"); err != nil {
		return nil, err
	}
	if in.NextToken != nil {
		return nil, failure("InvalidRequestException", "NextToken is currently not supported")
	}
	if len(in.TraceIds) > 5 {
		return nil, failure("InvalidRequestException", "Exceeding maximum query size: 5")
	}
	seen := make(map[api.TraceId]bool, len(in.TraceIds))
	for _, id := range in.TraceIds {
		if !traceIDPattern.MatchString(string(id)) {
			return nil, failure("InvalidRequestException", "Invalid trace id "+string(id)+": incorrect id format")
		}
		if seen[id] {
			return nil, failure("InvalidRequestException", "Containing duplicate trace ids")
		}
		seen[id] = true
	}
	out := &api.BatchGetTracesResult{Traces: api.TraceList{}, UnprocessedTraceIds: api.UnprocessedTraceIdList{}}
	scope, now := scopeFor(tx.Context()), s.clock.Now()
	for _, id := range in.TraceIds {
		rows, err := tx.TraceSegments(TraceKey{Scope: scope, ID: string(id)})
		if err != nil {
			return nil, err
		}
		rows = liveTraceSegments(rows, now)
		if len(rows) == 0 {
			continue
		}
		trace, err := assembleTrace(id, rows)
		if err != nil {
			return nil, err
		}
		out.Traces = append(out.Traces, trace)
	}
	return out, nil
}

// External subsegments join their parent, including inline parents. Ordinary
// segments with parent_id remain separate entries in the retrieved trace.
func assembleTrace(id api.TraceId, rows []SegmentRecord) (api.Trace, error) {
	out := api.Trace{Id: new(id), LimitExceeded: new(api.NullableBoolean(false)), Segments: api.SegmentList{}}
	documents := make(map[string]map[string]any, len(rows))
	reported := make(map[string]bool)
	var inferred []map[string]any
	for _, row := range rows {
		var document map[string]any
		decoder := json.NewDecoder(strings.NewReader(row.Document))
		decoder.UseNumber()
		if err := decoder.Decode(&document); err != nil {
			return out, err
		}
		documents[row.Key.ID] = document
		if request, ok := tracePath(document, "http", "request").(map[string]any); ok {
			delete(request, "traced")
		}
		if row.Subsegment && traceText(document, "namespace") == "aws" {
			if attributes, ok := document["aws"].(map[string]any); ok {
				delete(attributes, "resource_names")
				identity := traceEntityIdentity(&traceEntity{row: row, doc: document})
				if identity.name != traceText(document, "name") {
					attributes["resource_names"] = []string{identity.name}
				}
			}
		}
		if exceptions, ok := tracePath(document, "cause", "exceptions").([]any); ok {
			for _, exception := range exceptions {
				fields, ok := exception.(map[string]any)
				if !ok {
					continue
				}
				if stack, ok := fields["stack"].([]any); ok && len(stack) == 0 {
					delete(fields, "stack")
				}
			}
		}
		if !row.Subsegment && row.ParentID != "" {
			reported[row.ParentID] = true
		}
	}
	children := make(map[string][]*SegmentRecord)
	for index := range rows {
		row := &rows[index]
		if row.Subsegment {
			children[row.ParentID] = append(children[row.ParentID], row)
		}
	}
	for _, siblings := range children {
		slices.SortStableFunc(siblings, func(a, b *SegmentRecord) int {
			return cmp.Compare(a.InlineOrder, b.InlineOrder)
		})
	}
	var first, last float64
	include := func(row *SegmentRecord) {
		if row.Start <= 0 {
			return
		}
		if first == 0 || row.Start < first {
			first = row.Start
		}
		if row.End != nil && *row.End >= row.Start && *row.End > last {
			last = *row.End
		}
		if row.Subsegment && row.End != nil && !reported[row.Key.ID] {
			document := documents[row.Key.ID]
			namespace := traceText(document, "namespace")
			if namespace == "remote" || namespace == "aws" {
				inferred = append(inferred, inferredSegmentDocument(id, row, document))
			}
		}
	}
	for index := range rows {
		row := &rows[index]
		if row.Subsegment {
			continue
		}
		document := documents[row.Key.ID]
		include(row)
		attachSubsegments(document, documents, children, include)
		encoded, err := json.Marshal(document)
		if err != nil {
			return out, err
		}
		out.Segments = append(out.Segments, api.Segment{Id: new(api.SegmentId(row.Key.ID)), Document: new(api.SegmentDocument(encoded))})
	}
	for _, document := range inferred {
		encoded, err := json.Marshal(document)
		if err != nil {
			return out, err
		}
		out.Segments = append(out.Segments, api.Segment{Id: new(api.SegmentId(document["id"].(string))), Document: new(api.SegmentDocument(encoded))})
	}
	if last > 0 {
		out.Duration = new(api.NullableDouble(last - first))
	}
	return out, nil
}

// Each stored subsegment has one parent and one identity. Cycles cannot be
// reachable from an ordinary segment; orphan-only components stay unattached.
func attachSubsegments(document map[string]any, documents map[string]map[string]any, children map[string][]*SegmentRecord, include func(*SegmentRecord)) {
	id, _ := document["id"].(string)
	combined := make([]any, 0, len(children[id]))
	for _, row := range children[id] {
		childID := row.Key.ID
		child := documents[childID]
		delete(child, "type")
		delete(child, "parent_id")
		delete(child, "trace_id")
		include(row)
		attachSubsegments(child, documents, children, include)
		combined = append(combined, child)
	}
	if len(combined) != 0 {
		document["subsegments"] = combined
	}
}

func inferredSegmentID(traceID api.TraceId, parent, kind string) string {
	// Inferred identities are opaque in AWS. Derivation keeps repeated local
	// reads and restored traces stable without another resource lifecycle.
	digest := sha256.Sum256([]byte(string(traceID) + ":" + parent + ":" + kind))
	return hex.EncodeToString(digest[:8])
}

func inferredSegmentDocument(traceID api.TraceId, row *SegmentRecord, source map[string]any) map[string]any {
	id := inferredSegmentID(traceID, row.Key.ID, "service")
	document := map[string]any{"id": id, "trace_id": string(traceID), "parent_id": row.Key.ID, "inferred": true}
	for _, field := range []string{"name", "start_time", "end_time", "error", "fault", "throttle", "http", "aws"} {
		if value, present := source[field]; present {
			document[field] = value
		}
	}
	if traceText(source, "namespace") == "aws" {
		identity := traceEntityIdentity(&traceEntity{row: *row, doc: source})
		document["origin"] = identity.kind
		operation := traceText(source, "aws", "operation")
		if identity.kind == "AWS::SQS::Queue" || identity.kind == "AWS::SQS" && (operation == "SendMessage" || operation == "SendMessageBatch") {
			document["subsegments"] = []any{map[string]any{
				"id":   inferredSegmentID(traceID, row.Key.ID, "queue"),
				"name": "QueueTime", "start_time": source["start_time"], "end_time": source["end_time"],
			}}
		}
	}
	return document
}

func segmentName(name string) string {
	if len(name) <= 200 {
		return name
	}
	count := 0
	for offset := range name {
		if count == 200 {
			return name[:offset]
		}
		count++
	}
	return name
}
