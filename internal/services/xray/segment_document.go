package xray

import (
	"encoding/json"
	"io"
	"strings"

	api "stackd/internal/awsapi/xray"
)

func segmentFailure(id *string, code, kind string) *api.UnprocessedTraceSegment {
	message := "Invalid " + kind + ". ErrorCode: " + code
	if kind == "subsegment" {
		message += ", Cause: null"
	}
	return &api.UnprocessedTraceSegment{Id: (*api.String)(id), ErrorCode: new(api.String(code)), Message: new(api.String(message))}
}

// Decode the whole document before admitting any of its segments. Inline and
// independent submissions then use the same completion transition in the store.
func decodeSegments(document string) ([]SegmentRecord, *api.UnprocessedTraceSegment) {
	var value any
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		kind := "entity"
		if strings.HasPrefix(strings.TrimSpace(document), "{") {
			kind = "segment"
		}
		return nil, segmentFailure(nil, "ParseError", kind)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, segmentFailure(nil, "ParseError", "segment")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, segmentFailure(nil, "ParseError", "entity")
	}
	var records []SegmentRecord
	if rejected := collectSegments(root, "", "", 0, &records); rejected != nil {
		if id, present := root["id"].(string); present {
			rejected.Id = new(api.String(id))
		}
		return nil, rejected
	}
	return records, nil
}

func segmentTime(value any) *float64 {
	number, ok := value.(json.Number)
	if !ok {
		return nil
	}
	value64, err := number.Float64()
	if err != nil {
		return nil
	}
	return &value64
}

func collectSegments(document map[string]any, traceID, parentID string, order int64, records *[]SegmentRecord) *api.UnprocessedTraceSegment {
	id, present := document["id"].(string)
	var failureID *string
	if present {
		failureID = &id
	}
	name, _ := document["name"].(string)
	inline := parentID != ""
	kind := "segment"
	if inline {
		kind = "subsegment"
	} else {
		traceID, _ = document["trace_id"].(string)
		parentID, _ = document["parent_id"].(string)
		typeName, _ := document["type"].(string)
		if typeName == "subsegment" {
			kind = "subsegment"
		} else if typeName != "" && typeName != "segment" {
			return segmentFailure(failureID, "UnknownType", "entity")
		}
	}
	start, end := segmentTime(document["start_time"]), segmentTime(document["end_time"])
	inProgress, _ := document["in_progress"].(bool)
	var code string
	switch {
	case id == "":
		code = "MissingId"
	case !segmentIDPattern.MatchString(id):
		code = "InvalidId"
	case name == "":
		code = "MissingName"
	case traceID == "":
		code = "MissingTraceId"
	case !traceIDPattern.MatchString(traceID):
		code = "InvalidTraceId"
	case start == nil:
		code = "MissingStartTime"
	case inProgress && end != nil:
		code = "InProgressSegmentHasEndTime"
		if kind == "subsegment" {
			code = "InProgressSubsegmentHasEndTime"
		}
	case !inProgress && end == nil:
		code = "MissingEndTime"
	case kind == "subsegment" && parentID == "":
		code = "MissingParentId"
	case parentID != "" && !segmentIDPattern.MatchString(parentID):
		code = "InvalidParentId"
	}
	if code != "" {
		return segmentFailure(failureID, code, kind)
	}
	children, _ := document["subsegments"].([]any)
	delete(document, "subsegments")
	name = segmentName(name)
	document["name"] = name
	// The tree contains only decoded JSON values and the normalized name.
	encoded, _ := json.Marshal(document)
	*records = append(*records, SegmentRecord{Key: SegmentKey{TraceKey: TraceKey{ID: traceID}, ID: id}, ParentID: parentID, Subsegment: kind == "subsegment", InlineOrder: order, Start: *start, End: end, InProgress: inProgress, Document: string(encoded)})
	for index, value := range children {
		child, ok := value.(map[string]any)
		if !ok {
			return segmentFailure(failureID, "ParseError", "entity")
		}
		if rejected := collectSegments(child, traceID, id, int64(index+1), records); rejected != nil {
			return rejected
		}
	}
	return nil
}
