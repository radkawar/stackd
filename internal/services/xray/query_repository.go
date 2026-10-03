package xray

import "time"

// TraceRecord indexes the current assembled trace. Updated advances once per
// changed trace in an ingestion command, not once per individual segment.
type TraceRecord struct {
	Key      TraceKey
	Start    float64
	End      float64
	Updated  time.Time
	Revision int64
}

type GroupKey struct {
	Scope
	Name string
	ID   string
}

func (k GroupKey) ARN() string {
	result := "arn:" + k.Partition + ":xray:" + k.Region + ":" + k.AccountID + ":group/" + k.Name
	if k.ID != "" {
		result += "/" + k.ID
	}
	return result
}

// GroupRecord retains the current regional group configuration.
type GroupRecord struct {
	Key              GroupKey
	FilterExpression string
	Version          int64
	Tags             map[string]string
}

// GroupMembership retains the configuration and time at first match. Completed
// children predating that match contribute when the trace joins the group.
type GroupMembership struct {
	Version          int64
	Admitted         time.Time
	AdmittedRevision int64
}

func (m GroupMembership) IncludesCompletion(segment SegmentRecord, start, end time.Time) bool {
	if segment.Completed == nil {
		return false
	}
	at := *segment.Completed
	if m.Admitted.After(at) {
		at = m.Admitted
	}
	return !at.Before(start) && !at.After(end)
}

// TraceSelectionKind separates document, latest-receipt, service and immutable
// completion clocks. Graph aggregation uses completion, not the latest revision.
type TraceSelectionKind uint8

const (
	TraceStartTime TraceSelectionKind = iota
	TraceEventTime
	TraceServiceTime
	TraceCompletionTime
)

// TraceSelection applies the API's distinct trace, receipt and service clocks.
// Group selects retained ingestion membership, not the group's current filter.
type TraceSelection struct {
	Scope
	Start time.Time
	End   time.Time
	Kind  TraceSelectionKind
	Group *GroupKey
}

// TraceData contains index metadata and segment documents from one repository
// snapshot. Membership is populated only for a selected non-default group.
type TraceData struct {
	Record     TraceRecord
	Segments   []SegmentRecord
	Membership GroupMembership
}

// TimeBounds gives both repositories the same coarse service-index window.
// Positive service/edge predicates still use the original API window.
func (q TraceSelection) TimeBounds() (time.Time, time.Time) {
	if q.Kind == TraceServiceTime {
		return q.Start.Add(-time.Minute), q.End.Add(time.Minute)
	}
	return q.Start, q.End
}

// GroupMetricKey owns one pending, closed-minute match count.
type GroupMetricKey struct {
	Group  GroupKey
	Minute time.Time
}

type GroupMetricRecord struct {
	Key   GroupMetricKey
	Count int64
}
