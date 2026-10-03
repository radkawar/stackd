package stepfunctions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// TraceContext keeps the public admitted header separate from this execution's
// private X-Ray segment identity. An empty SegmentID means no sampled publisher.
type TraceContext struct {
	Header    string
	SegmentID string
}

// TracePublisher samples at admission and publishes committed workflow state.
// Publication is best effort: tracing failures never change execution outcomes.
type TracePublisher interface {
	BeginTracing(context.Context, ExecutionRecord, RevisionRecord, bool) (TraceContext, error)
	PublishTrace(context.Context, RevisionRecord, []TraceDocument) error
}

// TraceDocument is the X-Ray segment protocol emitted by actual workflow and
// command transitions. AWS is an open service-specific metadata document.
type TraceDocument struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	StartTime   float64        `json:"start_time"`
	EndTime     *float64       `json:"end_time,omitempty"`
	TraceID     string         `json:"trace_id,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	Type        string         `json:"type,omitempty"`
	Origin      string         `json:"origin,omitempty"`
	ResourceARN string         `json:"resource_arn,omitempty"`
	Namespace   string         `json:"namespace,omitempty"`
	InProgress  bool           `json:"in_progress,omitempty"`
	Fault       bool           `json:"fault,omitempty"`
	Error       bool           `json:"error,omitempty"`
	Throttle    bool           `json:"throttle,omitempty"`
	Cause       TraceCause     `json:"cause"`
	AWS         map[string]any `json:"aws,omitempty"`
	HTTP        *TraceHTTP     `json:"http,omitempty"`
}

type TraceCause struct {
	Message    string           `json:"message,omitempty"`
	Exceptions []TraceException `json:"exceptions,omitempty"`
}

type TraceException struct {
	Message   string `json:"message"`
	Type      string `json:"type"`
	Remote    bool   `json:"remote"`
	Truncated int    `json:"truncated"`
	Skipped   int    `json:"skipped"`
}

type TraceHTTP struct {
	Response TraceHTTPResponse `json:"response"`
}

type TraceHTTPResponse struct {
	Status        int   `json:"status"`
	ContentLength int64 `json:"content_length"`
}

// TraceSpanID derives stable opaque identities from the execution's random
// segment ID and existing state/task identities, without another span registry.
func TraceSpanID(segment, kind, identity string) string {
	digest := sha256.Sum256([]byte(segment + ":" + kind + ":" + identity))
	return hex.EncodeToString(digest[:8])
}

// TraceTimestamp gives workflow and command spans the same seconds conversion,
// avoiding independent rounding that can place a child outside its parent.
func TraceTimestamp(at time.Time) float64 {
	return float64(at.Unix()) + float64(at.Nanosecond())/float64(time.Second)
}

// TaskTrace provides the command edge with its owning workflow state and the
// first actual invocation identity. It does not carry caller credentials.
type TaskTrace struct {
	Header       string
	RedriveCount int64
	StateSpanID  string
	CallSpanID   string
}

type taskTraceKey struct{}

func taskTracingContext(ctx context.Context, execution ExecutionRecord, revision RevisionRecord, task TaskRecord, stateID int64) context.Context {
	if execution.TraceHeader == "" && !revision.TracingEnabled {
		return ctx
	}
	trace := TaskTrace{Header: execution.TraceHeader, RedriveCount: execution.RedriveCount}
	segment := execution.TraceSegmentID
	if segment == "" {
		segment = execution.Key.ARN
	}
	trace.StateSpanID = TraceSpanID(segment, "state", strconv.FormatInt(stateID, 10))
	trace.CallSpanID = TraceSpanID(segment, "task", task.Key.ID)
	return context.WithValue(ctx, taskTraceKey{}, trace)
}

// TracingTask returns source-owned workflow correlation for real command calls.
func TracingTask(ctx context.Context) (TaskTrace, bool) {
	trace, ok := ctx.Value(taskTraceKey{}).(TaskTrace)
	return trace, ok
}
