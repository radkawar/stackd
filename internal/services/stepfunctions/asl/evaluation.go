// Package asl compiles and evaluates Amazon States Language definitions.
// Resource execution, retained state and scheduling belong to Step Functions.
package asl

import (
	"io"
	"time"
)

// Language selects the expression rules of an ASL state.
type Language string

const (
	JSONPath Language = "JSONPath"
	JSONata  Language = "JSONata"
)

// Environment contains the immutable values visible at state entry. Assignments
// become visible only in the next state, never to another field in this one.
// Random belongs to this evaluation; callers provide a reproducible stream.
type Environment struct {
	Input         any
	ContextObject map[string]any
	Variables     map[string]any
	Result        any
	HasResult     bool
	ErrorOutput   any
	Now           time.Time
	Random        io.Reader
}

// EvaluationError is an ASL execution failure, not an API protocol error.
type EvaluationError struct {
	Name     string
	Cause    string
	Location string
}

func (e *EvaluationError) Error() string { return e.Name + ": " + e.Cause }
