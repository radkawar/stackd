package evaluator

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"
)

const (
	defaultMaxCallDepth  = 100
	defaultMaxOperations = 100000
)

// Options controls one evaluation without changing the compatibility wrappers.
// Bindings are copied into the evaluation root and are never retained by the
// compiled expression. A zero or negative MaxCallDepth or MaxOperations uses
// the safe runtime default; a positive value sets an explicit limit. A positive
// MaxSequenceLength enables the JSONata v2.2 sequence guardrail; zero or
// negative disables it. Timeout values at or below zero are ignored, while a
// non-zero Deadline is enforced.
type Options struct {
	Context           context.Context
	Bindings          map[string]any
	Timeout           time.Duration
	Deadline          time.Time
	MaxCallDepth      int
	MaxOperations     int64
	MaxSequenceLength int
	Timestamp         time.Time
}

type evalRuntime struct {
	ctx             context.Context
	deadline        time.Time
	startedAt       time.Time
	timeout         time.Duration
	timeoutValue    any
	timeoutDeadline bool
	maxDepth        int
	stackGuard      bool
	depth           int
	evalDepth       int
	budget          int64
	maxSequence     int
	timestamp       time.Time
}

func newEvalRuntime(options Options) *evalRuntime {
	startedAt := time.Now()
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := options.Deadline
	deadlineIsTimeout := false
	if options.Timeout > 0 {
		timeoutAt := startedAt.Add(options.Timeout)
		if deadline.IsZero() || timeoutAt.Before(deadline) {
			deadline = timeoutAt
			deadlineIsTimeout = true
		}
	}
	maxDepth := options.MaxCallDepth
	stackGuard := maxDepth > 0
	if maxDepth <= 0 {
		maxDepth = defaultMaxCallDepth
	}
	operations := options.MaxOperations
	if operations <= 0 {
		operations = defaultMaxOperations
	}
	timestamp := options.Timestamp
	if timestamp.IsZero() {
		timestamp = startedAt
	}
	timeoutValue := any(nil)
	if options.Timeout > 0 {
		milliseconds := float64(options.Timeout) / float64(time.Millisecond)
		if math.Trunc(milliseconds) == milliseconds {
			timeoutValue = int64(milliseconds)
		} else {
			timeoutValue = milliseconds
		}
	}
	return &evalRuntime{
		ctx:             ctx,
		deadline:        deadline,
		startedAt:       startedAt,
		timeout:         options.Timeout,
		timeoutValue:    timeoutValue,
		timeoutDeadline: deadlineIsTimeout,
		maxDepth:        maxDepth,
		stackGuard:      stackGuard,
		budget:          operations,
		maxSequence:     max(0, options.MaxSequenceLength),
		timestamp:       timestamp,
	}
}

func (r *evalRuntime) checkSequenceLength(length int) error {
	if r == nil || r.maxSequence == 0 || length <= r.maxSequence {
		return nil
	}
	return sequenceLengthError(r.maxSequence)
}

func (r *evalRuntime) checkSequenceLengthAttempted(length int) error {
	if r == nil || r.maxSequence == 0 || length <= r.maxSequence {
		return nil
	}
	return sequenceLengthError(length)
}

func sequenceLengthError(errorValue int) error {
	formatted := strconv.Itoa(errorValue)
	return runtimeError{
		code:  "D2015",
		msg:   "The maximum sequence length of " + formatted + " was exceeded.",
		value: float64(errorValue),
	}
}

func sequenceAllocationCapacity(requested int, runtime *evalRuntime) int {
	if requested < 0 {
		return 0
	}
	if runtime != nil && runtime.maxSequence > 0 && requested > runtime.maxSequence {
		return runtime.maxSequence
	}
	return requested
}

func (r *evalRuntime) check() error {
	if r == nil {
		return nil
	}
	select {
	case <-r.ctx.Done():
		return runtimeError{code: "U1001", msg: r.ctx.Err().Error(), cause: r.ctx.Err()}
	default:
	}
	if r.timeout > 0 && time.Since(r.startedAt) >= r.timeout {
		milliseconds := r.timeoutValue
		if milliseconds == nil {
			milliseconds = int64(1)
		}
		formatted := fmt.Sprint(milliseconds)
		return runtimeError{
			code:  "D1012",
			msg:   "Evaluation timeout after " + formatted + " milliseconds. Check for infinite loop",
			value: float64Value(milliseconds),
			cause: context.DeadlineExceeded,
		}
	}
	if !r.timeoutDeadline && !r.deadline.IsZero() && !time.Now().Before(r.deadline) {
		return runtimeError{code: "U1001", msg: context.DeadlineExceeded.Error(), cause: context.DeadlineExceeded}
	}
	if r.budget <= 0 {
		return runtimeError{code: "U1001", msg: "evaluation operation budget exceeded"}
	}
	r.budget--
	return nil
}

func (r *evalRuntime) enterCall() error {
	return r.enterCallWithError("U1001", "maximum call depth exceeded")
}

func (r *evalRuntime) enterStackCall() error {
	if r == nil {
		return nil
	}
	if !r.stackGuard {
		return r.enterCall()
	}
	return r.enterCallWithError("D1011", "Stack overflow. Check for non-terminating recursive function.  Consider rewriting as tail-recursive")
}

func (r *evalRuntime) enterEval() error {
	if r == nil || !r.stackGuard {
		return nil
	}
	r.evalDepth++
	// jsonata-js applies the stack guard at every evaluate(expr, ...) entry.
	// Tail calls remain bounded because the evaluator trampoline returns from
	// one expression before invoking the next tail-call body.
	if r.evalDepth > r.maxDepth {
		r.evalDepth--
		return runtimeError{
			code:  "D1011",
			msg:   "Stack overflow. Check for non-terminating recursive function.  Consider rewriting as tail-recursive",
			value: float64(r.maxDepth),
		}
	}
	return nil
}

func float64Value(value any) any {
	switch typed := value.(type) {
	case int64:
		return float64(typed)
	default:
		return value
	}
}

func (r *evalRuntime) leaveEval() {
	if r != nil && r.evalDepth > 0 {
		r.evalDepth--
	}
}

func (r *evalRuntime) enterCallWithError(code, message string) error {
	if err := r.check(); err != nil {
		return err
	}
	r.depth++
	if r.depth > r.maxDepth {
		r.depth--
		value := any(r.maxDepth)
		if code == "D1011" {
			value = float64(r.maxDepth)
		}
		return runtimeError{code: code, msg: message, value: value}
	}
	return nil
}

func (r *evalRuntime) leaveCall() {
	if r != nil && r.depth > 0 {
		r.depth--
	}
}

type tailCall struct {
	fn   callableValue
	args []any
}
