package evaluator

import (
	"math"
	"time"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// dateBuiltinSpecs remains family-local until the central registry integrates
// all Phase 5 builtin families together.
var dateBuiltinSpecs = []builtinSpec{
	{name: "fromMillis", signature: "<n-s?s?:s>", implementation: builtinFromMillis},
	{name: "toMillis", signature: "<s-s?:n>", implementation: builtinToMillis},
	{name: "now", signature: "<s?s?:s>", implementation: builtinNow},
	{name: "millis", signature: "<:n>", implementation: builtinMillis},
}

func builtinFromMillis(st state, args []any) (any, error) {
	if len(args) == 0 || value.IsUndefined(collapse(args[0])) {
		return value.Undefined, nil
	}
	millis, ok := strictNumeric(collapse(args[0]))
	if !ok || math.IsNaN(millis) || math.IsInf(millis, 0) || millis > math.MaxInt64 || millis < math.MinInt64 {
		return nil, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	picture, timezone, err := dateOptionalStrings(args[1:])
	if err != nil {
		return nil, err
	}
	return formatDateTime(st, int64(millis), picture, timezone)
}

func builtinToMillis(st state, args []any) (any, error) {
	if len(args) == 0 || value.IsUndefined(collapse(args[0])) {
		return value.Undefined, nil
	}
	timestamp, ok := collapse(args[0]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "timestamp must be a string"}
	}
	if len(args) < 2 || value.IsUndefined(collapse(args[1])) {
		millis, ok, err := parseISODateTime(st, timestamp)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, runtimeError{code: "D3110", msg: "timestamp must use ISO 8601 format"}
		}
		return float64(millis), nil
	}
	picture, ok := collapse(args[1]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "date/time picture must be a string"}
	}
	millis, matched, err := parseDateTime(st, timestamp, picture)
	if err != nil {
		return nil, err
	}
	if !matched {
		return value.Undefined, nil
	}
	return float64(millis), nil
}

func builtinNow(st state, args []any) (any, error) {
	picture, timezone, err := dateOptionalStrings(args)
	if err != nil {
		return nil, err
	}
	return formatDateTime(st, dateEvaluationTime(st).UnixMilli(), picture, timezone)
}

func builtinMillis(st state, _ []any) (any, error) {
	if err := dateCheck(st); err != nil {
		return nil, err
	}
	return float64(dateEvaluationTime(st).UnixMilli()), nil
}

func dateOptionalStrings(args []any) (*string, *string, error) {
	var result [2]*string
	for index := 0; index < len(args) && index < len(result); index++ {
		if value.IsUndefined(collapse(args[index])) {
			continue
		}
		text, ok := collapse(args[index]).(string)
		if !ok {
			return nil, nil, runtimeError{code: "T0410", msg: "date/time option must be a string"}
		}
		result[index] = &text
	}
	return result[0], result[1], nil
}

func dateEvaluationTime(st state) time.Time {
	if st.runtime != nil && !st.runtime.timestamp.IsZero() {
		return st.runtime.timestamp.UTC()
	}
	return time.Now().UTC()
}

func dateCheck(st state) error {
	if st.runtime == nil {
		return nil
	}
	return st.runtime.check()
}

func dateError(code, message string) error {
	return runtimeError{code: code, msg: message}
}
