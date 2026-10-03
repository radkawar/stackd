package evaluator

import (
	"errors"
	"reflect"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
	"github.com/tiaanduplessis/jsonata-go/jtypes"
)

func normalizeInputValue(runtime *evalRuntime, input any) (any, error) {
	return normalizeEvaluatorValue(runtime, input, nil)
}

func normalizeExtensionValue(runtime *evalRuntime, input any) (any, error) {
	return normalizeEvaluatorValue(runtime, input, mapExtensionValue)
}

func normalizeEvaluatorValue(runtime *evalRuntime, input any, mapper value.NormalizeMapper) (any, error) {
	maxDepth := defaultMaxCallDepth
	var check func() error
	if runtime != nil {
		maxDepth = runtime.maxDepth
		check = runtime.check
	}
	normalized, err := value.FromJSONSafeWithMapper(input, maxDepth, check, mapper)
	if err != nil {
		return nil, normalizationRuntimeError(err)
	}
	return normalized, nil
}

func mapExtensionValue(input any) (any, bool, error) {
	for {
		reflected, ok := input.(reflect.Value)
		if !ok {
			break
		}
		if !reflected.IsValid() {
			return value.Undefined, true, nil
		}
		if !reflected.CanInterface() {
			return nil, false, value.ErrUnsupportedValue
		}
		input = reflected.Interface()
	}
	if _, ok := callable(input); ok {
		return input, true, nil
	}
	if callable, ok := input.(jtypes.Callable); ok {
		return &legacyCallable{callable: callable}, true, nil
	}
	return input, false, nil
}

func normalizationRuntimeError(err error) error {
	switch {
	case errors.Is(err, value.ErrCyclicValue):
		return runtimeError{code: "T0412", msg: "input value is cyclic and not JSON-compatible", cause: err}
	case errors.Is(err, value.ErrNormalizationDepth):
		return runtimeError{code: "U1001", msg: "input value exceeds the maximum nesting depth", cause: err}
	case errors.Is(err, value.ErrUnsupportedValue):
		return runtimeError{code: "T0412", msg: "input value is not JSON-compatible", cause: err}
	case errors.Is(err, value.ErrNonFiniteValue):
		return runtimeError{code: "D1001", msg: "numeric value is not finite", cause: err}
	default:
		return err
	}
}

// NormalizeExtensionBindingSafe converts a public extension value while
// bounding cycles and nesting. Registrations supply a finite check callback;
// evaluations use the active runtime through normalizeExtensionValue.
func NormalizeExtensionBindingSafe(input any, maxDepth int, check func() error) (any, error) {
	if maxDepth <= 0 {
		maxDepth = defaultMaxCallDepth
	}
	normalized, err := value.FromJSONSafeWithMapper(input, maxDepth, check, mapExtensionValue)
	if err != nil {
		return nil, normalizationRuntimeError(err)
	}
	return normalized, nil
}
