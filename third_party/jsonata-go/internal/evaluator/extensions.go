package evaluator

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
	"github.com/tiaanduplessis/jsonata-go/jtypes"
)

var (
	errorType   = reflect.TypeOf((*error)(nil)).Elem()
	contextType = reflect.TypeOf((*context.Context)(nil)).Elem()
	stringType  = reflect.TypeOf("")
	bytesType   = reflect.TypeOf([]byte(nil))
)

// ReflectedExtension is the evaluator-facing description of a Go extension.
// The public jsonata.Extension type is converted to this form at registration.
type ReflectedExtension struct {
	Func               any
	UndefinedHandler   jtypes.ArgHandler
	EvalContextHandler jtypes.ArgHandler
}

// ExtensionArgCountError describes a reflected extension arity mismatch.
type ExtensionArgCountError struct {
	Func     string
	Expected int
	Received int
}

func (e *ExtensionArgCountError) Error() string {
	return fmt.Sprintf("function %q takes %d argument(s), got %d", e.Func, e.Expected, e.Received)
}

// ExtensionArgTypeError describes a reflected extension argument mismatch.
type ExtensionArgTypeError struct {
	Func  string
	Which int
}

func (e *ExtensionArgTypeError) Error() string {
	return fmt.Sprintf("argument %d of function %q does not match function signature", e.Which, e.Func)
}

type extensionParam struct {
	typ          reflect.Type
	optional     bool
	optionalType *extensionParam
	variant      bool
	variantTypes []extensionParam
}

type reflectedExtension struct {
	name                  string
	fn                    reflect.Value
	fastFloat64           func(float64) float64
	params                []extensionParam
	variadic              bool
	acceptsContext        bool
	undefinedHandler      jtypes.ArgHandler
	evaluationContextFunc jtypes.ArgHandler
}

// NewReflectedExtension validates and constructs an evaluator binding.
func NewReflectedExtension(name string, spec ReflectedExtension) (binding any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			binding = nil
			err = fmt.Errorf("extension metadata panicked: %v", recovered)
		}
	}()
	fn := reflect.ValueOf(spec.Func)
	if !fn.IsValid() || fn.Kind() != reflect.Func {
		return nil, errors.New("func must be a Go function")
	}
	typ := fn.Type()
	switch typ.NumOut() {
	case 1:
	case 2:
		if !typ.Out(1).Implements(errorType) {
			return nil, errors.New("func must return an error as its second value")
		}
	default:
		return nil, errors.New("func must return either 1 or 2 values")
	}

	first := 0
	acceptsContext := typ.NumIn() > 0 && typ.In(0) == contextType
	if acceptsContext {
		first = 1
		if typ.IsVariadic() && typ.NumIn() == 1 {
			return nil, errors.New("context.Context cannot be variadic")
		}
	}
	params := make([]extensionParam, typ.NumIn()-first)
	for i := range params {
		paramType := typ.In(i + first)
		if typ.IsVariadic() && i == len(params)-1 {
			paramType = paramType.Elem()
		}
		params[i] = newExtensionParam(paramType)
	}
	if err := validateExtensionParams(params, typ.IsVariadic()); err != nil {
		return nil, err
	}
	reflected := &reflectedExtension{
		name:                  name,
		fn:                    fn,
		params:                params,
		variadic:              typ.IsVariadic(),
		acceptsContext:        acceptsContext,
		undefinedHandler:      spec.UndefinedHandler,
		evaluationContextFunc: spec.EvalContextHandler,
	}
	// Keep the common primitive numeric extension on a direct call path. The
	// shape is deliberately exact: handlers, context-aware functions, errors,
	// optional/variant parameters, and named function types retain the general
	// reflective implementation and its conversion rules.
	if spec.UndefinedHandler == nil && spec.EvalContextHandler == nil &&
		typ.NumIn() == 1 && typ.In(0) == reflect.TypeOf(float64(0)) &&
		typ.NumOut() == 1 && typ.Out(0) == reflect.TypeOf(float64(0)) {
		if fast, ok := spec.Func.(func(float64) float64); ok {
			reflected.fastFloat64 = fast
		}
	}
	return reflected, nil
}

func newExtensionParam(typ reflect.Type) extensionParam {
	param := extensionParam{typ: typ}
	if reflect.PointerTo(typ).Implements(jtypes.TypeOptional) {
		optional := reflect.New(typ).Interface().(jtypes.Optional)
		underlying := newExtensionParam(optional.Type())
		param.optional = true
		param.optionalType = &underlying
	}
	if typ.Implements(jtypes.TypeVariant) {
		valid := reflect.Zero(typ).Interface().(jtypes.Variant).ValidTypes()
		param.variant = true
		param.variantTypes = make([]extensionParam, len(valid))
		for i := range valid {
			param.variantTypes[i] = newExtensionParam(valid[i])
		}
	}
	return param
}

func validateExtensionParams(params []extensionParam, variadic bool) error {
	hasOptional := false
	for i, param := range params {
		if param.optional && param.variant {
			return errors.New("parameters cannot be both optional and variant")
		}
		if hasOptional && !param.optional {
			return errors.New("a non-optional parameter cannot follow an optional parameter")
		}
		if param.optional {
			if param.optionalType.optional {
				return errors.New("optional parameters cannot have an optional underlying type")
			}
			if variadic && i == len(params)-1 {
				return errors.New("optional parameters cannot be variadic")
			}
			hasOptional = true
		}
		if !param.variant {
			continue
		}
		if !jtypes.TypeValue.ConvertibleTo(param.typ) {
			return errors.New("variant parameter types must be derived from reflect.Value")
		}
		if len(param.variantTypes) < 2 {
			return errors.New("variant parameters must have at least two valid types")
		}
		for _, valid := range param.variantTypes {
			if valid.optional || valid.variant {
				return errors.New("a variant parameter's valid types cannot be optional or variant")
			}
		}
	}
	return nil
}

func (c *reflectedExtension) callableName() string { return c.name }
func (c *reflectedExtension) callbackArity() int   { return len(c.params) }

// invokeStaticFloat64 is an opt-in dispatch path for the exact primitive
// extension shape described in NewReflectedExtension. It returns handled=false
// for every other extension so the normal reflective invocation remains the
// source of truth for conversions and extension features.
func (c *reflectedExtension) invokeStaticFloat64(st state, argument any) (result any, err error, handled bool) {
	if c == nil || c.fastFloat64 == nil {
		return nil, nil, false
	}
	if st.runtime != nil {
		if err := st.runtime.check(); err != nil {
			return nil, err, true
		}
	}
	number, ok := staticExtensionFloat64Argument(argument)
	if !ok {
		return nil, &ExtensionArgTypeError{Func: c.name, Which: 1}, true
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("extension %q panicked: %v", c.name, recovered)
		}
	}()
	result = c.fastFloat64(number)
	if st.runtime != nil {
		if checkErr := st.runtime.check(); checkErr != nil {
			return nil, checkErr, true
		}
	}
	result, err = normalizeExtensionValue(st.runtime, result)
	return result, err, true
}

// invokeStaticFloat64Default is the allocation-free success path used by the
// decoded arithmetic plan. The caller has already performed the complete
// default-input safety walk, and this exact extension shape has no handlers,
// context, error return, or container ownership to normalize. Failures still
// use the same public error classes as reflective invocation.
func (c *reflectedExtension) invokeStaticFloat64Default(argument any) (result float64, err error, handled bool) {
	if c == nil || c.fastFloat64 == nil {
		return 0, nil, false
	}
	number, ok := staticExtensionFloat64Argument(argument)
	if !ok {
		return 0, &ExtensionArgTypeError{Func: c.name, Which: 1}, true
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result = 0
			err = fmt.Errorf("extension %q panicked: %v", c.name, recovered)
		}
	}()
	result = c.fastFloat64(number)
	if math.IsNaN(result) || math.IsInf(result, 0) {
		return 0, normalizationRuntimeError(value.ErrNonFiniteValue), true
	}
	return result, nil, true
}

func staticExtensionFloat64Argument(argument any) (float64, bool) {
	switch value := argument.(type) {
	case int:
		return float64(value), true
	case int8:
		return float64(value), true
	case int16:
		return float64(value), true
	case int32:
		return float64(value), true
	case int64:
		return float64(value), true
	case uint:
		return float64(value), true
	case uint8:
		return float64(value), true
	case uint16:
		return float64(value), true
	case uint32:
		return float64(value), true
	case uint64:
		return float64(value), true
	case float32:
		return float64(value), true
	case float64:
		return value, true
	default:
		return 0, false
	}
}

func (c *reflectedExtension) invoke(st state, args []any) (result any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("extension %q panicked: %v", c.name, recovered)
		}
	}()
	if st.runtime != nil {
		if err := st.runtime.check(); err != nil {
			return nil, err
		}
	}

	argv := make([]reflect.Value, len(args))
	for i := range args {
		argv[i] = extensionReflectValue(st, args[i])
	}
	originalCount := len(argv)
	if c.evaluationContextFunc != nil && c.evaluationContextFunc(argv) {
		argv = append([]reflect.Value{extensionReflectValue(st, collapse(st.current))}, argv...)
	}
	if c.undefinedHandler != nil && c.undefinedHandler(argv) {
		return value.Undefined, nil
	}
	for i := len(argv); i < len(c.params); i++ {
		if !c.params[i].optional {
			break
		}
		argv = append(argv, reflect.Value{})
	}
	if c.variadic {
		if len(argv) < len(c.params)-1 {
			return nil, &ExtensionArgCountError{Func: c.name, Expected: len(c.params), Received: originalCount}
		}
	} else if len(argv) != len(c.params) {
		return nil, &ExtensionArgCountError{Func: c.name, Expected: len(c.params), Received: originalCount}
	}
	for i := range argv {
		paramIndex := i
		if paramIndex >= len(c.params) {
			paramIndex = len(c.params) - 1
		}
		converted, ok := convertExtensionArgument(argv[i], c.params[paramIndex])
		if !ok {
			return nil, &ExtensionArgTypeError{Func: c.name, Which: i + 1}
		}
		argv[i] = converted
	}
	if c.acceptsContext {
		ctx := context.Background()
		if st.runtime != nil && st.runtime.ctx != nil {
			ctx = st.runtime.ctx
		}
		if st.runtime != nil && !st.runtime.deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, st.runtime.deadline)
			defer cancel()
		}
		argv = append([]reflect.Value{reflect.ValueOf(ctx)}, argv...)
	}
	results := c.fn.Call(argv)
	if len(results) == 2 {
		callErr := extensionErrorResult(results[1])
		if callErr != nil {
			if errors.Is(callErr, jtypes.ErrUndefined) {
				return value.Undefined, nil
			}
			if st.runtime != nil && (errors.Is(callErr, context.Canceled) || errors.Is(callErr, context.DeadlineExceeded)) {
				if runtimeErr := st.runtime.check(); runtimeErr != nil {
					return nil, runtimeErr
				}
			}
			return nil, callErr
		}
	}
	if st.runtime != nil {
		if err := st.runtime.check(); err != nil {
			return nil, err
		}
	}
	return normalizeExtensionResult(st, results[0])
}

func extensionErrorResult(result reflect.Value) error {
	switch result.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if result.IsNil() {
			return nil
		}
	}
	return result.Interface().(error)
}

func convertExtensionArgument(arg reflect.Value, param extensionParam) (reflect.Value, bool) {
	if !arg.IsValid() {
		switch {
		case param.optional, param.typ == jtypes.TypeInterface, param.typ == jtypes.TypeValue:
			return reflect.Zero(param.typ), true
		default:
			return reflect.Value{}, false
		}
	}
	arg = jtypes.Resolve(arg)
	if arg.IsValid() && arg.Kind() == reflect.Struct && reflect.PointerTo(arg.Type()).Implements(jtypes.TypeCallable) && arg.CanAddr() {
		arg = arg.Addr()
	}
	if param.optional {
		converted, ok := convertExtensionArgument(arg, *param.optionalType)
		if !ok {
			return reflect.Value{}, false
		}
		optional := reflect.New(param.typ).Interface().(jtypes.Optional)
		optional.Set(converted)
		return reflect.ValueOf(optional).Elem(), true
	}
	if param.variant {
		for _, valid := range param.variantTypes {
			converted, ok := convertExtensionArgument(arg, valid)
			if ok {
				return reflect.ValueOf(converted).Convert(param.typ), true
			}
		}
		return reflect.Value{}, false
	}
	argType := arg.Type()
	switch {
	case argType == param.typ, argType.AssignableTo(param.typ):
		return arg, true
	case param.typ == jtypes.TypeValue:
		return reflect.ValueOf(arg), true
	case argType.ConvertibleTo(param.typ):
		if param.typ == stringType && argType != bytesType {
			return reflect.Value{}, false
		}
		return arg.Convert(param.typ), true
	case argType.Implements(jtypes.TypeConvertible) && arg.CanInterface():
		return arg.Interface().(jtypes.Convertible).ConvertTo(param.typ)
	default:
		return reflect.Value{}, false
	}
}

func extensionReflectValue(st state, input any) reflect.Value {
	input = collapse(input)
	if value.IsUndefined(input) {
		return reflect.Value{}
	}
	if fn, ok := callable(input); ok {
		return reflect.ValueOf(&extensionCallable{fn: fn, st: st})
	}
	public, ok := value.Public(input)
	if ok {
		if public == nil {
			return reflect.Zero(jtypes.TypeInterface)
		}
		return reflect.ValueOf(public)
	}
	return reflect.ValueOf(input)
}

func normalizeExtensionResult(st state, result reflect.Value) (any, error) {
	if !result.IsValid() {
		return value.Undefined, nil
	}
	if result.Type() == jtypes.TypeValue {
		result = result.Interface().(reflect.Value)
		if !result.IsValid() {
			return value.Undefined, nil
		}
	}
	switch result.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if result.IsNil() {
			return nil, nil
		}
	}
	return normalizeExtensionValue(st.runtime, result.Interface())
}

// NormalizeExtensionBinding converts public extension values to evaluator
// values while preserving callable values.
func NormalizeExtensionBinding(input any) any {
	normalized, err := NormalizeExtensionBindingSafe(input, defaultMaxCallDepth, nil)
	if err != nil {
		return value.Undefined
	}
	return normalized
}

type extensionCallable struct {
	fn callableValue
	st state
}

func (c *extensionCallable) Name() string { return c.fn.callableName() }

func (c *extensionCallable) ParamCount() int {
	if lambda, ok := c.fn.(*lambdaValue); ok {
		return len(lambda.params)
	}
	if arity, err := hofCallbackArity(c.fn); err == nil {
		return arity
	}
	return 1
}

func (c *extensionCallable) Call(argv []reflect.Value) (reflect.Value, error) {
	args := make([]any, len(argv))
	for i, arg := range argv {
		if !arg.IsValid() {
			args[i] = value.Undefined
		} else {
			normalized, err := normalizeExtensionValue(c.st.runtime, arg.Interface())
			if err != nil {
				return reflect.Value{}, err
			}
			args[i] = normalized
		}
	}
	result, err := c.fn.invoke(c.st, args)
	if err != nil {
		return reflect.Value{}, err
	}
	if value.IsUndefined(result) {
		return reflect.Value{}, nil
	}
	public, ok := value.Public(collapse(result))
	if !ok {
		return reflect.Value{}, errors.New("extension callable returned a non-public value")
	}
	if public == nil {
		return reflect.Zero(jtypes.TypeInterface), nil
	}
	return reflect.ValueOf(public), nil
}

type legacyCallable struct {
	mu       sync.Mutex
	callable jtypes.Callable
}

func (c *legacyCallable) callableName() string { return c.callable.Name() }
func (c *legacyCallable) callbackArity() int   { return c.callable.ParamCount() }

func (c *legacyCallable) invoke(st state, args []any) (result any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("extension callable %q panicked: %v", c.callable.Name(), recovered)
		}
	}()
	argv := make([]reflect.Value, len(args))
	for i := range args {
		argv[i] = extensionReflectValue(st, args[i])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if setter, ok := c.callable.(interface{ SetContext(reflect.Value) }); ok {
		setter.SetContext(extensionReflectValue(st, collapse(st.current)))
	}
	reflected, err := c.callable.Call(argv)
	if errors.Is(err, jtypes.ErrUndefined) {
		return value.Undefined, nil
	}
	if err != nil {
		return nil, err
	}
	if st.runtime != nil {
		if err := st.runtime.check(); err != nil {
			return nil, err
		}
	}
	return normalizeExtensionResult(st, reflected)
}
