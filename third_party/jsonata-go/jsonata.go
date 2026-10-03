package jsonata

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tiaanduplessis/jsonata-go/internal/evaluator"
	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
)

// Expr contains immutable compiled syntax and a copy-on-write registration
// snapshot. It may be registered and evaluated concurrently.
type Expr struct {
	source                    string
	node                      syntax.Node
	staticPath                *evaluator.StaticPathPlan
	staticComparison          *evaluator.StaticComparisonPlan
	staticFilterProject       *evaluator.StaticFilterProjectPlan
	staticSum                 *evaluator.StaticSumPlan
	staticContains            *evaluator.StaticContainsPlan
	staticMap                 *evaluator.StaticMapPlan
	staticTransform           *evaluator.StaticTransformPlan
	staticDescendantSum       *evaluator.StaticDescendantSumPlan
	staticExtensionArithmetic *evaluator.StaticExtensionArithmeticPlan
	registryMu                sync.RWMutex
	registry                  map[string]any
}

// EvalOptions controls one evaluation without changing the compatibility
// wrappers. Bindings are copied per call and are never retained by Expr.
type EvalOptions struct {
	Context  context.Context
	Bindings map[string]any
	Timeout  time.Duration
	// Timestamp exposes the v0.1.0 runtime's existing evaluation clock option.
	// Local ASL integration supplies its clock without altering the evaluator.
	Timestamp time.Time
	// MaxCallDepth defaults to 100 when zero or negative.
	MaxCallDepth int
	// MaxOperations defaults to 100,000 when zero or negative.
	MaxOperations int64
	// MaxSequenceLength limits JSONata sequences when positive. Zero or negative
	// disables this optional v2.2 guardrail.
	MaxSequenceLength int
}

func Compile(expression string) (*Expr, error) {
	n, err := syntax.Parse(expression)
	if err != nil {
		return nil, &Error{Code: err.Code, Token: err.Token, Value: err.Value, Position: err.Position, Message: err.Error()}
	}
	return &Expr{
		source:                    expression,
		node:                      n,
		staticPath:                evaluator.BuildStaticPathPlan(n),
		staticComparison:          evaluator.BuildStaticComparisonPlan(n),
		staticFilterProject:       evaluator.BuildStaticFilterProjectPlan(n),
		staticSum:                 evaluator.BuildStaticSumPlan(n),
		staticContains:            evaluator.BuildStaticContainsPlan(n),
		staticMap:                 evaluator.BuildStaticMapPlan(n),
		staticTransform:           evaluator.BuildStaticTransformPlan(n),
		staticDescendantSum:       evaluator.BuildStaticDescendantSumPlan(n),
		staticExtensionArithmetic: evaluator.BuildStaticExtensionArithmeticPlan(n),
		registry:                  packageRegistrySnapshot(),
	}, nil
}

func MustCompile(expression string) *Expr {
	e, err := Compile(expression)
	if err != nil {
		panic(err)
	}
	return e
}

func (e *Expr) String() string {
	if e == nil {
		return ""
	}
	return e.source
}

func (e *Expr) Eval(data interface{}) (interface{}, error) {
	return e.EvalWithOptions(data, EvalOptions{})
}

// EvalBindings evaluates an immutable expression with per-call variable
// bindings. The bindings are copied by the evaluator and never stored on Expr.
func (e *Expr) EvalBindings(data interface{}, bindings map[string]any) (interface{}, error) {
	return e.EvalWithOptions(data, EvalOptions{Bindings: bindings})
}

// EvalWithOptions evaluates an immutable expression with per-call controls.
func (e *Expr) EvalWithOptions(data any, options EvalOptions) (any, error) {
	if e == nil || e.node == nil {
		return nil, errors.New("jsonata: nil expression")
	}
	registry := e.registrySnapshot()
	if evalFastPathAllowedWithRegistry(e, options, registry) {
		if result, ok := evaluator.EvalStaticPath(e.staticPath, data); ok {
			return result, nil
		}
		if result, ok := evaluator.EvalStaticComparison(e.staticComparison, data); ok {
			return result, nil
		}
		if result, ok := evaluator.EvalStaticFilterProject(e.staticFilterProject, data); ok {
			return result, nil
		}
		if result, ok := evaluator.EvalStaticSum(e.staticSum, data); ok {
			return result, nil
		}
		if result, ok := evaluator.EvalStaticContains(e.staticContains, data); ok {
			return result, nil
		}
		if result, ok := evaluator.EvalStaticMap(e.staticMap, data); ok {
			return result, nil
		}
		if result, ok := evaluator.EvalStaticTransform(e.staticTransform, data); ok {
			return result, nil
		}
		if result, ok := evaluator.EvalStaticDescendantSum(e.staticDescendantSum, data); ok {
			return result, nil
		}
		if result, ok, err := evaluator.EvalStaticExtensionArithmetic(e.staticExtensionArithmetic, data, registry); ok {
			if err != nil {
				return nil, publicEvaluationError(err)
			}
			return result, nil
		}
	}
	v, err := evaluator.EvalWithOptions(e.node, data, evaluator.Options{
		Context:           options.Context,
		Bindings:          evaluationBindings(registry, options.Bindings),
		Timeout:           options.Timeout,
		MaxCallDepth:      options.MaxCallDepth,
		MaxOperations:     options.MaxOperations,
		MaxSequenceLength: options.MaxSequenceLength,
		Timestamp:         options.Timestamp,
	})
	if err != nil {
		return nil, publicEvaluationError(err)
	}
	return v, nil
}

// EvalNoInput evaluates against JSONata's empty input sequence. Eval(nil)
// remains the explicit JSON null input for compatibility.
func (e *Expr) EvalNoInput() (any, error) {
	return e.EvalNoInputWithOptions(EvalOptions{})
}

// EvalNoInputWithOptions evaluates against the empty input sequence with
// per-call bindings and limits.
func (e *Expr) EvalNoInputWithOptions(options EvalOptions) (any, error) {
	if e == nil || e.node == nil {
		return nil, errors.New("jsonata: nil expression")
	}
	v, err := evaluator.EvalNoInputWithOptions(e.node, evaluator.Options{
		Context:           options.Context,
		Bindings:          evaluationBindings(e.registrySnapshot(), options.Bindings),
		Timeout:           options.Timeout,
		MaxCallDepth:      options.MaxCallDepth,
		MaxOperations:     options.MaxOperations,
		MaxSequenceLength: options.MaxSequenceLength,
		Timestamp:         options.Timestamp,
	})
	if err != nil {
		return nil, publicEvaluationError(err)
	}
	return v, nil
}

// EvalNoInputBindings evaluates against the empty input sequence with
// per-call variable bindings.
func (e *Expr) EvalNoInputBindings(bindings map[string]any) (any, error) {
	return e.EvalNoInputWithOptions(EvalOptions{Bindings: bindings})
}

func (e *Expr) EvalBytes(data []byte) ([]byte, error) {
	if e == nil || e.node == nil {
		return nil, errors.New("jsonata: nil expression")
	}
	if evalFastPathAllowed(e, EvalOptions{}) {
		if out, ok := evaluator.EvalStaticPathBytes(e.staticPath, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticComparisonBytes(e.staticComparison, data); ok {
			return out, nil
		}
		if matched, ok := evaluator.EvalStaticContainsBytes(e.staticContains, data); ok {
			if matched {
				return []byte("true"), nil
			}
			return []byte("false"), nil
		}
		if out, ok := evaluator.EvalStaticFilterProjectBytes(e.staticFilterProject, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticSumBytes(e.staticSum, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticMapBytes(e.staticMap, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticDescendantSumBytes(e.staticDescendantSum, data); ok {
			return out, nil
		}
	}
	out, err := evaluator.EvalBytesWithOptions(e.node, data, evaluator.Options{
		Bindings: evaluationBindings(e.registrySnapshot(), nil),
	})
	if err != nil {
		return nil, publicEvaluationError(err)
	}
	return marshalJSON(out)
}

// EvalBytesWithOptions evaluates one JSON document with per-call controls.
func (e *Expr) EvalBytesWithOptions(data []byte, options EvalOptions) ([]byte, error) {
	if e == nil || e.node == nil {
		return nil, errors.New("jsonata: nil expression")
	}
	if err := contextErr(options.Context); err != nil {
		return nil, err
	}
	if evalFastPathAllowed(e, options) {
		if out, ok := evaluator.EvalStaticPathBytes(e.staticPath, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticComparisonBytes(e.staticComparison, data); ok {
			return out, nil
		}
		if matched, ok := evaluator.EvalStaticContainsBytes(e.staticContains, data); ok {
			if matched {
				return []byte("true"), nil
			}
			return []byte("false"), nil
		}
		if out, ok := evaluator.EvalStaticFilterProjectBytes(e.staticFilterProject, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticSumBytes(e.staticSum, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticMapBytes(e.staticMap, data); ok {
			return out, nil
		}
		if out, ok := evaluator.EvalStaticDescendantSumBytes(e.staticDescendantSum, data); ok {
			return out, nil
		}
	}
	out, err := evaluator.EvalBytesWithOptions(e.node, data, evaluator.Options{
		Context:           options.Context,
		Bindings:          evaluationBindings(e.registrySnapshot(), options.Bindings),
		Timeout:           options.Timeout,
		MaxCallDepth:      options.MaxCallDepth,
		MaxOperations:     options.MaxOperations,
		MaxSequenceLength: options.MaxSequenceLength,
		Timestamp:         options.Timestamp,
	})
	if err != nil {
		return nil, publicEvaluationError(err)
	}
	return marshalJSON(out)
}

func evalFastPathAllowed(e *Expr, options EvalOptions) bool {
	if e == nil {
		return false
	}
	return evalFastPathAllowedWithRegistry(e, options, e.registrySnapshot())
}

func evalFastPathAllowedWithRegistry(e *Expr, options EvalOptions, registry map[string]any) bool {
	if e == nil {
		return false
	}
	if options.Context != nil || options.Bindings != nil || options.Timeout > 0 ||
		!options.Timestamp.IsZero() || options.MaxCallDepth > 0 || options.MaxOperations > 0 || options.MaxSequenceLength > 0 {
		return false
	}
	if e.staticPath != nil && !e.staticPath.RegistryConflict(registry) {
		return true
	}
	if e.staticComparison != nil && !e.staticComparison.RegistryConflict(registry) {
		return true
	}
	if e.staticFilterProject != nil && !e.staticFilterProject.RegistryConflict(registry) {
		return true
	}
	if e.staticSum != nil && !e.staticSum.RegistryConflict(registry) {
		return true
	}
	if e.staticContains != nil && !e.staticContains.RegistryConflict(registry) {
		return true
	}
	if e.staticMap != nil && !e.staticMap.RegistryConflict(registry) {
		return true
	}
	if e.staticTransform != nil && !e.staticTransform.RegistryConflict(registry) {
		return true
	}
	if e.staticDescendantSum != nil && !e.staticDescendantSum.RegistryConflict(registry) {
		return true
	}
	if e.staticExtensionArithmetic != nil &&
		!e.staticExtensionArithmetic.RegistryConflict(registry) &&
		e.staticExtensionArithmetic.RegistryReady(registry) {
		return true
	}
	return false
}

func marshalJSON(v any) ([]byte, error) { return jsonMarshal(v) }

// Eval compiles and evaluates expression against data.
func Eval(expression string, data interface{}) (interface{}, error) {
	return EvalWithOptions(expression, data, EvalOptions{})
}

// EvalWithOptions compiles and evaluates an expression with per-call controls.
func EvalWithOptions(expression string, data any, options EvalOptions) (any, error) {
	e, err := Compile(expression)
	if err != nil {
		return nil, err
	}
	return e.EvalWithOptions(data, options)
}

// EvalNoInput compiles and evaluates an expression without an input value.
func EvalNoInput(expression string) (any, error) {
	return EvalNoInputWithOptions(expression, EvalOptions{})
}

// EvalNoInputWithOptions compiles and evaluates an expression without an
// input value and with per-call controls.
func EvalNoInputWithOptions(expression string, options EvalOptions) (any, error) {
	e, err := Compile(expression)
	if err != nil {
		return nil, err
	}
	return e.EvalNoInputWithOptions(options)
}

// EvalBytes compiles and evaluates expression against one JSON value.
func EvalBytes(expression string, data []byte) ([]byte, error) {
	return EvalBytesWithOptions(expression, data, EvalOptions{})
}

// EvalBytesWithOptions compiles and evaluates one JSON document with options.
func EvalBytesWithOptions(expression string, data []byte, options EvalOptions) ([]byte, error) {
	e, err := Compile(expression)
	if err != nil {
		return nil, err
	}
	return e.EvalBytesWithOptions(data, options)
}

// EvalContext is a compatibility convenience container for an input and its
// context. Use EvalOptions with EvalWithOptions for bindings and limits.
type EvalContext struct {
	Context context.Context
	Input   any
}

func NewEvalContext(ctx context.Context, input any) EvalContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return EvalContext{Context: ctx, Input: input}
}

// Engine is an instance-scoped entry point with a copy-on-write registry. Its
// zero value is ready for concurrent use.
type Engine struct {
	registryMu sync.RWMutex
	registry   map[string]any
}

func NewEngine() *Engine { return &Engine{} }
func (e *Engine) Compile(expression string) (*Expr, error) {
	if e == nil {
		return nil, fmt.Errorf("jsonata: nil engine")
	}
	n, err := syntax.Parse(expression)
	if err != nil {
		return nil, &Error{Code: err.Code, Token: err.Token, Value: err.Value, Position: err.Position, Message: err.Error()}
	}
	return &Expr{
		source:                    expression,
		node:                      n,
		staticPath:                evaluator.BuildStaticPathPlan(n),
		staticComparison:          evaluator.BuildStaticComparisonPlan(n),
		staticFilterProject:       evaluator.BuildStaticFilterProjectPlan(n),
		staticSum:                 evaluator.BuildStaticSumPlan(n),
		staticContains:            evaluator.BuildStaticContainsPlan(n),
		staticMap:                 evaluator.BuildStaticMapPlan(n),
		staticTransform:           evaluator.BuildStaticTransformPlan(n),
		staticDescendantSum:       evaluator.BuildStaticDescendantSumPlan(n),
		staticExtensionArithmetic: evaluator.BuildStaticExtensionArithmeticPlan(n),
		registry:                  e.registrySnapshot(),
	}, nil
}
func (e *Engine) Eval(ctx context.Context, expression string, input any) (any, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	x, err := e.Compile(expression)
	if err != nil {
		return nil, err
	}
	return x.EvalWithOptions(input, EvalOptions{Context: ctx})
}
func (e *Engine) Evaluate(ctx context.Context, expr *Expr, input any) (any, error) {
	if e == nil {
		return nil, fmt.Errorf("jsonata: nil engine")
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if expr == nil {
		return nil, fmt.Errorf("jsonata: nil expression")
	}
	return expr.EvalWithOptions(input, EvalOptions{Context: ctx})
}
func (e *Expr) EvalContext(ctx context.Context, input any) (any, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	return e.EvalWithOptions(input, EvalOptions{Context: ctx})
}
func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return &Error{Code: "U1001", Message: ctx.Err().Error(), cause: ctx.Err()}
	default:
		return nil
	}
}

func publicEvaluationError(err error) error {
	if err == nil {
		return nil
	}
	if evaluator.IsUndefined(err) {
		return ErrUndefined
	}
	var countError *evaluator.ExtensionArgCountError
	if errors.As(err, &countError) {
		return &ArgCountError{Func: countError.Func, Expected: countError.Expected, Received: countError.Received}
	}
	var typeError *evaluator.ExtensionArgTypeError
	if errors.As(err, &typeError) {
		return &ArgTypeError{Func: typeError.Func, Which: typeError.Which}
	}
	var coded interface{ JSONataCode() string }
	if !errors.As(err, &coded) {
		return err
	}
	public := &Error{Code: coded.JSONataCode(), Message: err.Error(), cause: err}
	var tokenized interface{ JSONataToken() string }
	if errors.As(err, &tokenized) {
		public.Token = tokenized.JSONataToken()
	}
	var valued interface{ JSONataValue() any }
	if errors.As(err, &valued) {
		public.Value = valued.JSONataValue()
	}
	var positioned interface{ JSONataPosition() (int, bool) }
	if errors.As(err, &positioned) {
		if position, ok := positioned.JSONataPosition(); ok {
			public.Position = position
		}
	}
	return public
}
