package asl

import (
	"context"
	"math"
	"regexp"
	"strconv"
)

// Diagnostic is an API-compatible definition validation finding.
type Diagnostic struct {
	Severity string
	Code     string
	Message  string
	Location string
}

type StateType string

const (
	Pass     StateType = "Pass"
	Task     StateType = "Task"
	Choice   StateType = "Choice"
	Wait     StateType = "Wait"
	Succeed  StateType = "Succeed"
	Fail     StateType = "Fail"
	Parallel StateType = "Parallel"
	Map      StateType = "Map"
)

// Definition is one transition and variable scope. Nested definitions inherit
// the machine query language, not the containing state's override.
type Definition struct {
	StartAt        string
	States         map[string]*State
	Language       Language
	TimeoutSeconds int64
	Variables      []string
}

type State struct {
	Name     string
	Type     StateType
	Next     string
	End      bool
	Language Language
	Dataflow
	Assign   *Template
	Retry    []Retrier
	Catch    []Catcher
	Pass     *PassState
	Task     *TaskState
	Choice   *ChoiceState
	Wait     *WaitState
	Fail     *FailState
	Parallel *ParallelState
	Map      *MapState
}

// Dataflow contains compiled transformations only. For JSONPath states the
// compiler supplies "$" for omitted paths; nil denotes an explicit JSON null.
// For JSONata states all three paths are nil. Nil templates mean absent fields,
// whereas an explicit JSON null is represented by a non-nil template.
type Dataflow struct {
	InputPath      *Path
	Parameters     *Template
	ResultSelector *Template
	ResultPath     *Path
	OutputPath     *Path
	Arguments      *Template
	Output         *Template
}

type PassState struct {
	Result    any
	HasResult bool
}

type TaskState struct {
	Resource         string
	Credentials      *Credentials
	TimeoutSeconds   *IntegerValue
	HeartbeatSeconds *IntegerValue
}

type Credentials struct {
	RoleArn *StringValue
}

type WaitState struct {
	Seconds   *IntegerValue
	Timestamp *StringValue
}

type FailState struct {
	Error *StringValue
	Cause *StringValue
}

type ParallelState struct {
	Branches []*Definition
}

type MapState struct {
	Processor                  *Definition
	ProcessorConfig            ProcessorConfig
	ItemsPath                  *Path
	Items                      *Template
	ItemReader                 *ItemReader
	ItemSelector               *Template
	ItemBatcher                *ItemBatcher
	ResultWriter               *ResultWriter
	MaxConcurrency             *IntegerValue
	ToleratedFailureCount      *IntegerValue
	ToleratedFailurePercentage *NumberValue
	Label                      string
}

type ProcessorConfig struct {
	Mode          string
	ExecutionType string
}

type ItemReader struct {
	Resource     string
	Parameters   *Template
	Arguments    *Template
	ReaderConfig *ReaderConfig
}

type ReaderConfig struct {
	InputType         string
	CSVHeaderLocation string
	CSVHeaders        []string
	CSVDelimiter      string
	MaxItems          *IntegerValue
	ManifestType      string
	ItemsPointer      string
	Transformation    string
}

type ItemBatcher struct {
	BatchInput            *Template
	MaxItemsPerBatch      *IntegerValue
	MaxInputBytesPerBatch *IntegerValue
}

type ResultWriter struct {
	Resource     string
	Parameters   *Template
	Arguments    *Template
	WriterConfig *WriterConfig
}

type WriterConfig struct {
	Transformation string
	OutputType     string
}

type Retrier struct {
	ErrorEquals     []string
	IntervalSeconds int64
	MaxAttempts     int64
	BackoffRate     float64
	MaxDelaySeconds int64
	JitterStrategy  string
}

type Catcher struct {
	ErrorEquals []string
	Next        string
	ResultPath  *Path
	Assign      *Template
	Output      *Template
}

type ChoiceState struct {
	Rules       []ChoiceRule
	Default     string
	defaultRule ChoiceRule
}

// ChoiceRule has either Condition (JSONata) or Predicate (JSONPath). Output and
// Assign belong to the selected rule, not to its transition target.
type ChoiceRule struct {
	Next      string
	Assign    *Template
	Output    *Template
	Condition *Template
	Predicate *ChoicePredicate
}

type ChoiceOperator string

type ChoicePredicate struct {
	Operator     ChoiceOperator
	Children     []*ChoicePredicate
	Variable     *Path
	Operand      any
	OperandPath  *Path
	pattern      *regexp.Regexp
	patternError error
}

// Scalar values are compiled once and preserve omission through a nil pointer.
// Evaluate also checks the field's runtime scalar type and bounds.
type IntegerValue struct {
	Value               int64
	Path                *Path
	Expression          *Expression
	minimum             int64
	maximum             int64
	language            Language
	coerceIntegerString bool
}

type NumberValue struct {
	Value      float64
	Path       *Path
	Expression *Expression
	minimum    float64
	maximum    float64
	language   Language
}

type StringValue struct {
	Value      string
	Path       *Path
	Expression *Expression
	language   Language
	timestamp  bool
}

func (v *IntegerValue) Evaluate(ctx context.Context, env Environment) (int64, error) {
	value, err := evaluateScalar(ctx, env, v.Value, v.Path, v.Expression)
	if err != nil {
		return 0, err
	}
	if v.coerceIntegerString {
		if text, ok := value.(string); ok {
			number, parseErr := strconv.ParseInt(text, 10, 64)
			if parseErr != nil {
				return 0, scalarError(v.language, "Expected an integer")
			}
			value = number
		}
	}
	number, ok := numberValue(value)
	if !ok || math.Trunc(number) != number || number < float64(v.minimum) || number > float64(v.maximum) {
		return 0, scalarError(v.language, "Expected an integer within the permitted range")
	}
	return int64(number), nil
}

func (v *NumberValue) Evaluate(ctx context.Context, env Environment) (float64, error) {
	value, err := evaluateScalar(ctx, env, v.Value, v.Path, v.Expression)
	if err != nil {
		return 0, err
	}
	number, ok := numberValue(value)
	if !ok || number < v.minimum || number > v.maximum {
		return 0, scalarError(v.language, "Expected a number within the permitted range")
	}
	return number, nil
}

func (v *StringValue) Evaluate(ctx context.Context, env Environment) (string, error) {
	value, err := evaluateScalar(ctx, env, v.Value, v.Path, v.Expression)
	if err != nil {
		return "", err
	}
	text, ok := value.(string)
	if !ok {
		return "", scalarError(v.language, "Expected a string")
	}
	if v.timestamp {
		if _, ok := compilerTimestamp(text); !ok {
			return "", scalarError(v.language, "Expected an RFC3339 timestamp")
		}
	}
	return text, nil
}

func evaluateScalar(ctx context.Context, env Environment, literal any, path *Path, expression *Expression) (any, error) {
	if expression != nil {
		return expression.Evaluate(ctx, env)
	}
	if path != nil {
		value, found, err := path.Lookup(env)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, &EvaluationError{Name: "States.Runtime", Cause: "The field path could not be found in the input"}
		}
		return value, nil
	}
	return literal, nil
}

func scalarError(language Language, cause string) error {
	name := "States.Runtime"
	if language == JSONata {
		name = "States.QueryEvaluationError"
	}
	return &EvaluationError{Name: name, Cause: cause}
}
