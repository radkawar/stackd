package asl

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Expression is immutable and can be evaluated concurrently with independent
// environments. Compiling never captures workflow input, variables or time.
type Expression struct {
	language   Language
	path       *Path
	intrinsic  *intrinsicCall
	jsonata    *jsonataExpression
	references []string
}

func CompileExpression(source string, language Language) (*Expression, error) {
	expression := &Expression{language: language}
	var err error
	switch language {
	case JSONPath:
		if strings.HasPrefix(source, "$") {
			expression.path, err = CompilePath(source, false)
			if err == nil {
				expression.references = expression.path.References()
			}
		} else {
			expression.intrinsic, err = compileIntrinsic(source)
			if err == nil {
				expression.references = expression.intrinsic.references()
			}
		}
	case JSONata:
		expression.jsonata, expression.references, err = compileJSONata(source)
	default:
		err = fmt.Errorf("unknown query language %q", language)
	}
	if err != nil {
		return nil, err
	}
	return expression, nil
}

func (e *Expression) Evaluate(ctx context.Context, env Environment) (any, error) {
	if e == nil {
		return nil, runtimeError("nil expression")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.language == JSONata {
		return evaluateJSONata(ctx, e.jsonata, env)
	}
	if e.path != nil {
		value, found, err := e.path.Lookup(env)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, runtimeError("path %q does not exist", e.path.source)
		}
		return value, nil
	}
	value, err := e.intrinsic.evaluate(ctx, env)
	if err != nil {
		return nil, runtimeError("intrinsic evaluation failed: %v", err)
	}
	return value, nil
}

func (e *Expression) References() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.references...)
}

func runtimeError(format string, args ...any) error {
	return &EvaluationError{Name: "States.Runtime", Cause: fmt.Sprintf(format, args...)}
}

func uniqueReferences(references []string) []string {
	if len(references) == 0 {
		return nil
	}
	sort.Strings(references)
	result := references[:1]
	for _, ref := range references[1:] {
		if ref != result[len(result)-1] {
			result = append(result, ref)
		}
	}
	return result
}
