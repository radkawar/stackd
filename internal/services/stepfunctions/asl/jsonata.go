package asl

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	jsonata "github.com/tiaanduplessis/jsonata-go"
)

type jsonataExpression struct {
	expression *jsonata.Expr
	needsClock bool
}

type jsonataEnvironmentKey struct{}

type jsonataInspection struct {
	references []string
	needsClock bool
}

func compileJSONata(source string) (*jsonataExpression, []string, error) {
	if !strings.HasPrefix(source, "{%") || !strings.HasSuffix(source, "%}") {
		return nil, nil, fmt.Errorf("JSONata expressions must start with {%% and end with %%}, with no surrounding whitespace")
	}
	// An isolated engine deliberately ignores the library's package registry.
	engine := jsonata.NewEngine()
	if err := engine.RegisterExts(jsonataExtensions()); err != nil {
		return nil, nil, err
	}
	expression, err := engine.Compile(source[2 : len(source)-2])
	if err != nil {
		return nil, nil, err
	}
	inspection := jsonataInspection{}
	if err := inspection.walk(expression.Syntax(), false, map[string]bool{}); err != nil {
		return nil, nil, err
	}
	return &jsonataExpression{expression: expression, needsClock: inspection.needsClock}, uniqueReferences(inspection.references), nil
}

func evaluateJSONata(ctx context.Context, expression *jsonataExpression, env Environment) (any, error) {
	fail := func(err error) (any, error) {
		return nil, &EvaluationError{Name: "States.QueryEvaluationError", Cause: err.Error()}
	}
	if expression.needsClock && env.Now.IsZero() {
		return fail(fmt.Errorf("evaluation clock is unavailable"))
	}
	bindings := make(map[string]any, len(env.Variables)+1)
	for name, value := range env.Variables {
		if strings.HasPrefix(name, "$") {
			return fail(fmt.Errorf("workflow variable names must not start with $"))
		}
		bindings[name] = value
	}
	states := map[string]any{"input": env.Input, "context": env.ContextObject}
	if env.HasResult {
		states["result"] = env.Result
	}
	if env.ErrorOutput != nil {
		states["errorOutput"] = env.ErrorOutput
	}
	bindings["states"] = states
	ctx = context.WithValue(ctx, jsonataEnvironmentKey{}, env)
	value, err := expression.expression.EvalNoInputWithOptions(jsonata.EvalOptions{
		Context: ctx, Bindings: bindings, Timestamp: env.Now,
		// The wall-clock deadline bounds computation. The library's default
		// operation counter charges each padded character and rejects native
		// 256-KiB expressions long before the allocation limit.
		Timeout: time.Second, MaxSequenceLength: 262144, MaxOperations: math.MaxInt64,
	})
	if err != nil {
		return fail(err)
	}
	return value, nil
}

func jsonataExtensions() map[string]jsonata.Extension {
	return map[string]jsonata.Extension{
		"eval": {Func: func(...any) (any, error) {
			return nil, fmt.Errorf("$eval is not supported in Step Functions; use $parse")
		}},
		"parse": {Func: parseJSON},
		"hash":  {Func: hashString},
		"partition": {Func: func(array []any, chunk float64) ([]any, error) {
			size, ok := intrinsicInteger(chunk, true)
			if !ok || size <= 0 {
				return nil, fmt.Errorf("$partition requires a positive chunk size")
			}
			return partitionArray(array, size), nil
		}},
		"range": {Func: func(first, last, delta float64) ([]any, error) {
			start, ok1 := intrinsicInteger(first, true)
			end, ok2 := intrinsicInteger(last, true)
			step, ok3 := intrinsicInteger(delta, true)
			if !ok1 || !ok2 || !ok3 {
				return nil, fmt.Errorf("$range arguments must be 32-bit integers")
			}
			return numberRange(start, end, step)
		}},
		"random": {Func: func(ctx context.Context, seeds ...float64) (float64, error) {
			if len(seeds) > 1 {
				return 0, fmt.Errorf("$random takes at most one seed")
			}
			if len(seeds) == 1 {
				seed, ok := seedValue(seeds[0])
				if !ok {
					return 0, fmt.Errorf("invalid $random seed")
				}
				return seededRandom(seed).Float64(), nil
			}
			env, ok := ctx.Value(jsonataEnvironmentKey{}).(Environment)
			if !ok {
				return 0, fmt.Errorf("evaluation environment is unavailable")
			}
			return randomUnit(env.Random)
		}},
		"uuid": {Func: func(ctx context.Context) (string, error) {
			env, ok := ctx.Value(jsonataEnvironmentKey{}).(Environment)
			if !ok {
				return "", fmt.Errorf("evaluation environment is unavailable")
			}
			return randomUUID(env.Random)
		}},
	}
}

// walk checks the canonical runtime AST, not source substrings. A nested
// arithmetic expression still has no implicit input; only path projections,
// predicates, sort keys and transformations establish a contextual value.
func (inspection *jsonataInspection) walk(node jsonata.SyntaxNode, contextual bool, locals map[string]bool) error {
	if node == nil {
		return nil
	}
	visit := func(child jsonata.SyntaxNode) error { return inspection.walk(child, contextual, locals) }
	switch n := node.(type) {
	case jsonata.SyntaxLiteral, jsonata.SyntaxPlaceholder:
		return nil
	case jsonata.SyntaxVariable:
		if n.Kind == jsonata.SyntaxVariableRoot {
			return fmt.Errorf("JSONata $$ cannot reference an implicit input document")
		}
		if n.Kind == jsonata.SyntaxVariableFocus {
			if !contextual {
				return fmt.Errorf("JSONata $ cannot reference an implicit input document")
			}
			return nil
		}
		if locals[n.Name] {
			return nil
		}
		if n.Name == "$eval" {
			return fmt.Errorf("$eval is not supported in Step Functions; use $parse")
		}
		if n.Name == "$now" || n.Name == "$millis" || n.Name == "$toMillis" {
			inspection.needsClock = true
		}
		if n.Name == "$states" || !jsonataBuiltin(n.Name) {
			inspection.references = append(inspection.references, n.Name)
		}
	case jsonata.SyntaxName, jsonata.SyntaxWildcard, jsonata.SyntaxParent:
		if !contextual {
			return fmt.Errorf("JSONata cannot reference an unqualified input field at the top level")
		}
	case jsonata.SyntaxPath:
		if err := visit(n.Base); err != nil {
			return err
		}
	case jsonata.SyntaxBinary:
		if n.Op == "@" || n.Op == "#" {
			if err := visit(n.Left); err != nil {
				return err
			}
			if variable, ok := n.Right.(jsonata.SyntaxVariable); ok {
				if variable.Name == "$states" {
					return fmt.Errorf("$states is reserved")
				}
				locals[variable.Name] = true
			}
			return nil
		}
		if n.Op == "." {
			if field, ok := statesField(n); ok {
				inspection.references = append(inspection.references, "$states."+field)
			}
			pathLocals := copyJSONataLocals(locals)
			if err := inspection.walk(n.Left, contextual, pathLocals); err != nil {
				return err
			}
			collectJSONataPathBindings(n.Left, pathLocals)
			return inspection.walk(n.Right, true, pathLocals)
		}
		if n.Op == "^" {
			if err := visit(n.Left); err != nil {
				return err
			}
			return inspection.walk(n.Right, true, locals)
		}
		if err := visit(n.Left); err != nil {
			return err
		}
		return visit(n.Right)
	case jsonata.SyntaxSelector:
		pathLocals := copyJSONataLocals(locals)
		if err := inspection.walk(n.Base, contextual, pathLocals); err != nil {
			return err
		}
		collectJSONataPathBindings(n.Base, pathLocals)
		return inspection.walk(n.Index, true, pathLocals)
	case jsonata.SyntaxArray:
		for _, child := range n.Items {
			if err := visit(child); err != nil {
				return err
			}
		}
	case jsonata.SyntaxObject:
		for _, pair := range n.Pairs {
			if err := visit(pair.KeyExpr); err != nil {
				return err
			}
			if err := visit(pair.Value); err != nil {
				return err
			}
		}
	case jsonata.SyntaxBlock:
		blockLocals := copyJSONataLocals(locals)
		for _, child := range n.Expressions {
			if err := inspection.walk(child, contextual, blockLocals); err != nil {
				return err
			}
		}
	case jsonata.SyntaxBind:
		if n.Variable.Name == "$states" {
			return fmt.Errorf("$states is reserved")
		}
		// A function can refer to itself, whereas x := x+1 reads the outer x.
		valueLocals := locals
		if _, lambda := n.Value.(jsonata.SyntaxLambda); lambda {
			valueLocals = copyJSONataLocals(locals)
			valueLocals[n.Variable.Name] = true
		}
		if err := inspection.walk(n.Value, contextual, valueLocals); err != nil {
			return err
		}
		locals[n.Variable.Name] = true
	case jsonata.SyntaxLambda:
		functionLocals := copyJSONataLocals(locals)
		for _, parameter := range n.Params {
			if parameter.Name == "$states" {
				return fmt.Errorf("$states is reserved")
			}
			functionLocals[parameter.Name] = true
		}
		return inspection.walk(n.Body, contextual, functionLocals)
	case jsonata.SyntaxApply:
		if err := visit(n.Left); err != nil {
			return err
		}
		return visit(n.Right)
	case jsonata.SyntaxUnary:
		return visit(n.Expr)
	case jsonata.SyntaxCall:
		if err := visit(n.Function); err != nil {
			return err
		}
		for _, argument := range n.Args {
			if err := visit(argument); err != nil {
				return err
			}
		}
	case jsonata.SyntaxTransform:
		transformLocals := copyJSONataLocals(locals)
		if err := inspection.walk(n.Path, true, transformLocals); err != nil {
			return err
		}
		if err := inspection.walk(n.Update, true, transformLocals); err != nil {
			return err
		}
		return inspection.walk(n.Delete, true, transformLocals)
	default:
		return fmt.Errorf("unsupported JSONata AST node %T", node)
	}
	return nil
}

func statesField(node jsonata.SyntaxNode) (string, bool) {
	binary, ok := node.(jsonata.SyntaxBinary)
	if !ok || binary.Op != "." {
		return "", false
	}
	if variable, ok := binary.Left.(jsonata.SyntaxVariable); ok && variable.Name == "$states" {
		switch field := binary.Right.(type) {
		case jsonata.SyntaxName:
			return field.Value, true
		case jsonata.SyntaxLiteral:
			if value, ok := field.Value.(string); ok {
				return value, true
			}
		case jsonata.SyntaxSelector:
			if name, ok := field.Base.(jsonata.SyntaxName); ok {
				return name.Value, true
			}
		}
	}
	return statesField(binary.Left)
}

func copyJSONataLocals(locals map[string]bool) map[string]bool {
	copy := make(map[string]bool, len(locals))
	for name := range locals {
		copy[name] = true
	}
	return copy
}

func jsonataBuiltin(name string) bool {
	// The JSONata 2.0.6 catalog plus documented Step Functions extensions.
	const names = " abs append assert average base64decode base64encode boolean ceil clone contains count decodeUrl decodeUrlComponent distinct each encodeUrl encodeUrlComponent error exists filter floor formatBase formatInteger formatNumber fromMillis join keys length lowercase lookup map match max merge millis min not now number pad parseInteger power random reduce replace reverse round shuffle sift single sort split spread sqrt string substring substringAfter substringBefore sum toMillis trim type uppercase zip partition range hash uuid parse "
	return strings.Contains(names, " "+strings.TrimPrefix(name, "$")+" ")
}

func collectJSONataPathBindings(node jsonata.SyntaxNode, locals map[string]bool) {
	switch n := node.(type) {
	case jsonata.SyntaxBinary:
		switch n.Op {
		case "@", "#":
			collectJSONataPathBindings(n.Left, locals)
			if variable, ok := n.Right.(jsonata.SyntaxVariable); ok {
				locals[variable.Name] = true
			}
		case ".", "^":
			collectJSONataPathBindings(n.Left, locals)
			collectJSONataPathBindings(n.Right, locals)
		}
	case jsonata.SyntaxSelector:
		collectJSONataPathBindings(n.Base, locals)
	}
}
