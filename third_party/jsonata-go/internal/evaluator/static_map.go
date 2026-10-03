package evaluator

import (
	"math"
	"strings"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
)

// StaticMapPlan describes the narrow AST shape
// $map(items, function($item){$item.price * $item.quantity}). It is immutable
// and is used only for ordinary decoded JSON input.
type StaticMapPlan struct {
	collection []string
	parameter  string
	left       []string
	right      []string
}

// BuildStaticMapPlan recognizes one-parameter callbacks whose body is exactly
// a product of two explicit paths rooted at that callback parameter.
func BuildStaticMapPlan(n syntax.Node) *StaticMapPlan {
	call, ok := n.(syntax.Call)
	if !ok || call.Partial || len(call.Args) != 2 {
		return nil
	}
	function, ok := call.Function.(syntax.Variable)
	if !ok || function.Kind != syntax.VariableNamed || function.Name != "$map" {
		return nil
	}
	collection, ok := staticPathFields(call.Args[0])
	if !ok || len(collection) == 0 {
		return nil
	}
	lambda, ok := call.Args[1].(syntax.Lambda)
	if !ok || len(lambda.Params) != 1 || lambda.Params[0].Kind != syntax.VariableNamed || lambda.Params[0].Name == "" {
		return nil
	}
	product, ok := lambda.Body.(syntax.Binary)
	if !ok || product.Op != "*" {
		return nil
	}
	parameter := lambda.Params[0].Name
	left, leftOK := staticLambdaPath(product.Left, parameter)
	right, rightOK := staticLambdaPath(product.Right, parameter)
	if !leftOK || !rightOK || len(left) == 0 || len(right) == 0 {
		return nil
	}
	if len(collection)+len(left)+len(right) > staticPathMaxFields {
		return nil
	}
	return &StaticMapPlan{
		collection: append([]string(nil), collection...),
		parameter:  parameter,
		left:       append([]string(nil), left...),
		right:      append([]string(nil), right...),
	}
}

func staticLambdaPath(n syntax.Node, parameter string) ([]string, bool) {
	switch x := n.(type) {
	case syntax.Path:
		base, ok := x.Base.(syntax.Variable)
		if !ok || base.Kind != syntax.VariableNamed || base.Name != parameter || len(x.Fields) == 0 {
			return nil, false
		}
		fields := make([]string, len(x.Fields))
		for i, field := range x.Fields {
			if field.Value == "" || strings.HasPrefix(field.Value, "$") {
				return nil, false
			}
			fields[i] = field.Value
		}
		return fields, true
	case syntax.Binary:
		if x.Op != "." {
			return nil, false
		}
		field, ok := x.Right.(syntax.Name)
		if !ok || field.Value == "" || strings.HasPrefix(field.Value, "$") {
			return nil, false
		}
		if base, ok := x.Left.(syntax.Variable); ok && base.Kind == syntax.VariableNamed && base.Name == parameter {
			return []string{field.Value}, true
		}
		prefix, ok := staticLambdaPath(x.Left, parameter)
		if !ok {
			return nil, false
		}
		return append(prefix, field.Value), true
	default:
		return nil, false
	}
}

func (p *StaticMapPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	// The registry is normally keyed without the JSONata sigil, but accepting
	// both spellings keeps this guard correct for direct/internal snapshots.
	if _, exists := registry["map"]; exists {
		return true
	}
	if _, exists := registry["$map"]; exists {
		return true
	}
	return staticFieldsRegistryConflict(p.collection, registry) ||
		staticFieldsRegistryConflict(p.left, registry) ||
		staticFieldsRegistryConflict(p.right, registry)
}

// EvalStaticMap returns ok=false whenever JSONata's sequence, undefined,
// coercion, or diagnostic semantics may be observable. The original AST must
// be evaluated in those cases.
func EvalStaticMap(plan *StaticMapPlan, input any) (any, bool) {
	if plan == nil || !staticPathInputSafe(input, defaultMaxCallDepth) {
		return nil, false
	}
	return evalStaticMapValidated(plan, input)
}

func evalStaticMapValidated(plan *StaticMapPlan, input any) (any, bool) {
	if plan == nil {
		return nil, false
	}
	collection, ok := staticValueAtPath(input, plan.collection)
	if !ok {
		return nil, false
	}
	items := staticMapItems(collection)
	if len(items) == 0 {
		return nil, false
	}
	work := staticPathMaxWork
	result := make([]any, 0, len(items))
	for _, item := range items {
		if !staticMapConsume(&work) {
			return nil, false
		}
		left, ok := staticScalarAtPath(item, plan.left)
		if !ok {
			return nil, false
		}
		right, ok := staticScalarAtPath(item, plan.right)
		if !ok {
			return nil, false
		}
		leftNumber, ok := strictNumeric(left)
		if !ok || math.IsNaN(leftNumber) || math.IsInf(leftNumber, 0) {
			return nil, false
		}
		rightNumber, ok := strictNumeric(right)
		if !ok || math.IsNaN(rightNumber) || math.IsInf(rightNumber, 0) {
			return nil, false
		}
		product := leftNumber * rightNumber
		if math.IsNaN(product) || math.IsInf(product, 0) {
			return nil, false
		}
		result = append(result, product)
	}
	if len(result) == 1 {
		return result[0], true
	}
	return result, true
}

func staticMapItems(collection any) []any {
	switch value := collection.(type) {
	case []any:
		return value
	case map[string]any:
		return []any{value}
	default:
		return []any{collection}
	}
}

func staticMapConsume(work *int) bool {
	if *work <= 0 {
		return false
	}
	*work--
	return true
}
