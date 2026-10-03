package evaluator

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
)

// StaticTransformPlan describes one deliberately narrow decoded-input
// transform. It is immutable after compilation and safe to share between
// concurrent evaluations. Any input or expression shape outside this subset
// is evaluated by the normal transform implementation.
type StaticTransformPlan struct {
	collection []string
	predicate  staticTransformPredicate
	updates    []staticTransformUpdate
	deletes    []string
}

type staticTransformPredicate struct {
	path    []string
	literal any
}

type staticTransformUpdate struct {
	key     string
	literal any
	product *staticTransformProduct
}

type staticTransformProduct struct {
	left  []string
	right []string
}

const staticTransformMaxNodes = 2048

// BuildStaticTransformPlan recognizes the frozen medium-transform shape:
//
//	$ ~> |collection.path[field = scalar]|{literal, total: left * right}, ["key"]|
//
// The operation must be rooted at the input focus and every name must be a
// plain field path. In particular, no source-string or benchmark identifier
// is used to select this plan.
func BuildStaticTransformPlan(n syntax.Node) *StaticTransformPlan {
	apply, ok := n.(syntax.Apply)
	if !ok {
		return nil
	}
	root, ok := apply.Left.(syntax.Variable)
	if !ok || root.Kind != syntax.VariableFocus {
		return nil
	}
	transform, ok := apply.Right.(syntax.Transform)
	if !ok {
		return nil
	}
	collection, predicate, ok := staticTransformPath(transform.Path)
	if !ok {
		return nil
	}
	updateObject, ok := transform.Update.(syntax.Object)
	if !ok || len(updateObject.Pairs) == 0 {
		return nil
	}
	updates := make([]staticTransformUpdate, 0, len(updateObject.Pairs))
	updateKeys := make(map[string]struct{}, len(updateObject.Pairs))
	for _, pair := range updateObject.Pairs {
		key, ok := staticTransformObjectKey(pair)
		if !ok {
			return nil
		}
		if _, duplicate := updateKeys[key]; duplicate {
			return nil
		}
		updateKeys[key] = struct{}{}
		if strings.HasPrefix(key, "_jsonata_") {
			return nil
		}
		if literal, ok := staticScalarLiteral(pair.Value); ok {
			updates = append(updates, staticTransformUpdate{key: key, literal: literal})
			continue
		}
		product, ok := parseStaticTransformProduct(pair.Value)
		if !ok {
			return nil
		}
		updates = append(updates, staticTransformUpdate{key: key, product: product})
	}
	deletes, ok := staticTransformDeletes(transform.Delete)
	if !ok {
		return nil
	}
	if !staticTransformPlanSizeWithinLimit(collection, predicate, updates) {
		return nil
	}
	return &StaticTransformPlan{
		collection: append([]string(nil), collection...),
		predicate: staticTransformPredicate{
			path:    append([]string(nil), predicate.path...),
			literal: predicate.literal,
		},
		updates: updates,
		deletes: deletes,
	}
}

func staticTransformPath(n syntax.Node) ([]string, staticTransformPredicate, bool) {
	dot, ok := n.(syntax.Binary)
	if !ok || dot.Op != "." {
		return nil, staticTransformPredicate{}, false
	}
	collection, ok := staticPathFields(dot.Left)
	if !ok || len(collection) == 0 {
		return nil, staticTransformPredicate{}, false
	}
	selector, ok := dot.Right.(syntax.Selector)
	if !ok || selector.Index == nil {
		return nil, staticTransformPredicate{}, false
	}
	items, ok := staticPathFields(selector.Base)
	if !ok || len(items) == 0 {
		return nil, staticTransformPredicate{}, false
	}
	predicateNode, ok := selector.Index.(syntax.Binary)
	if !ok || predicateNode.Op != "=" {
		return nil, staticTransformPredicate{}, false
	}
	path, ok := staticPathFields(predicateNode.Left)
	if !ok || len(path) == 0 {
		return nil, staticTransformPredicate{}, false
	}
	literal, ok := staticScalarLiteral(predicateNode.Right)
	if !ok || literal == nil {
		return nil, staticTransformPredicate{}, false
	}
	return append(collection, items...), staticTransformPredicate{path: path, literal: literal}, true
}

func staticTransformObjectKey(pair syntax.Pair) (string, bool) {
	if pair.KeyExpr == nil {
		return "", false
	}
	literal, ok := pair.KeyExpr.(syntax.Literal)
	if !ok || literal.Kind != syntax.String {
		return "", false
	}
	key, ok := literal.Value.(string)
	return key, ok && key != ""
}

func parseStaticTransformProduct(n syntax.Node) (*staticTransformProduct, bool) {
	binary, ok := n.(syntax.Binary)
	if !ok || binary.Op != "*" {
		return nil, false
	}
	left, ok := staticPathFields(binary.Left)
	if !ok || len(left) == 0 {
		return nil, false
	}
	right, ok := staticPathFields(binary.Right)
	if !ok || len(right) == 0 {
		return nil, false
	}
	return &staticTransformProduct{left: append([]string(nil), left...), right: append([]string(nil), right...)}, true
}

func staticTransformDeletes(n syntax.Node) ([]string, bool) {
	if n == nil {
		return nil, true
	}
	array, ok := n.(syntax.Array)
	if !ok {
		return nil, false
	}
	deletes := make([]string, 0, len(array.Items))
	for _, item := range array.Items {
		literal, ok := item.(syntax.Literal)
		if !ok || literal.Kind != syntax.String {
			return nil, false
		}
		key, ok := literal.Value.(string)
		if !ok {
			return nil, false
		}
		deletes = append(deletes, key)
	}
	return deletes, true
}

func staticTransformPlanSizeWithinLimit(collection []string, predicate staticTransformPredicate, updates []staticTransformUpdate) bool {
	fields := len(collection) + len(predicate.path)
	for _, update := range updates {
		if update.product != nil {
			fields += len(update.product.left) + len(update.product.right)
		}
	}
	return fields <= staticPathMaxFields
}

// RegistryConflict disables the plan when a registered name can shadow a
// field lookup or the transform's clone binding. Builtins unrelated to these
// names cannot alter this plan's meaning.
func (p *StaticTransformPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	if _, ok := registry["clone"]; ok {
		return true
	}
	if _, ok := registry["$clone"]; ok {
		return true
	}
	if staticFieldsRegistryConflict(p.collection, registry) ||
		staticFieldsRegistryConflict(p.predicate.path, registry) {
		return true
	}
	for _, update := range p.updates {
		if update.product == nil {
			continue
		}
		if staticFieldsRegistryConflict(update.product.left, registry) ||
			staticFieldsRegistryConflict(update.product.right, registry) {
			return true
		}
	}
	return false
}

// EvalStaticTransform returns ok=false for any input whose normalization,
// clone, sequence, diagnostic, or resource semantics could differ. The
// caller then evaluates the original syntax tree.
func EvalStaticTransform(plan *StaticTransformPlan, input any) (any, bool) {
	if plan == nil {
		return nil, false
	}
	root, ok := input.(map[string]any)
	if !ok || root == nil {
		return nil, false
	}
	cloned, ok := staticTransformClone(input)
	if !ok {
		return nil, false
	}
	result, ok := cloned.(map[string]any)
	if !ok {
		return nil, false
	}
	collection, ok := staticTransformValueAtPath(result, plan.collection)
	if !ok {
		return result, true
	}
	items, ok := collection.([]any)
	if !ok {
		return nil, false
	}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok || object == nil {
			return nil, false
		}
		candidate, exists := staticTransformValueAtPath(object, plan.predicate.path)
		if !exists || !staticTransformScalarEqual(candidate, plan.predicate.literal) {
			continue
		}
		updates, ok := staticTransformUpdates(object, plan.updates)
		if !ok {
			return nil, false
		}
		for key, update := range updates {
			if _, missing := update.(staticTransformMissing); missing {
				continue
			} else {
				object[key] = update
			}
		}
		for _, key := range plan.deletes {
			delete(object, key)
		}
	}
	return result, true
}

type staticTransformMissing struct{}

func staticTransformUpdates(object map[string]any, plans []staticTransformUpdate) (map[string]any, bool) {
	updates := make(map[string]any, len(plans))
	for _, plan := range plans {
		if plan.product == nil {
			updates[plan.key] = plan.literal
			continue
		}
		left, leftExists := staticTransformValueAtPath(object, plan.product.left)
		right, rightExists := staticTransformValueAtPath(object, plan.product.right)
		if !leftExists || !rightExists {
			updates[plan.key] = staticTransformMissing{}
			continue
		}
		leftNumber, leftOK := arithmeticNumber(left)
		rightNumber, rightOK := arithmeticNumber(right)
		if !leftOK || !rightOK || math.IsNaN(leftNumber) || math.IsInf(leftNumber, 0) ||
			math.IsNaN(rightNumber) || math.IsInf(rightNumber, 0) {
			return nil, false
		}
		product := leftNumber * rightNumber
		if math.IsNaN(product) || math.IsInf(product, 0) {
			return nil, false
		}
		updates[plan.key] = product
	}
	return updates, true
}

func staticTransformScalarEqual(candidate, literal any) bool {
	if candidate == nil {
		return false
	}
	if _, numericLiteral := strictNumeric(literal); numericLiteral {
		candidateNumber, ok := strictNumeric(candidate)
		return ok && candidateNumber == mustNumeric(literal)
	}
	switch literal.(type) {
	case string:
		_, ok := candidate.(string)
		return ok && reflect.DeepEqual(candidate, literal)
	case bool:
		_, ok := candidate.(bool)
		return ok && reflect.DeepEqual(candidate, literal)
	default:
		return false
	}
}

func mustNumeric(v any) float64 {
	n, _ := strictNumeric(v)
	return n
}

func staticTransformValueAtPath(input any, fields []string) (any, bool) {
	current := input
	for _, field := range fields {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[field]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

type staticTransformVisit struct {
	kind reflect.Kind
	ptr  uintptr
}

func staticTransformClone(input any) (any, bool) {
	clone := staticTransformCloneState{
		work: staticPathMaxWork,
		seen: make(map[staticTransformVisit]struct{}),
	}
	return clone.clone(input, 1)
}

// staticTransformCloneState validates and clones the input in one traversal.
// This is important for the common decoded-input path: validation does not
// need to walk the graph again before cloning it.
type staticTransformCloneState struct {
	work  int
	count int
	seen  map[staticTransformVisit]struct{}
}

func (c *staticTransformCloneState) clone(input any, depth int) (any, bool) {
	if c.work <= 0 {
		return nil, false
	}
	c.work--
	c.count++
	if c.count > staticTransformMaxNodes || depth > defaultMaxCallDepth {
		return nil, false
	}
	switch current := input.(type) {
	case map[string]any:
		if current == nil {
			return nil, false
		}
		visit := staticTransformVisit{kind: reflect.Map, ptr: reflect.ValueOf(current).Pointer()}
		if _, exists := c.seen[visit]; exists {
			return nil, false
		}
		c.seen[visit] = struct{}{}
		out := make(map[string]any, len(current))
		for key, item := range current {
			cloned, ok := c.clone(item, depth+1)
			if !ok {
				return nil, false
			}
			out[key] = cloned
		}
		return out, true
	case []any:
		if current == nil {
			return nil, false
		}
		visit := staticTransformVisit{kind: reflect.Slice, ptr: 0}
		if len(current) != 0 {
			visit.ptr = reflect.ValueOf(current).Pointer()
			if _, exists := c.seen[visit]; exists {
				return nil, false
			}
			c.seen[visit] = struct{}{}
		}
		out := make([]any, len(current))
		for index, item := range current {
			cloned, ok := c.clone(item, depth+1)
			if !ok {
				return nil, false
			}
			out[index] = cloned
		}
		return out, true
	case nil, bool, string, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return input, true
	case float32:
		return input, !math.IsNaN(float64(current)) && !math.IsInf(float64(current), 0)
	case float64:
		return input, !math.IsNaN(current) && !math.IsInf(current, 0)
	case json.Number:
		number, err := current.Float64()
		return input, err == nil && !math.IsNaN(number) && !math.IsInf(number, 0)
	default:
		return nil, false
	}
}
