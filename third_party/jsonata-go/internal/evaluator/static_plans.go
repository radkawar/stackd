package evaluator

import (
	"math"
	"strings"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// StaticSumPlan describes a narrow, immutable reduction over ordinary decoded
// JSON input. It is intentionally kept separate from the general evaluator:
// the plan is used only when every value that could affect the result is
// scalar, finite, and represented by the same JSON-compatible Go types that
// the normal evaluator accepts.
type StaticSumPlan struct {
	mode       staticSumMode
	path       []string
	collection []string
	predicate  []staticSumPredicate
	projection staticSumProjection
}

type staticSumMode uint8

const (
	staticSumPath staticSumMode = iota + 1
	staticSumFilter
	staticSumProjectedPath
)

type staticSumPredicate struct {
	path    []string
	literal any
	truthy  bool
}

type staticSumProjection struct {
	left  []string
	right []string
}

// StaticComparisonPlan describes a scalar field comparison whose operands do
// not depend on the evaluation environment. The plan is immutable after
// construction and is safe to share between concurrent evaluations.
type StaticComparisonPlan struct {
	path            []string
	registryAliases []string
	operator        string
	literal         any
}

// BuildStaticComparisonPlan recognizes only equality and inequality between a
// static field path and a scalar literal. All other comparisons use the full
// evaluator because their coercion and sequence rules are broader.
func BuildStaticComparisonPlan(n syntax.Node) *StaticComparisonPlan {
	binary, ok := n.(syntax.Binary)
	if !ok || (binary.Op != "=" && binary.Op != "!=") {
		return nil
	}
	if path, ok := staticPathFields(binary.Left); ok {
		if literal, ok := staticScalarLiteral(binary.Right); ok {
			return newStaticComparisonPlan(path, binary.Op, literal)
		}
	}
	if path, ok := staticPathFields(binary.Right); ok {
		if literal, ok := staticScalarLiteral(binary.Left); ok {
			return newStaticComparisonPlan(path, binary.Op, literal)
		}
	}
	return nil
}

func newStaticComparisonPlan(path []string, operator string, literal any) *StaticComparisonPlan {
	if len(path) == 0 || len(path) > staticPathMaxFields {
		return nil
	}
	return &StaticComparisonPlan{
		path:            append([]string(nil), path...),
		registryAliases: staticRegistryAliases(path),
		operator:        operator,
		literal:         literal,
	}
}

// RegistryConflict reports whether a registered name can change the meaning
// of a field in this plan. Unrelated extensions do not invalidate it.
func (p *StaticComparisonPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	return staticPathsRegistryConflict(registry, p.registryAliases, p.path)
}

// EvalStaticComparison returns ok=false whenever normalisation or JSONata
// sequence semantics could affect the answer. In that case the caller must
// evaluate the original syntax tree.
func EvalStaticComparison(plan *StaticComparisonPlan, input any) (any, bool) {
	if plan == nil {
		return nil, false
	}
	valueAtPath, found, valid := staticPathSelectAndValidate(input, plan.path, defaultMaxCallDepth)
	if !valid || !found {
		return nil, false
	}
	if _, ambiguous := valueAtPath.(map[string]any); ambiguous {
		return nil, false
	}
	if _, ambiguous := valueAtPath.([]any); ambiguous {
		return nil, false
	}
	if !staticScalarTypesCompatible(valueAtPath, plan.literal) {
		return nil, false
	}
	matched := staticScalarEqual(valueAtPath, plan.literal)
	if plan.operator == "!=" {
		matched = !matched
	}
	return matched, true
}

// StaticFilterProjectPlan describes the common JSONata shape
// `items[field = literal].projection`. It deliberately excludes path
// flattening, dynamic bindings, and all non-scalar intermediate values.
type StaticFilterProjectPlan struct {
	collection      []string
	predicate       []string
	projection      []string
	registryAliases []string
	literal         any
}

// BuildStaticFilterProjectPlan recognizes one static equality predicate and a
// static scalar projection. The AST shape is the selector followed by a path
// step, which is the parser representation of the documented form.
func BuildStaticFilterProjectPlan(n syntax.Node) *StaticFilterProjectPlan {
	path, ok := n.(syntax.Binary)
	if !ok || path.Op != "." {
		return nil
	}
	selector, ok := path.Left.(syntax.Selector)
	if !ok || selector.Index == nil {
		return nil
	}
	collection, ok := staticPathFields(selector.Base)
	if !ok {
		return nil
	}
	predicate, literal, ok := staticEqualityPredicate(selector.Index)
	if !ok {
		return nil
	}
	projection, ok := staticPathFields(path.Right)
	if !ok {
		return nil
	}
	if len(collection) == 0 || len(predicate) == 0 || len(projection) == 0 ||
		len(collection)+len(predicate)+len(projection) > staticPathMaxFields {
		return nil
	}
	return &StaticFilterProjectPlan{
		collection:      append([]string(nil), collection...),
		predicate:       append([]string(nil), predicate...),
		projection:      append([]string(nil), projection...),
		registryAliases: staticRegistryAliases(collection, predicate, projection),
		literal:         literal,
	}
}

func staticEqualityPredicate(n syntax.Node) ([]string, any, bool) {
	binary, ok := n.(syntax.Binary)
	if !ok || binary.Op != "=" {
		return nil, nil, false
	}
	path, pathOK := staticPathFields(binary.Left)
	literal, literalOK := staticScalarLiteral(binary.Right)
	if !pathOK || !literalOK {
		return nil, nil, false
	}
	return path, literal, true
}

func (p *StaticFilterProjectPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	return staticPathsRegistryConflict(registry, p.registryAliases, p.collection, p.predicate, p.projection)
}

// EvalStaticFilterProject preserves JSONata's singleton collapse: a single
// projected match is scalar, while multiple matches are returned as an array
// at the public boundary. Empty or ambiguous matches use the normal evaluator.
func EvalStaticFilterProject(plan *StaticFilterProjectPlan, input any) (any, bool) {
	if plan == nil || !staticPathInputSafe(input, defaultMaxCallDepth) {
		return nil, false
	}
	return evalStaticFilterProjectValidated(plan, input)
}

func evalStaticFilterProjectValidated(plan *StaticFilterProjectPlan, input any) (any, bool) {
	if plan == nil {
		return nil, false
	}
	collection, ok := staticValueAtPath(input, plan.collection)
	if !ok {
		return nil, false
	}
	items, ok := collection.([]any)
	if !ok {
		return nil, false
	}
	projected := make([]any, 0, len(items))
	for _, item := range items {
		if _, isMap := item.(map[string]any); !isMap {
			return nil, false
		}
		predicate, ok := staticScalarAtPath(item, plan.predicate)
		if !ok {
			return nil, false
		}
		if !staticScalarTypesCompatible(predicate, plan.literal) {
			return nil, false
		}
		if !staticScalarEqual(predicate, plan.literal) {
			continue
		}
		result, ok := staticScalarAtPath(item, plan.projection)
		if !ok {
			return nil, false
		}
		public, ok := value.Public(result)
		if !ok {
			return nil, false
		}
		projected = append(projected, public)
	}
	if len(projected) == 0 {
		return nil, false
	}
	if len(projected) == 1 {
		return projected[0], true
	}
	return projected, true
}

func staticScalarLiteral(n syntax.Node) (any, bool) {
	literal, ok := n.(syntax.Literal)
	if !ok {
		return nil, false
	}
	switch literal.Kind {
	case syntax.String:
		_, ok := literal.Value.(string)
		return literal.Value, ok
	case syntax.Number:
		var parsed any
		var err error
		if literal.NumberParsed {
			parsed = literal.NumberValue
		} else {
			text, ok := literal.Value.(string)
			if !ok {
				return nil, false
			}
			parsed, err = parseNumber(text)
			if err != nil {
				return nil, false
			}
		}
		number, ok := numeric(parsed)
		return parsed, ok && !math.IsNaN(number) && !math.IsInf(number, 0)
	case syntax.True, syntax.False:
		return literal.Kind == syntax.True, true
	case syntax.Null:
		return nil, true
	default:
		return nil, false
	}
}

func staticFieldsRegistryConflict(fields []string, registry map[string]any) bool {
	for _, field := range fields {
		if _, exists := registry[field]; exists {
			return true
		}
		if _, exists := registry["$"+field]; exists {
			return true
		}
	}
	return false
}

func staticRegistryAliases(paths ...[]string) []string {
	count := 0
	for _, path := range paths {
		count += len(path)
	}
	aliases := make([]string, 0, count)
	for _, path := range paths {
		for _, field := range path {
			aliases = append(aliases, "$"+field)
		}
	}
	return aliases
}

func staticPathsRegistryConflict(registry map[string]any, aliases []string, paths ...[]string) bool {
	index := 0
	for _, path := range paths {
		for _, field := range path {
			if _, exists := registry[field]; exists {
				return true
			}
			if _, exists := registry[aliases[index]]; exists {
				return true
			}
			index++
		}
	}
	return false
}

func staticValueAtPath(input any, fields []string) (any, bool) {
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

func staticScalarAtPath(input any, fields []string) (any, bool) {
	current, ok := staticValueAtPath(input, fields)
	if !ok || current == nil {
		return nil, false
	}
	switch current.(type) {
	case map[string]any, []any, value.Array, value.OrderedObject, sequence:
		return nil, false
	}
	return current, true
}

func staticScalarTypesCompatible(valueAtPath, literal any) bool {
	if literal == nil || valueAtPath == nil {
		return false
	}
	if _, literalNumeric := staticLiteralNumeric(literal); literalNumeric {
		_, valueNumeric := numeric(valueAtPath)
		return valueNumeric
	}
	switch literal.(type) {
	case string:
		_, ok := valueAtPath.(string)
		return ok
	case bool:
		_, ok := valueAtPath.(bool)
		return ok
	default:
		return false
	}
}

// staticLiteralNumeric avoids repeatedly asking strconv to parse literals
// which are plainly non-numeric. Invalid ParseFloat errors allocate, and the
// equality/filter plans evaluate the same literal once per input item. The
// leading-byte check is only a fast rejection; numeric() remains the
// authority for all potentially numeric forms, preserving its coercion rules.
func staticLiteralNumeric(literal any) (float64, bool) {
	text, isString := literal.(string)
	if !isString {
		return numeric(literal)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, false
	}
	first := text[0]
	if (first < '0' || first > '9') && first != '+' && first != '-' && first != '.' && first != 'I' && first != 'N' {
		return 0, false
	}
	return numeric(text)
}

func staticScalarEqual(a, b any) bool {
	if left, ok := a.(string); ok {
		right, rightOK := b.(string)
		return rightOK && left == right
	}
	if left, ok := a.(bool); ok {
		right, rightOK := b.(bool)
		return rightOK && left == right
	}
	left, leftOK := strictNumeric(a)
	right, rightOK := strictNumeric(b)
	return leftOK && rightOK && left == right
}

// BuildStaticSumPlan recognises only calls to the built-in $sum with a static
// path, or a static collection selector followed by a scalar path/product.
// No source-text matching is used: all decisions are made from the parsed AST.
func BuildStaticSumPlan(n syntax.Node) *StaticSumPlan {
	call, ok := n.(syntax.Call)
	if !ok || call.Partial || len(call.Args) != 1 {
		return nil
	}
	function, ok := call.Function.(syntax.Variable)
	if !ok || function.Kind != syntax.VariableNamed || function.Name != "$sum" {
		return nil
	}
	argument := call.Args[0]

	if path, ok := staticPathFields(argument); ok && len(path) > 0 && len(path) <= staticPathMaxFields {
		return &StaticSumPlan{mode: staticSumPath, path: append([]string(nil), path...)}
	}

	dot, ok := argument.(syntax.Binary)
	if !ok || dot.Op != "." {
		return nil
	}
	if base, baseOK := staticPathFields(dot.Left); baseOK {
		if projection, projectionOK := parseStaticSumProjection(dot.Right); projectionOK && len(projection.right) > 0 {
			if len(base)+len(projection.left)+len(projection.right) <= staticPathMaxFields {
				return &StaticSumPlan{
					mode:       staticSumProjectedPath,
					collection: append([]string(nil), base...),
					projection: projection,
				}
			}
		}
	}
	selector, ok := dot.Left.(syntax.Selector)
	if !ok || selector.Index == nil {
		return nil
	}
	collection, ok := staticPathFields(selector.Base)
	if !ok || len(collection) == 0 {
		return nil
	}
	predicate, ok := staticSumPredicates(selector.Index)
	if !ok {
		return nil
	}
	projection, ok := parseStaticSumProjection(dot.Right)
	if !ok || len(collection)+len(projection.left)+len(projection.right) > staticPathMaxFields {
		return nil
	}
	for _, item := range predicate {
		if len(collection)+len(projection.left)+len(projection.right)+len(item.path) > staticPathMaxFields {
			return nil
		}
	}
	return &StaticSumPlan{
		mode:       staticSumFilter,
		collection: append([]string(nil), collection...),
		predicate:  predicate,
		projection: projection,
	}
}

func (p *StaticSumPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	if _, exists := registry["sum"]; exists {
		return true
	}
	if _, exists := registry["$sum"]; exists {
		return true
	}
	if staticFieldsRegistryConflict(p.path, registry) ||
		staticFieldsRegistryConflict(p.collection, registry) ||
		staticFieldsRegistryConflict(p.projection.left, registry) ||
		staticFieldsRegistryConflict(p.projection.right, registry) {
		return true
	}
	for _, predicate := range p.predicate {
		if staticFieldsRegistryConflict(predicate.path, registry) {
			return true
		}
	}
	return false
}

func staticSumPredicates(n syntax.Node) ([]staticSumPredicate, bool) {
	if binary, ok := n.(syntax.Binary); ok && binary.Op == "and" {
		left, ok := staticSumPredicates(binary.Left)
		if !ok {
			return nil, false
		}
		right, ok := staticSumPredicates(binary.Right)
		if !ok {
			return nil, false
		}
		return append(left, right...), true
	}
	if binary, ok := n.(syntax.Binary); ok && binary.Op == "=" {
		path, pathOK := staticPathFields(binary.Left)
		literal, literalOK := staticScalarLiteral(binary.Right)
		if !pathOK || !literalOK || literal == nil {
			return nil, false
		}
		return []staticSumPredicate{{path: append([]string(nil), path...), literal: literal}}, true
	}
	name, ok := n.(syntax.Name)
	if !ok || name.Value == "" {
		return nil, false
	}
	path, ok := staticPathFields(name)
	if !ok {
		return nil, false
	}
	return []staticSumPredicate{{path: append([]string(nil), path...), truthy: true}}, true
}

func parseStaticSumProjection(n syntax.Node) (staticSumProjection, bool) {
	if path, ok := staticPathFields(n); ok && len(path) > 0 {
		return staticSumProjection{left: append([]string(nil), path...)}, true
	}
	binary, ok := n.(syntax.Binary)
	if !ok || binary.Op != "*" {
		return staticSumProjection{}, false
	}
	left, leftOK := staticPathFields(binary.Left)
	right, rightOK := staticPathFields(binary.Right)
	if !leftOK || !rightOK || len(left) == 0 || len(right) == 0 {
		return staticSumProjection{}, false
	}
	return staticSumProjection{left: append([]string(nil), left...), right: append([]string(nil), right...)}, true
}

// EvalStaticSum returns ok=false for an empty/missing sequence or whenever a
// full evaluation may observe a different error or sequence result. This is
// deliberate: the public fast-path interface cannot represent ErrUndefined,
// so ambiguous cases must use the original evaluator.
func EvalStaticSum(plan *StaticSumPlan, input any) (any, bool) {
	if plan == nil || !staticPathInputSafe(input, defaultMaxCallDepth) {
		return nil, false
	}
	return evalStaticSumValidated(plan, input)
}

func evalStaticSumValidated(plan *StaticSumPlan, input any) (any, bool) {
	if plan == nil {
		return nil, false
	}
	if plan.mode == staticSumProjectedPath {
		return evalStaticSumProjectedPath(input, plan)
	}
	work := staticPathMaxWork
	var values []any
	var ok bool
	if plan.mode == staticSumPath {
		values, ok = staticSumPathValues(input, plan.path, &work)
		if ok {
			values, ok = staticSumFlattenArrays(values, &work)
		}
	} else {
		values, ok = staticSumFilteredValues(input, plan, &work)
	}
	if !ok || len(values) == 0 {
		return nil, false
	}
	var total float64
	for _, item := range values {
		number, numericOK := strictNumeric(item)
		if !numericOK || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, false
		}
		total += number
		if math.IsNaN(total) || math.IsInf(total, 0) {
			return nil, false
		}
	}
	return total, true
}

// evalStaticSumProjectedPath streams the projected leaves directly into the
// reduction. The materialized path and flattening slices are observable only
// internally, so retaining their exact traversal and work accounting while
// avoiding them preserves the fallback boundary and result semantics.
func evalStaticSumProjectedPath(input any, plan *StaticSumPlan) (float64, bool) {
	work := staticPathMaxWork
	var total float64
	count := 0
	var visit func(any, []string) bool
	visit = func(current any, fields []string) bool {
		if !staticSumConsume(&work) {
			return false
		}
		if len(fields) == 0 {
			// staticSumPathValues leaves the terminal array grouped. Flattening
			// consumes once for that group, then once per member; the projected
			// item loop consumes once per member as well.
			if !staticSumConsume(&work) {
				return false
			}
			project := func(item any) bool {
				if !staticSumConsume(&work) {
					return false
				}
				object, ok := item.(map[string]any)
				if !ok {
					return false
				}
				projected, ok := staticSumProject(object, plan.projection, &work)
				if !ok {
					return false
				}
				number, ok := projected.(float64)
				if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
					return false
				}
				total += number
				if math.IsNaN(total) || math.IsInf(total, 0) {
					return false
				}
				count++
				return true
			}
			if items, ok := current.([]any); ok {
				for _, item := range items {
					if !project(item) {
						return false
					}
				}
				return true
			}
			return project(current)
		}
		switch value := current.(type) {
		case []any:
			for _, item := range value {
				if !visit(item, fields) {
					return false
				}
			}
			return true
		case map[string]any:
			item, ok := value[fields[0]]
			return ok && visit(item, fields[1:])
		default:
			return false
		}
	}
	if !visit(input, plan.collection) || count == 0 {
		return 0, false
	}
	return total, true
}

func staticSumProjectedPathValues(input any, plan *StaticSumPlan, work *int) ([]any, bool) {
	collections, ok := staticSumPathValues(input, plan.collection, work)
	if !ok {
		return nil, false
	}
	items, ok := staticSumFlattenArrays(collections, work)
	if !ok || len(items) == 0 {
		return nil, false
	}
	values := make([]any, 0, len(items))
	for _, item := range items {
		if !staticSumConsume(work) {
			return nil, false
		}
		if _, ok := item.(map[string]any); !ok {
			return nil, false
		}
		projected, ok := staticSumProject(item, plan.projection, work)
		if !ok {
			return nil, false
		}
		values = append(values, projected)
	}
	return values, true
}

func staticSumPathValues(input any, fields []string, work *int) ([]any, bool) {
	if len(fields) == 0 {
		if !staticSumConsume(work) {
			return nil, false
		}
		// Keep the terminal array boundary. The $sum signature accepts one
		// array level, while nested arrays remain non-numeric and must fall
		// back to the full evaluator rather than being recursively flattened.
		return []any{input}, true
	}
	if !staticSumConsume(work) {
		return nil, false
	}
	switch current := input.(type) {
	case []any:
		var out []any
		for _, item := range current {
			values, ok := staticSumPathValues(item, fields, work)
			if !ok {
				return nil, false
			}
			out = append(out, values...)
		}
		return out, true
	case map[string]any:
		item, ok := current[fields[0]]
		if !ok {
			return nil, false
		}
		return staticSumPathValues(item, fields[1:], work)
	default:
		return nil, false
	}
}

func staticSumFilteredValues(input any, plan *StaticSumPlan, work *int) ([]any, bool) {
	collections, ok := staticSumPathValues(input, plan.collection, work)
	if !ok {
		return nil, false
	}
	items, ok := staticSumFlattenArrays(collections, work)
	if !ok || len(items) == 0 {
		return nil, false
	}
	values := make([]any, 0, len(items))
	for _, item := range items {
		if !staticSumConsume(work) {
			return nil, false
		}
		if _, ok := item.(map[string]any); !ok {
			return nil, false
		}
		matched, ok := staticSumMatches(item, plan.predicate)
		if !ok {
			return nil, false
		}
		if !matched {
			continue
		}
		projected, ok := staticSumProject(item, plan.projection, work)
		if !ok {
			return nil, false
		}
		values = append(values, projected)
	}
	return values, true
}

func staticSumMatches(item any, predicates []staticSumPredicate) (bool, bool) {
	for _, predicate := range predicates {
		valueAtPath, ok := staticScalarAtPath(item, predicate.path)
		if !ok {
			return false, false
		}
		if predicate.truthy {
			active, ok := valueAtPath.(bool)
			if !ok {
				return false, false
			}
			if !active {
				return false, true
			}
			continue
		}
		if !staticScalarTypesCompatible(valueAtPath, predicate.literal) {
			return false, false
		}
		if !staticScalarEqual(valueAtPath, predicate.literal) {
			return false, true
		}
	}
	return true, true
}

func staticSumProject(item any, projection staticSumProjection, work *int) (any, bool) {
	left, ok := staticScalarAtPath(item, projection.left)
	if !ok {
		return nil, false
	}
	leftNumber, ok := strictNumeric(left)
	if !ok || math.IsNaN(leftNumber) || math.IsInf(leftNumber, 0) {
		return nil, false
	}
	if len(projection.right) == 0 {
		return leftNumber, true
	}
	right, ok := staticScalarAtPath(item, projection.right)
	if !ok {
		return nil, false
	}
	rightNumber, ok := strictNumeric(right)
	if !ok || math.IsNaN(rightNumber) || math.IsInf(rightNumber, 0) {
		return nil, false
	}
	if !staticSumConsume(work) {
		return nil, false
	}
	product := leftNumber * rightNumber
	if math.IsNaN(product) || math.IsInf(product, 0) {
		return nil, false
	}
	return product, true
}

func staticSumFlattenArrays(values []any, work *int) ([]any, bool) {
	out := make([]any, 0, len(values))
	appendValue := func(item any) bool {
		if !staticSumConsume(work) {
			return false
		}
		switch current := item.(type) {
		case []any:
			for _, nested := range current {
				if !staticSumConsume(work) {
					return false
				}
				out = append(out, nested)
			}
		default:
			out = append(out, item)
		}
		return true
	}
	for _, item := range values {
		if !appendValue(item) {
			return nil, false
		}
	}
	return out, true
}

func staticSumConsume(work *int) bool {
	if *work <= 0 {
		return false
	}
	*work--
	return true
}
