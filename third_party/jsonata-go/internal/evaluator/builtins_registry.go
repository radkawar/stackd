package evaluator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

type builtinFunc func(state, []any) (any, error)

type builtinSpec struct {
	name            string
	signature       string
	parsedSignature *functionSignature
	implementation  builtinFunc
}

type builtinValue struct {
	spec builtinSpec
}

func (f builtinValue) callableName() string { return f.spec.name }

func (f builtinValue) invoke(st state, args []any) (any, error) {
	if f.spec.implementation == nil {
		return nil, runtimeError{code: "T1008", msg: "attempted to call a non-function"}
	}
	prepared := args
	if f.spec.signature != "" {
		signature, err := builtinSignature(f.spec)
		if err != nil {
			return nil, runtimeError{code: "T0410", msg: err.Error()}
		}
		if fixedBuiltinArityExceeded(signature, len(args)) {
			return nil, runtimeError{code: "T0410", msg: "function has too many arguments", token: f.spec.name}
		}
		prepared, err = prepareBuiltinSignatureArgs(signature, args, signatureContext(signature, st.current), st.runtime)
		if err != nil {
			return nil, withRuntimeToken(err, f.spec.name)
		}
	}
	if err := rejectUTF16StringArguments(f.spec.name, prepared); err != nil {
		return nil, withRuntimeToken(err, f.spec.name)
	}
	return f.spec.implementation(st, prepared)
}

func fixedBuiltinArityExceeded(signature functionSignature, count int) bool {
	if count <= len(signature.params) {
		return false
	}
	for _, param := range signature.params {
		if param.variadic {
			return false
		}
	}
	return true
}

// builtinKnownNames is the canonical catalog. Implementations are overlaid by
// family-owned specs so that adding a family does not require editing this
// registry file.
var builtinKnownNames = []string{
	"abs", "append", "assert", "average", "base64decode", "base64encode",
	"boolean", "ceil", "clone", "contains", "count", "decodeUrl",
	"decodeUrlComponent", "distinct", "each", "encodeUrl",
	"encodeUrlComponent", "error", "eval", "exists", "filter", "floor",
	"formatBase", "formatInteger", "formatNumber", "fromMillis", "join",
	"keys", "length", "lowercase", "lookup", "map", "match", "max",
	"merge", "millis", "min", "not", "now", "number", "pad",
	"parseInteger", "power", "random", "reduce", "replace", "reverse",
	"round", "shuffle", "sift", "single", "sort", "split", "spread",
	"sqrt", "string", "substring", "substringAfter", "substringBefore",
	"sum", "toMillis", "trim", "type", "uppercase", "zip",
}

func phase3BuiltinSpecs() []builtinSpec {
	return []builtinSpec{
		{name: "append", signature: "<xx:a>", implementation: builtinAppend},
		{name: "eval", signature: "<sj?:x>", implementation: builtinEval},
	}
}

func builtinCatalog() ([]builtinSpec, error) {
	specs := make([]builtinSpec, len(builtinKnownNames))
	positions := make(map[string]int, len(builtinKnownNames))
	for index, name := range builtinKnownNames {
		if _, exists := positions[name]; exists {
			return nil, fmt.Errorf("duplicate builtin name %q", name)
		}
		positions[name] = index
		specs[index] = builtinSpec{name: name}
	}

	seen := make(map[string]string)
	families := []struct {
		name  string
		specs []builtinSpec
	}{
		{name: "phase3", specs: phase3BuiltinSpecs()},
		{name: "scalar", specs: scalarBuiltinSpecs},
		{name: "string", specs: stringBuiltinSpecs},
		{name: "collection", specs: collectionBuiltinSpecs},
		{name: "regex", specs: regexBuiltinSpecs},
		{name: "format", specs: formatBuiltinSpecs},
		{name: "date", specs: dateBuiltinSpecs},
		{name: "higher-order", specs: hofBuiltinSpecs},
		{name: "misc", specs: miscBuiltinSpecs},
	}
	for _, family := range families {
		for _, spec := range family.specs {
			if spec.name == "" {
				return nil, fmt.Errorf("%s builtin implementation has empty name", family.name)
			}
			position, known := positions[spec.name]
			if !known {
				return nil, fmt.Errorf("unknown %s builtin implementation %q", family.name, spec.name)
			}
			if previous, duplicate := seen[spec.name]; duplicate {
				return nil, fmt.Errorf("duplicate builtin implementation %q in %s and %s", spec.name, previous, family.name)
			}
			seen[spec.name] = family.name
			specs[position] = spec
		}
	}
	for index := range specs {
		if err := prepareBuiltinSignature(&specs[index]); err != nil {
			return nil, err
		}
	}
	return specs, nil
}

var builtinRegistry struct {
	once     sync.Once
	registry map[string]builtinSpec
	err      error
}

func builtinRegistryData() (map[string]builtinSpec, error) {
	builtinRegistry.once.Do(func() {
		catalog, err := builtinCatalog()
		if err != nil {
			builtinRegistry.err = err
			return
		}
		builtinRegistry.registry, builtinRegistry.err = buildBuiltinRegistry(catalog)
	})
	return builtinRegistry.registry, builtinRegistry.err
}

func buildBuiltinRegistry(specs []builtinSpec) (map[string]builtinSpec, error) {
	registry := make(map[string]builtinSpec, len(specs))
	for _, spec := range specs {
		if spec.name == "" {
			return nil, fmt.Errorf("builtin name cannot be empty")
		}
		if spec.implementation != nil && !canonicalBuiltinName(spec.name) {
			return nil, fmt.Errorf("unknown builtin implementation %q", spec.name)
		}
		if _, exists := registry[spec.name]; exists {
			return nil, fmt.Errorf("duplicate builtin name %q", spec.name)
		}
		if err := prepareBuiltinSignature(&spec); err != nil {
			return nil, err
		}
		registry[spec.name] = spec
	}
	return registry, nil
}

// prepareBuiltinSignature parses a signature while the immutable builtin
// catalog is being assembled. The parsed tree is shared by all values made
// from the registry and is never modified after construction.
func prepareBuiltinSignature(spec *builtinSpec) error {
	if spec.signature == "" || spec.parsedSignature != nil {
		return nil
	}
	parsed, err := parseFunctionSignature(spec.signature)
	if err != nil {
		return err
	}
	spec.parsedSignature = &parsed
	return nil
}

func builtinSignature(spec builtinSpec) (functionSignature, error) {
	if spec.parsedSignature != nil {
		return *spec.parsedSignature, nil
	}
	return parseFunctionSignature(spec.signature)
}

func canonicalBuiltinName(name string) bool {
	for _, known := range builtinKnownNames {
		if name == known {
			return true
		}
	}
	return false
}

func builtinFor(name string) (callableValue, bool) {
	if len(name) < 2 || name[0] != '$' {
		return nil, false
	}
	spec, ok := builtinSpecFor(name[1:])
	if !ok || spec.implementation == nil {
		return nil, false
	}
	return builtinValue{spec: spec}, true
}

func knownBareBuiltin(name string) bool {
	_, ok := builtinSpecFor(name)
	return ok
}

func builtinSpecFor(name string) (builtinSpec, bool) {
	registry, err := builtinRegistryData()
	if err != nil {
		return builtinSpec{}, false
	}
	spec, ok := registry[name]
	return spec, ok
}

func builtinAppend(st state, args []any) (any, error) {
	if len(args) != 2 {
		return nil, functionArityError("$append", 2, len(args))
	}
	total := itemsLength(args[0]) + itemsLength(args[1])
	if st.runtime != nil {
		if err := st.runtime.check(); err != nil {
			return nil, err
		}
		if !value.IsUndefined(args[0]) && !value.IsUndefined(args[1]) {
			if err := st.runtime.checkSequenceLengthAttempted(total); err != nil {
				return nil, err
			}
		}
	}
	left, right := items(args[0]), items(args[1])
	capacity := bulkOperationCapacity(total, st.runtime)
	result := make([]any, 0, capacity)
	count := 0
	for _, input := range [][]any{left, right} {
		for _, item := range input {
			if st.runtime != nil && count%bulkOperationCheckStride == 0 {
				if err := st.runtime.check(); err != nil {
					return nil, err
				}
			}
			result = append(result, item)
			count++
		}
	}
	if len(result) == 1 {
		return result[0], nil
	}
	return value.Array{Items: result}, nil
}

func builtinEval(st state, args []any) (any, error) {
	if len(args) < 1 || len(args) > 2 {
		return nil, functionArityError("$eval", 1, len(args))
	}
	source, ok := collapse(args[0]).(string)
	if !ok {
		return value.Undefined, nil
	}
	parsed, parseErr := syntax.Parse(source)
	if parseErr != nil {
		return nil, runtimeError{code: "D3120", msg: parseErr.Error()}
	}
	current := st.current
	if len(args) == 2 && !value.IsUndefined(args[1]) {
		current = collapse(args[1])
	}
	dynamicState := st
	dynamicState.current = current
	dynamicState.tail = false
	result, err := evalWithBindings(parsed, dynamicState)
	if err == nil {
		return result, nil
	}
	if value.IsUndefined(result) {
		return result, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	var runtimeErr runtimeError
	if errors.As(err, &runtimeErr) && (runtimeErr.code == "U1001" || runtimeErr.cause != nil) {
		return nil, err
	}
	return nil, runtimeError{code: "D3121", msg: err.Error(), cause: err}
}
