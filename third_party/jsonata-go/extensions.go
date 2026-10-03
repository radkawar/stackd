package jsonata

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"unicode"

	"github.com/tiaanduplessis/jsonata-go/internal/evaluator"
)

// registrationNormalizationOperations bounds eager ownership copies before an
// evaluation runtime exists to provide its own operation budget.
const registrationNormalizationOperations = 100_000

var errRegistrationNormalizationBudget = errors.New("jsonata: variable normalization operation budget exceeded")

var packageRegistry struct {
	sync.RWMutex
	values map[string]any
}

// Extension describes a Go function exposed to JSONata.
type Extension struct {
	Func               interface{}
	UndefinedHandler   func([]reflect.Value) bool
	EvalContextHandler func([]reflect.Value) bool
}

// RegisterExts registers extensions for expressions compiled afterward.
func RegisterExts(exts map[string]Extension) error {
	values, err := processExtensions(exts)
	if err != nil {
		return err
	}
	packageRegistry.Lock()
	packageRegistry.values = mergeRegistry(packageRegistry.values, values)
	packageRegistry.Unlock()
	return nil
}

// RegisterVars registers variables for expressions compiled afterward.
func RegisterVars(vars map[string]interface{}) error {
	values, err := processVariables(vars)
	if err != nil {
		return err
	}
	packageRegistry.Lock()
	packageRegistry.values = mergeRegistry(packageRegistry.values, values)
	packageRegistry.Unlock()
	return nil
}

// RegisterExts registers extensions only for this compiled expression.
func (e *Expr) RegisterExts(exts map[string]Extension) error {
	if e == nil {
		return fmt.Errorf("jsonata: nil expression")
	}
	values, err := processExtensions(exts)
	if err != nil {
		return err
	}
	e.registryMu.Lock()
	e.registry = mergeRegistry(e.registry, values)
	e.registryMu.Unlock()
	return nil
}

// RegisterVars registers variables only for this compiled expression.
func (e *Expr) RegisterVars(vars map[string]interface{}) error {
	if e == nil {
		return fmt.Errorf("jsonata: nil expression")
	}
	values, err := processVariables(vars)
	if err != nil {
		return err
	}
	e.registryMu.Lock()
	e.registry = mergeRegistry(e.registry, values)
	e.registryMu.Unlock()
	return nil
}

// RegisterExts registers extensions for expressions subsequently compiled by
// this engine.
func (e *Engine) RegisterExts(exts map[string]Extension) error {
	if e == nil {
		return fmt.Errorf("jsonata: nil engine")
	}
	values, err := processExtensions(exts)
	if err != nil {
		return err
	}
	e.registryMu.Lock()
	e.registry = mergeRegistry(e.registry, values)
	e.registryMu.Unlock()
	return nil
}

// RegisterVars registers variables for expressions subsequently compiled by
// this engine.
func (e *Engine) RegisterVars(vars map[string]interface{}) error {
	if e == nil {
		return fmt.Errorf("jsonata: nil engine")
	}
	values, err := processVariables(vars)
	if err != nil {
		return err
	}
	e.registryMu.Lock()
	e.registry = mergeRegistry(e.registry, values)
	e.registryMu.Unlock()
	return nil
}

func processExtensions(exts map[string]Extension) (map[string]any, error) {
	names := sortedKeys(exts)
	values := make(map[string]any, len(exts))
	for _, name := range names {
		if !validRegistryName(name) {
			return nil, fmt.Errorf("%s is not a valid name", name)
		}
		extension := exts[name]
		binding, err := evaluator.NewReflectedExtension(name, evaluator.ReflectedExtension{
			Func:               extension.Func,
			UndefinedHandler:   extension.UndefinedHandler,
			EvalContextHandler: extension.EvalContextHandler,
		})
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid function: %s", name, err)
		}
		values[name] = binding
	}
	return values, nil
}

func processVariables(vars map[string]interface{}) (map[string]any, error) {
	names := sortedKeys(vars)
	values := make(map[string]any, len(vars))
	for _, name := range names {
		if !validRegistryName(name) {
			return nil, fmt.Errorf("%s is not a valid name", name)
		}
		operationsRemaining := registrationNormalizationOperations
		normalized, err := evaluator.NormalizeExtensionBindingSafe(vars[name], 100, func() error {
			operationsRemaining--
			if operationsRemaining < 0 {
				return errRegistrationNormalizationBudget
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid variable: %w", name, publicEvaluationError(err))
		}
		values[name] = normalized
	}
	return values, nil
}

func sortedKeys[T any](values map[string]T) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func validRegistryName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func mergeRegistry(base, overrides map[string]any) map[string]any {
	if len(base) == 0 && len(overrides) == 0 {
		return nil
	}
	merged := make(map[string]any, len(base)+len(overrides))
	for name, value := range base {
		merged[name] = value
	}
	for name, value := range overrides {
		merged[name] = value
	}
	return merged
}

func packageRegistrySnapshot() map[string]any {
	packageRegistry.RLock()
	snapshot := packageRegistry.values
	packageRegistry.RUnlock()
	return snapshot
}

func (e *Expr) registrySnapshot() map[string]any {
	e.registryMu.RLock()
	snapshot := e.registry
	e.registryMu.RUnlock()
	return snapshot
}

func (e *Engine) registrySnapshot() map[string]any {
	e.registryMu.RLock()
	snapshot := e.registry
	e.registryMu.RUnlock()
	return snapshot
}

func evaluationBindings(registry, call map[string]any) map[string]any {
	if len(call) == 0 {
		return registry
	}
	return mergeRegistry(registry, call)
}
