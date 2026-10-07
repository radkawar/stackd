package cloudformation

import (
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type resourceSchemaMode uint8

const (
	resourceCreateSchema resourceSchemaMode = iota
	resourceStringLimitsSchema
	resourceTemplateSchema
	resourceUpdateSchema
)

type resourceSchemaKey struct {
	typeName string
	mode     resourceSchemaMode
}

type compiledResourceSchema struct {
	once   sync.Once
	schema *jsonschema.Schema
	err    error
}

// The cache is bounded by the generated built-in type inventory. Schemas are
// compiled once, on first use, and never resolve host files or remote URLs.
var compiledResourceSchemas sync.Map

type resourceSchemaLoader struct{}

func (resourceSchemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external registry schema reference is unavailable: %s", url)
}

func validateCompiledResourceSchema(typeName string, properties Properties, limits bool) error {
	mode := resourceCreateSchema
	if limits {
		mode = resourceStringLimitsSchema
	}
	return validateCompiledResourceSchemaMode(typeName, properties, mode)
}

func validateCompiledResourceSchemaMode(typeName string, properties Properties, mode resourceSchemaMode) error {
	contract, known := resourceSchemas[typeName]
	if !known {
		return nil
	}
	definition := contract.StructureJSON
	switch mode {
	case resourceStringLimitsSchema:
		definition = contract.StringLimitsJSON
	case resourceTemplateSchema:
		if contract.TemplateStructureJSON != "" {
			definition = contract.TemplateStructureJSON
		} else {
			mode = resourceCreateSchema
		}
	case resourceUpdateSchema:
		if contract.UpdateStructureJSON != "" {
			definition = contract.UpdateStructureJSON
		} else {
			mode = resourceCreateSchema
		}
	}
	if definition == "" {
		return fmt.Errorf("resource type %s has no generated structure contract", typeName)
	}
	key := resourceSchemaKey{typeName: typeName, mode: mode}
	cached, found := compiledResourceSchemas.Load(key)
	if !found {
		cached, _ = compiledResourceSchemas.LoadOrStore(key, &compiledResourceSchema{})
	}
	compiled := cached.(*compiledResourceSchema)
	compiled.once.Do(func() {
		document, err := jsonschema.UnmarshalJSON(strings.NewReader(definition))
		if err != nil {
			compiled.err = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft7)
		compiler.UseLoader(resourceSchemaLoader{})
		const location = "urn:stackd:cloudformation:structure"
		if err := compiler.AddResource(location, document); err != nil {
			compiled.err = err
			return
		}
		compiled.schema, compiled.err = compiler.Compile(location)
	})
	if compiled.err != nil {
		return fmt.Errorf("resource type %s has invalid generated schema: %w", typeName, compiled.err)
	}
	if err := compiled.schema.Validate(map[string]any(properties)); err != nil {
		return fmt.Errorf("resource type %s violates registry properties: %w", typeName, err)
	}
	return nil
}
