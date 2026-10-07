package cloudformation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// resourceSchema contains authoritative registry contracts, not owner behavior.
// Identifier paths use the registry's /properties root and * array components.
type resourceSchema struct {
	Version, ReplacementStrategy                                                string
	Properties, Required, CreateOnly, ReadOnly, PrimaryIdentifier               []string
	AdditionalIdentifiers                                                       [][]string
	StructureJSON, StringLimitsJSON, TemplateStructureJSON, UpdateStructureJSON string
	Tagging                                                                     resourceTaggingSchema
	HandlerPermissions                                                          map[string][]string
}
type resourceTaggingSchema struct {
	Taggable, TagOnCreate, TagUpdatable, CloudFormationSystemTags bool
	TagProperty                                                   string
	Permissions                                                   []string
}

// ErrCreateOnly marks immutable property mutation for Cloud Control admission.
var ErrCreateOnly = errors.New("create-only property cannot be updated")

func validateResourceStructure(resource TemplateResource) error {
	return validateResourceProperties(resource.Type, resource.Properties, resourceTemplateSchema)
}

// ValidateResourceProperties checks the captured registry's property, required
// and read-only contracts. Handlers still validate supported values and effects.
// Unknown types belong to explicitly injected handlers and have no registry facts.
func ValidateResourceProperties(typeName string, properties Properties) error {
	return validateResourceProperties(typeName, properties, resourceCreateSchema)
}

func validateResourceProperties(typeName string, properties Properties, mode resourceSchemaMode) error {
	schema, known := resourceSchemas[typeName]
	if !known {
		return nil
	}
	for _, path := range schema.ReadOnly {
		if len(resourcePathValues(properties, resourcePathParts(path))) != 0 {
			return fmt.Errorf("resource property %s%s is read-only", typeName, path)
		}
	}
	return validateCompiledResourceSchemaMode(typeName, properties, mode)
}

// ValidateResourceUpdate rejects immutable changes rather than interpreting a
// registry create-only annotation as permission to replace an owner resource.
func ValidateResourceUpdate(typeName string, previous, desired Properties) error {
	if err := validateResourceProperties(typeName, desired, resourceUpdateSchema); err != nil {
		return err
	}
	for _, path := range resourceSchemas[typeName].CreateOnly {
		parts := resourcePathParts(path)
		a, _ := json.Marshal(resourcePathValues(previous, parts))
		b, _ := json.Marshal(resourcePathValues(desired, parts))
		if !bytes.Equal(a, b) {
			return fmt.Errorf("%w: %s%s", ErrCreateOnly, typeName, path)
		}
	}
	return nil
}

// ValidateResourcePatchPath admits a JSON Patch mutation destination. Testing or
// reading a copy source does not mutate that path and must not call this check.
func ValidateResourcePatchPath(typeName, path string) error {
	schema := resourceSchemas[typeName]
	parts := resourcePathParts("/properties" + path)
	for _, readonly := range schema.ReadOnly {
		if resourcePathsOverlap(parts, resourcePathParts(readonly)) {
			return fmt.Errorf("resource property %s%s is read-only", typeName, readonly)
		}
	}
	for _, immutable := range schema.CreateOnly {
		if resourcePathsOverlap(parts, resourcePathParts(immutable)) {
			return fmt.Errorf("%w: %s%s", ErrCreateOnly, typeName, immutable)
		}
	}
	return nil
}

// ResourceIdentifier projects the registry's primary identifier in schema order.
// Cloud Control represents compound identifiers with | separated components.
func ResourceIdentifier(typeName string, properties Properties) (string, error) {
	paths := resourceSchemas[typeName].PrimaryIdentifier
	if len(paths) == 0 {
		return "", fmt.Errorf("resource type %s has no captured primary identifier", typeName)
	}
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		found := resourcePathValues(properties, resourcePathParts(path))
		if len(found) != 1 {
			return "", fmt.Errorf("resource type %s requires identifier property %s", typeName, path)
		}
		text, ok := found[0].(string)
		if !ok || text == "" {
			return "", fmt.Errorf("resource identifier property %s must be a nonempty string", path)
		}
		values = append(values, text)
	}
	return strings.Join(values, "|"), nil
}

// WritableResourceProperties returns an independent desired-state model with
// read-only observations removed. Validate user input before stripping it.
func WritableResourceProperties(typeName string, properties Properties) (Properties, error) {
	out, err := cloneOwnerProperties(properties)
	if err != nil {
		return nil, err
	}
	for _, path := range resourceSchemas[typeName].ReadOnly {
		removeResourcePath(out, resourcePathParts(path))
	}
	return out, nil
}
func resourcePathParts(path string) []string {
	path = strings.TrimPrefix(path, "/properties")
	if path == "" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	return parts
}
func resourcePathValues(value any, parts []string) []any {
	if len(parts) == 0 {
		return []any{value}
	}
	if parts[0] == "*" {
		var out []any
		if list, ok := value.([]any); ok {
			for _, item := range list {
				out = append(out, resourcePathValues(item, parts[1:])...)
			}
		}
		return out
	}
	var fields map[string]any
	switch value := value.(type) {
	case Properties:
		fields = value
	case map[string]any:
		fields = value
	}
	child, exists := fields[parts[0]]
	if !exists {
		return nil
	}
	return resourcePathValues(child, parts[1:])
}
func resourcePathsOverlap(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] && a[i] != "*" && b[i] != "*" {
			return false
		}
	}
	return true
}
func cloneResourceValue(value any) any {
	switch value := value.(type) {
	case Properties:
		out := make(Properties, len(value))
		for key, child := range value {
			out[key] = cloneResourceValue(child)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			out[key] = cloneResourceValue(child)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = cloneResourceValue(child)
		}
		return out
	default:
		return value
	}
}
