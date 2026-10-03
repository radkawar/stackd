package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// schema retains the published constraints even when a Go field cannot encode
// them (union branch requirements, enum values, and numeric limits). The entire
// unmodified input is also emitted as SourceSchemas JSON metadata.
type schema struct {
	Ref         string             `yaml:"$ref"`
	Type        types              `yaml:"type"`
	Format      string             `yaml:"format"`
	Properties  map[string]*schema `yaml:"properties"`
	Required    []string           `yaml:"required"`
	Items       *schema            `yaml:"items"`
	OneOf       []*schema          `yaml:"oneOf"`
	AnyOf       []*schema          `yaml:"anyOf"`
	AllOf       []*schema          `yaml:"allOf"`
	Enum        []string           `yaml:"enum"`
	Const       *string            `yaml:"const"`
	Nullable    bool               `yaml:"nullable"`
	Minimum     *float64           `yaml:"minimum"`
	Maximum     *float64           `yaml:"maximum"`
	Default     any                `yaml:"default"`
	MinItems    *uint64            `yaml:"minItems"`
	UniqueItems bool               `yaml:"uniqueItems"`
	Title       string             `yaml:"title"`
	Description string             `yaml:"description"`
	Schema      string             `yaml:"$schema"`
	Example     any                `yaml:"example"`
	Examples    any                `yaml:"examples"`
}

type types []string

func (t *types) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var value string
		if err := n.Decode(&value); err != nil {
			return err
		}
		*t = []string{value}
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: invalid schema type", n.Line)
	}
	var values []string
	if err := n.Decode(&values); err != nil {
		return err
	}
	*t = values
	return nil
}

func (s *schema) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!bool" {
		if n.Value == "true" {
			*s = schema{}
			return nil
		}
		return fmt.Errorf("line %d: false schemas cannot be represented as a Go value", n.Line)
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected schema object", n.Line)
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		switch key {
		case "$ref", "$schema", "type", "format", "properties", "required", "items", "oneOf", "anyOf", "allOf", "enum", "const", "nullable", "minimum", "maximum", "default", "minItems", "uniqueItems", "title", "description", "example", "examples":
		default:
			return fmt.Errorf("line %d: unsupported schema keyword %q", n.Content[i].Line, key)
		}
	}
	type plain schema
	return n.Decode((*plain)(s))
}

type document struct {
	Source               source
	Schemas              map[string]*schema
	Shapes               map[string]*shape
	RawJSON              string
	OpenAPIVersion       string
	SpecificationVersion string
}

func loadDocument(path string, input source) (*document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected document object", path)
	}
	node := root.Content[0]
	var original map[string]any
	if err := node.Decode(&original); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	raw, err := json.Marshal(original)
	if err != nil {
		return nil, fmt.Errorf("%s: JSON conversion: %w", path, err)
	}
	d := &document{Source: input, Schemas: map[string]*schema{}, Shapes: map[string]*shape{}, RawJSON: string(raw)}
	definitions := member(node, "definitions")
	components := member(member(node, "components"), "schemas")
	if definitions != nil && components != nil {
		return nil, fmt.Errorf("%s: mixed definitions and components are unsupported", path)
	}
	if input.DefinitionsRefFix {
		if definitions == nil {
			return nil, fmt.Errorf("%s: explicit definitions reference correction no longer applies", path)
		}
		components = definitions
	} else if definitions != nil {
		return nil, fmt.Errorf("%s: definitions require an explicit source reference correction", path)
	}
	if components == nil || components.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: missing component schemas", path)
	}
	for i := 0; i < len(components.Content); i += 2 {
		name := components.Content[i].Value
		if _, exists := d.Schemas[name]; exists {
			return nil, fmt.Errorf("%s: duplicate component %s", path, name)
		}
		var s schema
		if err := components.Content[i+1].Decode(&s); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", path, name, err)
		}
		d.Schemas[name] = &s
	}
	if openapi := member(node, "openapi"); openapi != nil {
		d.OpenAPIVersion = openapi.Value
		if version := member(member(node, "info"), "version"); version != nil {
			d.SpecificationVersion = version.Value
		}
		if d.OpenAPIVersion != "3.0.0" || d.SpecificationVersion == "" {
			return nil, fmt.Errorf("%s: unsupported OpenAPI version %q", path, d.OpenAPIVersion)
		}
		// Inline operation schemas are not declarations, but unsupported shapes
		// in them must fail rather than disappearing during component generation.
		if err := d.validateOperationSchemas(member(node, "paths")); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else {
		rootSchema := *node
		rootSchema.Content = nil
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value != "definitions" && node.Content[i].Value != "components" {
				rootSchema.Content = append(rootSchema.Content, node.Content[i:i+2]...)
			}
		}
		var s schema
		if err := rootSchema.Decode(&s); err != nil {
			return nil, fmt.Errorf("%s/root: %w", path, err)
		}
		if len(s.Type) == 1 && s.Type[0] == "array" {
			if s.Items == nil || s.Items.Ref != "#/components/schemas/"+input.Root {
				return nil, fmt.Errorf("%s: unexpected array root", path)
			}
			if _, err := d.normalize(&s, "$root"); err != nil {
				return nil, err
			}
		} else {
			if _, duplicate := d.Schemas[input.Root]; duplicate {
				return nil, fmt.Errorf("%s: duplicate root declaration", path)
			}
			d.Schemas[input.Root] = &s
		}
	}
	if err := d.normalizeAll(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

func member(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func (d *document) validateOperationSchemas(n *yaml.Node) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == "schema" {
				var s schema
				if err := n.Content[i+1].Decode(&s); err != nil {
					return err
				}
				// Multiple event response references are a tagged arbitrary JSON
				// body at this boundary; their concrete components are generated.
				if _, err := d.normalize(&s, "$operation.record"); err != nil {
					return err
				}
			} else if err := d.validateOperationSchemas(n.Content[i+1]); err != nil {
				return err
			}
		}
	} else {
		for _, child := range n.Content {
			if err := d.validateOperationSchemas(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *document) normalizeAll() error {
	for _, name := range sortedKeys(d.Schemas) {
		s, err := d.normalize(d.Schemas[name], name)
		if err != nil {
			return err
		}
		d.Shapes[name] = s
	}
	return nil
}

type field struct {
	Shape    *shape
	Required bool
}
type shape struct {
	Kind, Ref, Format string
	Nullable          bool
	Properties        map[string]field
	Items             *shape
	Enum              []string
}

func (d *document) normalize(s *schema, path string) (*shape, error) {
	result := &shape{Kind: "any", Nullable: s.Nullable, Format: s.Format, Properties: map[string]field{}, Enum: slices.Clone(s.Enum)}
	if s.Const != nil {
		result.Enum = append(result.Enum, *s.Const)
	}
	for _, kind := range s.Type {
		if kind == "null" {
			result.Nullable = true
			continue
		}
		if result.Kind != "any" {
			return nil, fmt.Errorf("%s: unsupported heterogeneous type array", path)
		}
		switch kind {
		case "string", "integer", "number", "boolean", "array", "object":
			result.Kind = kind
		default:
			return nil, fmt.Errorf("%s: unsupported type %q", path, kind)
		}
	}
	if len(s.Type) == 1 && s.Type[0] == "null" {
		result.Kind = "null"
	}
	if s.Ref != "" {
		const prefix = "#/components/schemas/"
		if !strings.HasPrefix(s.Ref, prefix) {
			return nil, fmt.Errorf("%s: unsupported reference %q", path, s.Ref)
		}
		result.Ref = strings.TrimPrefix(s.Ref, prefix)
		if _, ok := d.Schemas[result.Ref]; !ok {
			return nil, fmt.Errorf("%s: unresolved reference %q", path, s.Ref)
		}
		if len(s.Type) != 0 || len(s.Properties) != 0 || len(s.OneOf)+len(s.AnyOf)+len(s.AllOf) != 0 {
			return nil, fmt.Errorf("%s: reference with structural siblings is unsupported", path)
		}
		result.Kind = "ref"
	}
	if s.Format != "" {
		switch s.Format {
		case "uint", "uint16", "uint32", "uint64", "int32", "int64":
			if result.Kind != "integer" {
				return nil, fmt.Errorf("%s: integer format on %s", path, result.Kind)
			}
		case "double", "float":
			if result.Kind != "number" {
				return nil, fmt.Errorf("%s: number format on %s", path, result.Kind)
			}
		default:
			return nil, fmt.Errorf("%s: unsupported format %q", path, s.Format)
		}
	}
	for _, name := range sortedKeys(s.Properties) {
		child, err := d.normalize(s.Properties[name], path+"."+name)
		if err != nil {
			return nil, err
		}
		result.Properties[name] = field{Shape: child, Required: slices.Contains(s.Required, name)}
	}
	if len(s.Properties) > 0 && result.Kind == "any" {
		result.Kind = "object"
	}
	if len(s.Properties) > 0 && result.Kind != "object" {
		return nil, fmt.Errorf("%s: properties on non-object schema", path)
	}
	if (s.Items != nil || s.MinItems != nil || s.UniqueItems) && result.Kind != "array" {
		return nil, fmt.Errorf("%s: array constraints on non-array schema", path)
	}
	if (s.Minimum != nil || s.Maximum != nil) && result.Kind != "integer" && result.Kind != "number" {
		return nil, fmt.Errorf("%s: numeric bounds on non-numeric schema", path)
	}
	if s.Items != nil {
		child, err := d.normalize(s.Items, path+"[]")
		if err != nil {
			return nil, err
		}
		result.Items = child
	}
	if result.Kind == "array" && result.Items == nil {
		return nil, fmt.Errorf("%s: array without items", path)
	}
	for _, union := range [][]*schema{s.OneOf, s.AnyOf} {
		if len(union) == 0 {
			continue
		}
		var combined *shape
		for _, branch := range union {
			item, err := d.normalize(branch, path)
			if err != nil {
				return nil, err
			}
			if combined == nil {
				combined = item
			} else {
				combined, err = combine(combined, item, false, path)
				if err != nil {
					return nil, err
				}
			}
		}
		if result.Kind == "any" && len(result.Properties) == 0 {
			nullable := result.Nullable
			result = combined
			result.Nullable = result.Nullable || nullable
		} else {
			var err error
			result, err = combine(result, combined, true, path)
			if err != nil {
				return nil, err
			}
		}
	}
	for _, branch := range s.AllOf {
		item, err := d.normalize(branch, path)
		if err != nil {
			return nil, err
		}
		if result.Kind == "any" && len(result.Properties) == 0 {
			nullable := result.Nullable
			result = item
			result.Nullable = result.Nullable || nullable
		} else {
			result, err = combine(result, item, true, path)
			if err != nil {
				return nil, err
			}
		}
	}
	for _, name := range s.Required {
		if _, exists := result.Properties[name]; !exists {
			return nil, fmt.Errorf("%s: required property %s is undeclared", path, name)
		}
	}
	slices.Sort(result.Enum)
	result.Enum = slices.Compact(result.Enum)
	return result, nil
}

// combine forms an ordinary Go representation of alternatives. Required fields
// are intersected for unions and united for intersections. Branch-specific
// constraints remain available in SourceSchemas; structs are not validators.
func combine(a, b *shape, intersection bool, path string) (*shape, error) {
	if a.Kind == "null" {
		out := *b
		out.Nullable = true
		return &out, nil
	}
	if b.Kind == "null" {
		out := *a
		out.Nullable = true
		return &out, nil
	}
	if a.Kind == "any" || b.Kind == "any" {
		other := a
		if a.Kind == "any" {
			other = b
		}
		if intersection {
			out := *other
			return &out, nil
		}
		if other.Kind == "object" {
			out := *other
			out.Properties = map[string]field{}
			for name, f := range other.Properties {
				f.Required = false
				out.Properties[name] = f
			}
			return &out, nil
		}
		return &shape{Kind: "any"}, nil
	}
	if a.Kind != b.Kind || a.Ref != b.Ref || a.Format != b.Format {
		if !intersection && strings.HasSuffix(path, ".record") {
			return &shape{Kind: "any"}, nil
		}
		return nil, fmt.Errorf("%s: incompatible schema alternatives %s/%s and %s/%s", path, a.Kind, a.Ref, b.Kind, b.Ref)
	}
	out := *a
	out.Nullable = a.Nullable || b.Nullable
	out.Enum = append(slices.Clone(a.Enum), b.Enum...)
	if intersection && len(a.Enum) > 0 && len(b.Enum) > 0 && !slices.Equal(a.Enum, b.Enum) {
		return nil, fmt.Errorf("%s: intersecting distinct enums is unsupported", path)
	}
	if a.Kind == "object" {
		out.Properties = map[string]field{}
		for name, f := range a.Properties {
			if other, ok := b.Properties[name]; ok {
				var err error
				f.Shape, err = combine(f.Shape, other.Shape, intersection, path+"."+name)
				if err != nil {
					return nil, err
				}
				if intersection {
					f.Required = f.Required || other.Required
				} else {
					f.Required = f.Required && other.Required
				}
			} else if !intersection {
				f.Required = false
			}
			out.Properties[name] = f
		}
		for name, f := range b.Properties {
			if _, ok := out.Properties[name]; !ok {
				if !intersection {
					f.Required = false
				}
				out.Properties[name] = f
			}
		}
	} else if a.Kind == "array" {
		var err error
		out.Items, err = combine(a.Items, b.Items, intersection, path+"[]")
		if err != nil {
			return nil, err
		}
	}
	return &out, nil
}

func applyDeltas(docs []*document, d delta) error {
	var request *document
	versions := map[string]bool{}
	for _, doc := range docs {
		if doc.Source.Role == "request" {
			if request != nil {
				return fmt.Errorf("multiple request schemas")
			}
			request = doc
		}
		if doc.Source.Role == "events" {
			versions[doc.Source.Version] = true
		}
	}
	if request == nil || len(d.SchemaVersions) == 0 || len(d.Evidence) == 0 {
		return fmt.Errorf("missing request schema or explicit delta evidence")
	}
	for _, version := range d.SchemaVersions {
		if !versions[version] {
			return fmt.Errorf("schema version %s has no pinned event source", version)
		}
		delete(versions, version)
	}
	if len(versions) != 0 {
		return fmt.Errorf("event schemas missing from subscription schemaVersion delta")
	}
	apis := map[string]bool{}
	for _, doc := range docs {
		if doc.Source.Role != "events" {
			continue
		}
		api := apiName(doc.Source.API)
		apis[api] = true
		rule, exists := d.SchemaVersionRules[api]
		if !exists {
			return fmt.Errorf("missing schemaVersion admission rule for %s", api)
		}
		if !rule.Required && rule.Default == "" {
			return fmt.Errorf("%s: optional schemaVersion requires a default", api)
		}
		if rule.Default != "" {
			found := false
			for _, candidate := range docs {
				if candidate.Source.Role == "events" && candidate.Source.API == doc.Source.API && candidate.Source.Version == rule.Default {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: schemaVersion default has no matching source", api)
			}
		}
	}
	if len(apis) != len(d.SchemaVersionRules) {
		return fmt.Errorf("schemaVersion rule for unknown API")
	}
	root := request.Schemas[request.Source.Root]
	if _, exists := root.Properties["schemaVersion"]; exists {
		return fmt.Errorf("schemaVersion delta already present upstream")
	}
	request.Schemas["SchemaVersion"] = &schema{Type: types{"string"}, Enum: slices.Clone(d.SchemaVersions)}
	root.Properties["schemaVersion"] = &schema{Ref: "#/components/schemas/SchemaVersion"}
	buffering := request.Schemas["BufferingCfg"]
	if buffering == nil {
		return fmt.Errorf("missing BufferingCfg")
	}
	for property, changes := range d.Buffering {
		s := buffering.Properties[property]
		if s == nil {
			return fmt.Errorf("delta targets unknown buffering field %s", property)
		}
		for name, value := range changes {
			n := float64(value)
			switch name {
			case "minimum":
				s.Minimum = &n
			case "maximum":
				s.Maximum = &n
			case "default":
				s.Default = value
			default:
				return fmt.Errorf("unsupported delta constraint %s", name)
			}
		}
	}
	return request.normalizeAll()
}
