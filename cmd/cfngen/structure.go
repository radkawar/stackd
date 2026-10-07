package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var intrinsicSchema = map[string]any{
	"type": "object", "minProperties": 1, "maxProperties": 1,
	"properties":           map[string]any{"Ref": map[string]any{}},
	"patternProperties":    map[string]any{"^Fn::": map[string]any{}},
	"additionalProperties": false,
}

// Registry structure is separate from supported owner values and effects. Keep
// recursive references and object/array shape, but leave type coercion, enums,
// numeric bounds and semantic patterns at the service handler boundary.
func structuralSchema(raw json.RawMessage, limits bool) (string, error) {
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", err
	}
	projected, err := projectSchema(document, limits, false)
	if err != nil {
		return "", err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft7)
	compiler.UseLoader(schemaLoader{})
	if err := compiler.AddResource("urn:stackd:cloudformation:structure", projected); err != nil {
		return "", err
	}
	if _, err := compiler.Compile("urn:stackd:cloudformation:structure"); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(projected)
	return string(encoded), err
}

type schemaLoader struct{}

func (schemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external registry schema reference is unavailable: %s", url)
}

func projectSchema(value any, limits, intrinsic bool) (any, error) {
	if boolean, ok := value.(bool); ok {
		return boolean, nil
	}
	node, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid registry schema node %T", value)
	}
	out := make(map[string]any)
	for key, value := range node {
		switch key {
		case "$ref":
			reference, ok := value.(string)
			if !ok || !strings.HasPrefix(reference, "#/") {
				return nil, fmt.Errorf("unsupported external registry reference %v", value)
			}
			out[key] = reference
		case "definitions", "$defs", "properties", "patternProperties":
			fields, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid registry %s", key)
			}
			projected := make(map[string]any, len(fields))
			for name, child := range fields {
				var err error
				projected[name], err = projectSchema(child, limits, true)
				if err != nil {
					return nil, err
				}
			}
			out[key] = projected
		case "items", "additionalProperties":
			if _, ok := value.(bool); key == "additionalProperties" && limits && ok {
				out[key] = true
				continue
			}
			var err error
			if tuple, ok := value.([]any); ok {
				projected := make([]any, len(tuple))
				for i, child := range tuple {
					projected[i], err = projectSchema(child, limits, true)
					if err != nil {
						return nil, err
					}
				}
				out[key] = projected
			} else {
				out[key], err = projectSchema(value, limits, true)
				if err != nil {
					return nil, err
				}
			}
		case "allOf", "anyOf", "oneOf":
			branches, ok := value.([]any)
			if !ok {
				return nil, fmt.Errorf("invalid registry %s", key)
			}
			projected := make([]any, len(branches))
			for i, child := range branches {
				var err error
				projected[i], err = projectSchema(child, limits, false)
				if err != nil {
					return nil, err
				}
			}
			// Dropping value constraints can make otherwise distinct branches
			// structurally identical; owner validation retains exclusivity.
			if key == "oneOf" {
				key = "anyOf"
			}
			out[key] = projected
		case "required":
			if !limits {
				out[key] = value
			}
		case "minLength", "maxLength":
			if limits {
				out[key] = value
			}
		}
	}
	if !intrinsic {
		return out, nil
	}
	// This is the same pre-evaluation exemption as the template evaluator:
	// exactly one Ref/Fn::* field. It never permits extra sibling properties.
	return map[string]any{"anyOf": []any{out, intrinsicSchema}}, nil
}
