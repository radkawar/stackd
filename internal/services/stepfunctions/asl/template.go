package asl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Template represents both JSONPath payload templates and JSONata value
// templates. Object order is retained so evaluations consume random input in
// document order, never Go map iteration order.
type Template struct {
	literal    any
	expression *Expression
	fields     []templateField
	items      []*Template
	object     bool
	array      bool
}

type templateField struct {
	name  string
	value *Template
}

func CompileTemplate(raw json.RawMessage, language Language) (*Template, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if language != JSONPath && language != JSONata {
		return nil, fmt.Errorf("unknown query language %q", language)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	template, err := compileTemplateValue(decoder, language)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values in template")
		}
		return nil, err
	}
	return template, nil
}

func compileTemplateValue(decoder *json.Decoder, language Language) (*Template, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	template := &Template{}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			template.object = true
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key must be a string")
				}
				dynamic := language == JSONPath && strings.HasSuffix(key, ".$")
				if dynamic {
					key = strings.TrimSuffix(key, ".$")
				}
				if seen[key] {
					return nil, fmt.Errorf("duplicate resolved template key %q", key)
				}
				seen[key] = true
				var child *Template
				if dynamic {
					argument, err := decoder.Token()
					if err != nil {
						return nil, err
					}
					source, ok := argument.(string)
					if !ok {
						return nil, fmt.Errorf("dynamic template field %q must contain a string", key)
					}
					expression, err := CompileExpression(source, JSONPath)
					if err != nil {
						return nil, fmt.Errorf("template field %q: %w", key, err)
					}
					child = &Template{expression: expression}
				} else {
					child, err = compileTemplateValue(decoder, language)
					if err != nil {
						return nil, fmt.Errorf("template field %q: %w", key, err)
					}
				}
				template.fields = append(template.fields, templateField{name: key, value: child})
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
		case '[':
			template.array = true
			for decoder.More() {
				child, err := compileTemplateValue(decoder, language)
				if err != nil {
					return nil, err
				}
				template.items = append(template.items, child)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", value)
		}
	case string:
		if language == JSONata && (strings.HasPrefix(strings.TrimSpace(value), "{%") || strings.HasSuffix(strings.TrimSpace(value), "%}")) {
			template.expression, err = CompileExpression(value, JSONata)
			if err != nil {
				return nil, err
			}
		} else {
			template.literal = value
		}
	default:
		template.literal = value
	}
	return template, nil
}

func (t *Template) Evaluate(ctx context.Context, env Environment) (any, error) {
	if t == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.expression != nil {
		return t.expression.Evaluate(ctx, env)
	}
	if t.object {
		result := make(map[string]any, len(t.fields))
		for _, field := range t.fields {
			value, err := field.value.Evaluate(ctx, env)
			if err != nil {
				return nil, err
			}
			result[field.name] = value
		}
		return result, nil
	}
	if t.array {
		result := make([]any, len(t.items))
		for i, item := range t.items {
			value, err := item.Evaluate(ctx, env)
			if err != nil {
				return nil, err
			}
			result[i] = value
		}
		return result, nil
	}
	return t.literal, nil
}

func (t *Template) References() []string {
	if t == nil {
		return nil
	}
	if t.expression != nil {
		return t.expression.References()
	}
	var refs []string
	for _, field := range t.fields {
		refs = append(refs, field.value.References()...)
	}
	for _, item := range t.items {
		refs = append(refs, item.References()...)
	}
	return uniqueReferences(refs)
}
