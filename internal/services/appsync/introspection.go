package appsync

import (
	"fmt"
	"slices"

	"github.com/vektah/gqlparser/v2/ast"
)

type introspectionSchema struct{ schema *ast.Schema }
type introspectionType struct {
	schema *ast.Schema
	typ    *ast.Type
}
type introspectionFieldValue struct {
	schema *ast.Schema
	field  *ast.FieldDefinition
}
type introspectionInputValue struct {
	schema            *ast.Schema
	name, description string
	typ               *ast.Type
	defaultValue      *ast.Value
	directives        ast.DirectiveList
}
type introspectionEnum struct{ value *ast.EnumValueDefinition }
type introspectionDirective struct {
	schema    *ast.Schema
	directive *ast.DirectiveDefinition
}

func introspectionField(source any, name string, args map[string]any) (any, error) {
	switch object := source.(type) {
	case introspectionSchema:
		schema := object.schema
		switch name {
		case "description":
			return nullableText(schema.Description), nil
		case "types":
			names := make([]string, 0, len(schema.Types))
			for name := range schema.Types {
				names = append(names, name)
			}
			slices.Sort(names)
			out := make([]any, 0, len(names))
			for _, name := range names {
				out = append(out, introspectionType{schema: schema, typ: ast.NamedType(name, nil)})
			}
			return out, nil
		case "queryType":
			return introNamed(schema, schema.Query), nil
		case "mutationType":
			return introNamed(schema, schema.Mutation), nil
		case "subscriptionType":
			return introNamed(schema, schema.Subscription), nil
		case "directives":
			names := make([]string, 0, len(schema.Directives))
			for name := range schema.Directives {
				names = append(names, name)
			}
			slices.Sort(names)
			out := make([]any, 0, len(names))
			for _, name := range names {
				out = append(out, introspectionDirective{schema: schema, directive: schema.Directives[name]})
			}
			return out, nil
		}
	case introspectionType:
		typ, schema := object.typ, object.schema
		if name == "kind" {
			if typ.NonNull {
				return "NON_NULL", nil
			}
			if typ.Elem != nil {
				return "LIST", nil
			}
			return string(schema.Types[typ.NamedType].Kind), nil
		}
		if name == "ofType" {
			if typ.NonNull {
				inner := *typ
				inner.NonNull = false
				return introspectionType{schema: schema, typ: &inner}, nil
			}
			if typ.Elem != nil {
				return introspectionType{schema: schema, typ: typ.Elem}, nil
			}
			return nil, nil
		}
		if typ.NonNull || typ.Elem != nil {
			return nil, nil
		}
		definition := schema.Types[typ.NamedType]
		deprecated, _ := args["includeDeprecated"].(bool)
		switch name {
		case "name":
			return definition.Name, nil
		case "description":
			return nullableText(definition.Description), nil
		case "specifiedByURL":
			if directive := definition.Directives.ForName("specifiedBy"); directive != nil {
				if arg := directive.Arguments.ForName("url"); arg != nil {
					return arg.Value.Value(nil)
				}
			}
			return nil, nil
		case "isOneOf":
			return definition.Directives.ForName("oneOf") != nil, nil
		case "fields":
			if definition.Kind != ast.Object && definition.Kind != ast.Interface {
				return nil, nil
			}
			out := []any{}
			for _, field := range definition.Fields {
				if !deprecated && field.Directives.ForName("deprecated") != nil || len(field.Name) > 1 && field.Name[:2] == "__" {
					continue
				}
				out = append(out, introspectionFieldValue{schema: schema, field: field})
			}
			return out, nil
		case "inputFields":
			if definition.Kind != ast.InputObject {
				return nil, nil
			}
			out := []any{}
			for _, field := range definition.Fields {
				if !deprecated && field.Directives.ForName("deprecated") != nil {
					continue
				}
				out = append(out, introspectionInputValue{schema: schema, name: field.Name, description: field.Description, typ: field.Type, defaultValue: field.DefaultValue, directives: field.Directives})
			}
			return out, nil
		case "interfaces":
			if definition.Kind != ast.Object && definition.Kind != ast.Interface {
				return nil, nil
			}
			out := []any{}
			for _, name := range definition.Interfaces {
				out = append(out, introspectionType{schema: schema, typ: ast.NamedType(name, nil)})
			}
			return out, nil
		case "possibleTypes":
			if definition.Kind != ast.Union && definition.Kind != ast.Interface {
				return nil, nil
			}
			out := []any{}
			for _, possible := range schema.PossibleTypes[definition.Name] {
				out = append(out, introNamed(schema, possible))
			}
			return out, nil
		case "enumValues":
			if definition.Kind != ast.Enum {
				return nil, nil
			}
			out := []any{}
			for _, value := range definition.EnumValues {
				if !deprecated && value.Directives.ForName("deprecated") != nil {
					continue
				}
				out = append(out, introspectionEnum{value: value})
			}
			return out, nil
		}
	case introspectionFieldValue:
		field := object.field
		switch name {
		case "name":
			return field.Name, nil
		case "description":
			return nullableText(field.Description), nil
		case "type":
			return introspectionType{schema: object.schema, typ: field.Type}, nil
		case "isDeprecated":
			return field.Directives.ForName("deprecated") != nil, nil
		case "deprecationReason":
			return deprecationReason(field.Directives), nil
		case "args":
			return introspectionArguments(object.schema, field.Arguments, args), nil
		}
	case introspectionInputValue:
		switch name {
		case "name":
			return object.name, nil
		case "description":
			return nullableText(object.description), nil
		case "type":
			return introspectionType{schema: object.schema, typ: object.typ}, nil
		case "defaultValue":
			if object.defaultValue != nil {
				return object.defaultValue.String(), nil
			}
			return nil, nil
		case "isDeprecated":
			return object.directives.ForName("deprecated") != nil, nil
		case "deprecationReason":
			return deprecationReason(object.directives), nil
		}
	case introspectionEnum:
		switch name {
		case "name":
			return object.value.Name, nil
		case "description":
			return nullableText(object.value.Description), nil
		case "isDeprecated":
			return object.value.Directives.ForName("deprecated") != nil, nil
		case "deprecationReason":
			return deprecationReason(object.value.Directives), nil
		}
	case introspectionDirective:
		directive := object.directive
		switch name {
		case "name":
			return directive.Name, nil
		case "description":
			return nullableText(directive.Description), nil
		case "isRepeatable":
			return directive.IsRepeatable, nil
		case "locations":
			out := make([]any, len(directive.Locations))
			for i, v := range directive.Locations {
				out[i] = string(v)
			}
			return out, nil
		case "args":
			return introspectionArguments(object.schema, directive.Arguments, args), nil
		}
	}
	return nil, fmt.Errorf("unknown introspection field %s", name)
}
func introNamed(schema *ast.Schema, definition *ast.Definition) any {
	if definition == nil {
		return nil
	}
	return introspectionType{schema: schema, typ: ast.NamedType(definition.Name, nil)}
}
func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func deprecationReason(directives ast.DirectiveList) any {
	directive := directives.ForName("deprecated")
	if directive == nil {
		return nil
	}
	if arg := directive.Arguments.ForName("reason"); arg != nil {
		value, _ := arg.Value.Value(nil)
		return value
	}
	return "No longer supported"
}
func introspectionArguments(schema *ast.Schema, arguments ast.ArgumentDefinitionList, args map[string]any) []any {
	deprecated, _ := args["includeDeprecated"].(bool)
	out := []any{}
	for _, argument := range arguments {
		if !deprecated && argument.Directives.ForName("deprecated") != nil {
			continue
		}
		out = append(out, introspectionInputValue{schema: schema, name: argument.Name, description: argument.Description, typ: argument.Type, defaultValue: argument.DefaultValue, directives: argument.Directives})
	}
	return out
}
