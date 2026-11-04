package icebergmeta

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Column is a Hive storage descriptor column derived from the current schema.
type Column struct{ Name, Type, Comment string }

type nestedType struct {
	Type            string          `json:"type"`
	Fields          []Field         `json:"fields,omitempty"`
	ElementID       int             `json:"element-id,omitempty"`
	Element         json.RawMessage `json:"element,omitempty"`
	ElementRequired bool            `json:"element-required,omitempty"`
	KeyID           int             `json:"key-id,omitempty"`
	Key             json.RawMessage `json:"key,omitempty"`
	ValueID         int             `json:"value-id,omitempty"`
	Value           json.RawMessage `json:"value,omitempty"`
	ValueRequired   bool            `json:"value-required,omitempty"`
}

var decimalType = regexp.MustCompile(`^decimal\(\s*([0-9]+)\s*,\s*([0-9]+)\s*\)$`)
var fixedType = regexp.MustCompile(`^fixed\[([0-9]+)\]$`)
var parameterTransform = regexp.MustCompile(`^(bucket|truncate)\[([0-9]+)\]$`)
var hiveIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func primitiveHive(name string) (string, error) {
	switch name {
	case "boolean", "int", "float", "double", "date", "string", "binary":
		return name, nil
	case "long":
		return "bigint", nil
	case "timestamp", "timestamptz":
		return "timestamp", nil
	case "time", "uuid":
		return "string", nil
	}
	if match := decimalType.FindStringSubmatch(name); match != nil {
		precision, _ := strconv.Atoi(match[1])
		scale, _ := strconv.Atoi(match[2])
		if precision < 1 || precision > 38 || scale > precision {
			return "", invalid("Invalid Iceberg decimal type %q", name)
		}
		return fmt.Sprintf("decimal(%d,%d)", precision, scale), nil
	}
	if match := fixedType.FindStringSubmatch(name); match != nil {
		length, err := strconv.Atoi(match[1])
		if err == nil && length > 0 {
			return "binary", nil
		}
	}
	return "", unsupported("Unsupported Iceberg v1/v2 type %q", name)
}

func hiveType(raw json.RawMessage) (string, error) {
	var primitive string
	if err := json.Unmarshal(raw, &primitive); err == nil {
		return primitiveHive(primitive)
	}
	var nested nestedType
	if err := json.Unmarshal(raw, &nested); err != nil {
		return "", invalid("Invalid Iceberg type: %v", err)
	}
	switch nested.Type {
	case "struct":
		parts := make([]string, 0, len(nested.Fields))
		for _, field := range nested.Fields {
			typ, err := hiveType(field.Type)
			if err != nil {
				return "", err
			}
			name := field.Name
			if !hiveIdentifier.MatchString(name) {
				name = "`" + strings.ReplaceAll(name, "`", "``") + "`"
			}
			parts = append(parts, name+":"+typ)
		}
		return "struct<" + strings.Join(parts, ",") + ">", nil
	case "list":
		element, err := hiveType(nested.Element)
		if err != nil {
			return "", err
		}
		return "array<" + element + ">", nil
	case "map":
		key, err := hiveType(nested.Key)
		if err != nil {
			return "", err
		}
		value, err := hiveType(nested.Value)
		if err != nil {
			return "", err
		}
		return "map<" + key + "," + value + ">", nil
	default:
		return "", unsupported("Unsupported Iceberg nested type %q", nested.Type)
	}
}

func Columns(metadata Metadata) ([]Column, error) {
	schema, ok := findSchema(metadata, metadata.CurrentSchemaID)
	if !ok {
		return nil, invalid("Current schema %d does not exist", metadata.CurrentSchemaID)
	}
	columns := make([]Column, 0, len(schema.Fields))
	for _, field := range schema.Fields {
		typ, err := hiveType(field.Type)
		if err != nil {
			return nil, err
		}
		columns = append(columns, Column{Name: field.Name, Type: typ, Comment: field.Doc})
	}
	return columns, nil
}

// walkSchema traverses every field ID, including list elements and map keys and
// values. Rewrite mode assigns fresh server IDs; read-only validation never
// copies or rewrites the caller's schema/type JSON.
func walkSchema(schema *Schema, rewrite bool, visit func(int) (int, error)) error {
	var walkType func(*json.RawMessage) error
	walkFields := func(fields []Field) error {
		names := make(map[string]bool, len(fields))
		for i := range fields {
			f := &fields[i]
			if f.Name == "" || names[f.Name] {
				return invalid("Empty or duplicate field name %q", f.Name)
			}
			names[f.Name] = true
			id, err := visit(f.ID)
			if err != nil {
				return err
			}
			if rewrite {
				f.ID = id
			}
			if err := walkType(&f.Type); err != nil {
				return err
			}
		}
		return nil
	}
	walkType = func(raw *json.RawMessage) error {
		var primitive string
		if err := json.Unmarshal(*raw, &primitive); err == nil {
			_, err := primitiveHive(primitive)
			return err
		}
		var nested nestedType
		if err := json.Unmarshal(*raw, &nested); err != nil {
			return invalid("Invalid Iceberg type: %v", err)
		}
		// Edit the original object to preserve extension keys in nested types.
		var object map[string]json.RawMessage
		if rewrite {
			if err := json.Unmarshal(*raw, &object); err != nil {
				return invalid("Invalid nested type: %v", err)
			}
		}
		put := func(key string, value any) {
			if rewrite {
				object[key], _ = json.Marshal(value)
			}
		}
		switch nested.Type {
		case "struct":
			if nested.Fields == nil {
				return invalid("Struct type requires fields")
			}
			if err := walkFields(nested.Fields); err != nil {
				return err
			}
			put("fields", nested.Fields)
		case "list":
			id, err := visit(nested.ElementID)
			if err != nil {
				return err
			}
			put("element-id", id)
			if err := walkType(&nested.Element); err != nil {
				return err
			}
			put("element", nested.Element)
		case "map":
			key, err := visit(nested.KeyID)
			if err != nil {
				return err
			}
			put("key-id", key)
			value, err := visit(nested.ValueID)
			if err != nil {
				return err
			}
			put("value-id", value)
			if err := walkType(&nested.Key); err != nil {
				return err
			}
			put("key", nested.Key)
			if err := walkType(&nested.Value); err != nil {
				return err
			}
			put("value", nested.Value)
		default:
			return unsupported("Unsupported Iceberg nested type %q", nested.Type)
		}
		if rewrite {
			data, err := json.Marshal(object)
			if err != nil {
				return err
			}
			*raw = data
		}
		return nil
	}
	if schema.Type != "struct" {
		return invalid("Schema type must be struct")
	}
	if schema.Fields == nil {
		return invalid("Schema fields must be an array")
	}
	return walkFields(schema.Fields)
}

func schemaIDs(schema Schema) (map[int]bool, int, error) {
	ids := make(map[int]bool)
	last := 0
	err := walkSchema(&schema, false, func(id int) (int, error) {
		if id <= 0 || ids[id] {
			return 0, invalid("Invalid or duplicate schema field ID %d", id)
		}
		ids[id] = true
		if id > last {
			last = id
		}
		return id, nil
	})
	if err != nil {
		return nil, 0, err
	}
	for _, id := range schema.IdentifierFieldIDs {
		if !ids[id] {
			return nil, 0, invalid("Identifier field ID %d is missing", id)
		}
	}
	return ids, last, nil
}

func validTransform(transform string) bool {
	switch transform {
	case "identity", "void", "year", "month", "day", "hour":
		return true
	}
	match := parameterTransform.FindStringSubmatch(transform)
	if match == nil {
		return false
	}
	n, err := strconv.Atoi(match[2])
	return err == nil && n > 0
}

func validateSpec(spec PartitionSpec, schema Schema, version int) error {
	ids, _, err := schemaIDs(schema)
	if err != nil {
		return err
	}
	seen := make(map[int]bool)
	names := make(map[string]bool)
	for i, field := range spec.Fields {
		if !ids[field.SourceID] {
			return invalid("Partition source ID %d does not exist", field.SourceID)
		}
		if field.FieldID < 1000 || seen[field.FieldID] {
			return invalid("Invalid or duplicate partition field ID %d", field.FieldID)
		}
		if version == 1 && field.FieldID != 1000+i {
			return invalid("Version 1 partition IDs must be sequential starting at 1000")
		}
		if field.Name == "" || names[field.Name] {
			return invalid("Empty or duplicate partition field name %q", field.Name)
		}
		if !validTransform(field.Transform) {
			return unsupported("Unsupported partition transform %q", field.Transform)
		}
		seen[field.FieldID], names[field.Name] = true, true
	}
	return nil
}

func validateOrder(order SortOrder, schema Schema) error {
	ids, _, err := schemaIDs(schema)
	if err != nil {
		return err
	}
	for _, field := range order.Fields {
		if !ids[field.SourceID] {
			return invalid("Sort source ID %d does not exist", field.SourceID)
		}
		if !validTransform(field.Transform) || field.Transform == "void" {
			return unsupported("Unsupported sort transform %q", field.Transform)
		}
		if field.Direction != "asc" && field.Direction != "desc" {
			return invalid("Invalid sort direction %q", field.Direction)
		}
		if field.NullOrder != "nulls-first" && field.NullOrder != "nulls-last" {
			return invalid("Invalid null order %q", field.NullOrder)
		}
	}
	return nil
}

func findSchema(metadata Metadata, id int) (Schema, bool) {
	for _, schema := range metadata.Schemas {
		if schema.SchemaID == id {
			return schema, true
		}
	}
	return Schema{}, false
}
