package main

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
)

// These data-only types are reproduced in the generated package. Keeping
// metadata as Go literals avoids parsing schemas or allocating decoded copies
// of every schema at runtime.
type IntegerConstraint struct{ Minimum, Maximum, Default uint64 }
type SourceInfo struct {
	URL, Revision, API, Version, OpenAPIVersion, SpecificationVersion string
	Limitations                                                       []string
}
type Version struct {
	API            string
	Events         []string
	OmitFields     map[string][]string
	Fields         map[string][]string
	FieldTypes     map[string]map[string]string
	FieldEnums     map[string]map[string][]string
	RequiredFields map[string][]string
	Source         string
	Limitations    []string
}

type recordField struct {
	Type     string
	Enum     []string
	Required bool
}

func literal(value any) string {
	var out strings.Builder
	writeLiteral(&out, reflect.ValueOf(value))
	return out.String()
}

func literalType(t reflect.Type) string {
	if t.Name() != "" {
		return t.Name()
	}
	switch t.Kind() {
	case reflect.Slice:
		return "[]" + literalType(t.Elem())
	case reflect.Map:
		return "map[" + literalType(t.Key()) + "]" + literalType(t.Elem())
	default:
		panic("unsupported metadata type: " + t.String())
	}
}

func writeLiteral(out *strings.Builder, value reflect.Value) {
	switch value.Kind() {
	case reflect.Struct:
		out.WriteString(literalType(value.Type()) + "{")
		for i := range value.NumField() {
			out.WriteString(value.Type().Field(i).Name + ":")
			writeLiteral(out, value.Field(i))
			out.WriteString(",")
		}
		out.WriteString("}")
	case reflect.Map:
		out.WriteString(literalType(value.Type()))
		if value.IsNil() {
			out.WriteString("(nil)")
			return
		}
		out.WriteString("{")
		keys := value.MapKeys()
		slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
		for _, key := range keys {
			writeLiteral(out, key)
			out.WriteString(":")
			writeLiteral(out, value.MapIndex(key))
			out.WriteString(",")
		}
		out.WriteString("}")
	case reflect.Slice:
		out.WriteString(literalType(value.Type()))
		if value.IsNil() {
			out.WriteString("(nil)")
			return
		}
		out.WriteString("{")
		for i := range value.Len() {
			writeLiteral(out, value.Index(i))
			out.WriteString(",")
		}
		out.WriteString("}")
	case reflect.String, reflect.Bool, reflect.Uint64:
		fmt.Fprintf(out, "%#v", value.Interface())
	default:
		panic("unsupported metadata value: " + value.Type().String())
	}
}

func renderMetadata(pkg string, docs []*document, deltas delta) ([]byte, error) {
	if err := validateTransports(docs); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(generatedHeader(pkg))
	out.WriteString("type SourceInfo struct { URL, Revision, API, Version, OpenAPIVersion, SpecificationVersion string; Limitations []string }\n\n")
	sources := map[string]SourceInfo{}
	schemas := map[string]string{}
	enums := map[string][]string{}
	defaults := map[string]string{}
	for _, doc := range docs {
		src := doc.Source
		sources[src.File] = SourceInfo{URL: src.URL, Revision: src.Revision, API: apiName(src.API), Version: src.Version, OpenAPIVersion: doc.OpenAPIVersion, SpecificationVersion: doc.SpecificationVersion, Limitations: src.Limitations}
		schemas[src.File] = doc.RawJSON
		if src.Role == "transport" {
			continue
		}
		for _, name := range sortedKeys(doc.Shapes) {
			goName, err := declarationName(doc, name)
			if err != nil {
				return nil, err
			}
			collectEnums(goName, doc.Shapes[name], enums)
			collectDefaults(goName, doc.Schemas[name], defaults)
		}
	}
	fmt.Fprintf(&out, "var Sources = %s\n\n", literal(sources))
	out.WriteString("// SourceSchemas preserves the complete, unmodified published documents as JSON.\n// Union branch constraints are authoritative here; generated structs represent\n// their fields but do not replace schema validation. RequestDeltas records the\n// separately evidenced subscription changes applied to generated metadata.\n")
	fmt.Fprintf(&out, "var SourceSchemas = %s\n\n", literal(schemas))
	fmt.Fprintf(&out, "var EnumValues = %s\n\n", literal(enums))
	fmt.Fprintf(&out, "var Defaults = %s\n\n", literal(defaults))
	if pkg == "extensionapi" {
		out.WriteString("// APIVersion is the Extensions HTTP path version, distinct from OpenAPI info.version.\n")
		if len(docs) != 1 {
			return nil, fmt.Errorf("expected one Extensions source")
		}
		fmt.Fprintf(&out, "const APIVersion = %q\n", docs[0].Source.Version)
		return out.Bytes(), nil
	}
	out.WriteString("type IntegerConstraint struct { Minimum, Maximum, Default uint64 }\n\n")
	out.WriteString("// Version describes actual pinned event schemas. OmitFields contains dotted\n// record paths absent from this version, relative to the union of published\n// fields. Fields/FieldTypes/FieldEnums/RequiredFields retain further differences;\n// omission alone is not a substitute for value or required-field validation.\n")
	out.WriteString("type Version struct { API string; Events []string; OmitFields map[string][]string; Fields map[string][]string; FieldTypes map[string]map[string]string; FieldEnums map[string]map[string][]string; RequiredFields map[string][]string; Source string; Limitations []string }\n\n")
	limits := map[string]IntegerConstraint{}
	var port IntegerConstraint
	for _, doc := range docs {
		if doc.Source.Role != "request" {
			continue
		}
		for property, s := range doc.Schemas["BufferingCfg"].Properties {
			constraint, err := integerConstraint(s, true)
			if err != nil {
				return nil, fmt.Errorf("BufferingCfg.%s: %w", property, err)
			}
			limits[property] = constraint
		}
		for _, branch := range doc.Schemas["Destination"].AnyOf {
			if s := branch.Properties["port"]; s != nil {
				constraint, err := integerConstraint(s, false)
				if err != nil {
					return nil, fmt.Errorf("invalid Destination.port: %w", err)
				}
				port = constraint
			}
		}
	}
	if len(limits) == 0 || port.Maximum == 0 {
		return nil, fmt.Errorf("missing subscription limits")
	}
	fmt.Fprintf(&out, "var BufferingLimits = %s\n\n", literal(limits))
	fmt.Fprintf(&out, "var DestinationPortLimits = %s\n\n", literal(port))
	out.WriteString("// NativeEventTypeValues is deserialization vocabulary, not accepted subscription\n// filters. EnumValues[\"EventType\"] contains the supported category values.\n")
	fmt.Fprintf(&out, "var NativeEventTypeValues = %s\n\n", literal(deltas.NativeEventTypeValues))
	out.WriteString("type SchemaVersionRule struct { Required bool; Default SchemaVersion }\n")
	fmt.Fprintf(&out, "var SchemaVersionRules = %s\n\n", literal(deltas.SchemaVersionRules))
	out.WriteString("// RequestDeltas identifies supported changes to the published request schema.\n")
	out.WriteString("type RequestDeltaEvidence struct { Source, Revision, Description string }\n")
	fmt.Fprintf(&out, "var RequestDeltas = %s\n\n", literal(deltas.Evidence))
	versions, err := versionMetadata(docs)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&out, "var Versions = %s\n", strings.Replace(literal(versions), "map[string]Version", "map[SchemaVersion]Version", 1))
	return out.Bytes(), nil
}

func apiName(name string) string {
	switch name {
	case "logs":
		return "Logs"
	case "telemetry":
		return "Telemetry"
	case "extensions":
		return "Extensions"
	default:
		return name
	}
}

func collectEnums(path string, s *shape, into map[string][]string) {
	if len(s.Enum) > 0 {
		values := slices.Clone(s.Enum)
		slices.Sort(values)
		into[path] = slices.Compact(values)
	}
	for _, name := range sortedKeys(s.Properties) {
		collectEnums(path+"."+name, s.Properties[name].Shape, into)
	}
	if s.Items != nil {
		collectEnums(path+"[]", s.Items, into)
	}
}

func collectDefaults(path string, s *schema, into map[string]string) {
	if s.Default != nil {
		into[path] = fmt.Sprint(s.Default)
	}
	for _, name := range sortedKeys(s.Properties) {
		collectDefaults(path+"."+name, s.Properties[name], into)
	}
	if s.Items != nil {
		collectDefaults(path+"[]", s.Items, into)
	}
	for _, branches := range [][]*schema{s.AnyOf, s.OneOf, s.AllOf} {
		for _, branch := range branches {
			collectDefaults(path, branch, into)
		}
	}
}

func integerConstraint(s *schema, requireDefault bool) (IntegerConstraint, error) {
	var c IntegerConstraint
	if s.Minimum == nil || s.Maximum == nil {
		return c, fmt.Errorf("missing bounds")
	}
	values := []float64{*s.Minimum, *s.Maximum}
	if s.Default != nil {
		switch value := s.Default.(type) {
		case int:
			values = append(values, float64(value))
		case uint64:
			values = append(values, float64(value))
		case float64:
			values = append(values, value)
		default:
			return c, fmt.Errorf("non-numeric default %T", s.Default)
		}
	} else if requireDefault {
		return c, fmt.Errorf("missing default")
	}
	for _, value := range values {
		if value < 0 || value >= math.Exp2(64) || math.IsNaN(value) || math.Trunc(value) != value {
			return c, fmt.Errorf("invalid unsigned integer bound/default %v", value)
		}
	}
	c.Minimum, c.Maximum = uint64(values[0]), uint64(values[1])
	if c.Minimum > c.Maximum {
		return c, fmt.Errorf("inverted bounds")
	}
	if len(values) == 3 {
		c.Default = uint64(values[2])
		if c.Default < c.Minimum || c.Default > c.Maximum {
			return c, fmt.Errorf("default outside bounds")
		}
	}
	return c, nil
}

// events follows discriminated alternatives rather than guessing event names
// from Go component names. Arbitrary function/extension/fault records stay raw.
func events(doc *document) (map[string]*schema, error) {
	root := doc.Schemas[doc.Source.Root]
	if root == nil {
		return nil, fmt.Errorf("%s: missing event root %s", doc.Source.File, doc.Source.Root)
	}
	result := map[string]*schema{}
	branches := root.OneOf
	if len(branches) == 0 {
		branches = root.AnyOf
	}
	if len(branches) == 0 {
		return nil, fmt.Errorf("%s: missing event alternatives", doc.Source.File)
	}
	for _, branch := range branches {
		tag := branch.Properties["type"]
		record := branch.Properties["record"]
		if tag == nil || record == nil {
			return nil, fmt.Errorf("%s: event alternative lacks type/record", doc.Source.File)
		}
		var name string
		if tag.Const != nil {
			name = *tag.Const
		} else if len(tag.Enum) == 1 {
			name = tag.Enum[0]
		}
		if name == "" {
			return nil, fmt.Errorf("%s: event alternative lacks a single discriminator", doc.Source.File)
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("%s: duplicate event %s", doc.Source.File, name)
		}
		result[name] = record
	}
	return result, nil
}

func fields(doc *document, s *shape, prefix string, visiting map[string]bool, into map[string]recordField) error {
	if s.Kind == "ref" {
		if visiting[s.Ref] {
			return fmt.Errorf("%s: recursive record schema %s", doc.Source.File, s.Ref)
		}
		visiting[s.Ref] = true
		defer delete(visiting, s.Ref)
		return fields(doc, doc.Shapes[s.Ref], prefix, visiting, into)
	}
	if s.Kind != "object" {
		return nil
	}
	for _, name := range sortedKeys(s.Properties) {
		f := s.Properties[name]
		path := prefix + name
		resolved := f.Shape
		if resolved.Kind == "ref" {
			resolved = doc.Shapes[resolved.Ref]
		}
		values := slices.Clone(resolved.Enum)
		slices.Sort(values)
		typ := resolved.Kind
		if resolved.Format != "" {
			typ += ":" + resolved.Format
		}
		if f.Shape.Nullable {
			typ += "?"
		}
		into[path] = recordField{Type: typ, Enum: slices.Compact(values), Required: f.Required}
		if f.Shape.Kind == "array" {
			if err := fields(doc, f.Shape.Items, path+"[].", visiting, into); err != nil {
				return err
			}
		} else if err := fields(doc, f.Shape, path+".", visiting, into); err != nil {
			return err
		}
	}
	return nil
}

func versionMetadata(docs []*document) (map[string]Version, error) {
	all := map[string]map[string]bool{}
	perVersion := map[string]map[string]map[string]recordField{}
	result := map[string]Version{}
	for _, doc := range docs {
		if doc.Source.Role != "events" {
			continue
		}
		version := doc.Source.Version
		if _, duplicate := result[version]; duplicate {
			return nil, fmt.Errorf("duplicate event version %s", version)
		}
		events, err := events(doc)
		if err != nil {
			return nil, err
		}
		v := Version{API: apiName(doc.Source.API), Events: sortedKeys(events), OmitFields: map[string][]string{}, Fields: map[string][]string{}, FieldTypes: map[string]map[string]string{}, FieldEnums: map[string]map[string][]string{}, RequiredFields: map[string][]string{}, Source: doc.Source.File, Limitations: doc.Source.Limitations}
		perVersion[version] = map[string]map[string]recordField{}
		for _, event := range v.Events {
			s, err := doc.normalize(events[event], event+".record")
			if err != nil {
				return nil, err
			}
			f := map[string]recordField{}
			if err := fields(doc, s, "", map[string]bool{}, f); err != nil {
				return nil, err
			}
			perVersion[version][event] = f
			if all[event] == nil {
				all[event] = map[string]bool{}
			}
			v.Fields[event] = sortedKeys(f)
			v.FieldTypes[event] = map[string]string{}
			v.FieldEnums[event] = map[string][]string{}
			for _, path := range v.Fields[event] {
				all[event][path] = true
				v.FieldTypes[event][path] = f[path].Type
				if len(f[path].Enum) > 0 {
					v.FieldEnums[event][path] = f[path].Enum
				}
				if f[path].Required {
					v.RequiredFields[event] = append(v.RequiredFields[event], path)
				}
			}
		}
		result[version] = v
	}
	for version, v := range result {
		for _, event := range v.Events {
			f := perVersion[version][event]
			for _, path := range sortedKeys(all[event]) {
				if _, exists := f[path]; exists {
					continue
				}
				// Missing parents imply their children. Avoid asking consumers to
				// traverse omitted objects or arrays unnecessarily.
				covered := false
				for _, parent := range v.OmitFields[event] {
					if strings.HasPrefix(path, parent+".") || strings.HasPrefix(path, parent+"[].") {
						covered = true
						break
					}
				}
				if !covered {
					v.OmitFields[event] = append(v.OmitFields[event], path)
				}
			}
		}
		result[version] = v
	}
	return result, nil
}

func validateTransports(docs []*document) error {
	for _, transport := range docs {
		if transport.Source.Role != "transport" {
			continue
		}
		var http *document
		for _, candidate := range docs {
			if candidate.Source.Role == "events" && candidate.Source.API == transport.Source.API && candidate.Source.Version == transport.Source.Version {
				http = candidate
				break
			}
		}
		if http == nil {
			return fmt.Errorf("%s: transport has no matching event source", transport.Source.File)
		}
		if !reflect.DeepEqual(transport.Shapes, http.Shapes) {
			return fmt.Errorf("%s and %s: HTTP/TCP event shapes differ; explicit transport treatment is required", transport.Source.File, http.Source.File)
		}
	}
	return nil
}
