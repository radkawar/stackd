package glue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/bufbuild/protocompile"
	"github.com/dlclark/regexp2"
	"github.com/hamba/avro/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// All resolvers are in-memory: customer schemas never open host files or fetch
// remote references while a resource transaction is held.
type registrySchemaLoader struct{}

func (registrySchemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference is unavailable: %s", url)
}

type registrySchemaRegexp struct{ re *regexp2.Regexp }

func (r registrySchemaRegexp) String() string { return r.re.String() }
func (r registrySchemaRegexp) MatchString(v string) bool {
	matched, err := r.re.MatchString(v)
	return err == nil && matched
}
func compileRegistrySchemaRegexp(pattern string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(pattern, regexp2.ECMAScript|regexp2.Unicode)
	if err != nil {
		return nil, err
	}
	return registrySchemaRegexp{re: re}, nil
}

type parsedRegistrySchema struct {
	canonical string
	avro      avro.Schema
	json      any
	protobuf  protoreflect.FileDescriptor
}

func parseRegistrySchema(ctx context.Context, format, definition string) (parsedRegistrySchema, error) {
	var out parsedRegistrySchema
	if len(definition) == 0 || len(definition) > 170000 {
		return out, errors.New("schema definition must contain 1 to 170000 bytes")
	}
	switch format {
	case "AVRO":
		parsed, err := avro.ParseWithCache(definition, "", &avro.SchemaCache{})
		if err != nil {
			return out, err
		}
		out.avro = parsed
		// Parsing canonical form discards defaults, which affect compatibility.
		// Keep all properties and normalize JSON object ordering instead.
		document, err := decodeRegistryJSON(definition)
		if err != nil {
			return out, err
		}
		out.json = document
	case "JSON":
		document, err := decodeRegistryJSON(definition)
		if err != nil {
			return out, err
		}
		out.json = document
		if object, ok := out.json.(map[string]any); ok {
			if draft, ok := object["$schema"].(string); ok {
				draft = strings.TrimSuffix(strings.Replace(draft, "https://", "http://", 1), "#")
				if draft != "http://json-schema.org/draft-04/schema" && draft != "http://json-schema.org/draft-06/schema" && draft != "http://json-schema.org/draft-07/schema" {
					return out, errors.New("glue supports JSON Schema draft-04, draft-06 and draft-07")
				}
			}
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft7)
		compiler.UseLoader(registrySchemaLoader{})
		compiler.UseRegexpEngine(compileRegistrySchemaRegexp)
		if err := compiler.AddResource("urn:stackd:glue:schema", out.json); err != nil {
			return out, err
		}
		if _, err := compiler.Compile("urn:stackd:glue:schema"); err != nil {
			return out, err
		}
	case "PROTOBUF":
		resolver := &protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(map[string]string{"schema.proto": definition})}
		compiler := protocompile.Compiler{Resolver: protocompile.WithStandardImports(resolver), MaxParallelism: 1}
		files, err := compiler.Compile(ctx, "schema.proto")
		if err != nil {
			return out, err
		}
		out.protobuf = files[0]
		if out.protobuf.Syntax() != protoreflect.Proto2 && out.protobuf.Syntax() != protoreflect.Proto3 {
			return out, errors.New("glue supports proto2 and proto3 only")
		}
		if out.protobuf.Extensions().Len() != 0 {
			return out, errors.New("protobuf extensions are not supported")
		}
		if err := validateRegistryMessages(out.protobuf.Messages()); err != nil {
			return out, err
		}
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(protodesc.ToFileDescriptorProto(out.protobuf))
		if err != nil {
			return out, err
		}
		out.canonical = base64.StdEncoding.EncodeToString(encoded)
		return out, nil
	default:
		return out, errors.New("DataFormat must be AVRO, JSON or PROTOBUF")
	}
	encoded, err := json.Marshal(out.json)
	if err != nil {
		return out, err
	}
	out.canonical = string(encoded)
	return out, nil
}

func validateRegistryMessages(messages protoreflect.MessageDescriptors) error {
	for i := range messages.Len() {
		message := messages.Get(i)
		if message.Extensions().Len() != 0 || message.ExtensionRanges().Len() != 0 {
			return errors.New("protobuf extensions are not supported")
		}
		for j := range message.Fields().Len() {
			if message.Fields().Get(j).Kind() == protoreflect.GroupKind {
				return errors.New("protobuf groups are not supported")
			}
		}
		if err := validateRegistryMessages(message.Messages()); err != nil {
			return err
		}
	}
	return nil
}

func registryCompatible(reader, writer parsedRegistrySchema, format string) error {
	switch format {
	case "AVRO":
		return avro.NewSchemaCompatibility().Compatible(reader.avro, writer.avro)
	case "JSON":
		return registryJSONContains(reader.json, writer.json)
	case "PROTOBUF":
		return registryProtoContains(reader.protobuf, writer.protobuf)
	default:
		return errors.New("unknown schema format")
	}
}

// registryJSONContains checks whether every writer instance is accepted by the
// reader. Unsupported constraint algebra is explicit, never an assumed success.
func registryJSONContains(reader, writer any) error {
	if rb, ok := reader.(bool); ok {
		if rb {
			return nil
		}
		if wb, ok := writer.(bool); ok && !wb {
			return nil
		}
		return errors.New("reader rejects writer instances")
	}
	if wb, ok := writer.(bool); ok {
		if !wb {
			return nil
		}
		writer = map[string]any{}
	}
	r, _ := reader.(map[string]any)
	w, _ := writer.(map[string]any)
	for _, m := range []map[string]any{r, w} {
		for key := range m {
			switch key {
			case "$schema", "$id", "id", "title", "description", "default", "examples", "type", "properties", "required", "additionalProperties", "items", "enum", "const", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties":
			default:
				// TODO: Comeback implement JSON compatibility for references, composition, pattern/dependency constraints and exclusive/multiple bounds using evidenced containment rules.
				return failure("InvalidInputException", "JSON compatibility for keyword "+key+" is not implemented")
			}
		}
	}
	rtypes := registryJSONTypes(r["type"])
	wtypes := registryJSONTypes(w["type"])
	for typ := range wtypes {
		if !rtypes[typ] && !(typ == "integer" && rtypes["number"]) {
			return fmt.Errorf("reader type excludes writer type %s", typ)
		}
	}
	if allowed, ok := r["enum"].([]any); ok {
		values, ok := w["enum"].([]any)
		if !ok {
			if v, has := w["const"]; has {
				values = []any{v}
			} else {
				return errors.New("writer enum is unrestricted")
			}
		}
		for _, v := range values {
			matched := false
			for _, a := range allowed {
				if registryJSONEqual(v, a) {
					matched = true
					break
				}
			}
			if !matched {
				return errors.New("reader enum excludes writer value")
			}
		}
	}
	if c, ok := r["const"]; ok {
		if v, exists := w["const"]; !exists || !registryJSONEqual(c, v) {
			return errors.New("reader constant differs from writer")
		}
	}
	for _, key := range []string{"minimum", "minLength", "minItems", "minProperties"} {
		if rv, ok := r[key].(json.Number); ok {
			wv, exists := w[key].(json.Number)
			if !exists || registryJSONNumberCmp(wv, rv) < 0 {
				return fmt.Errorf("reader %s is more restrictive", key)
			}
		}
	}
	for _, key := range []string{"maximum", "maxLength", "maxItems", "maxProperties"} {
		if rv, ok := r[key].(json.Number); ok {
			wv, exists := w[key].(json.Number)
			if !exists || registryJSONNumberCmp(wv, rv) > 0 {
				return fmt.Errorf("reader %s is more restrictive", key)
			}
		}
	}
	if rtypes["object"] && wtypes["object"] {
		rp, _ := r["properties"].(map[string]any)
		wp, _ := w["properties"].(map[string]any)
		rrequired := registryStringSet(r["required"])
		wrequired := registryStringSet(w["required"])
		for key := range rrequired {
			if !wrequired[key] {
				return fmt.Errorf("reader requires property %s", key)
			}
		}
		ra, ok := r["additionalProperties"]
		if !ok {
			ra = true
		}
		wa, ok := w["additionalProperties"]
		if !ok {
			wa = true
		}
		for key, rs := range rp {
			ws, ok := wp[key]
			if !ok {
				ws = wa
			}
			if err := registryJSONContains(rs, ws); err != nil {
				return err
			}
		}
		for key, ws := range wp {
			if _, ok := rp[key]; !ok {
				if err := registryJSONContains(ra, ws); err != nil {
					return err
				}
			}
		}
		if err := registryJSONContains(ra, wa); err != nil {
			return err
		}
	}
	if rtypes["array"] && wtypes["array"] {
		ri, ok := r["items"]
		if !ok {
			ri = true
		}
		wi, ok := w["items"]
		if !ok {
			wi = true
		}
		if _, ok := ri.([]any); ok {
			return failure("InvalidInputException", "JSON tuple compatibility is not implemented")
		}
		if _, ok := wi.([]any); ok {
			return failure("InvalidInputException", "JSON tuple compatibility is not implemented")
		}
		if err := registryJSONContains(ri, wi); err != nil {
			return err
		}
	}
	return nil
}
func decodeRegistryJSON(definition string) (any, error) {
	return jsonschema.UnmarshalJSON(strings.NewReader(definition))
}
func registryJSONNumberCmp(a, b json.Number) int {
	var x, y big.Rat
	x.SetString(string(a))
	y.SetString(string(b))
	return x.Cmp(&y)
}
func registryJSONEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && registryJSONNumberCmp(x, y) == 0
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !registryJSONEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for key, v := range x {
			other, ok := y[key]
			if !ok || !registryJSONEqual(v, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
func registryJSONTypes(v any) map[string]bool {
	if v == nil {
		return map[string]bool{"null": true, "boolean": true, "object": true, "array": true, "number": true, "integer": true, "string": true}
	}
	if s, ok := v.(string); ok {
		out := map[string]bool{s: true}
		if s == "number" {
			out["integer"] = true
		}
		return out
	}
	out := registryStringSet(v)
	if out["number"] {
		out["integer"] = true
	}
	return out
}
func registryStringSet(v any) map[string]bool {
	out := map[string]bool{}
	if values, ok := v.([]any); ok {
		for _, v := range values {
			if s, ok := v.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

func registryProtoContains(reader, writer protoreflect.FileDescriptor) error {
	seen := map[[2]protoreflect.FullName]bool{}
	for i := range writer.Messages().Len() {
		wm := writer.Messages().Get(i)
		rm := reader.Messages().ByName(wm.Name())
		if rm == nil || rm.FullName() != wm.FullName() {
			return fmt.Errorf("reader is missing message %s", wm.FullName())
		}
		if err := registryProtoMessageContains(rm, wm, seen); err != nil {
			return err
		}
	}
	for i := range writer.Services().Len() {
		ws := writer.Services().Get(i)
		rs := reader.Services().ByName(ws.Name())
		if rs == nil {
			return fmt.Errorf("reader is missing service %s", ws.FullName())
		}
		for j := range ws.Methods().Len() {
			wm := ws.Methods().Get(j)
			rm := rs.Methods().ByName(wm.Name())
			if rm == nil || rm.Input().FullName() != wm.Input().FullName() || rm.Output().FullName() != wm.Output().FullName() || rm.IsStreamingClient() != wm.IsStreamingClient() || rm.IsStreamingServer() != wm.IsStreamingServer() {
				return fmt.Errorf("reader RPC method differs: %s", wm.FullName())
			}
		}
	}
	return nil
}
func registryProtoMessageContains(reader, writer protoreflect.MessageDescriptor, seen map[[2]protoreflect.FullName]bool) error {
	pair := [2]protoreflect.FullName{reader.FullName(), writer.FullName()}
	if seen[pair] {
		return nil
	}
	seen[pair] = true
	for i := range reader.Fields().Len() {
		r := reader.Fields().Get(i)
		w := writer.Fields().ByNumber(r.Number())
		if w == nil {
			if r.Cardinality() == protoreflect.Required {
				return fmt.Errorf("writer lacks required field %s", r.FullName())
			}
			continue
		}
		if r.Cardinality() == protoreflect.Required && w.Cardinality() != protoreflect.Required {
			return fmt.Errorf("writer field %s is optional", w.FullName())
		}
		if r.IsList() != w.IsList() || r.IsMap() != w.IsMap() {
			return fmt.Errorf("field cardinality changed: %s", r.FullName())
		}
		if r.ContainingOneof() != nil || w.ContainingOneof() != nil {
			if r.ContainingOneof() == nil || w.ContainingOneof() == nil || r.ContainingOneof().Name() != w.ContainingOneof().Name() {
				// TODO: Comeback support safe protobuf oneof migrations after native compatibility evidence.
				return failure("InvalidInputException", "Protobuf oneof migration compatibility is not implemented")
			}
		}
		if r.Kind() != w.Kind() {
			// TODO: Comeback implement protobuf cross-scalar wire-compatible evolution, including packed and numeric coercion boundaries.
			return failure("InvalidInputException", "Protobuf scalar type migration compatibility is not implemented")
		}
		if r.Kind() == protoreflect.MessageKind {
			if err := registryProtoMessageContains(r.Message(), w.Message(), seen); err != nil {
				return err
			}
		}
		if r.Kind() == protoreflect.EnumKind {
			for j := range w.Enum().Values().Len() {
				if r.Enum().Values().ByNumber(w.Enum().Values().Get(j).Number()) == nil && reader.ParentFile().Syntax() == protoreflect.Proto2 {
					return fmt.Errorf("reader enum excludes writer value for %s", r.FullName())
				}
			}
		}
	}
	return nil
}
