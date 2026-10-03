package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"stackd/internal/awsschema"
	"stackd/internal/smithy"
)

type contract struct {
	Info       awsschema.ServiceInfo
	Operations []awsschema.Operation
	Shapes     []awsschema.Shape
}

func parseModel(name string, data []byte, source awsschema.Source) (contract, error) {
	return parseModelWithCorrections(name, data, source, modelCorrectionsJSON)
}

func parseModelWithCorrections(name string, data []byte, source awsschema.Source, corrections []byte) (contract, error) {
	var model smithy.Model
	var result contract
	if err := json.Unmarshal(data, &model); err != nil {
		return result, fmt.Errorf("%s: decode Smithy model: %w", name, err)
	}
	if model.Smithy != "2.0" {
		return result, fmt.Errorf("%s: unsupported Smithy version %q", name, model.Smithy)
	}
	checksum := sha256.Sum256(data)
	source.SHA256 = hex.EncodeToString(checksum[:])
	if err := applyModelCorrections(name, &model, &source, corrections); err != nil {
		return result, fmt.Errorf("%s: %w", name, err)
	}
	addSmithyPrelude(&model)
	var service smithy.Shape
	for id, shape := range model.Shapes {
		if shape.Type != "service" {
			continue
		}
		if result.Info.ID != "" {
			return result, fmt.Errorf("%s: expected exactly one service", name)
		}
		result.Info = awsschema.ServiceInfo{Name: name, ID: awsschema.ShapeID(id), Version: shape.Version, Source: source, TargetPrefix: shapeName(awsschema.ShapeID(id))}
		service = shape
	}
	if result.Info.ID == "" || result.Info.Version == "" {
		return result, fmt.Errorf("%s: missing service or API version", name)
	}

	var serviceTrait struct {
		SDKID                 string `json:"sdkId"`
		EndpointPrefix        string `json:"endpointPrefix"`
		ARNNamespace          string `json:"arnNamespace"`
		CloudTrailEventSource string `json:"cloudTrailEventSource"`
	}
	if err := decodeTrait(service.Traits, "aws.api#service", &serviceTrait); err != nil {
		return result, err
	}
	result.Info.SDKID, result.Info.EndpointPrefix, result.Info.ARNNamespace = serviceTrait.SDKID, serviceTrait.EndpointPrefix, serviceTrait.ARNNamespace
	result.Info.CloudTrailEventSource = serviceTrait.CloudTrailEventSource
	// Native request-ID-matched CloudTrail captures supersede these two stale
	// Smithy metadata values; see testdata/aws/{resourcegroups,appregistry}/native-audit.json.
	switch name {
	case "resourcegroups":
		result.Info.CloudTrailEventSource = "resource-groups.amazonaws.com"
	case "servicecatalogappregistry":
		result.Info.CloudTrailEventSource = "servicecatalog-appregistry.amazonaws.com"
	}
	var signing struct {
		Name string `json:"name"`
	}
	if err := decodeTrait(service.Traits, "aws.auth#sigv4", &signing); err != nil {
		return result, err
	}
	result.Info.SigningName = signing.Name
	var namespace struct {
		URI string `json:"uri"`
	}
	if err := decodeTrait(service.Traits, "smithy.api#xmlNamespace", &namespace); err != nil {
		return result, err
	}
	result.Info.XMLNamespace = namespace.URI
	var restXML struct{ NoErrorWrapping bool }
	if err := decodeTrait(service.Traits, "aws.protocols#restXml", &restXML); err != nil {
		return result, err
	}
	result.Info.XMLNoErrorWrapping = restXML.NoErrorWrapping
	for _, protocol := range []awsschema.Protocol{awsschema.RPCV2CBOR, awsschema.AWSJSON10, awsschema.AWSJSON11, awsschema.AWSQuery, awsschema.EC2Query, awsschema.RestJSON, awsschema.RestXML} {
		trait := "aws.protocols#" + string(protocol)
		if protocol == awsschema.RPCV2CBOR {
			trait = "smithy.protocols#" + string(protocol)
		}
		if hasTrait(service.Traits, trait) {
			result.Info.Protocols = append(result.Info.Protocols, protocol)
		}
	}
	if len(result.Info.Protocols) == 0 {
		return result, fmt.Errorf("%s: missing supported AWS protocol", name)
	}
	result.Info.Protocol = result.Info.Protocols[0]
	result.Info.QueryCompatible = hasTrait(service.Traits, "aws.protocols#awsQueryCompatible")
	for _, auth := range []string{"aws.auth#sigv4", "aws.auth#sigv4a"} {
		if hasTrait(service.Traits, auth) {
			result.Info.AuthSchemes = append(result.Info.AuthSchemes, awsschema.ShapeID(auth))
		}
	}
	if hasTrait(service.Traits, "smithy.api#auth") {
		if err := decodeTrait(service.Traits, "smithy.api#auth", &result.Info.AuthSchemes); err != nil {
			return result, err
		}
	}
	operations, err := smithy.OperationTargets(model, service)
	if err != nil {
		return result, err
	}
	var pagination awsschema.Pagination
	if err := decodeTrait(service.Traits, "smithy.api#paginated", &pagination); err != nil {
		return result, err
	}
	for _, ref := range operations {
		shape, ok := model.Shapes[string(ref.Target)]
		if !ok || shape.Type != "operation" {
			return result, fmt.Errorf("%s: invalid operation target %q", name, ref.Target)
		}
		op := awsschema.Operation{Name: awsschema.OperationName(shapeName(ref.Target)), ID: ref.Target, Input: shape.Input.Target, Output: shape.Output.Target, ReadOnly: hasTrait(shape.Traits, "smithy.api#readonly"), Idempotent: hasTrait(shape.Traits, "smithy.api#idempotent"), OptionalAuth: hasTrait(shape.Traits, "smithy.api#optionalAuth")}
		op.UnsignedPayload = hasTrait(shape.Traits, "aws.auth#unsignedPayload")
		op.XMLUnwrappedOutput = hasTrait(shape.Traits, "aws.customizations#s3UnwrappedXmlOutput")
		var compression struct {
			Encodings []string `json:"encodings"`
		}
		if err := decodeTrait(shape.Traits, "smithy.api#requestCompression", &compression); err != nil {
			return result, err
		}
		op.RequestCompression = compression.Encodings
		var checksum struct {
			RequestAlgorithmMember  string `json:"requestAlgorithmMember"`
			RequestChecksumRequired bool   `json:"requestChecksumRequired"`
		}
		if err := decodeTrait(shape.Traits, "aws.protocols#httpChecksum", &checksum); err != nil {
			return result, err
		}
		op.RequestChecksumAlgorithmMember = checksum.RequestAlgorithmMember
		op.RequestChecksumRequired = checksum.RequestChecksumRequired
		if result.Info.Protocol == awsschema.RestJSON || result.Info.Protocol == awsschema.RestXML {
			var binding struct {
				Method, URI string
				Code        int
			}
			if err := decodeTrait(shape.Traits, "smithy.api#http", &binding); err != nil {
				return result, err
			}
			if binding.Method == "" || !strings.HasPrefix(binding.URI, "/") {
				return result, fmt.Errorf("%s: REST protocol requires an HTTP method and URI", op.ID)
			}
			if binding.Code == 0 {
				binding.Code = 200
			}
			op.HTTPMethod, op.HTTPURI, op.HTTPStatus = binding.Method, binding.URI, binding.Code
		}
		if op.Input == "" {
			op.Input = "smithy.api#Unit"
		}
		if op.Output == "" {
			op.Output = "smithy.api#Unit"
		}
		for _, e := range append(slices.Clone(service.Errors), shape.Errors...) {
			op.Errors = append(op.Errors, e.Target)
		}
		slices.Sort(op.Errors)
		op.Errors = slices.Compact(op.Errors)
		if hasTrait(shape.Traits, "smithy.api#paginated") {
			op.Pagination = pagination
			if err := decodeTrait(shape.Traits, "smithy.api#paginated", &op.Pagination); err != nil {
				return result, err
			}
		}
		op.AuthSchemes = slices.Clone(result.Info.AuthSchemes)
		if hasTrait(shape.Traits, "smithy.api#auth") {
			if err := decodeTrait(shape.Traits, "smithy.api#auth", &op.AuthSchemes); err != nil {
				return result, err
			}
		}
		result.Operations = append(result.Operations, op)
	}
	slices.SortFunc(result.Operations, func(a, b awsschema.Operation) int { return strings.Compare(string(a.Name), string(b.Name)) })
	for i := 1; i < len(result.Operations); i++ {
		if result.Operations[i-1].Name == result.Operations[i].Name {
			return result, fmt.Errorf("%s: duplicate operation name", name)
		}
	}
	for _, id := range sortedKeys(model.Shapes) {
		shape := model.Shapes[id]
		if shape.Type == "service" || shape.Type == "operation" || shape.Type == "resource" {
			continue
		}
		compiled, err := compileShape(awsschema.ShapeID(id), shape, result.Info.Protocol)
		if err != nil {
			return result, fmt.Errorf("%s: %w", id, err)
		}
		// Native AppRegistry identifier validation matches the complete input.
		// The model's ungrouped alternation accidentally admits trailing bytes;
		// native-boundaries.json captures rejection before missing-owner lookup.
		if id == "com.amazonaws.servicecatalogappregistry#ApplicationSpecifier" || id == "com.amazonaws.servicecatalogappregistry#AttributeGroupSpecifier" {
			compiled.Constraints.Pattern = "^(?:" + compiled.Constraints.Pattern + ")$"
		}
		result.Shapes = append(result.Shapes, compiled)
	}
	slices.SortFunc(result.Shapes, func(a, b awsschema.Shape) int { return strings.Compare(string(a.ID), string(b.ID)) })
	if err := validateContract(result); err != nil {
		return result, err
	}
	return result, nil
}

func compileShape(id awsschema.ShapeID, raw smithy.Shape, protocol awsschema.Protocol) (awsschema.Shape, error) {
	s := awsschema.Shape{ID: id, Kind: raw.Type, Sensitive: hasTrait(raw.Traits, "smithy.api#sensitive"), Sparse: hasTrait(raw.Traits, "smithy.api#sparse"), Streaming: hasTrait(raw.Traits, "smithy.api#streaming"), XMLFlattened: hasTrait(raw.Traits, "smithy.api#xmlFlattened"), Default: string(raw.Traits["smithy.api#default"])}
	s.JSONIntegerCoercion = hasTrait(raw.Traits, jsonIntegerCoercionTrait)
	if hasTrait(raw.Traits, openEnumTrait) {
		// Retain known values as string-shape metadata without treating the
		// upstream enum as a service-side admission constraint.
		s.Kind = "string"
	}
	var err error
	s.Constraints, err = compileConstraints(raw.Traits)
	if err != nil {
		return s, err
	}
	if err := decodeTrait(raw.Traits, "smithy.api#xmlName", &s.XMLName); err != nil {
		return s, err
	}
	var namespace struct{ URI, Prefix string }
	if err := decodeTrait(raw.Traits, "smithy.api#xmlNamespace", &namespace); err != nil {
		return s, err
	}
	s.XMLNamespace, s.XMLNamespacePrefix = namespace.URI, namespace.Prefix
	if err := decodeTrait(raw.Traits, "smithy.api#timestampFormat", &s.TimestampFormat); err != nil {
		return s, err
	}
	if err := decodeTrait(raw.Traits, "smithy.api#mediaType", &s.MediaType); err != nil {
		return s, err
	}
	if err := decodeTrait(raw.Traits, "smithy.api#error", &s.Error.Fault); err != nil {
		return s, err
	}
	if err := decodeTrait(raw.Traits, "smithy.api#httpError", &s.Error.HTTPStatus); err != nil {
		return s, err
	}
	var queryError struct {
		Code             string `json:"code"`
		HTTPResponseCode int    `json:"httpResponseCode"`
	}
	if err := decodeTrait(raw.Traits, "aws.protocols#awsQueryError", &queryError); err != nil {
		return s, err
	}
	s.Error.Code = queryError.Code
	// The legacy enum trait annotates string shapes. Retain its values without
	// changing the wire kind: service-specific errors can differ from modeled
	// enum-shape validation (Account rejects unknown contact types during access checks).
	if err := decodeTrait(raw.Traits, "smithy.api#enum", &s.Enum); err != nil {
		return s, err
	}
	for i := range s.Enum {
		if s.Enum[i].Name == "" {
			s.Enum[i].Name = s.Enum[i].Value
		}
	}
	if queryError.HTTPResponseCode != 0 {
		s.Error.HTTPStatus = queryError.HTTPResponseCode
	}
	if s.Error.Fault != "" && s.Error.Code == "" {
		s.Error.Code = shapeName(id)
	}
	for _, name := range sortedKeys(raw.Members) {
		ref := raw.Members[name]
		if raw.Type == "enum" || raw.Type == "intEnum" {
			value := string(ref.Traits["smithy.api#enumValue"])
			if raw.Type == "enum" {
				var text string
				if err := decodeTrait(ref.Traits, "smithy.api#enumValue", &text); err != nil {
					return s, err
				}
				value = text
			}
			s.Enum = append(s.Enum, awsschema.EnumValue{Name: name, Value: value})
			continue
		}
		member, err := compileMember(name, ref, protocol)
		if err != nil {
			return s, err
		}
		s.Members = append(s.Members, member)
	}
	for _, item := range []struct {
		name string
		raw  smithy.Reference
		out  *awsschema.Member
	}{{"member", raw.Member, &s.Member}, {"key", raw.Key, &s.Key}, {"value", raw.Value, &s.Value}} {
		if item.raw.Target == "" {
			continue
		}
		*item.out, err = compileMember(item.name, item.raw, protocol)
		if err != nil {
			return s, err
		}
	}
	return s, nil
}

func compileMember(name string, ref smithy.Reference, protocol awsschema.Protocol) (awsschema.Member, error) {
	m := awsschema.Member{Name: name, Target: ref.Target, Required: hasTrait(ref.Traits, "smithy.api#required"), Sensitive: hasTrait(ref.Traits, "smithy.api#sensitive"), IdempotencyToken: hasTrait(ref.Traits, "smithy.api#idempotencyToken"), XMLFlattened: hasTrait(ref.Traits, "smithy.api#xmlFlattened"), Default: string(ref.Traits["smithy.api#default"])}
	m.JSONResponseNull = hasTrait(ref.Traits, jsonResponseNullTrait)
	m.XMLAttribute = hasTrait(ref.Traits, "smithy.api#xmlAttribute")
	var namespace struct{ URI, Prefix string }
	if err := decodeTrait(ref.Traits, "smithy.api#xmlNamespace", &namespace); err != nil {
		return m, err
	}
	m.XMLNamespace, m.XMLNamespacePrefix = namespace.URI, namespace.Prefix
	m.HTTPLabel = hasTrait(ref.Traits, "smithy.api#httpLabel")
	m.HostLabel = hasTrait(ref.Traits, "smithy.api#hostLabel")
	m.HTTPPayload = hasTrait(ref.Traits, "smithy.api#httpPayload")
	m.HTTPResponseCode = hasTrait(ref.Traits, "smithy.api#httpResponseCode")
	m.HTTPQueryParams = hasTrait(ref.Traits, "smithy.api#httpQueryParams")
	m.HTTPPrefixHeadersSet = hasTrait(ref.Traits, "smithy.api#httpPrefixHeaders")
	m.EventHeader = hasTrait(ref.Traits, "smithy.api#eventHeader")
	m.EventPayload = hasTrait(ref.Traits, "smithy.api#eventPayload")
	for trait, destination := range map[string]*string{
		"smithy.api#httpQuery":         &m.HTTPQuery,
		"smithy.api#httpHeader":        &m.HTTPHeader,
		"smithy.api#httpPrefixHeaders": &m.HTTPPrefixHeaders,
	} {
		if err := decodeTrait(ref.Traits, trait, destination); err != nil {
			return m, err
		}
	}
	var err error
	m.Constraints, err = compileConstraints(ref.Traits)
	if err != nil {
		return m, err
	}
	if err := decodeTrait(ref.Traits, "smithy.api#jsonName", &m.JSONName); err != nil {
		return m, err
	}
	if err := decodeTrait(ref.Traits, "smithy.api#xmlName", &m.XMLName); err != nil {
		return m, err
	}
	if protocol == awsschema.EC2Query {
		if err := decodeTrait(ref.Traits, "aws.protocols#ec2QueryName", &m.EC2QueryName); err != nil {
			return m, err
		}
		if m.EC2QueryName == "" {
			m.EC2QueryName = m.XMLName
			if m.EC2QueryName == "" {
				m.EC2QueryName = m.Name
			}
			first, size := utf8.DecodeRuneInString(m.EC2QueryName)
			m.EC2QueryName = string(unicode.ToUpper(first)) + m.EC2QueryName[size:]
		}
	}
	if err := decodeTrait(ref.Traits, "smithy.api#timestampFormat", &m.TimestampFormat); err != nil {
		return m, err
	}
	return m, nil
}

func compileConstraints(t smithy.Traits) (awsschema.Constraints, error) {
	var c awsschema.Constraints
	for _, item := range []struct {
		trait string
		out   *awsschema.Bounds
	}{{"smithy.api#length", &c.Length}, {"smithy.api#range", &c.Range}} {
		var raw struct {
			Min json.Number `json:"min"`
			Max json.Number `json:"max"`
		}
		if err := decodeTrait(t, item.trait, &raw); err != nil {
			return c, err
		}
		if raw.Min != "" {
			item.out.Min = awsschema.Bound{Set: true, Value: string(raw.Min)}
		}
		if raw.Max != "" {
			item.out.Max = awsschema.Bound{Set: true, Value: string(raw.Max)}
		}
	}
	if err := decodeTrait(t, "smithy.api#pattern", &c.Pattern); err != nil {
		return c, err
	}
	c.UniqueItems = hasTrait(t, "smithy.api#uniqueItems")
	return c, nil
}

func validateContract(c contract) error {
	shapes := map[awsschema.ShapeID]awsschema.Shape{}
	names := map[string]awsschema.ShapeID{}
	for _, shape := range c.Shapes {
		switch shape.Kind {
		case "structure", "union", "list", "set", "map", "enum", "intEnum", "string", "blob", "boolean", "byte", "short", "integer", "long", "float", "double", "timestamp", "document":
		default:
			return fmt.Errorf("%s: unsupported shape kind %q", shape.ID, shape.Kind)
		}
		name := exportedName(shapeName(shape.ID))
		if other, exists := names[name]; exists && !sameScalarType(shapes[other], shape) {
			return fmt.Errorf("shape name collision %s and %s", other, shape.ID)
		}
		names[name] = shape.ID
		shapes[shape.ID] = shape
	}
	check := func(id awsschema.ShapeID) error {
		if id != "" {
			if _, exists := shapes[id]; !exists {
				return fmt.Errorf("unresolved shape target %s", id)
			}
		}
		return nil
	}
	for _, op := range c.Operations {
		for _, id := range append([]awsschema.ShapeID{op.Input, op.Output}, op.Errors...) {
			if err := check(id); err != nil {
				return fmt.Errorf("%s: %w", op.ID, err)
			}
		}
	}
	for _, shape := range c.Shapes {
		for _, member := range append(slices.Clone(shape.Members), shape.Member, shape.Key, shape.Value) {
			if err := check(member.Target); err != nil {
				return fmt.Errorf("%s: %w", shape.ID, err)
			}
		}
	}
	return nil
}

// Distinct scalar shapes may share a Go representation. Their modeled
// constraints remain attached to their separate IDs in the wire catalog.
func sameScalarType(a, b awsschema.Shape) bool {
	if a.Kind != b.Kind || len(a.Enum) != 0 || len(b.Enum) != 0 {
		return false
	}
	switch a.Kind {
	case "string", "boolean", "byte", "short", "integer", "long", "float", "double", "timestamp":
		return true
	}
	return false
}

func decodeTrait(t smithy.Traits, name string, out any) error {
	if raw, ok := t[name]; ok {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("invalid %s trait: %w", name, err)
		}
	}
	return nil
}
func hasTrait(t smithy.Traits, name string) bool { _, ok := t[name]; return ok }
func shapeName(id awsschema.ShapeID) string {
	_, name, found := strings.Cut(string(id), "#")
	if !found {
		return string(id)
	}
	return name
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
