package appconfig

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"stackd/internal/awswire"
)

// Published verbatim at:
// https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-type-reference-feature-flags.html
//
//go:embed feature_flags_schema.json
var featureFlagsSchemaJSON []byte

var featureFlagsSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(featureFlagsSchemaJSON))
	if err != nil {
		return nil, err
	}
	definitions := document.(map[string]any)["definitions"].(map[string]any)
	// Both homogeneous-array alternatives match the empty array. Native accepts
	// it; the published oneOf inadvertently excludes it. Keep the fixture intact
	// and adjust only this calibrated discrepancy in the compiled schema.
	array := definitions["attributeValue"].(map[string]any)["oneOf"].([]any)[3].(map[string]any)
	array["anyOf"] = array["oneOf"]
	delete(array, "oneOf")
	return contentSchema(document, jsonschema.Draft7)
})

type featureFlagViolation struct {
	Constraint string `json:"Constraint"`
	Location   string `json:"Location"`
	Type       string `json:"Type"`
	Value      string `json:"Value"`
}

func featureFlagError(constraint, location string, value any) *awswire.Error {
	text, ok := value.(string)
	if !ok && value != nil {
		encoded, _ := json.Marshal(value)
		text = string(encoded)
	}
	details, _ := json.Marshal(map[string]any{"InvalidConfiguration": []featureFlagViolation{{constraint, location, "NotSatisfied", text}}})
	err := failure("BadRequestException", "Error invoking extension AppConfig Feature Flags Helper: Invalid 'Content' data")
	err.Reason = "InvalidConfiguration"
	err.Details = map[string]json.RawMessage{"Details": details}
	return err
}

func flagObject(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func flagKeys(object map[string]any) []string { return slices.Sorted(maps.Keys(object)) }

// Native's hosted helper ignores unknown definition properties, but not unknown
// attribute values. Known fields retain their types for schema validation.
func keepFlagFields(object map[string]any, allowed ...string) {
	for key := range object {
		if !slices.Contains(allowed, key) {
			delete(object, key)
		}
	}
}

func normalizeFlagBoolean(object map[string]any, key, path string, defaultMissing bool) error {
	value, exists := object[key]
	if !exists && !defaultMissing {
		return nil
	}
	if value == nil {
		object[key] = false
		return nil
	}
	if text, ok := value.(string); ok {
		parsed, err := strconv.ParseBool(text)
		if err != nil {
			return featureFlagError("Boolean", path, value)
		}
		object[key] = parsed
	} else if _, ok := value.(bool); !ok {
		return featureFlagError("Boolean", path, value)
	}
	return nil
}

func parseFeatureFlags(content []byte) (map[string]any, error) {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(content))
	if err != nil {
		return nil, featureFlagError("JSON", "", string(content))
	}
	root, ok := document.(map[string]any)
	if !ok {
		return nil, featureFlagError("Object", "", document)
	}
	keepFlagFields(root, "version", "flags", "values")
	if _, exists := root["version"]; !exists {
		return nil, featureFlagError("Required", "version", "")
	}
	if root["version"] != "1" {
		return nil, featureFlagError("OneOf(1)", "version", root["version"])
	}
	for _, definition := range flagObject(root["flags"]) {
		flag := flagObject(definition)
		keepFlagFields(flag, "name", "description", "_createdAt", "_updatedAt", "_deprecation", "attributes")
		for _, attribute := range flagObject(flag["attributes"]) {
			keepFlagFields(flagObject(attribute), "description", "constraints")
		}
	}
	for name, value := range flagObject(root["values"]) {
		flag := flagObject(value)
		if flag == nil {
			continue // The published schema reports the invalid object type.
		}
		variants, hasVariants := flag["_variants"]
		if hasVariants {
			for key := range flag {
				if key != "_variants" && key != "_createdAt" && key != "_updatedAt" {
					return nil, featureFlagError("StrictVariants", "values."+name, value)
				}
			}
			if list, ok := variants.([]any); ok {
				for i, v := range list {
					variant := flagObject(v)
					if variant == nil {
						continue
					}
					keepFlagFields(variant, "name", "enabled", "rule", "attributeValues")
					if err := normalizeFlagBoolean(variant, "enabled", fmt.Sprintf("values.%s._variants.%d.enabled", name, i), false); err != nil {
						return nil, err
					}
				}
			}
		} else if err := normalizeFlagBoolean(flag, "enabled", "values."+name+".enabled", true); err != nil {
			return nil, err
		}
	}
	schema, err := featureFlagsSchema()
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(root); err != nil {
		var validation *jsonschema.ValidationError
		if errors.As(err, &validation) {
			for len(validation.Causes) != 0 {
				validation = validation.Causes[0]
			}
			return nil, featureFlagError("Schema", strings.Join(validation.InstanceLocation, "."), "")
		}
		return nil, err
	}
	if err := validateFlagValues(root); err != nil {
		return nil, err
	}
	return root, nil
}

func validateFeatureFlags(content []byte) error {
	_, err := parseFeatureFlags(content)
	return err
}

func validateFlagValues(root map[string]any) error {
	definitions := flagObject(root["flags"])
	values := flagObject(root["values"])
	for _, name := range flagKeys(values) {
		flag := flagObject(values[name])
		attributes := flagObject(flagObject(definitions[name])["attributes"])
		path := "values." + name
		schemas := make(map[string]*jsonschema.Schema, len(attributes))
		for _, key := range flagKeys(attributes) {
			constraints := flagObject(flagObject(attributes[key])["constraints"])
			if len(constraints) == 0 {
				continue
			}
			schema, err := contentSchema(flagAttributeSchema(constraints), jsonschema.Draft7)
			if err != nil {
				return featureFlagError("Constraint", "flags."+name+".attributes."+key+".constraints", constraints)
			}
			schemas[key] = schema
		}
		if list, ok := flag["_variants"].([]any); ok {
			seen := make(map[string]bool, len(list))
			for i, raw := range list {
				variant := flagObject(raw)
				variantName := variant["name"].(string)
				if seen[variantName] {
					return featureFlagError("UniqueVariantNames", path+"._variants", variantName)
				}
				seen[variantName] = true
				rule, _ := variant["rule"].(string)
				variantPath := fmt.Sprintf("%s._variants.%d", path, i)
				if i == len(list)-1 && rule != "" {
					return featureFlagError("Empty", variantPath+".rule", rule)
				}
				if i < len(list)-1 {
					if rule == "" {
						return featureFlagError("NonEmpty", variantPath+".rule", rule)
					}
					if err := validateVariantRule(rule); err != nil {
						return featureFlagError("RuleIsValid", variantPath+".rule", rule)
					}
				}
				if err := validateFlagAttributes(attributes, schemas, flagObject(variant["attributeValues"]), variantPath+".attributeValues", false); err != nil {
					return err
				}
			}
		} else if err := validateFlagAttributes(attributes, schemas, flag, path, true); err != nil {
			return err
		}
	}
	return nil
}

func validateFlagAttributes(definitions map[string]any, schemas map[string]*jsonschema.Schema, values map[string]any, path string, flag bool) error {
	for _, key := range flagKeys(values) {
		if flag && (key == "enabled" || key == "_createdAt" || key == "_updatedAt") {
			continue
		}
		if _, ok := definitions[key]; !ok {
			return featureFlagError("DefinedAttribute", path+"."+key, values[key])
		}
	}
	for _, key := range flagKeys(definitions) {
		constraints := flagObject(flagObject(definitions[key])["constraints"])
		value, present := values[key]
		if !present {
			if constraints["required"] == true {
				return featureFlagError("Required", path+"."+key, "")
			}
			continue
		}
		schema := schemas[key]
		if schema == nil {
			continue
		}
		if err := schema.Validate(value); err != nil {
			return featureFlagError("AttributeConstraint", path+"."+key, value)
		}
	}
	return nil
}

func flagAttributeSchema(constraints map[string]any) map[string]any {
	document := make(map[string]any, len(constraints))
	for key, value := range constraints {
		switch key {
		case "required":
		case "elements":
			document["items"] = flagAttributeSchema(flagObject(value))
		default:
			document[key] = value
		}
	}
	return document
}

// normalizeFeatureFlags is the hosted helper's storage representation, not the
// data API representation. Entries preserve creation times and change update
// times only when their semantic content changes from the preceding version.
func normalizeFeatureFlags(content, previous []byte, now time.Time) ([]byte, error) {
	root, err := parseFeatureFlags(content)
	if err != nil {
		return nil, err
	}
	var old map[string]any
	if len(previous) != 0 {
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(previous))
		if err != nil {
			return nil, err
		}
		old = flagObject(document)
	}
	stamp := now.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano)
	for _, section := range []string{"flags", "values"} {
		entries := flagObject(root[section])
		if len(entries) == 0 {
			delete(root, section)
			continue
		}
		oldEntries := flagObject(old[section])
		for name, raw := range entries {
			entry := flagObject(raw)
			before := flagObject(oldEntries[name])
			created, _ := entry["_createdAt"].(string)
			if created == "" {
				created, _ = before["_createdAt"].(string)
			}
			if created == "" {
				created = stamp
			}
			updated, _ := before["_updatedAt"].(string)
			delete(entry, "_createdAt")
			delete(entry, "_updatedAt")
			delete(before, "_createdAt")
			delete(before, "_updatedAt")
			// The helper omits empty optional definition collections and variants.
			for _, key := range []string{"attributes", "_variants"} {
				if value, ok := entry[key].(map[string]any); ok && len(value) == 0 {
					delete(entry, key)
				}
				if value, ok := entry[key].([]any); ok && len(value) == 0 {
					delete(entry, key)
				}
			}
			if updated == "" || !reflect.DeepEqual(entry, before) {
				updated = stamp
			}
			entry["_createdAt"] = created
			entry["_updatedAt"] = updated
		}
	}
	return json.Marshal(root)
}

// GetLatestConfiguration has no Agent evaluation context. Native AppConfig
// returns each multi-variant flag's final (default) variant, never its rules.
func (*Service) servedContent(profileType string, content []byte) ([]byte, error) {
	if profileType != "AWS.AppConfig.FeatureFlags" {
		return content, nil
	}
	// Admission already validated schemas and rule expressions. Polling only
	// decodes and projects immutable content; it does not compile validators.
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	root := flagObject(document)
	if root == nil {
		return nil, featureFlagError("Object", "", document)
	}
	values := flagObject(root["values"])
	if root["values"] != nil && values == nil {
		return nil, featureFlagError("Object", "values", root["values"])
	}
	served := make(map[string]any, len(values))
	for name, raw := range values {
		flag := flagObject(raw)
		if flag == nil {
			return nil, featureFlagError("Object", "values."+name, raw)
		}
		if err := normalizeFlagBoolean(flag, "enabled", "values."+name+".enabled", true); err != nil {
			return nil, err
		}
		attributes := flag
		result := map[string]any{"enabled": flag["enabled"] == true}
		if variants, ok := flag["_variants"].([]any); ok && len(variants) != 0 {
			variant := flagObject(variants[len(variants)-1])
			if variant == nil {
				return nil, featureFlagError("Object", "values."+name+"._variants", variants)
			}
			if err := normalizeFlagBoolean(variant, "enabled", "values."+name+"._variants.enabled", true); err != nil {
				return nil, err
			}
			result["enabled"] = variant["enabled"] == true
			result["_variant"] = variant["name"]
			attributes = flagObject(variant["attributeValues"])
		}
		if result["enabled"] == true {
			for key, value := range attributes {
				if key != "enabled" && !strings.HasPrefix(key, "_") {
					result[key] = value
				}
			}
		}
		served[name] = result
	}
	return json.Marshal(served)
}
