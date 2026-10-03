package cloudformation

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Template holds customer expressions, not provisioned resource state.
type Template struct {
	Description        string
	Parameters         map[string]TemplateParameter
	Resources          map[string]TemplateResource
	Outputs            map[string]TemplateOutput
	Mappings           map[string]map[string]map[string]any
	Conditions         map[string]any
	Metadata           map[string]any
	Rules              map[string]TemplateRule
	LanguageExtensions bool
}

type TemplateParameter struct {
	Type, Description                     string
	Default                               any
	NoEcho                                bool
	AllowedValues                         []string
	AllowedPattern, ConstraintDescription string
	MinLength, MaxLength                  *int
	MinValue, MaxValue                    *float64
	pattern                               *regexp.Regexp
}

type TemplateResource struct {
	Type, Condition, DeletionPolicy, UpdateReplacePolicy string
	Properties                                           Properties
	DependsOn                                            []string
	Metadata                                             map[string]any
}

type TemplateOutput struct {
	Value                  any
	Description, Condition string
	ExportName             any
}

type Evaluation struct {
	Scope              Scope
	StackID, StackName string
	Parameters         map[string]string
	ResolvedParameters map[string]string
	Resources          map[string]ResourceResult
	Imports            map[string]string
}

type OutputValue struct {
	Value, Description, ExportName string
}

var templateLogicalID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// ParseTemplate accepts a single JSON or YAML document. Admission rejects
// unsupported effects even when hidden inside an inactive conditional branch.
func ParseTemplate(body string) (*Template, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, fmt.Errorf("template body is empty")
	}
	if strings.HasPrefix(trimmed, "{") && !json.Valid([]byte(trimmed)) {
		return nil, fmt.Errorf("template body is not valid JSON")
	}
	decoder := yaml.NewDecoder(strings.NewReader(body))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("template must contain exactly one document")
	}
	if len(document.Content) != 1 {
		return nil, fmt.Errorf("template must be an object")
	}
	value, err := templateYAML(document.Content[0], 0, false)
	if err != nil {
		return nil, err
	}
	root, err := templateObject(value, "template")
	if err != nil {
		return nil, err
	}
	if err := templateFields(root, "template", "AWSTemplateFormatVersion", "Description", "Metadata", "Parameters", "Mappings", "Conditions", "Rules", "Resources", "Outputs", "Transform"); err != nil {
		return nil, err
	}
	if version, exists := root["AWSTemplateFormatVersion"]; exists && version != "2010-09-09" {
		return nil, fmt.Errorf("AWSTemplateFormatVersion must be 2010-09-09")
	}
	t := &Template{Parameters: map[string]TemplateParameter{}, Resources: map[string]TemplateResource{}, Outputs: map[string]TemplateOutput{}, Mappings: map[string]map[string]map[string]any{}, Conditions: map[string]any{}, Rules: map[string]TemplateRule{}}
	if transform, exists := root["Transform"]; exists {
		if list, ok := transform.([]any); ok && len(list) == 1 {
			transform = list[0]
		}
		if name, ok := transform.(string); !ok || name != "AWS::LanguageExtensions" {
			// TODO: Comeback: execute custom macros, SAM and Include through real transform owners.
			return nil, fmt.Errorf("only the AWS::LanguageExtensions transform is supported")
		}
		// TODO: Comeback: support ForEach, ToJsonString and expanded Ref/GetAtt syntax; currently Length only.
		t.LanguageExtensions = true
	}
	if t.Description, err = templateString(root, "Description", "template", false); err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(t.Description) > 1024 {
		return nil, fmt.Errorf("template Description exceeds 1024 characters")
	}
	if raw, exists := root["Metadata"]; exists {
		if t.Metadata, err = templateObject(raw, "Metadata"); err != nil {
			return nil, err
		}
	}
	for _, section := range []string{"Parameters", "Mappings", "Conditions", "Rules", "Resources", "Outputs"} {
		raw, exists := root[section]
		if !exists {
			continue
		}
		entries, err := templateObject(raw, section)
		if err != nil {
			return nil, err
		}
		for _, name := range templateKeys(entries) {
			if !templateLogicalID.MatchString(name) {
				return nil, fmt.Errorf("%s logical ID %q must start with a letter and contain only alphanumeric characters", section, name)
			}
			path := section + "." + name
			if section == "Conditions" {
				t.Conditions[name] = entries[name]
				continue
			}
			entry, err := templateObject(entries[name], path)
			if err != nil {
				return nil, err
			}
			switch section {
			case "Rules":
				rule, err := parseTemplateRule(entry, path)
				if err != nil {
					return nil, err
				}
				t.Rules[name] = rule
			case "Parameters":
				parameter, err := parseTemplateParameter(entry, path)
				if err != nil {
					return nil, err
				}
				t.Parameters[name] = parameter
			case "Resources":
				resource, err := parseTemplateResource(entry, path)
				if err != nil {
					return nil, err
				}
				t.Resources[name] = resource
			case "Outputs":
				output, err := parseTemplateOutput(entry, path)
				if err != nil {
					return nil, err
				}
				t.Outputs[name] = output
			case "Mappings":
				mapping := map[string]map[string]any{}
				for key, raw := range entry {
					values, err := templateObject(raw, path+"."+key)
					if err != nil {
						return nil, err
					}
					for attribute, value := range values {
						if err := templateMappingValue(value); err != nil {
							return nil, fmt.Errorf("%s.%s.%s: %w", path, key, attribute, err)
						}
					}
					mapping[key] = values
				}
				t.Mappings[name] = mapping
			}
		}
	}
	if len(t.Resources) == 0 {
		return nil, fmt.Errorf("template must contain at least one resource")
	}
	if len(t.Resources) > 500 || len(t.Parameters) > 200 || len(t.Outputs) > 200 || len(t.Mappings) > 200 {
		return nil, fmt.Errorf("template exceeds resource, parameter, output or mapping quota")
	}
	for name := range t.Parameters {
		if _, exists := t.Resources[name]; exists {
			return nil, fmt.Errorf("logical ID %s is used by both a parameter and a resource", name)
		}
	}
	if err := t.validateExpressions(); err != nil {
		return nil, err
	}
	return t, nil
}

func templateYAML(node *yaml.Node, depth int, untagged bool) (any, error) {
	if depth > 128 {
		return nil, fmt.Errorf("template nesting exceeds 128 levels")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return nil, fmt.Errorf("YAML aliases and anchors are not supported (line %d)", node.Line)
	}
	if !untagged && strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		name := strings.TrimPrefix(node.Tag, "!")
		if name != "Ref" && name != "Condition" {
			name = "Fn::" + name
		}
		if (!templateIntrinsic(name) && !templateRuleIntrinsic(name)) || name == "Fn::Length" {
			// TODO: Comeback: implement remaining intrinsic functions with authoritative service context.
			return nil, fmt.Errorf("unsupported YAML intrinsic %s at line %d", node.Tag, node.Line)
		}
		value, err := templateYAML(node, depth+1, true)
		if err != nil {
			return nil, err
		}
		return map[string]any{name: value}, nil
	}
	if !untagged && (node.Kind == yaml.MappingNode && node.Tag != "!!map" || node.Kind == yaml.SequenceNode && node.Tag != "!!seq") {
		return nil, fmt.Errorf("unsupported YAML tag %s at line %d", node.Tag, node.Line)
	}
	switch node.Kind {
	case yaml.MappingNode:
		result := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || key.Anchor != "" {
				return nil, fmt.Errorf("YAML object keys must be strings; merge keys are unsupported (line %d)", key.Line)
			}
			if _, exists := result[key.Value]; exists {
				return nil, fmt.Errorf("duplicate template key %q at line %d", key.Value, key.Line)
			}
			value, err := templateYAML(node.Content[i+1], depth+1, false)
			if err != nil {
				return nil, err
			}
			result[key.Value] = value
		}
		return result, nil
	case yaml.SequenceNode:
		result := make([]any, len(node.Content))
		for i, child := range node.Content {
			value, err := templateYAML(child, depth+1, false)
			if err != nil {
				return nil, err
			}
			result[i] = value
		}
		return result, nil
	case yaml.ScalarNode:
		if untagged {
			return node.Value, nil
		}
		switch node.Tag {
		case "!!str":
			if node.Style == 0 {
				switch strings.ToLower(node.Value) {
				case "yes", "on", "y":
					return true, nil
				case "no", "off", "n":
					return false, nil
				}
			}
			return node.Value, nil
		case "!!timestamp":
			if node.Style&yaml.TaggedStyle == 0 {
				return node.Value, nil // Unquoted template version dates remain strings.
			}
		case "!!bool":
			var value bool
			if err := node.Decode(&value); err != nil {
				return nil, err
			}
			return value, nil
		case "!!int", "!!float":
			var value float64
			if err := node.Decode(&value); err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				return nil, fmt.Errorf("invalid finite number at line %d", node.Line)
			}
			return value, nil
		case "!!null":
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unsupported YAML tag %s at line %d", node.Tag, node.Line)
}

func parseTemplateParameter(entry map[string]any, path string) (TemplateParameter, error) {
	var p TemplateParameter
	if err := templateFields(entry, path, "Type", "Description", "Default", "NoEcho", "AllowedValues", "AllowedPattern", "ConstraintDescription", "MinLength", "MaxLength", "MinValue", "MaxValue"); err != nil {
		return p, err
	}
	var err error
	if p.Type, err = templateString(entry, "Type", path, true); err != nil {
		return p, err
	}
	switch p.Type {
	case "String", "Number", "List<Number>", "CommaDelimitedList", "AWS::SSM::Parameter::Name", "AWS::SSM::Parameter::Value<String>", "AWS::SSM::Parameter::Value<List<String>>", "AWS::SSM::Parameter::Value<CommaDelimitedList>":
	default:
		// TODO: Comeback: validate AWS-specific resource identifier parameter types through their owners.
		return p, fmt.Errorf("%s.Type %q is unsupported", path, p.Type)
	}
	for key, target := range map[string]*string{"Description": &p.Description, "AllowedPattern": &p.AllowedPattern, "ConstraintDescription": &p.ConstraintDescription} {
		if *target, err = templateString(entry, key, path, false); err != nil {
			return p, err
		}
	}
	if utf8.RuneCountInString(p.Description) > 4000 {
		return p, fmt.Errorf("%s.Description exceeds 4000 characters", path)
	}
	if raw, exists := entry["NoEcho"]; exists {
		text, err := templateScalar(raw)
		if err != nil || (text != "true" && text != "false") {
			return p, fmt.Errorf("%s.NoEcho must be a boolean", path)
		}
		p.NoEcho = text == "true"
	}
	if raw, exists := entry["AllowedValues"]; exists {
		values, ok := raw.([]any)
		if !ok || len(values) == 0 {
			return p, fmt.Errorf("%s.AllowedValues must be a nonempty list", path)
		}
		for _, value := range values {
			text, err := templateScalar(value)
			if err != nil {
				return p, fmt.Errorf("%s.AllowedValues must contain scalar values", path)
			}
			p.AllowedValues = append(p.AllowedValues, text)
		}
	}
	for key, target := range map[string]**int{"MinLength": &p.MinLength, "MaxLength": &p.MaxLength} {
		if raw, exists := entry[key]; exists {
			text, err := templateScalar(raw)
			value, parseErr := strconv.Atoi(text)
			if err != nil || parseErr != nil || value < 0 || p.Type != "String" {
				return p, fmt.Errorf("%s.%s requires a nonnegative integer and String type", path, key)
			}
			*target = &value
		}
	}
	for key, target := range map[string]**float64{"MinValue": &p.MinValue, "MaxValue": &p.MaxValue} {
		if raw, exists := entry[key]; exists {
			text, err := templateScalar(raw)
			value, parseErr := strconv.ParseFloat(text, 64)
			if err != nil || parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) || p.Type != "Number" {
				return p, fmt.Errorf("%s.%s requires a finite number and Number type", path, key)
			}
			*target = &value
		}
	}
	if p.MinLength != nil && p.MaxLength != nil && *p.MinLength > *p.MaxLength || p.MinValue != nil && p.MaxValue != nil && *p.MinValue > *p.MaxValue {
		return p, fmt.Errorf("%s minimum constraint exceeds maximum", path)
	}
	if _, exists := entry["AllowedPattern"]; exists {
		if p.Type != "String" && p.Type != "CommaDelimitedList" {
			return p, fmt.Errorf("%s.AllowedPattern requires String or CommaDelimitedList type", path)
		}
		p.pattern, err = regexp.Compile("^(?:" + p.AllowedPattern + ")$")
		if err != nil {
			// TODO: Comeback: support Java-regex constructs beyond Go RE2 for parameter patterns.
			return p, fmt.Errorf("%s.AllowedPattern is invalid or unsupported: %w", path, err)
		}
	}
	if raw, exists := entry["Default"]; exists {
		value, err := templateScalar(raw)
		if err != nil {
			return p, fmt.Errorf("%s.Default must be a scalar value", path)
		}
		p.Default = value
		if err := p.validate(value); err != nil {
			return p, fmt.Errorf("%s.Default: %w", path, err)
		}
	}
	return p, nil
}

func parseTemplateResource(entry map[string]any, path string) (TemplateResource, error) {
	r := TemplateResource{Properties: Properties{}}
	if err := templateFields(entry, path, "Type", "Condition", "Properties", "DependsOn", "DeletionPolicy", "UpdateReplacePolicy", "Metadata"); err != nil {
		// TODO: Comeback: implement CreationPolicy signaling and UpdatePolicy effects before admitting them.
		return r, err
	}
	var err error
	for key, target := range map[string]*string{"Type": &r.Type, "Condition": &r.Condition, "DeletionPolicy": &r.DeletionPolicy, "UpdateReplacePolicy": &r.UpdateReplacePolicy} {
		if *target, err = templateString(entry, key, path, key == "Type"); err != nil {
			return r, err
		}
	}
	if !strings.HasPrefix(r.Type, "AWS::") || r.Type == "AWS::CloudFormation::CustomResource" || r.Type == "AWS::CloudFormation::Stack" {
		// TODO: Comeback: nested stacks, custom-resource callbacks and registry providers need real lifecycle owners.
		return r, fmt.Errorf("%s.Type %q is unsupported", path, r.Type)
	}
	for _, key := range []string{"DeletionPolicy", "UpdateReplacePolicy"} {
		if raw, exists := entry[key]; exists && raw != "Delete" && raw != "Retain" {
			if key == "DeletionPolicy" && raw == "RetainExceptOnCreate" {
				continue
			}
			// TODO: Comeback: implement resource snapshots before admitting Snapshot policies.
			return r, fmt.Errorf("%s.%s policy %q is unsupported", path, key, raw)
		}
	}
	if raw, exists := entry["Properties"]; exists {
		properties, err := templateObject(raw, path+".Properties")
		if err != nil {
			return r, err
		}
		r.Properties = Properties(properties)
	}
	if raw, exists := entry["Metadata"]; exists {
		if r.Metadata, err = templateObject(raw, path+".Metadata"); err != nil {
			return r, err
		}
	}
	if raw, exists := entry["DependsOn"]; exists {
		if name, ok := raw.(string); ok {
			r.DependsOn = []string{name}
		} else if names, ok := raw.([]any); ok {
			for _, raw := range names {
				name, ok := raw.(string)
				if !ok || name == "" {
					return r, fmt.Errorf("%s.DependsOn must contain logical IDs", path)
				}
				r.DependsOn = append(r.DependsOn, name)
			}
		} else {
			return r, fmt.Errorf("%s.DependsOn must be a logical ID or list", path)
		}
	}
	return r, nil
}

func parseTemplateOutput(entry map[string]any, path string) (TemplateOutput, error) {
	var o TemplateOutput
	if err := templateFields(entry, path, "Value", "Description", "Condition", "Export"); err != nil {
		return o, err
	}
	var exists bool
	if o.Value, exists = entry["Value"]; !exists || o.Value == nil {
		return o, fmt.Errorf("%s.Value is required", path)
	}
	var err error
	if o.Description, err = templateString(entry, "Description", path, false); err != nil {
		return o, err
	}
	if utf8.RuneCountInString(o.Description) > 1024 {
		return o, fmt.Errorf("%s.Description exceeds 1024 characters", path)
	}
	if o.Condition, err = templateString(entry, "Condition", path, false); err != nil {
		return o, err
	}
	if raw, exists := entry["Export"]; exists {
		export, err := templateObject(raw, path+".Export")
		if err != nil {
			return o, err
		}
		if err := templateFields(export, path+".Export", "Name"); err != nil {
			return o, err
		}
		if o.ExportName, exists = export["Name"]; !exists || o.ExportName == nil {
			return o, fmt.Errorf("%s.Export.Name is required", path)
		}
	}
	return o, nil
}

// BindParameters uses defaults for omitted keys; previous values require an
// explicit UsePreviousValue request, including when the template has a default.
func (t *Template) BindParameters(input, previous map[string]string, usePrevious map[string]bool) (map[string]string, error) {
	for name := range input {
		if _, exists := t.Parameters[name]; !exists {
			return nil, fmt.Errorf("parameter %s does not exist in the template", name)
		}
	}
	for name, use := range usePrevious {
		if _, exists := t.Parameters[name]; !exists {
			return nil, fmt.Errorf("parameter %s does not exist in the template", name)
		}
		if _, exists := input[name]; use && exists {
			return nil, fmt.Errorf("parameter %s cannot specify both a value and UsePreviousValue", name)
		}
	}
	bound := make(map[string]string, len(t.Parameters))
	for _, name := range templateKeys(t.Parameters) {
		parameter := t.Parameters[name]
		value, exists := input[name]
		if usePrevious[name] {
			value, exists = previous[name]
			if !exists {
				return nil, fmt.Errorf("parameter %s has no previous value", name)
			}
		}
		if !exists && parameter.Default != nil {
			var err error
			value, err = templateScalar(parameter.Default)
			if err != nil {
				return nil, fmt.Errorf("parameter %s default: %w", name, err)
			}
			exists = true
		}
		if !exists {
			return nil, fmt.Errorf("parameter %s must have a value", name)
		}
		if err := parameter.validate(value); err != nil {
			return nil, fmt.Errorf("parameter %s: %w", name, err)
		}
		bound[name] = value
	}
	return bound, nil
}

func (p TemplateParameter) validate(value string) error {
	if err := templateDynamicReference(value); err != nil {
		return err
	}
	fail := func(reason string) error {
		if p.ConstraintDescription != "" {
			return fmt.Errorf("%s", p.ConstraintDescription)
		}
		return fmt.Errorf("%s", reason)
	}
	if p.MinLength != nil && utf8.RuneCountInString(value) < *p.MinLength || p.MaxLength != nil && utf8.RuneCountInString(value) > *p.MaxLength {
		return fail("value violates length constraints")
	}
	values := []string{value}
	if p.Type == "CommaDelimitedList" || p.Type == "List<Number>" {
		values = templateListParameter(value)
	}
	for _, item := range values {
		if p.Type == "Number" || p.Type == "List<Number>" {
			number, err := strconv.ParseFloat(item, 64)
			if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
				return fail("value must be a finite number")
			}
			if p.MinValue != nil && number < *p.MinValue || p.MaxValue != nil && number > *p.MaxValue {
				return fail("value violates numeric constraints")
			}
		}
		if len(p.AllowedValues) != 0 && !slices.Contains(p.AllowedValues, item) {
			return fail("value is not in AllowedValues")
		}
		if p.pattern != nil && !p.pattern.MatchString(item) {
			return fail("value does not match AllowedPattern")
		}
	}
	return nil
}

func templateListParameter(value string) []string {
	values := strings.Split(value, ",")
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	return values
}

func (t *Template) Capabilities() []string {
	capability := ""
	for _, resource := range t.Resources {
		if !strings.HasPrefix(resource.Type, "AWS::IAM::") {
			continue
		}
		capability = "CAPABILITY_IAM"
		var name string
		switch resource.Type {
		case "AWS::IAM::Role":
			name = "RoleName"
		case "AWS::IAM::User":
			name = "UserName"
		case "AWS::IAM::Group":
			name = "GroupName"
		case "AWS::IAM::InstanceProfile":
			name = "InstanceProfileName"
		case "AWS::IAM::ManagedPolicy":
			name = "ManagedPolicyName"
		}
		if _, exists := resource.Properties[name]; name != "" && exists {
			capability = "CAPABILITY_NAMED_IAM"
			break
		}
	}
	var capabilities []string
	if capability != "" {
		capabilities = append(capabilities, capability)
	}
	if t.LanguageExtensions {
		capabilities = append(capabilities, "CAPABILITY_AUTO_EXPAND")
	}
	return capabilities
}

func (t *Template) ValidateHandlers(handlers map[string]ResourceHandler) error {
	for _, name := range templateKeys(t.Resources) {
		resource := t.Resources[name]
		if err := validateResourceStructure(resource); err != nil {
			return fmt.Errorf("resource %s: %w", name, err)
		}
		handler := handlers[resource.Type]
		if handler == nil {
			// TODO: Comeback: add typed resource handlers rather than accepting unsupported resource effects.
			return fmt.Errorf("resource %s has unsupported type %s", name, resource.Type)
		}
		if !templateHasIntrinsic(map[string]any(resource.Properties)) {
			if err := handler.Validate(resource.Properties); err != nil {
				return fmt.Errorf("resource %s: %w", name, err)
			}
		}
	}
	return nil
}

func templateObject(value any, path string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	return object, nil
}

func templateFields(object map[string]any, path string, allowed ...string) error {
	for _, key := range templateKeys(object) {
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("%s.%s is unsupported", path, key)
		}
	}
	return nil
}

func templateString(object map[string]any, key, path string, required bool) (string, error) {
	value, exists := object[key]
	if !exists && !required {
		return "", nil
	}
	text, ok := value.(string)
	if !ok || required && text == "" {
		return "", fmt.Errorf("%s.%s must be a string (nonempty when required)", path, key)
	}
	return text, nil
}

func templateScalar(value any) (string, error) {
	switch value := value.(type) {
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case float64:
		if !math.IsInf(value, 0) && !math.IsNaN(value) {
			return strconv.FormatFloat(value, 'f', -1, 64), nil
		}
	case int:
		return strconv.Itoa(value), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case json.Number:
		return value.String(), nil
	}
	return "", fmt.Errorf("value must be a scalar string, number or boolean")
}

func templateMappingValue(value any) error {
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if _, err := templateScalar(item); err != nil {
				return fmt.Errorf("mapping lists must contain literal scalar values")
			}
		}
		return nil
	}
	if _, err := templateScalar(value); err != nil {
		return fmt.Errorf("mapping values must be literal scalar values or lists")
	}
	return nil
}

func templateKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
