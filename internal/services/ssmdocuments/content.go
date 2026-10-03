package ssmdocuments

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Document is a selected immutable document. The agent owns interpolation and execution.
type Document struct {
	Name, Version, Content, Hash, ARN, Owner, Format, SchemaVersion, Description, TargetType string
	Parameters                                                                               map[string]Parameter
	MainSteps                                                                                []Step
	// Tags are current resource tags for the consuming command's IAM evaluation.
	Tags map[string]string
	// Shared is owner permission for this selected version, not an IAM grant.
	Shared bool
}
type Parameter struct {
	Type              string          `json:"type"`
	Description       string          `json:"description,omitempty"`
	Default           json.RawMessage `json:"default,omitempty"`
	AllowedValues     []string        `json:"allowedValues,omitempty"`
	AllowedPattern    string          `json:"allowedPattern,omitempty"`
	MinChars          *int            `json:"minChars,omitempty"`
	MaxChars          *int            `json:"maxChars,omitempty"`
	MinItems          *int            `json:"minItems,omitempty"`
	MaxItems          *int            `json:"maxItems,omitempty"`
	InterpolationType string          `json:"interpolationType,omitempty"`
	DisplayType       string          `json:"displayType,omitempty"`
}
type Step struct {
	Name           string              `json:"name"`
	Action         string              `json:"action"`
	Inputs         json.RawMessage     `json:"inputs"`
	Precondition   map[string][]string `json:"precondition,omitempty"`
	TimeoutSeconds int                 `json:"timeoutSeconds,omitempty"`
	MaxAttempts    int                 `json:"maxAttempts,omitempty"`
	OnFailure      string              `json:"onFailure,omitempty"`
	Settings       json.RawMessage     `json:"settings,omitempty"`
}
type contentDocument struct {
	SchemaVersion string               `json:"schemaVersion"`
	Description   string               `json:"description"`
	Parameters    map[string]Parameter `json:"parameters"`
	MainSteps     []Step               `json:"mainSteps"`
	RuntimeConfig map[string]struct {
		Properties   json.RawMessage     `json:"properties"`
		Settings     json.RawMessage     `json:"settings,omitempty"`
		Description  string              `json:"description,omitempty"`
		Precondition map[string][]string `json:"precondition,omitempty"`
	} `json:"runtimeConfig,omitempty"`
}

var parameterNamePattern = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
var stepNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
var parameterReference = regexp.MustCompile(`^\{\{\s*([a-zA-Z0-9]+)\s*\}\}$`)
var embeddedParameterReference = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9]+)\s*\}\}`)

func decodeContent(content, format string) (contentDocument, error) {
	var out contentDocument
	data := []byte(content)
	if format == "YAML" {
		var tree any
		if err := yaml.Unmarshal(data, &tree); err != nil {
			return out, failure("InvalidDocumentContent", err.Error())
		}
		var err error
		data, err = json.Marshal(tree)
		if err != nil {
			return out, failure("InvalidDocumentContent", "YAML document keys must be strings.")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return out, failure("InvalidDocumentContent", err.Error())
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return out, failure("InvalidDocumentContent", "Document must contain exactly one object.")
	}
	// A native null default is absent in metadata and remains null only in the
	// original source delivered to the agent.
	for name, parameter := range out.Parameters {
		if bytes.Equal(bytes.TrimSpace(parameter.Default), []byte("null")) {
			parameter.Default = nil
			out.Parameters[name] = parameter
		}
	}
	return out, nil
}
func validateContent(content, format string) (contentDocument, error) {
	var empty contentDocument
	if len(content) > 64*1024 {
		return empty, failure("MaxDocumentSizeExceeded", "Document content exceeds 64 KiB.")
	}
	if format != "JSON" && format != "YAML" {
		return empty, failure("InvalidDocumentContent", "Command documents require JSON or YAML.")
	}
	doc, err := decodeContent(content, format)
	if err != nil {
		return doc, err
	}
	if doc.SchemaVersion != "1.2" && doc.SchemaVersion != "2.0" && doc.SchemaVersion != "2.2" {
		return doc, failure("InvalidDocumentSchemaVersion", "Command documents require schema version 1.2, 2.0 or 2.2.")
	}
	if doc.SchemaVersion == "1.2" {
		if len(doc.RuntimeConfig) == 0 || doc.MainSteps != nil {
			return doc, failure("InvalidDocumentContent", "Schema 1.2 requires runtimeConfig and does not accept mainSteps.")
		}
	} else if len(doc.MainSteps) == 0 || doc.RuntimeConfig != nil {
		return doc, failure("InvalidDocumentContent", "Schema "+doc.SchemaVersion+" requires mainSteps and does not accept runtimeConfig.")
	}
	for name, p := range doc.Parameters {
		if !parameterNamePattern.MatchString(name) {
			return doc, failure("InvalidDocumentContent", "Invalid parameter name: "+name)
		}
		if p.Type != "String" && p.Type != "StringList" {
			return doc, failure("InvalidDocumentContent", "Command parameters must be String or StringList.")
		}
		if p.InterpolationType != "" && p.InterpolationType != "ENV_VAR" {
			return doc, failure("InvalidDocumentContent", "Unsupported interpolationType.")
		}
		if p.AllowedPattern != "" {
			if _, err := regexp.Compile(p.AllowedPattern); err != nil {
				return doc, failure("InvalidDocumentContent", "Parameter allowedPattern is not supported by the agent: "+err.Error())
			}
		}
		for _, bound := range []*int{p.MinChars, p.MaxChars, p.MinItems, p.MaxItems} {
			if bound != nil && *bound < 0 {
				return doc, failure("InvalidDocumentContent", "Parameter bounds cannot be negative.")
			}
		}
		if p.MinChars != nil && p.MaxChars != nil && *p.MinChars > *p.MaxChars || p.MinItems != nil && p.MaxItems != nil && *p.MinItems > *p.MaxItems {
			return doc, failure("InvalidDocumentContent", "Parameter bounds are inconsistent.")
		}
		if p.Default != nil {
			if _, err := defaultValues(p); err != nil {
				return doc, err
			}
		}
	}
	names := map[string]bool{}
	for _, step := range doc.executionSteps() {
		if doc.SchemaVersion != "1.2" && (!stepNamePattern.MatchString(step.Name) || names[step.Name]) {
			return doc, failure("InvalidDocumentContent", "Step names must be unique alphanumeric identifiers.")
		}
		names[step.Name] = true
		if step.Action != "aws:runShellScript" {
			// TODO: Comeback: implement additional document plugins through real agent data planes, never local substitutes.
			return doc, failure("InvalidDocumentContent", "Unsupported command plugin: "+step.Action)
		}
		if step.TimeoutSeconds < 0 || step.MaxAttempts < 0 {
			return doc, failure("InvalidDocumentContent", "Step timeout and attempts cannot be negative.")
		}
		if doc.SchemaVersion == "2.0" && step.Precondition != nil {
			return doc, failure("InvalidDocumentContent", "Preconditions require schema version 2.2.")
		}
		for op, args := range step.Precondition {
			if op != "StringEquals" || len(args) != 2 {
				return doc, failure("InvalidDocumentContent", "Preconditions require StringEquals with two operands.")
			}
		}
		properties := shellProperties(doc.SchemaVersion, step.Inputs)
		for _, property := range properties {
			var inputs map[string]json.RawMessage
			if json.Unmarshal(property, &inputs) != nil || inputs == nil {
				return doc, failure("InvalidDocumentContent", "Shell inputs must be an object.")
			}
			_, ok := inputs["runCommand"]
			if !ok && doc.SchemaVersion != "1.2" {
				return doc, failure("InvalidDocumentContent", "Shell inputs require runCommand.")
			}
			for key, raw := range inputs {
				switch key {
				case "runCommand", "workingDirectory", "timeoutSeconds", "onSuccess", "onFailure", "finallyStep", "id":
				case "commands", "precondition":
					if doc.SchemaVersion != "1.2" {
						return doc, failure("InvalidDocumentContent", "Unsupported shell input: "+key)
					}
				default:
					return doc, failure("InvalidDocumentContent", "Unsupported shell input: "+key)
				}
				var scalar string
				var values []string
				if json.Unmarshal(raw, &scalar) == nil {
					values = []string{scalar}
				} else if err := json.Unmarshal(raw, &values); err != nil && key == "runCommand" {
					return doc, failure("InvalidDocumentContent", "runCommand must be a string or string list.")
				}
				for _, text := range values {
					for _, match := range embeddedParameterReference.FindAllStringSubmatch(text, -1) {
						if _, ok := doc.Parameters[match[1]]; !ok {
							return doc, failure("InvalidDocumentContent", "Parameter "+match[1]+" is not declared.")
						}
					}
				}
			}
		}
	}
	return doc, nil
}

// executionSteps mirrors the agent's plugin identities. Legacy properties are
// one plugin's executions, not separate invocation plugins named after their id.
func (doc contentDocument) executionSteps() []Step {
	if doc.SchemaVersion != "1.2" {
		return doc.MainSteps
	}
	steps := make([]Step, 0, len(doc.RuntimeConfig))
	for name, plugin := range doc.RuntimeConfig {
		steps = append(steps, Step{Name: name, Action: name, Inputs: plugin.Properties, Settings: plugin.Settings})
	}
	slices.SortFunc(steps, func(a, b Step) int { return strings.Compare(a.Name, b.Name) })
	return steps
}

func shellProperties(schema string, inputs json.RawMessage) []json.RawMessage {
	if schema == "1.2" {
		var properties []json.RawMessage
		if json.Unmarshal(inputs, &properties) == nil {
			return properties
		}
	}
	return []json.RawMessage{inputs}
}
func defaultValues(p Parameter) ([]string, error) {
	if p.Default == nil {
		return nil, failure("InvalidParameters", "A required parameter is missing.")
	}
	var one string
	if p.Type == "String" && json.Unmarshal(p.Default, &one) == nil {
		return []string{one}, nil
	}
	var values []string
	if p.Type == "StringList" && json.Unmarshal(p.Default, &values) == nil && values != nil {
		return values, nil
	}
	return nil, failure("InvalidDocumentContent", "Parameter default does not match its type.")
}
func validateParameter(name string, p Parameter, values []string) error {
	bad := func(reason string) error {
		return failure("InvalidParameters", fmt.Sprintf("Parameter %s %s", name, reason))
	}
	if p.Type == "String" && len(values) != 1 {
		return bad("requires exactly one string.")
	}
	if p.MinItems != nil && len(values) < *p.MinItems || p.MaxItems != nil && len(values) > *p.MaxItems {
		return bad("violates its item count bounds.")
	}
	var pattern *regexp.Regexp
	if p.AllowedPattern != "" {
		var err error
		pattern, err = regexp.Compile("^(?:" + p.AllowedPattern + ")$")
		if err != nil {
			return bad("has an unsupported allowedPattern.")
		}
	}
	for _, v := range values {
		if len(p.AllowedValues) > 0 && !slices.Contains(p.AllowedValues, v) {
			return bad("is not an allowed value.")
		}
		if pattern != nil && !pattern.MatchString(v) {
			return bad("does not match allowedPattern.")
		}
		n := utf8.RuneCountInString(v)
		if p.MinChars != nil && n < *p.MinChars || p.MaxChars != nil && n > *p.MaxChars {
			return bad("violates its character count bounds.")
		}
	}
	return nil
}

// ValidateParameters applies defaults and admission constraints without substituting any script text.
func ValidateParameters(doc Document, input map[string][]string) (map[string][]string, error) {
	for name := range input {
		if _, ok := doc.Parameters[name]; !ok {
			return nil, failure("InvalidParameters", "Unknown parameter: "+name)
		}
	}
	out := make(map[string][]string, len(doc.Parameters))
	for name, p := range doc.Parameters {
		v, ok := input[name]
		if !ok {
			var err error
			v, err = defaultValues(p)
			if err != nil {
				return nil, failure("InvalidParameters", "Missing required parameter: "+name)
			}
		}
		if err := validateParameter(name, p, v); err != nil {
			return nil, err
		}
		out[name] = slices.Clone(v)
	}
	return out, nil
}

// ExecutionTimeout returns the service's execution component of delivery expiry.
// Pass submitted parameters, not defaults: native expiry uses 3600 seconds when a
// referenced timeout parameter is omitted, even if the document default differs.
// The official agent independently applies its plugin timeout fallback rules.
func ExecutionTimeout(doc Document, parameters map[string][]string) (time.Duration, error) {
	var total time.Duration
	for _, step := range doc.MainSteps {
		property := step.Inputs
		if doc.SchemaVersion == "1.2" {
			// Native delivery expiry counts only the first legacy property,
			// although the official agent executes every property in the plugin.
			properties := shellProperties(doc.SchemaVersion, step.Inputs)
			if len(properties) == 0 {
				total += time.Hour
				continue
			}
			property = properties[0]
		}
		var inputs struct {
			Timeout json.RawMessage `json:"timeoutSeconds"`
		}
		if err := json.Unmarshal(property, &inputs); err != nil {
			return 0, err
		}
		seconds := int64(3600)
		if len(inputs.Timeout) > 0 {
			var scalar string
			if json.Unmarshal(inputs.Timeout, &scalar) != nil {
				scalar = string(inputs.Timeout)
			}
			if match := parameterReference.FindStringSubmatch(scalar); match != nil {
				values, supplied := parameters[match[1]]
				if !supplied {
					scalar = "3600"
				} else {
					if len(values) != 1 {
						return 0, failure("InvalidParameters", "timeoutSeconds requires one value.")
					}
					scalar = values[0]
				}
			}
			n, err := strconv.ParseInt(strings.TrimSpace(scalar), 10, 64)
			if err == nil && n >= 1 && n <= 172800 {
				seconds = n
			}
		}
		total += time.Duration(seconds) * time.Second
	}
	return total, nil
}

// JSONContent supplies the native agent's JSON payload while Content retains original source bytes.
func JSONContent(doc Document) ([]byte, error) {
	if doc.Format == "JSON" {
		return []byte(doc.Content), nil
	}
	var tree any
	if err := yaml.Unmarshal([]byte(doc.Content), &tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}
