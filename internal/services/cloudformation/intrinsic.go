package cloudformation

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type templateNoValue struct{}

type templateEvaluator struct {
	template        *Template
	input           Evaluation
	conditions      map[string]bool
	visiting        map[string]bool
	imports         map[string]bool
	eventProjection bool
}

func (t *Template) evaluator(input Evaluation) *templateEvaluator {
	return &templateEvaluator{template: t, input: input, conditions: map[string]bool{}, visiting: map[string]bool{}, imports: map[string]bool{}}
}

func (e *templateEvaluator) condition(name string) (bool, error) {
	if name == "" {
		return true, nil
	}
	if value, exists := e.conditions[name]; exists {
		return value, nil
	}
	if e.visiting[name] {
		return false, fmt.Errorf("condition dependency cycle at %s", name)
	}
	expression, exists := e.template.Conditions[name]
	if !exists {
		return false, fmt.Errorf("undefined condition %s", name)
	}
	e.visiting[name] = true
	defer delete(e.visiting, name)
	// Conditions choose the deployed branch using real values, even when its
	// event properties subsequently resolve NoEcho references as "****".
	projecting := e.eventProjection
	e.eventProjection = false
	value, err := e.resolve(expression)
	e.eventProjection = projecting
	if err != nil {
		return false, fmt.Errorf("condition %s: %w", name, err)
	}
	result, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("condition %s must evaluate to a boolean", name)
	}
	e.conditions[name] = result
	return result, nil
}

func (e *templateEvaluator) resolve(value any) (any, error) {
	switch value := value.(type) {
	case map[string]any:
		name, argument, intrinsic, err := templateFunction(value)
		if err != nil {
			return nil, err
		}
		if intrinsic {
			resolved, err := e.function(name, argument)
			if err == nil {
				if text, ok := resolved.(string); ok {
					err = templateDynamicReference(text)
				}
			}
			return resolved, err
		}
		result := make(map[string]any, len(value))
		for _, key := range templateKeys(value) {
			resolved, err := e.resolve(value[key])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			if _, omit := resolved.(templateNoValue); !omit {
				result[key] = resolved
			}
		}
		return result, nil
	case []any:
		result := make([]any, 0, len(value))
		for index, item := range value {
			resolved, err := e.resolve(item)
			if err != nil {
				return nil, fmt.Errorf("list element %d: %w", index, err)
			}
			if _, omit := resolved.(templateNoValue); !omit {
				result = append(result, resolved)
			}
		}
		return result, nil
	case string:
		return value, templateDynamicReference(value)
	default:
		return value, nil
	}
}

func (e *templateEvaluator) reference(name string) (any, error) {
	switch name {
	case "AWS::AccountId":
		return e.input.Scope.Account, nil
	case "AWS::Region":
		return e.input.Scope.Region, nil
	case "AWS::Partition":
		return e.input.Scope.Partition, nil
	case "AWS::StackId":
		return e.input.StackID, nil
	case "AWS::StackName":
		return e.input.StackName, nil
	case "AWS::URLSuffix":
		switch e.input.Scope.Partition {
		case "aws", "aws-us-gov":
			return "amazonaws.com", nil
		case "aws-cn":
			return "amazonaws.com.cn", nil
		default:
			// TODO: Comeback: derive isolated-partition DNS suffixes from the service endpoint catalog.
			return nil, fmt.Errorf("AWS::URLSuffix is unsupported for partition %q", e.input.Scope.Partition)
		}
	case "AWS::NoValue":
		return templateNoValue{}, nil
	}
	if parameter, exists := e.template.Parameters[name]; exists {
		value, exists := e.input.Parameters[name]
		if !exists {
			return nil, fmt.Errorf("parameter %s has no bound value", name)
		}
		if strings.HasPrefix(parameter.Type, "AWS::SSM::Parameter::Value<") {
			var exists bool
			value, exists = e.input.ResolvedParameters[name]
			if !exists {
				return nil, fmt.Errorf("SSM parameter %s has no admitted resolved value", name)
			}
		}
		if e.eventProjection && parameter.NoEcho {
			value = "****"
		}
		if parameter.Type == "CommaDelimitedList" || parameter.Type == "List<Number>" || parameter.Type == "AWS::SSM::Parameter::Value<List<String>>" || parameter.Type == "AWS::SSM::Parameter::Value<CommaDelimitedList>" {
			items := templateListParameter(value)
			values := make([]any, len(items))
			for i, item := range items {
				values[i] = item
			}
			return values, nil
		}
		return value, nil
	}
	if _, exists := e.template.Resources[name]; exists {
		resource, exists := e.input.Resources[name]
		if !exists {
			return nil, fmt.Errorf("resource %s has not been resolved", name)
		}
		return resource.Ref, nil
	}
	return nil, fmt.Errorf("undefined Ref %s", name)
}

func (e *templateEvaluator) attribute(resource, attribute string) (any, error) {
	result, exists := e.input.Resources[resource]
	if !exists {
		return nil, fmt.Errorf("resource %s has not been resolved", resource)
	}
	value, exists := result.Attributes[attribute]
	if !exists {
		return nil, fmt.Errorf("resource %s has no attribute %s", resource, attribute)
	}
	return value, nil
}

func (e *templateEvaluator) text(value any) (string, error) {
	resolved, err := e.resolve(value)
	if err != nil {
		return "", err
	}
	return templateScalar(resolved)
}

func (e *templateEvaluator) function(name string, argument any) (any, error) {
	switch name {
	case "Ref":
		return e.reference(argument.(string))
	case "Condition":
		return e.condition(argument.(string))
	case "Fn::GetAtt":
		resource, attribute, err := templateGetAtt(argument)
		if err != nil {
			return nil, err
		}
		return e.attribute(resource, attribute)
	case "Fn::GetAZs":
		region, err := e.text(argument)
		if err != nil {
			return nil, err
		}
		if region == "" {
			region = e.input.Scope.Region
		}
		if e.input.AvailabilityZones == nil {
			return nil, failure("NotImplementedException", "EC2 availability zone owner is unavailable.", 501)
		}
		zones, err := e.input.AvailabilityZones.CloudFormationAvailabilityZones(e.input.Context, region)
		if err != nil {
			return nil, err
		}
		result := make([]any, len(zones))
		for i, zone := range zones {
			result[i] = zone
		}
		return result, nil
	case "Fn::Sub":
		text, variables, err := templateSub(argument)
		if err != nil {
			return nil, err
		}
		resolved := make(map[string]string, len(variables))
		for _, key := range templateKeys(variables) {
			value, err := e.text(variables[key])
			if err != nil {
				return nil, fmt.Errorf("Fn::Sub variable %s: %w", key, err)
			}
			resolved[key] = value
		}
		var failure error
		result := templateSubVariable.ReplaceAllStringFunc(text, func(match string) string {
			if failure != nil {
				return ""
			}
			name := match[2 : len(match)-1]
			if strings.HasPrefix(name, "!") {
				return "${" + name[1:] + "}"
			}
			if value, exists := resolved[name]; exists {
				return value
			}
			var value any
			if resource, attribute, found := strings.Cut(name, "."); found {
				value, failure = e.attribute(resource, attribute)
			} else {
				value, failure = e.reference(name)
			}
			if failure != nil {
				return ""
			}
			result, err := templateScalar(value)
			failure = err
			return result
		})
		return result, failure
	case "Fn::If":
		arguments := argument.([]any)
		condition, err := e.condition(arguments[0].(string))
		if err != nil {
			return nil, err
		}
		if condition {
			return e.resolve(arguments[1])
		}
		return e.resolve(arguments[2])
	case "Fn::Equals":
		arguments := argument.([]any)
		left, err := e.text(arguments[0])
		if err != nil {
			return nil, err
		}
		right, err := e.text(arguments[1])
		return left == right, err
	case "Fn::And", "Fn::Or", "Fn::Not":
		arguments := argument.([]any)
		result := name == "Fn::And"
		for _, argument := range arguments {
			value, err := e.resolve(argument)
			if err != nil {
				return nil, err
			}
			boolean, ok := value.(bool)
			if !ok {
				return nil, fmt.Errorf("%s operands must be conditions", name)
			}
			switch name {
			case "Fn::And":
				result = result && boolean
			case "Fn::Or":
				result = result || boolean
			case "Fn::Not":
				result = !boolean
			}
		}
		return result, nil
	case "Fn::Join":
		arguments := argument.([]any)
		resolved, err := e.resolve(arguments[1])
		if err != nil {
			return nil, err
		}
		items, ok := resolved.([]any)
		if !ok {
			return nil, fmt.Errorf("Fn::Join requires a list")
		}
		parts := make([]string, len(items))
		for i, item := range items {
			parts[i], err = templateScalar(item)
			if err != nil {
				return nil, fmt.Errorf("Fn::Join element %d: %w", i, err)
			}
		}
		return strings.Join(parts, arguments[0].(string)), nil
	case "Fn::Split":
		arguments := argument.([]any)
		text, err := e.text(arguments[1])
		if err != nil {
			return nil, err
		}
		parts := strings.Split(text, arguments[0].(string))
		result := make([]any, len(parts))
		for i, part := range parts {
			result[i] = part
		}
		return result, nil
	case "Fn::Select":
		arguments := argument.([]any)
		text, err := e.text(arguments[0])
		if err != nil {
			return nil, err
		}
		index, err := strconv.Atoi(text)
		if err != nil || index < 0 {
			return nil, fmt.Errorf("Fn::Select index must be a nonnegative integer")
		}
		value, err := e.resolve(arguments[1])
		if err != nil {
			return nil, err
		}
		items, ok := value.([]any)
		if !ok || index >= len(items) || items[index] == nil {
			return nil, fmt.Errorf("Fn::Select index %d does not identify a non-null list element", index)
		}
		return items[index], nil
	case "Fn::FindInMap":
		arguments := argument.([]any)
		keys := [3]string{}
		for i := range keys {
			var err error
			keys[i], err = e.text(arguments[i])
			if err != nil {
				return nil, err
			}
		}
		value, exists := e.template.Mappings[keys[0]][keys[1]][keys[2]]
		if !exists {
			return nil, fmt.Errorf("Fn::FindInMap cannot find %s.%s.%s", keys[0], keys[1], keys[2])
		}
		return e.resolve(value)
	case "Fn::ImportValue":
		name, err := e.text(argument)
		if err != nil {
			return nil, err
		}
		value, exists := e.input.Imports[name]
		if !exists {
			return nil, fmt.Errorf("no export named %s found", name)
		}
		e.imports[name] = true
		return value, nil
	case "Fn::Base64":
		text, err := e.text(argument)
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.EncodeToString([]byte(text)), nil
	case "Fn::Length":
		value, err := e.resolve(argument)
		if err != nil {
			return nil, err
		}
		items, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("Fn::Length requires an array")
		}
		return float64(len(items)), nil
	default:
		return nil, fmt.Errorf("intrinsic %s is unsupported", name)
	}
}

// ResolveResource removes AWS::NoValue properties and list members recursively.
// The caller validates the resulting properties with the registered handler.
func (t *Template) ResolveResource(logicalID string, input Evaluation) (Properties, error) {
	resource, exists := t.Resources[logicalID]
	if !exists {
		return nil, fmt.Errorf("undefined resource %s", logicalID)
	}
	e := t.evaluator(input)
	enabled, err := e.condition(resource.Condition)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, fmt.Errorf("resource %s is disabled by its condition", logicalID)
	}
	resolved, err := e.resolve(map[string]any(resource.Properties))
	if err != nil {
		return nil, fmt.Errorf("resource %s: %w", logicalID, err)
	}
	properties, ok := resolved.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("resource %s Properties must resolve to an object", logicalID)
	}
	return Properties(properties), nil
}

// eventProperties freezes the native stack-event view, not the resource input.
// Literal values are not secrets merely because they equal a NoEcho parameter.
func (t *Template) eventProperties(logicalID string, input Evaluation, resolved Properties) Properties {
	for _, parameter := range t.Parameters {
		if !parameter.NoEcho {
			continue
		}
		e := t.evaluator(input)
		e.eventProjection = true
		value, err := e.resolve(map[string]any(t.Resources[logicalID].Properties))
		if err != nil {
			// Native uses this sentinel when masking makes an expression
			// unevaluable, such as a numeric Select index or a list's index 1.
			return Properties{"****": "****"}
		}
		resolved = Properties(value.(map[string]any))
		break
	}
	return Properties(contextValue(resolved).(map[string]any))
}

// ResolveOutputs returns imports used by enabled resources as well as outputs,
// so a stack cannot drop its cross-stack dependency merely by omitting an output.
func (t *Template) ResolveOutputs(input Evaluation) (map[string]OutputValue, []string, error) {
	e := t.evaluator(input)
	_, err := t.order(e)
	if err != nil {
		return nil, nil, err
	}
	outputs := make(map[string]OutputValue, len(t.Outputs))
	exports := map[string]bool{}
	for _, name := range templateKeys(t.Outputs) {
		output := t.Outputs[name]
		enabled, err := e.condition(output.Condition)
		if err != nil {
			return nil, nil, err
		}
		if !enabled {
			continue
		}
		value, err := e.resolve(output.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("output %s: %w", name, err)
		}
		if _, omit := value.(templateNoValue); omit {
			continue
		}
		text, err := templateScalar(value)
		if err != nil {
			return nil, nil, fmt.Errorf("output %s: %w", name, err)
		}
		exportName := ""
		if output.ExportName != nil {
			exportName, err = e.text(output.ExportName)
			if err != nil {
				return nil, nil, fmt.Errorf("output %s export: %w", name, err)
			}
			if exportName == "" || exports[exportName] {
				return nil, nil, fmt.Errorf("output %s export name must be nonempty and unique", name)
			}
			exports[exportName] = true
		}
		outputs[name] = OutputValue{Value: text, Description: output.Description, ExportName: exportName}
	}
	return outputs, templateKeys(e.imports), nil
}

func templateIntrinsic(name string) bool {
	switch name {
	case "Ref", "Condition", "Fn::GetAtt", "Fn::GetAZs", "Fn::Sub", "Fn::Join", "Fn::Split", "Fn::Select", "Fn::FindInMap", "Fn::If", "Fn::Equals", "Fn::And", "Fn::Or", "Fn::Not", "Fn::ImportValue", "Fn::Base64", "Fn::Length":
		return true
	}
	return false
}

func templateFunction(object map[string]any) (string, any, bool, error) {
	for key, argument := range object {
		_, condition := argument.(string)
		if key != "Ref" && !strings.HasPrefix(key, "Fn::") && !(key == "Condition" && condition && len(object) == 1) {
			continue
		}
		if len(object) != 1 {
			return "", nil, false, fmt.Errorf("intrinsic %s must be the only object key", key)
		}
		if !templateIntrinsic(key) {
			// TODO: Comeback: implement remaining intrinsics rather than forwarding unevaluated expressions.
			return "", nil, false, fmt.Errorf("intrinsic %s is unsupported", key)
		}
		return key, argument, true, nil
	}
	return "", nil, false, nil
}

func templateHasIntrinsic(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		_, _, intrinsic, _ := templateFunction(value)
		if intrinsic {
			return true
		}
		for _, value := range value {
			if templateHasIntrinsic(value) {
				return true
			}
		}
	case []any:
		for _, value := range value {
			if templateHasIntrinsic(value) {
				return true
			}
		}
	}
	return false
}

func templateGetAtt(argument any) (string, string, error) {
	if text, ok := argument.(string); ok {
		resource, attribute, found := strings.Cut(text, ".")
		if found && resource != "" && attribute != "" {
			return resource, attribute, nil
		}
	}
	if values, ok := argument.([]any); ok && len(values) == 2 {
		resource, resourceOK := values[0].(string)
		attribute, attributeOK := values[1].(string)
		if resourceOK && attributeOK && resource != "" && attribute != "" {
			return resource, attribute, nil
		}
	}
	return "", "", fmt.Errorf("Fn::GetAtt requires a resource logical ID and attribute name")
}

var templateSubVariable = regexp.MustCompile(`\$\{([^}]*)\}`)
var templateSubName = regexp.MustCompile(`^[A-Za-z0-9_.:]+$`)

func templateSub(argument any) (string, map[string]any, error) {
	text, ok := argument.(string)
	var variables map[string]any
	if !ok {
		values, list := argument.([]any)
		if !list || len(values) != 2 {
			return "", nil, fmt.Errorf("Fn::Sub requires a string or a string and variable map")
		}
		text, ok = values[0].(string)
		variables, list = values[1].(map[string]any)
		if !ok || !list {
			return "", nil, fmt.Errorf("Fn::Sub requires a string and variable map")
		}
	}
	for _, match := range templateSubVariable.FindAllStringSubmatch(text, -1) {
		name := strings.TrimPrefix(match[1], "!")
		if !templateSubName.MatchString(name) {
			return "", nil, fmt.Errorf("Fn::Sub contains an invalid variable name")
		}
	}
	if strings.Contains(templateSubVariable.ReplaceAllString(text, ""), "${") {
		return "", nil, fmt.Errorf("Fn::Sub contains an unterminated variable")
	}
	for key := range variables {
		if !templateSubName.MatchString(key) {
			return "", nil, fmt.Errorf("Fn::Sub contains an invalid map key")
		}
	}
	return text, variables, nil
}

func templateDynamicReference(text string) error {
	if strings.Contains(text, "{{resolve:") {
		// TODO: Comeback: resolve SSM and Secrets Manager dynamic references using current execution authority.
		return fmt.Errorf("dynamic references are unsupported")
	}
	return nil
}
