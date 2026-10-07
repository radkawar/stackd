package cloudformation

import (
	"fmt"
	"strings"
)

func (t *Template) validateExpressions() error {
	for _, name := range templateKeys(t.Rules) {
		rule := t.Rules[name]
		if rule.Condition != nil {
			if err := t.validateRuleExpression(rule.Condition, true); err != nil {
				return fmt.Errorf("rule %s condition: %w", name, err)
			}
		}
		for _, assertion := range rule.Assertions {
			if err := t.validateRuleExpression(assertion.Assert, true); err != nil {
				return fmt.Errorf("rule %s: %w", name, err)
			}
		}
	}
	for _, name := range templateKeys(t.Conditions) {
		if err := t.validateCondition(t.Conditions[name]); err != nil {
			return fmt.Errorf("condition %s: %w", name, err)
		}
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var conditionCycle func(string) error
	conditionCycle = func(name string) error {
		if visiting[name] {
			return fmt.Errorf("condition dependency cycle at %s", name)
		}
		if visited[name] {
			return nil
		}
		visiting[name] = true
		if err := templateConditionReferences(t.Conditions[name], conditionCycle); err != nil {
			return err
		}
		delete(visiting, name)
		visited[name] = true
		return nil
	}
	for _, name := range templateKeys(t.Conditions) {
		if err := conditionCycle(name); err != nil {
			return err
		}
	}
	for _, name := range templateKeys(t.Resources) {
		resource := t.Resources[name]
		if err := t.validateConditionName(resource.Condition, true); err != nil {
			return fmt.Errorf("resource %s: %w", name, err)
		}
		for _, dependency := range resource.DependsOn {
			if _, exists := t.Resources[dependency]; !exists {
				return fmt.Errorf("resource %s depends on undefined resource %s", name, dependency)
			}
		}
		if err := t.validateExpression(map[string]any(resource.Properties), true, false); err != nil {
			return fmt.Errorf("resource %s: %w", name, err)
		}
		if err := t.validateExpression(resource.Metadata, true, false); err != nil {
			return fmt.Errorf("resource %s metadata: %w", name, err)
		}
		for key, expression := range map[string]any{"DeletionPolicy": resource.DeletionPolicy, "UpdateReplacePolicy": resource.UpdateReplacePolicy} {
			if expression == nil {
				continue
			}
			if err := t.validatePolicyExpression(expression, key, true, false, map[string]bool{}); err != nil {
				return fmt.Errorf("resource %s %s: %w", name, key, err)
			}
		}
	}
	for _, name := range templateKeys(t.Outputs) {
		output := t.Outputs[name]
		if err := t.validateConditionName(output.Condition, true); err != nil {
			return fmt.Errorf("output %s: %w", name, err)
		}
		if err := t.validateExpression(output.Value, true, false); err != nil {
			return fmt.Errorf("output %s: %w", name, err)
		}
		if err := t.validateExpression(output.ExportName, false, false); err != nil {
			return fmt.Errorf("output %s export name: %w", name, err)
		}
	}
	return nil
}

func (t *Template) validateConditionName(name string, optional bool) error {
	if name == "" && optional {
		return nil
	}
	if _, exists := t.Conditions[name]; !exists {
		return fmt.Errorf("undefined condition %s", name)
	}
	return nil
}

func (t *Template) validateCondition(expression any) error {
	object, ok := expression.(map[string]any)
	if !ok {
		return fmt.Errorf("condition must be a boolean intrinsic function")
	}
	name, _, _, err := templateFunction(object)
	if err != nil {
		return err
	}
	switch name {
	case "Condition", "Fn::Equals", "Fn::And", "Fn::Or", "Fn::Not":
		return t.validateExpression(expression, false, true)
	default:
		return fmt.Errorf("condition must use Equals, And, Or, Not or Condition")
	}
}

func (t *Template) validateReference(name string, resources bool) error {
	switch name {
	case "AWS::AccountId", "AWS::Region", "AWS::Partition", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix", "AWS::NoValue":
		return nil
	case "AWS::NotificationARNs":
		// TODO: Comeback: thread actual stack notification ARNs into template evaluation when notifications are supported.
		return fmt.Errorf("AWS::NotificationARNs is unsupported")
	}
	if _, exists := t.Parameters[name]; exists {
		return nil
	}
	if _, exists := t.Resources[name]; exists {
		if !resources {
			return fmt.Errorf("resource reference %s is not permitted in this expression", name)
		}
		return nil
	}
	return fmt.Errorf("undefined Ref %s", name)
}

func (t *Template) validateExpression(expression any, resources, conditions bool) error {
	switch expression := expression.(type) {
	case string:
		return templateDynamicReference(expression)
	case []any:
		for _, item := range expression {
			if err := t.validateExpression(item, resources, conditions); err != nil {
				return err
			}
		}
	case map[string]any:
		name, argument, intrinsic, err := templateFunction(expression)
		if err != nil {
			return err
		}
		if !intrinsic {
			for _, key := range templateKeys(expression) {
				if err := t.validateExpression(expression[key], resources, conditions); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			}
			return nil
		}
		if err := t.validateFunction(name, argument, resources, conditions); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func (t *Template) validateFunction(name string, argument any, resources, conditions bool) error {
	switch name {
	case "Ref":
		name, ok := argument.(string)
		if !ok || name == "" {
			return fmt.Errorf("requires a literal logical ID")
		}
		return t.validateReference(name, resources)
	case "Condition":
		if !conditions {
			return fmt.Errorf("condition references are supported only within Conditions")
		}
		name, ok := argument.(string)
		if !ok {
			return fmt.Errorf("requires a literal condition name")
		}
		return t.validateConditionName(name, false)
	case "Fn::GetAtt":
		resource, _, err := templateGetAtt(argument)
		if err != nil {
			return err
		}
		if !resources {
			return fmt.Errorf("resource attributes are not permitted in this expression")
		}
		if _, exists := t.Resources[resource]; !exists {
			return fmt.Errorf("undefined resource %s", resource)
		}
		return nil
	case "Fn::GetAZs":
		if _, ok := argument.(string); ok {
			return nil
		}
		object, ok := argument.(map[string]any)
		if !ok || len(object) != 1 {
			return fmt.Errorf("region must be a string or Ref")
		}
		ref, ok := object["Ref"]
		if !ok {
			return fmt.Errorf("only Ref is supported for the region")
		}
		return t.validateFunction("Ref", ref, resources, conditions)
	case "Fn::Sub":
		text, variables, err := templateSub(argument)
		if err != nil {
			return err
		}
		if err := templateDynamicReference(text); err != nil {
			return err
		}
		for _, match := range templateSubVariable.FindAllStringSubmatch(text, -1) {
			name := match[1]
			if _, exists := variables[name]; exists || strings.HasPrefix(name, "!") {
				continue
			}
			if resource, attribute, found := strings.Cut(name, "."); found {
				if err := t.validateFunction("Fn::GetAtt", []any{resource, attribute}, resources, conditions); err != nil {
					return err
				}
			} else if err := t.validateReference(name, resources); err != nil {
				return err
			}
		}
		for _, value := range variables {
			if err := t.validateExpression(value, resources, conditions); err != nil {
				return err
			}
		}
		return nil
	case "Fn::If":
		arguments, err := templateArguments(argument, 3, 3)
		if err != nil {
			return err
		}
		condition, ok := arguments[0].(string)
		if !ok {
			return fmt.Errorf("first argument must be a literal condition name")
		}
		if err := t.validateConditionName(condition, false); err != nil {
			return err
		}
		return t.validateExpression(arguments[1:], resources, conditions)
	case "Fn::And", "Fn::Or", "Fn::Not", "Fn::Equals":
		if !conditions {
			return fmt.Errorf("boolean functions are supported only within Conditions")
		}
		minimum, maximum := 2, 2
		if name == "Fn::And" || name == "Fn::Or" {
			maximum = 10
		} else if name == "Fn::Not" {
			minimum, maximum = 1, 1
		}
		arguments, err := templateArguments(argument, minimum, maximum)
		if err != nil {
			return err
		}
		if name == "Fn::Equals" {
			return t.validateExpression(arguments, false, true)
		}
		for _, value := range arguments {
			if err := t.validateCondition(value); err != nil {
				return err
			}
		}
		return nil
	case "Fn::Join", "Fn::Split", "Fn::Select", "Fn::FindInMap":
		count := 2
		if name == "Fn::FindInMap" {
			count = 3
		}
		arguments, err := templateArguments(argument, count, count)
		if err != nil {
			return err
		}
		if name == "Fn::Join" || name == "Fn::Split" {
			if _, ok := arguments[0].(string); !ok {
				return fmt.Errorf("delimiter must be a literal string")
			}
		}
		if name == "Fn::FindInMap" {
			if key, ok := arguments[0].(string); ok {
				if _, exists := t.Mappings[key]; !exists {
					return fmt.Errorf("undefined mapping %s", key)
				}
			}
		}
		return t.validateExpression(arguments, resources, conditions)
	case "Fn::ImportValue":
		if conditions {
			return fmt.Errorf("imports are not permitted in Conditions")
		}
		return t.validateExpression(argument, false, false)
	case "Fn::Length":
		if !t.LanguageExtensions {
			return fmt.Errorf("requires the AWS::LanguageExtensions transform")
		}
		return t.validateExpression(argument, false, conditions)
	case "Fn::Base64":
		return t.validateExpression(argument, resources, conditions)
	}
	return fmt.Errorf("unsupported intrinsic")
}

func templateArguments(argument any, minimum, maximum int) ([]any, error) {
	arguments, ok := argument.([]any)
	if !ok || len(arguments) < minimum || len(arguments) > maximum {
		if minimum == maximum {
			return nil, fmt.Errorf("requires a list of %d arguments", minimum)
		}
		return nil, fmt.Errorf("requires between %d and %d arguments", minimum, maximum)
	}
	return arguments, nil
}

func templateConditionReferences(expression any, visit func(string) error) error {
	switch expression := expression.(type) {
	case map[string]any:
		for key, value := range expression {
			if key == "Condition" {
				if name, ok := value.(string); ok {
					if err := visit(name); err != nil {
						return err
					}
				}
			}
			if key == "Fn::If" {
				if values, ok := value.([]any); ok && len(values) == 3 {
					if name, ok := values[0].(string); ok {
						if err := visit(name); err != nil {
							return err
						}
					}
				}
			}
			if err := templateConditionReferences(value, visit); err != nil {
				return err
			}
		}
	case []any:
		for _, value := range expression {
			if err := templateConditionReferences(value, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

// Order computes selected-branch implicit dependencies and explicit DependsOn
// edges. A false-conditioned resource disables its dependents transitively.
func (t *Template) Order(input Evaluation) ([]string, error) {
	return t.order(t.evaluator(input))
}

func (t *Template) order(e *templateEvaluator) ([]string, error) {
	for _, name := range templateKeys(t.Conditions) {
		if _, err := e.condition(name); err != nil {
			return nil, err
		}
	}
	enabled := make(map[string]bool, len(t.Resources))
	dependencies := make(map[string]map[string]bool, len(t.Resources))
	for _, name := range templateKeys(t.Resources) {
		resource := t.Resources[name]
		active, err := e.condition(resource.Condition)
		if err != nil {
			return nil, err
		}
		enabled[name] = active
		dependencies[name] = map[string]bool{}
		if !active {
			continue
		}
		for _, dependency := range resource.DependsOn {
			dependencies[name][dependency] = true
		}
		if err := e.dependencies(map[string]any(resource.Properties), dependencies[name]); err != nil {
			return nil, fmt.Errorf("resource %s: %w", name, err)
		}
	}
	// Fixed-point exclusion handles a false condition anywhere in a dependency
	// chain, including a chain whose remaining nodes contain a cycle.
	for changed := true; changed; {
		changed = false
		for name, active := range enabled {
			if !active {
				continue
			}
			for dependency := range dependencies[name] {
				if !enabled[dependency] {
					enabled[name] = false
					changed = true
					break
				}
			}
		}
	}
	state := make(map[string]uint8, len(t.Resources))
	order := make([]string, 0, len(t.Resources))
	var visit func(string) error
	visit = func(name string) error {
		if !enabled[name] || state[name] == 2 {
			return nil
		}
		if state[name] == 1 {
			return fmt.Errorf("resource dependency cycle at %s", name)
		}
		state[name] = 1
		for _, dependency := range templateKeys(dependencies[name]) {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[name] = 2
		order = append(order, name)
		return nil
	}
	for _, name := range templateKeys(t.Resources) {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	for _, name := range order {
		if err := e.collectImports(map[string]any(t.Resources[name].Properties)); err != nil {
			return nil, fmt.Errorf("resource %s: %w", name, err)
		}
	}
	for _, name := range templateKeys(t.Outputs) {
		output := t.Outputs[name]
		active, err := e.condition(output.Condition)
		if err != nil {
			return nil, err
		}
		if active {
			if err := e.collectImports(output.Value); err != nil {
				return nil, fmt.Errorf("output %s: %w", name, err)
			}
			if err := e.collectImports(output.ExportName); err != nil {
				return nil, fmt.Errorf("output %s export name: %w", name, err)
			}
		}
	}
	return order, nil
}

func (e *templateEvaluator) dependencies(expression any, dependencies map[string]bool) error {
	switch expression := expression.(type) {
	case map[string]any:
		name, argument, intrinsic, err := templateFunction(expression)
		if err != nil {
			return err
		}
		if intrinsic {
			switch name {
			case "Ref":
				name := argument.(string)
				if _, exists := e.template.Resources[name]; exists {
					dependencies[name] = true
				}
				return nil
			case "Fn::GetAtt":
				name, _, err := templateGetAtt(argument)
				if err != nil {
					return err
				}
				dependencies[name] = true
				return nil
			case "Fn::If":
				values := argument.([]any)
				active, err := e.condition(values[0].(string))
				if err != nil {
					return err
				}
				if active {
					return e.dependencies(values[1], dependencies)
				}
				return e.dependencies(values[2], dependencies)
			case "Fn::Sub":
				text, variables, err := templateSub(argument)
				if err != nil {
					return err
				}
				for _, match := range templateSubVariable.FindAllStringSubmatch(text, -1) {
					name := match[1]
					if _, exists := variables[name]; exists || strings.HasPrefix(name, "!") {
						continue
					}
					resource, _, _ := strings.Cut(name, ".")
					if _, exists := e.template.Resources[resource]; exists {
						dependencies[resource] = true
					}
				}
				for _, value := range variables {
					if err := e.dependencies(value, dependencies); err != nil {
						return err
					}
				}
				return nil
			}
			return e.dependencies(argument, dependencies)
		}
		for _, value := range expression {
			if err := e.dependencies(value, dependencies); err != nil {
				return err
			}
		}
	case []any:
		for _, value := range expression {
			if err := e.dependencies(value, dependencies); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectImports walks only selected expressions without resolving resource
// attributes, which are not available yet during admission.
func (e *templateEvaluator) collectImports(expression any) error {
	switch expression := expression.(type) {
	case map[string]any:
		name, argument, intrinsic, err := templateFunction(expression)
		if err != nil {
			return err
		}
		if intrinsic {
			switch name {
			case "Fn::ImportValue":
				_, err := e.resolve(expression)
				return err
			case "Fn::If":
				values := argument.([]any)
				active, err := e.condition(values[0].(string))
				if err != nil {
					return err
				}
				if active {
					return e.collectImports(values[1])
				}
				return e.collectImports(values[2])
			case "Fn::Sub":
				_, variables, err := templateSub(argument)
				if err != nil {
					return err
				}
				for _, value := range variables {
					if err := e.collectImports(value); err != nil {
						return err
					}
				}
				return nil
			}
			return e.collectImports(argument)
		}
		for _, value := range expression {
			if err := e.collectImports(value); err != nil {
				return err
			}
		}
	case []any:
		for _, value := range expression {
			if err := e.collectImports(value); err != nil {
				return err
			}
		}
	}
	return nil
}
