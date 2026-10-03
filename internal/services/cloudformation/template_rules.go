package cloudformation

import (
	"fmt"
	"reflect"
)

// TemplateRule assertions run against admitted parameters before provisioning.
type TemplateRule struct {
	Condition  any
	Assertions []TemplateAssertion
}
type TemplateAssertion struct {
	Assert      any
	Description string
}

func parseTemplateRule(entry map[string]any, path string) (TemplateRule, error) {
	var rule TemplateRule
	if err := templateFields(entry, path, "RuleCondition", "Assertions"); err != nil {
		return rule, err
	}
	rule.Condition = entry["RuleCondition"]
	assertions, ok := entry["Assertions"].([]any)
	if !ok || len(assertions) == 0 {
		return rule, fmt.Errorf("%s.Assertions must be a nonempty list", path)
	}
	for _, raw := range assertions {
		assertion, err := templateObject(raw, path+".Assertions")
		if err != nil {
			return rule, err
		}
		if err := templateFields(assertion, path+".Assertions", "Assert", "AssertDescription"); err != nil {
			return rule, err
		}
		expression, ok := assertion["Assert"]
		if !ok {
			return rule, fmt.Errorf("%s assertion requires Assert", path)
		}
		description, err := templateString(assertion, "AssertDescription", path, false)
		if err != nil {
			return rule, err
		}
		rule.Assertions = append(rule.Assertions, TemplateAssertion{Assert: expression, Description: description})
	}
	return rule, nil
}
func templateRuleIntrinsic(name string) bool {
	switch name {
	case "Ref", "Fn::Equals", "Fn::And", "Fn::Or", "Fn::Not", "Fn::Contains", "Fn::EachMemberEquals", "Fn::EachMemberIn":
		return true
	}
	return false
}
func (t *Template) validateRuleExpression(value any, boolean bool) error {
	switch v := value.(type) {
	case map[string]any:
		if len(v) != 1 {
			return fmt.Errorf("rule expression must contain exactly one function")
		}
		for name, arg := range v {
			if !templateRuleIntrinsic(name) {
				return fmt.Errorf("unsupported rule function %s", name)
			}
			if name == "Ref" {
				key, ok := arg.(string)
				if !ok {
					return fmt.Errorf("rule Ref requires parameter name")
				}
				if _, ok := t.Parameters[key]; !ok {
					return fmt.Errorf("rule Ref %s is not a parameter", key)
				}
				if boolean {
					return fmt.Errorf("rule assertion requires a boolean function")
				}
				return nil
			}
			min, max := 2, 2
			switch name {
			case "Fn::Not":
				min, max = 1, 1
			case "Fn::And", "Fn::Or":
				max = 10
			}
			args, err := templateArguments(arg, min, max)
			if err != nil {
				return err
			}
			for _, a := range args {
				if err := t.validateRuleExpression(a, name == "Fn::And" || name == "Fn::Or" || name == "Fn::Not"); err != nil {
					return err
				}
			}
		}
	case []any:
		if boolean {
			return fmt.Errorf("rule assertion requires a boolean function")
		}
		for _, a := range v {
			if err := t.validateRuleExpression(a, false); err != nil {
				return err
			}
		}
	default:
		if boolean {
			return fmt.Errorf("rule assertion requires a boolean function")
		}
		if _, err := templateScalar(v); err != nil {
			return err
		}
	}
	return nil
}
func (e *templateEvaluator) ruleExpression(value any) (any, error) {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, a := range v {
			resolved, err := e.ruleExpression(a)
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}
		return out, nil
	case map[string]any:
		for name, arg := range v {
			if name == "Ref" {
				return e.reference(arg.(string))
			}
			raw := arg.([]any)
			args := make([]any, len(raw))
			for i, a := range raw {
				resolved, err := e.ruleExpression(a)
				if err != nil {
					return nil, err
				}
				args[i] = resolved
			}
			switch name {
			case "Fn::Equals":
				return templateRuleEqual(args[0], args[1]), nil
			case "Fn::And", "Fn::Or", "Fn::Not":
				result := name != "Fn::Or"
				for _, a := range args {
					b, ok := a.(bool)
					if !ok {
						return nil, fmt.Errorf("%s requires boolean arguments", name)
					}
					if name == "Fn::And" {
						result = result && b
					} else if name == "Fn::Or" {
						result = result || b
					} else {
						result = !b
					}
				}
				return result, nil
			case "Fn::Contains", "Fn::EachMemberEquals", "Fn::EachMemberIn":
				list, ok := args[0].([]any)
				if !ok {
					return nil, fmt.Errorf("%s first argument must be a list", name)
				}
				if name == "Fn::Contains" {
					for _, item := range list {
						if templateRuleEqual(item, args[1]) {
							return true, nil
						}
					}
					return false, nil
				}
				if name == "Fn::EachMemberEquals" {
					for _, item := range list {
						if !templateRuleEqual(item, args[1]) {
							return false, nil
						}
					}
					return true, nil
				}
				allowed, ok := args[1].([]any)
				if !ok {
					return nil, fmt.Errorf("Fn::EachMemberIn second argument must be a list")
				}
				for _, item := range list {
					found := false
					for _, candidate := range allowed {
						if templateRuleEqual(item, candidate) {
							found = true
							break
						}
					}
					if !found {
						return false, nil
					}
				}
				return true, nil
			}
		}
	}
	return value, nil
}
func templateRuleEqual(a, b any) bool {
	left, e1 := templateScalar(a)
	right, e2 := templateScalar(b)
	if e1 == nil && e2 == nil {
		return left == right
	}
	return reflect.DeepEqual(a, b)
}
func (t *Template) ValidateRules(input Evaluation) error {
	e := t.evaluator(input)
	for _, name := range templateKeys(t.Rules) {
		rule := t.Rules[name]
		if rule.Condition != nil {
			value, err := e.ruleExpression(rule.Condition)
			if err != nil {
				return fmt.Errorf("rule %s: %w", name, err)
			}
			if value != true {
				continue
			}
		}
		for _, assertion := range rule.Assertions {
			value, err := e.ruleExpression(assertion.Assert)
			if err != nil {
				return fmt.Errorf("rule %s: %w", name, err)
			}
			if value != true {
				reason := assertion.Description
				if reason == "" {
					reason = "assertion failed"
				}
				return fmt.Errorf("rule %s: %s", name, reason)
			}
		}
	}
	return nil
}
