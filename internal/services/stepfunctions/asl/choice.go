package asl

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const compilerChoiceOperators = "StringEquals StringEqualsPath StringLessThan StringLessThanPath StringGreaterThan StringGreaterThanPath StringLessThanEquals StringLessThanEqualsPath StringGreaterThanEquals StringGreaterThanEqualsPath StringMatches NumericEquals NumericEqualsPath NumericLessThan NumericLessThanPath NumericGreaterThan NumericGreaterThanPath NumericLessThanEquals NumericLessThanEqualsPath NumericGreaterThanEquals NumericGreaterThanEqualsPath BooleanEquals BooleanEqualsPath TimestampEquals TimestampEqualsPath TimestampLessThan TimestampLessThanPath TimestampGreaterThan TimestampGreaterThanPath TimestampLessThanEquals TimestampLessThanEqualsPath TimestampGreaterThanEquals TimestampGreaterThanEqualsPath IsNull IsPresent IsNumeric IsString IsBoolean IsTimestamp"

func (c *compiler) choices(object map[string]any, ctx compileContext, location string) *ChoiceState {
	choice := &ChoiceState{Default: c.optionalString(object, "Default", location)}
	if _, exists := object["Default"]; exists && choice.Default == "" {
		c.schema("Default must be a non-empty state name", location+"/Default")
	}
	entries := c.array(object["Choices"], location+"/Choices", true)
	choice.Rules = make([]ChoiceRule, 0, len(entries))
	for i, value := range entries {
		at := fmt.Sprintf("%s/Choices[%d]", location, i)
		object := c.object(value, at)
		rule := ChoiceRule{Next: c.requiredString(object, "Next", at), Assign: c.assignment(object, ctx, at)}
		if ctx.language == JSONata {
			c.fields(object, "Condition Next Assign Output Comment", at)
			condition, exists := object["Condition"]
			if !exists {
				c.schema("Condition is required", at+"/Condition")
			} else {
				_, boolean := condition.(bool)
				text, expression := condition.(string)
				if !boolean && (!expression || !strings.HasPrefix(text, "{%")) {
					c.schema("Condition must be a boolean or JSONata expression", at+"/Condition")
				}
			}
			rule.Condition = c.template(object, "Condition", false, ctx, at)
			rule.Output = c.template(object, "Output", false, ctx, at)
		} else {
			rule.Predicate = c.predicate(object, ctx, at, true)
		}
		c.optionalString(object, "Comment", at)
		choice.Rules = append(choice.Rules, rule)
	}
	return choice
}

func (c *compiler) predicate(object map[string]any, ctx compileContext, location string, top bool) *ChoicePredicate {
	fields := "Comment Variable And Or Not " + compilerChoiceOperators
	if top {
		fields += " Next Assign"
	}
	c.fields(object, fields, location)
	c.optionalString(object, "Comment", location)
	operators := append([]string{"And", "Or", "Not"}, strings.Fields(compilerChoiceOperators)...)
	operator := ""
	for _, candidate := range operators {
		if _, exists := object[candidate]; exists {
			if operator != "" {
				c.schema("Choice rule must contain exactly one operator", location)
			}
			operator = candidate
		}
	}
	predicate := &ChoicePredicate{Operator: ChoiceOperator(operator)}
	if operator == "" {
		c.schema("Choice rule requires a comparison or boolean operator", location)
		return predicate
	}
	if operator == "And" || operator == "Or" || operator == "Not" {
		if _, exists := object["Variable"]; exists {
			c.schema("Boolean choice rules cannot contain Variable", location+"/Variable")
		}
		if operator == "Not" {
			predicate.Children = []*ChoicePredicate{c.predicate(c.object(object[operator], location+"/Not"), ctx, location+"/Not", false)}
		} else {
			entries := c.array(object[operator], location+"/"+operator, true)
			for i, entry := range entries {
				at := fmt.Sprintf("%s/%s[%d]", location, operator, i)
				predicate.Children = append(predicate.Children, c.predicate(c.object(entry, at), ctx, at, false))
			}
		}
		return predicate
	}
	if _, exists := object["Variable"]; !exists {
		c.schema("Variable is required for a data-test choice", location+"/Variable")
	}
	predicate.Variable = c.path(object, "Variable", true, false, false, ctx, location)
	if strings.HasSuffix(operator, "Path") {
		predicate.OperandPath = c.path(object, operator, true, false, false, ctx, location)
		return predicate
	}
	operand := object[operator]
	predicate.Operand = operand
	switch {
	case strings.HasPrefix(operator, "Is"), operator == "BooleanEquals":
		if _, ok := operand.(bool); !ok {
			c.schema(operator+" requires a boolean", location+"/"+operator)
		}
	case strings.HasPrefix(operator, "Numeric"):
		if number, ok := numberValue(operand); !ok {
			c.schema(operator+" requires a number", location+"/"+operator)
		} else {
			predicate.Operand = number
		}
	case strings.HasPrefix(operator, "Timestamp"):
		text, ok := operand.(string)
		if !ok {
			c.schema(operator+" requires a timestamp", location+"/"+operator)
		} else if timestamp, valid := compilerTimestamp(text); !valid {
			c.schema(operator+" requires an RFC3339 timestamp", location+"/"+operator)
		} else {
			predicate.Operand = timestamp
		}
	default:
		text, ok := operand.(string)
		if !ok {
			c.schema(operator+" requires a string", location+"/"+operator)
		} else if operator == "StringMatches" {
			predicate.pattern, predicate.patternError = compilerStringPattern(text)
		}
	}
	return predicate
}

// SelectChoice evaluates rules in authored order against the state's effective
// input. The returned rule carries the selected transition and its own Assign
// and Output. For a default transition it carries the state's Assign and Output.
func SelectChoice(ctx context.Context, state *State, env Environment) (*ChoiceRule, error) {
	if state == nil || state.Choice == nil {
		return nil, &EvaluationError{Name: "States.Runtime", Cause: "Expected a Choice state"}
	}
	for i := range state.Choice.Rules {
		rule := &state.Choice.Rules[i]
		var matches bool
		if rule.Condition != nil {
			value, err := rule.Condition.Evaluate(ctx, env)
			if err != nil {
				return nil, err
			}
			var ok bool
			matches, ok = value.(bool)
			if !ok {
				return nil, scalarError(JSONata, "Choice Condition must evaluate to a boolean")
			}
		} else {
			var err error
			matches, err = rule.Predicate.evaluate(ctx, env)
			if err != nil {
				return nil, err
			}
		}
		if matches {
			return rule, nil
		}
	}
	if state.Choice.Default != "" {
		return &state.Choice.defaultRule, nil
	}
	// Native Step Functions reports States.Runtime for an unmatched Choice.
	return nil, &EvaluationError{Name: "States.Runtime", Cause: "Failed to transition out of the state. The state does not point to a next state."}
}

func (predicate *ChoicePredicate) evaluate(ctx context.Context, env Environment) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if predicate == nil {
		return false, &EvaluationError{Name: "States.Runtime", Cause: "Missing choice predicate"}
	}
	operator := string(predicate.Operator)
	switch operator {
	case "And", "Or":
		for _, child := range predicate.Children {
			value, err := child.evaluate(ctx, env)
			if err != nil {
				return false, err
			}
			if operator == "And" && !value {
				return false, nil
			}
			if operator == "Or" && value {
				return true, nil
			}
		}
		return operator == "And", nil
	case "Not":
		value, err := predicate.Children[0].evaluate(ctx, env)
		return !value, err
	}
	value, found, err := predicate.Variable.Lookup(env)
	if err != nil {
		return false, err
	}
	if operator == "IsPresent" {
		expected, _ := predicate.Operand.(bool)
		return found == expected, nil
	}
	if !found {
		return false, &EvaluationError{Name: "States.Runtime", Cause: "The choice state's condition path references an invalid value."}
	}
	operand := predicate.Operand
	if predicate.OperandPath != nil {
		operand, found, err = predicate.OperandPath.Lookup(env)
		if err != nil {
			return false, err
		}
		if !found {
			return false, &EvaluationError{Name: "States.Runtime", Cause: "The choice state's comparison path references an invalid value."}
		}
		operator = strings.TrimSuffix(operator, "Path")
	}
	if strings.HasPrefix(operator, "Is") {
		expected, _ := operand.(bool)
		matches := false
		switch operator {
		case "IsNull":
			matches = value == nil
		case "IsNumeric":
			_, matches = numberValue(value)
		case "IsString":
			_, matches = value.(string)
		case "IsBoolean":
			_, matches = value.(bool)
		case "IsTimestamp":
			if text, ok := value.(string); ok {
				_, matches = compilerTimestamp(text)
			}
		}
		return matches == expected, nil
	}
	if operator == "BooleanEquals" {
		left, lok := value.(bool)
		right, rok := operand.(bool)
		return lok && rok && left == right, nil
	}
	if operator == "StringMatches" {
		if predicate.patternError != nil {
			return false, &EvaluationError{Name: "States.Runtime", Cause: predicate.patternError.Error()}
		}
		text, ok := value.(string)
		return ok && predicate.pattern.MatchString(text), nil
	}
	comparison := 0
	switch {
	case strings.HasPrefix(operator, "String"):
		left, lok := value.(string)
		right, rok := operand.(string)
		if !lok || !rok {
			return false, nil
		}
		comparison = strings.Compare(left, right)
		operator = strings.TrimPrefix(operator, "String")
	case strings.HasPrefix(operator, "Numeric"):
		left, lok := numberValue(value)
		right, rok := numberValue(operand)
		if !lok || !rok {
			return false, nil
		}
		if left < right {
			comparison = -1
		} else if left > right {
			comparison = 1
		}
		operator = strings.TrimPrefix(operator, "Numeric")
	case strings.HasPrefix(operator, "Timestamp"):
		text, ok := value.(string)
		if !ok {
			return false, nil
		}
		left, ok := compilerTimestamp(text)
		if !ok {
			return false, nil
		}
		right, ok := operand.(time.Time)
		if !ok {
			text, stringOK := operand.(string)
			if !stringOK {
				return false, nil
			}
			right, ok = compilerTimestamp(text)
			if !ok {
				return false, nil
			}
		}
		comparison = left.Compare(right)
		operator = strings.TrimPrefix(operator, "Timestamp")
	default:
		return false, &EvaluationError{Name: "States.Runtime", Cause: "Invalid choice operator"}
	}
	switch operator {
	case "Equals":
		return comparison == 0, nil
	case "LessThan":
		return comparison < 0, nil
	case "GreaterThan":
		return comparison > 0, nil
	case "LessThanEquals":
		return comparison <= 0, nil
	case "GreaterThanEquals":
		return comparison >= 0, nil
	}
	return false, &EvaluationError{Name: "States.Runtime", Cause: "Invalid choice comparison"}
}

func compilerStringPattern(pattern string) (*regexp.Regexp, error) {
	var expression strings.Builder
	expression.WriteString("(?s)^")
	escaped := false
	for _, character := range pattern {
		if escaped {
			if character != '*' && character != '\\' {
				return nil, fmt.Errorf("invalid escape in StringMatches")
			}
			expression.WriteString(regexp.QuoteMeta(string(character)))
			escaped = false
			continue
		}
		switch character {
		case '\\':
			escaped = true
		case '*':
			expression.WriteString(".*")
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	if escaped {
		return nil, fmt.Errorf("open escape in StringMatches")
	}
	expression.WriteString("$")
	return regexp.Compile(expression.String())
}

var compilerTimestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

func compilerTimestamp(text string) (time.Time, bool) {
	if !compilerTimestampPattern.MatchString(text) {
		return time.Time{}, false
	}
	timestamp, err := time.Parse(time.RFC3339Nano, text)
	return timestamp, err == nil
}
