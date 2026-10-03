package eventpattern

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrEmptyAnythingButList identifies the empty negated operator lists for which
// native TestEventPattern returns InternalFailure rather than a pattern error.
var ErrEmptyAnythingButList = errors.New("empty anything-but operator list")

func compileTerm(input value) (term, error) {
	if input.kind == arrayValue {
		return term{}, fmt.Errorf("nested match arrays are not allowed")
	}
	if input.kind != objectValue {
		return term{match: exact(input)}, nil
	}
	if len(input.members) != 1 {
		return term{}, fmt.Errorf("a match expression must contain exactly one operator")
	}
	operator := input.members[0]
	operand := operator.value
	switch operator.name {
	case "exists":
		if operand.kind != boolValue {
			return term{}, fmt.Errorf("exists requires a boolean")
		}
		return term{absent: operand.text == "false", match: func(value) bool { return true }}, nil
	case "numeric":
		predicate, err := numeric(operand)
		return term{match: predicate}, err
	case "cidr":
		if operand.kind != stringValue {
			return term{}, fmt.Errorf("cidr requires a string")
		}
		predicate, err := cidr(operand.text)
		return term{match: predicate}, err
	case "anything-but":
		return anythingBut(operand)
	case "prefix", "suffix", "equals-ignore-case", "wildcard":
		predicate, err := stringOperator(operator.name, operand)
		return term{match: predicate}, err
	default:
		return term{}, fmt.Errorf("unrecognized match operator %q", operator.name)
	}
}

func exact(expected value) func(value) bool {
	if expected.kind == numberValue {
		number, numeric := comparable(expected.text)
		return func(actual value) bool {
			if actual.kind != numberValue {
				return false
			}
			other, ok := comparable(actual.text)
			return (numeric && ok && number == other) || actual.text == expected.text
		}
	}
	return func(actual value) bool { return actual.kind == expected.kind && actual.text == expected.text }
}

func stringOperator(operator string, operand value) (func(value) bool, error) {
	fold := operator == "equals-ignore-case"
	if operand.kind == objectValue && (operator == "prefix" || operator == "suffix") {
		if len(operand.members) != 1 || operand.members[0].name != "equals-ignore-case" {
			return nil, fmt.Errorf("%s only accepts equals-ignore-case as a nested operator", operator)
		}
		fold = true
		operand = operand.members[0].value
	}
	if operand.kind != stringValue {
		return nil, fmt.Errorf("%s requires a string", operator)
	}
	expected := operand.text
	if fold {
		compiled, err := caseInsensitive(expected, operator)
		if err != nil {
			return nil, err
		}
		return func(v value) bool { return v.kind == stringValue && compiled.MatchString(v.text) }, nil
	}
	if operator == "wildcard" {
		compiled, err := wildcard(expected)
		if err != nil {
			return nil, err
		}
		return func(v value) bool { return v.kind == stringValue && compiled.MatchString(v.text) }, nil
	}
	return func(v value) bool {
		if v.kind != stringValue {
			return false
		}
		actual := v.text
		switch operator {
		case "prefix":
			return strings.HasPrefix(actual, expected)
		case "suffix":
			return strings.HasSuffix(actual, expected)
		default:
			return actual == expected
		}
	}, nil
}

func anythingBut(operand value) (term, error) {
	var exclusions []func(value) bool
	if operand.kind == objectValue {
		if len(operand.members) != 1 {
			return term{}, fmt.Errorf("anything-but requires exactly one nested operator")
		}
		op := operand.members[0]
		switch op.name {
		case "prefix", "suffix", "equals-ignore-case", "wildcard":
		default:
			return term{}, fmt.Errorf("unsupported anything-but operator %q", op.name)
		}
		items := []value{op.value}
		if op.value.kind == arrayValue {
			items = op.value.items
		}
		if len(items) == 0 {
			return term{}, ErrEmptyAnythingButList
		}
		for _, item := range items {
			if item.kind != stringValue {
				return term{}, fmt.Errorf("anything-but string operations require strings")
			}
			if item.text == "" && (op.name == "prefix" || op.name == "suffix") {
				return term{}, fmt.Errorf("anything-but prefix and suffix must not be empty")
			}
			predicate, err := stringOperator(op.name, item)
			if err != nil {
				return term{}, err
			}
			exclusions = append(exclusions, predicate)
		}
	} else {
		items := []value{operand}
		if operand.kind == arrayValue {
			items = operand.items
		}
		if len(items) == 0 {
			return term{}, fmt.Errorf("anything-but list must not be empty")
		}
		kind := items[0].kind
		for _, item := range items {
			if (kind != stringValue && kind != numberValue) || item.kind != kind {
				return term{}, fmt.Errorf("anything-but requires only strings or only numbers")
			}
			if kind == numberValue {
				if _, ok := comparable(item.text); !ok {
					return term{}, fmt.Errorf("cannot compare number %s", item.text)
				}
			}
			exclusions = append(exclusions, exact(item))
		}
	}
	return term{match: func(v value) bool {
		for _, excluded := range exclusions {
			if excluded(v) {
				return false
			}
		}
		return true
	}}, nil
}

func wildcard(pattern string) (*regexp.Regexp, error) {
	var expression strings.Builder
	expression.WriteString("\\A(?s:")
	previousStar := false
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case '*':
			if previousStar {
				return nil, fmt.Errorf("consecutive wildcard characters are not allowed")
			}
			expression.WriteString(".*")
			previousStar = true
			continue
		case '\\':
			i++
			if i >= len(runes) || (runes[i] != '*' && runes[i] != '\\') {
				return nil, fmt.Errorf("wildcard escaping supports only * and backslash")
			}
			r = runes[i]
		}
		expression.WriteString(regexp.QuoteMeta(string(r)))
		previousStar = false
	}
	expression.WriteString(")\\z")
	return regexp.Compile(expression.String())
}
