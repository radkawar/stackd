package filterpolicy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

type predicateKind uint8

const (
	exactPredicate predicateKind = iota
	presentPredicate
	absentPredicate
	prefixPredicate
	suffixPredicate
	foldPredicate
	regexpPredicate
	cidrPredicate
	numericPredicate
	excludePredicate
)

type scalarKind uint8

const (
	invalidScalar scalarKind = iota
	stringScalar
	numberScalar
	boolScalar
	nullScalar
)

type scalar struct {
	kind    scalarKind
	text    string
	number  decimal
	boolean bool
}

type predicate struct {
	kind        predicateKind
	value       scalar
	pattern     *regexp.Regexp
	network     netip.Prefix
	comparisons []comparison
	excluded    []predicate
}

func makeScalar(value any) scalar {
	switch value := value.(type) {
	case string:
		return scalar{kind: stringScalar, text: value}
	case json.Number:
		if number, ok := parseDecimal(string(value)); ok {
			return scalar{kind: numberScalar, number: number}
		}
	case decimal:
		return scalar{kind: numberScalar, number: value}
	case bool:
		return scalar{kind: boolScalar, boolean: value}
	case nil:
		return scalar{kind: nullScalar}
	}
	return scalar{}
}

func compilePredicate(value any) (predicate, int, error) {
	object, operator := value.(map[string]any)
	if !operator {
		actual := makeScalar(value)
		if actual.kind == invalidScalar {
			return predicate{}, 0, fmt.Errorf("match values must be scalars or operator objects")
		}
		if actual.kind == numberScalar && !actual.number.validPolicyNumber() {
			return predicate{}, 0, fmt.Errorf("numbers must be between -1e9 and 1e9 with at most five decimal places")
		}
		return predicate{kind: exactPredicate, value: actual}, 0, nil
	}
	if len(object) != 1 {
		return predicate{}, 0, fmt.Errorf("a match expression requires exactly one operator")
	}
	for name, operand := range object {
		switch name {
		case "exists":
			exists, ok := operand.(bool)
			if !ok {
				return predicate{}, 0, fmt.Errorf("exists requires a boolean")
			}
			if exists {
				return predicate{kind: presentPredicate}, 0, nil
			}
			return predicate{kind: absentPredicate}, 0, nil
		case "prefix", "suffix", "equals-ignore-case", "wildcard":
			return compileString(name, operand)
		case "cidr":
			text, ok := operand.(string)
			if !ok {
				return predicate{}, 0, fmt.Errorf("cidr requires a string")
			}
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return predicate{}, 0, fmt.Errorf("invalid cidr: %w", err)
			}
			return predicate{kind: cidrPredicate, network: prefix.Masked()}, 0, nil
		case "numeric":
			p, err := compileNumeric(operand)
			return p, 0, err
		case "anything-but":
			return compileExclusion(operand)
		default:
			return predicate{}, 0, fmt.Errorf("unsupported operator %q", name)
		}
	}
	panic("nonempty operator object")
}

func compileString(name string, operand any) (predicate, int, error) {
	fold := false
	if nested, ok := operand.(map[string]any); ok {
		if (name != "prefix" && name != "suffix") || len(nested) != 1 {
			return predicate{}, 0, fmt.Errorf("%s does not support this nested expression", name)
		}
		var exists bool
		operand, exists = nested["equals-ignore-case"]
		if !exists {
			return predicate{}, 0, fmt.Errorf("%s only supports equals-ignore-case nesting", name)
		}
		fold = true
	}
	text, ok := operand.(string)
	if !ok {
		return predicate{}, 0, fmt.Errorf("%s requires a string", name)
	}
	p := predicate{value: scalar{kind: stringScalar, text: text}}
	if fold {
		expression := "(?i)" + regexp.QuoteMeta(text)
		if name == "prefix" {
			expression = "\\A" + expression
		} else {
			expression += "\\z"
		}
		p.kind = regexpPredicate
		p.pattern = regexp.MustCompile(expression)
		return p, 0, nil
	}
	switch name {
	case "prefix":
		p.kind = prefixPredicate
	case "suffix":
		p.kind = suffixPredicate
	case "equals-ignore-case":
		p.kind = foldPredicate
	case "wildcard":
		pattern, points, err := compileWildcard(text)
		if err != nil {
			return predicate{}, 0, err
		}
		p.kind, p.pattern = regexpPredicate, pattern
		return p, points, nil
	}
	return p, 0, nil
}

func compileExclusion(operand any) (predicate, int, error) {
	p := predicate{kind: excludePredicate}
	if nested, ok := operand.(map[string]any); ok {
		if len(nested) != 1 {
			return predicate{}, 0, fmt.Errorf("anything-but requires one nested string operator")
		}
		for name, value := range nested {
			switch name {
			case "prefix", "suffix", "wildcard", "equals-ignore-case":
				inner, points, err := compileString(name, value)
				if err != nil {
					return predicate{}, 0, err
				}
				p.value.kind = stringScalar
				p.excluded = []predicate{inner}
				return p, 1 + points, nil
			default:
				return predicate{}, 0, fmt.Errorf("anything-but does not support nested %q", name)
			}
		}
	}
	items, array := operand.([]any)
	if !array {
		items = []any{operand}
	}
	if len(items) == 0 {
		return predicate{}, 0, fmt.Errorf("anything-but requires a nonempty value list")
	}
	for _, item := range items {
		s := makeScalar(item)
		if s.kind != stringScalar && s.kind != numberScalar {
			return predicate{}, 0, fmt.Errorf("anything-but requires strings or numbers")
		}
		if p.value.kind != invalidScalar && p.value.kind != s.kind {
			return predicate{}, 0, fmt.Errorf("anything-but values must have the same type")
		}
		if s.kind == numberScalar && !s.number.validPolicyNumber() {
			return predicate{}, 0, fmt.Errorf("numbers must be between -1e9 and 1e9 with at most five decimal places")
		}
		p.value.kind = s.kind
		p.excluded = append(p.excluded, predicate{kind: exactPredicate, value: s})
	}
	return p, 1, nil
}

func compileWildcard(text string) (*regexp.Regexp, int, error) {
	var expression strings.Builder
	expression.WriteString("\\A(?s:")
	wildcards := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '*':
			wildcards++
			if wildcards > 3 {
				return nil, 0, fmt.Errorf("wildcard patterns may contain at most three wildcards")
			}
			expression.WriteString(".*")
		case '\\':
			i++
			if i == len(text) || (text[i] != '*' && text[i] != '\\') {
				return nil, 0, fmt.Errorf("wildcard escape must precede * or backslash")
			}
			expression.WriteString(regexp.QuoteMeta(text[i : i+1]))
		default:
			// Copy a whole literal run so UTF-8 is never split by QuoteMeta.
			start := i
			for i+1 < len(text) && text[i+1] != '*' && text[i+1] != '\\' {
				i++
			}
			expression.WriteString(regexp.QuoteMeta(text[start : i+1]))
		}
	}
	expression.WriteString(")\\z")
	pattern, err := regexp.Compile(expression.String())
	if err != nil {
		return nil, 0, fmt.Errorf("invalid wildcard: %w", err)
	}
	points := wildcards
	if wildcards > 1 {
		points *= 3
	}
	return pattern, points, nil
}

func (p *predicate) match(actual scalar) bool {
	switch p.kind {
	case presentPredicate:
		// Native SNS treats a body null scalar as present, unlike the current
		// documentation's non-null wording. Empty containers never get here.
		return actual.kind != invalidScalar
	case absentPredicate:
		return false
	case exactPredicate:
		if p.value.kind != actual.kind {
			return false
		}
		switch actual.kind {
		case stringScalar:
			return actual.text == p.value.text
		case numberScalar:
			return actual.number.compare(p.value.number) == 0
		case boolScalar:
			return actual.boolean == p.value.boolean
		case nullScalar:
			return true
		}
	case prefixPredicate:
		return actual.kind == stringScalar && strings.HasPrefix(actual.text, p.value.text)
	case suffixPredicate:
		return actual.kind == stringScalar && strings.HasSuffix(actual.text, p.value.text)
	case foldPredicate:
		return actual.kind == stringScalar && strings.EqualFold(actual.text, p.value.text)
	case regexpPredicate:
		return actual.kind == stringScalar && p.pattern.MatchString(actual.text)
	case cidrPredicate:
		if actual.kind == stringScalar {
			address, err := netip.ParseAddr(actual.text)
			return err == nil && address.Zone() == "" && p.network.Contains(address)
		}
	case numericPredicate:
		if actual.kind != numberScalar {
			return false
		}
		for _, comparison := range p.comparisons {
			order := actual.number.compare(comparison.value)
			switch comparison.operator {
			case "=":
				if order != 0 {
					return false
				}
			case "<":
				if order >= 0 {
					return false
				}
			case "<=":
				if order > 0 {
					return false
				}
			case ">":
				if order <= 0 {
					return false
				}
			case ">=":
				if order < 0 {
					return false
				}
			}
		}
		return true
	case excludePredicate:
		if actual.kind != p.value.kind {
			return false
		}
		for _, excluded := range p.excluded {
			if excluded.match(actual) {
				return false
			}
		}
		return true
	}
	return false
}
