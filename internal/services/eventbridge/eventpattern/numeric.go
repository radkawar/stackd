package eventpattern

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

type comparison struct {
	operator string
	value    float64
}

// Comparable numbers round-trip through binary64 without changing their
// decimal value. This is wider than the range still described in AWS's guide.
func comparable(text string) (float64, bool) {
	number, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
		return 0, false
	}
	if number == 0 {
		coefficient, _, _ := strings.Cut(strings.ToLower(text), "e")
		return 0, strings.Trim(coefficient, "-+.0") == ""
	}
	decimal, ok := new(big.Rat).SetString(text)
	if !ok {
		return 0, false
	}
	roundTrip, _ := new(big.Rat).SetString(strconv.FormatFloat(number, 'g', -1, 64))
	return number, decimal.Cmp(roundTrip) == 0
}

func eventNumber(text string) string {
	if !strings.ContainsAny(text, ".eE") {
		return text
	}
	// TestEventPattern parses floating event values through binary64, while
	// integer event values retain their exact decimal representation.
	number, _ := strconv.ParseFloat(text, 64)
	return strconv.FormatFloat(number, 'g', -1, 64)
}

func numeric(operand value) (func(value) bool, error) {
	if operand.kind != arrayValue || (len(operand.items) != 2 && len(operand.items) != 4) {
		return nil, fmt.Errorf("numeric requires one comparison or a lower and upper bound")
	}
	var comparisons []comparison
	for i := 0; i < len(operand.items); i += 2 {
		operator, bound := operand.items[i], operand.items[i+1]
		if operator.kind != stringValue || bound.kind != numberValue {
			return nil, fmt.Errorf("numeric comparisons require an operator and number")
		}
		switch operator.text {
		case "=", ">", ">=", "<", "<=":
		default:
			return nil, fmt.Errorf("unrecognized numeric operator %q", operator.text)
		}
		number, ok := comparable(bound.text)
		if !ok {
			return nil, fmt.Errorf("numeric bound is invalid")
		}
		comparisons = append(comparisons, comparison{operator: operator.text, value: number})
	}
	if len(comparisons) == 2 {
		lower, upper := comparisons[0], comparisons[1]
		if (lower.operator != ">" && lower.operator != ">=") || (upper.operator != "<" && upper.operator != "<=") || lower.value >= upper.value {
			return nil, fmt.Errorf("numeric range must contain an increasing lower and upper bound")
		}
	}
	return func(actual value) bool {
		if actual.kind != numberValue {
			return false
		}
		number, ok := comparable(actual.text)
		if !ok {
			return false
		}
		for _, bound := range comparisons {
			matched := false
			switch bound.operator {
			case "=":
				matched = number == bound.value
			case ">":
				matched = number > bound.value
			case ">=":
				matched = number >= bound.value
			case "<":
				matched = number < bound.value
			case "<=":
				matched = number <= bound.value
			}
			if !matched {
				return false
			}
		}
		return true
	}, nil
}
