package filterpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// decimal keeps the original base-ten value, rather than rounding published
// numbers through float64 or to the policy's five-decimal-place precision.
// Its canonical value is sign * digits * 10^exponent; zero has sign zero.
type decimal struct {
	digits   string
	exponent int64
	sign     int8
}

type comparison struct {
	operator string
	value    decimal
}

func parseDecimal(text string) (decimal, bool) {
	if text == "" {
		return decimal{}, false
	}
	sign := int8(1)
	if text[0] == '-' || text[0] == '+' {
		if text[0] == '-' {
			sign = -1
		}
		text = text[1:]
	}
	if text == "" {
		return decimal{}, false
	}
	mantissa := text
	var exponent int64
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		mantissa = text[:index]
		exponentText := text[index+1:]
		negative := false
		if exponentText != "" && (exponentText[0] == '-' || exponentText[0] == '+') {
			negative = exponentText[0] == '-'
			exponentText = exponentText[1:]
		}
		if exponentText == "" {
			return decimal{}, false
		}
		// Exponents larger than any representable message length are ordered
		// exactly against every legal policy operand without allocating 10^n.
		const exponentLimit int64 = 1 << 60
		for _, digit := range exponentText {
			if digit < '0' || digit > '9' {
				return decimal{}, false
			}
			value := int64(digit - '0')
			if exponent > (exponentLimit-value)/10 {
				exponent = exponentLimit
			} else {
				exponent = exponent*10 + value
			}
		}
		if negative {
			exponent = -exponent
		}
	}
	integer, fraction, point := strings.Cut(mantissa, ".")
	if integer == "" || (point && fraction == "") {
		return decimal{}, false
	}
	for _, digit := range integer {
		if digit < '0' || digit > '9' {
			return decimal{}, false
		}
	}
	for _, digit := range fraction {
		if digit < '0' || digit > '9' {
			return decimal{}, false
		}
	}
	digits := integer
	if point {
		digits += fraction
		exponent -= int64(len(fraction))
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return decimal{}, true
	}
	trimmed := strings.TrimRight(digits, "0")
	exponent += int64(len(digits) - len(trimmed))
	return decimal{digits: trimmed, exponent: exponent, sign: sign}, true
}

func (d decimal) validPolicyNumber() bool {
	if d.sign == 0 {
		return true
	}
	if d.exponent < -5 {
		return false
	}
	d.sign = 1
	return d.compare(decimal{digits: "1", exponent: 9, sign: 1}) <= 0
}

func (d decimal) compare(other decimal) int {
	if d.sign < other.sign {
		return -1
	}
	if d.sign > other.sign {
		return 1
	}
	if d.sign == 0 {
		return 0
	}
	leftMagnitude := int64(len(d.digits)) + d.exponent
	rightMagnitude := int64(len(other.digits)) + other.exponent
	if leftMagnitude < rightMagnitude {
		return -int(d.sign)
	}
	if leftMagnitude > rightMagnitude {
		return int(d.sign)
	}
	for i := range max(len(d.digits), len(other.digits)) {
		left, right := byte('0'), byte('0')
		if i < len(d.digits) {
			left = d.digits[i]
		}
		if i < len(other.digits) {
			right = other.digits[i]
		}
		if left < right {
			return -int(d.sign)
		}
		if left > right {
			return int(d.sign)
		}
	}
	return 0
}

func compileNumeric(operand any) (predicate, error) {
	items, ok := operand.([]any)
	if !ok || (len(items) != 2 && len(items) != 4) {
		return predicate{}, fmt.Errorf("numeric requires a comparison or a lower and upper bound")
	}
	p := predicate{kind: numericPredicate}
	lower, upper := -1, -1
	for i := 0; i < len(items); i += 2 {
		operator, ok := items[i].(string)
		if !ok {
			return predicate{}, fmt.Errorf("numeric comparison operators must be strings")
		}
		switch operator {
		case "=":
			if len(items) != 2 {
				return predicate{}, fmt.Errorf("numeric equality must be a single comparison")
			}
		case ">", ">=":
			if lower >= 0 {
				return predicate{}, fmt.Errorf("numeric permits only one lower bound")
			}
			lower = len(p.comparisons)
		case "<", "<=":
			if upper >= 0 {
				return predicate{}, fmt.Errorf("numeric permits only one upper bound")
			}
			upper = len(p.comparisons)
		default:
			return predicate{}, fmt.Errorf("unsupported numeric operator %q", operator)
		}
		text, ok := items[i+1].(json.Number)
		if !ok {
			return predicate{}, fmt.Errorf("numeric operands must be numbers")
		}
		value, ok := parseDecimal(string(text))
		if !ok || !value.validPolicyNumber() {
			return predicate{}, fmt.Errorf("numbers must be between -1e9 and 1e9 with at most five decimal places")
		}
		p.comparisons = append(p.comparisons, comparison{operator: operator, value: value})
	}
	if lower >= 0 && upper >= 0 {
		lo, hi := p.comparisons[lower], p.comparisons[upper]
		order := lo.value.compare(hi.value)
		if order > 0 || (order == 0 && (lo.operator == ">" || hi.operator == "<")) {
			return predicate{}, fmt.Errorf("numeric lower and upper bounds describe an empty range")
		}
	}
	return p, nil
}
