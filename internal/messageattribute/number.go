// Package messageattribute owns exact numeric attribute parsing and rendering.
package messageattribute

import (
	"cmp"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrNumberSyntax    = errors.New("invalid number syntax")
	ErrNumberPrecision = errors.New("number exceeds 38 precision digits")
	ErrNumberRange     = errors.New("number scale is outside the supported range")
)

var numberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// Number is a parsed attribute with native precision and scale constraints.
// SNS preserves the input spelling in notifications; SQS renders String().
type Number struct {
	digits   string
	exponent int
	negative bool
}

// ParseNumber validates before trimming trailing zeroes, accepting at most 38
// precision digits and scales in [minimumScale,126). SNS/SQS use -128; DynamoDB
// supports -130. Leading zeroes do not contribute to precision.
func ParseNumber(input string, minimumScale int) (Number, error) {
	if !numberPattern.MatchString(input) {
		return Number{}, ErrNumberSyntax
	}
	exponent := 0
	mantissa := input
	if i := strings.IndexAny(input, "eE"); i >= 0 {
		mantissa = input[:i]
		var err error
		exponent, err = strconv.Atoi(input[i+1:])
		if err != nil {
			return Number{}, ErrNumberRange
		}
	}
	negative := strings.HasPrefix(mantissa, "-")
	mantissa = strings.TrimPrefix(strings.TrimPrefix(mantissa, "-"), "+")
	fraction := 0
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		fraction = len(mantissa) - i - 1
		mantissa = mantissa[:i] + mantissa[i+1:]
	}
	digits := strings.TrimLeft(mantissa, "0")
	if len(digits) > 38 {
		return Number{}, ErrNumberPrecision
	}
	if digits == "" {
		digits = "0"
		negative = false
	}
	// Compare the original exponent before addition/subtraction, including
	// untrusted exponents at the host integer boundary; no saturating arithmetic.
	adjustment := len(digits) - 1 - fraction
	if exponent < minimumScale-adjustment || exponent >= 126-adjustment {
		return Number{}, ErrNumberRange
	}
	return Number{digits: digits, exponent: exponent - fraction, negative: negative}, nil
}

// Compare orders parsed numbers exactly, without converting to floating point
// or allocating expanded decimal representations.
func (n Number) Compare(other Number) int {
	if n.digits == "0" {
		if other.digits == "0" {
			return 0
		}
		if other.negative {
			return 1
		}
		return -1
	}
	if other.digits == "0" {
		if n.negative {
			return -1
		}
		return 1
	}
	if n.negative != other.negative {
		if n.negative {
			return -1
		}
		return 1
	}
	order := cmp.Compare(len(n.digits)+n.exponent, len(other.digits)+other.exponent)
	if order == 0 {
		for i := 0; i < max(len(n.digits), len(other.digits)); i++ {
			a, b := byte('0'), byte('0')
			if i < len(n.digits) {
				a = n.digits[i]
			}
			if i < len(other.digits) {
				b = other.digits[i]
			}
			if order = cmp.Compare(a, b); order != 0 {
				break
			}
		}
	}
	if n.negative {
		return -order
	}
	return order
}

func (n Number) String() string {
	if n.digits == "0" {
		return "0"
	}
	digits := strings.TrimRight(n.digits, "0")
	exponent := n.exponent + len(n.digits) - len(digits)
	point := len(digits) + exponent
	var result string
	switch {
	case point >= len(digits):
		result = digits + strings.Repeat("0", point-len(digits))
	case point > 0:
		result = digits[:point] + "." + digits[point:]
	default:
		result = "0." + strings.Repeat("0", -point) + digits
	}
	if n.negative {
		return "-" + result
	}
	return result
}
