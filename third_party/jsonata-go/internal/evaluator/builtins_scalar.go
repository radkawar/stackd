package evaluator

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

var scalarBuiltinSpecs = []builtinSpec{
	{name: "abs", signature: "<n-:n>", implementation: builtinAbs},
	{name: "assert", signature: "<bs?:x>", implementation: builtinAssert},
	{name: "boolean", signature: "<x-:b>", implementation: builtinBoolean},
	{name: "ceil", signature: "<n-:n>", implementation: builtinCeil},
	{name: "error", signature: "<s?:x>", implementation: builtinError},
	{name: "exists", signature: "<x:b>", implementation: builtinExists},
	{name: "floor", signature: "<n-:n>", implementation: builtinFloor},
	{name: "not", signature: "<x-:b>", implementation: builtinNot},
	{name: "number", signature: "<(nsb)-:n>", implementation: builtinNumber},
	{name: "power", signature: "<n-n:n>", implementation: builtinPower},
	{name: "round", signature: "<n-n?:n>", implementation: builtinRound},
	{name: "sqrt", signature: "<n-:n>", implementation: builtinSqrt},
}

var scalarDecimalNumberPattern = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

func builtinAbs(_ state, args []any) (any, error) {
	if value := scalarNumberArgument(args); value.undefined {
		return undefinedValue(), nil
	} else if !value.valid {
		return nil, scalarNumberTypeError()
	} else {
		return finiteResult(math.Abs(value.number))
	}
}

func builtinAssert(_ state, args []any) (any, error) {
	if len(args) == 0 || !scalarBooleanValue(args[0]) {
		message := "$assert() statement failed"
		if len(args) > 1 && !isUndefinedValue(args[1]) {
			message = args[1].(string)
			if message == "" {
				message = "$assert() statement failed"
			}
		}
		return nil, runtimeError{code: "D3141", msg: message}
	}
	return undefinedValue(), nil
}

func builtinBoolean(_ state, args []any) (any, error) {
	if len(args) == 0 {
		return false, nil
	}
	if isUndefinedValue(args[0]) {
		return undefinedValue(), nil
	}
	return scalarBooleanValue(args[0]), nil
}

func builtinCeil(_ state, args []any) (any, error) {
	return scalarUnaryNumber(args, math.Ceil)
}

func builtinError(_ state, args []any) (any, error) {
	message := "$error() function evaluated"
	if len(args) > 0 && !isUndefinedValue(args[0]) {
		message = args[0].(string)
		if message == "" {
			message = "$error() function evaluated"
		}
	}
	return nil, runtimeError{code: "D3137", msg: message}
}

func builtinExists(_ state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$exists", 1, len(args))
	}
	return !isUndefinedValue(args[0]), nil
}

func builtinFloor(_ state, args []any) (any, error) {
	return scalarUnaryNumber(args, math.Floor)
}

func builtinNot(_ state, args []any) (any, error) {
	if len(args) == 0 {
		return nil, functionArityError("$not", 1, len(args))
	}
	if isUndefinedValue(args[0]) {
		return undefinedValue(), nil
	}
	return !scalarBooleanValue(args[0]), nil
}

func builtinNumber(_ state, args []any) (any, error) {
	if len(args) == 0 || isUndefinedValue(args[0]) {
		return undefinedValue(), nil
	}
	input := collapse(args[0])
	if number, ok := strictNumeric(input); ok {
		return finiteResult(number)
	}
	if boolean, ok := input.(bool); ok {
		if boolean {
			return 1.0, nil
		}
		return 0.0, nil
	}
	text, ok := input.(string)
	if !ok {
		return nil, scalarNumberTypeError()
	}
	result, err := parseScalarNumber(text)
	if err != nil || !isFiniteNumber(result) {
		return nil, runtimeError{
			code:  "D3030",
			msg:   fmt.Sprintf("Unable to cast value to a number: %q", text),
			value: text,
		}
	}
	return result, nil
}

func parseScalarNumber(text string) (float64, error) {
	if text == "" {
		return 0, fmt.Errorf("empty number")
	}
	if len(text) > 2 && text[0] == '0' {
		base := 0
		switch text[1] {
		case 'x', 'X':
			base = 16
		case 'b', 'B':
			base = 2
		case 'o', 'O':
			base = 8
		}
		if base != 0 {
			if len(text) == 2 || text[2] == '+' || text[2] == '-' {
				return 0, fmt.Errorf("invalid radix number")
			}
			integer, ok := new(big.Int).SetString(text[2:], base)
			if !ok {
				return 0, fmt.Errorf("invalid radix number")
			}
			result, _ := new(big.Float).SetInt(integer).Float64()
			if math.IsInf(result, 0) || math.IsNaN(result) {
				return 0, fmt.Errorf("number is not finite")
			}
			return result, nil
		}
	}
	if !scalarDecimalNumberPattern.MatchString(text) {
		return 0, fmt.Errorf("invalid decimal number")
	}
	result, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(result, 0) || math.IsNaN(result) {
		return 0, fmt.Errorf("number is not finite")
	}
	return result, nil
}

func builtinPower(_ state, args []any) (any, error) {
	if len(args) < 2 {
		return undefinedValue(), nil
	}
	if isUndefinedValue(args[0]) {
		return undefinedValue(), nil
	}
	if isUndefinedValue(args[1]) {
		return nil, runtimeError{code: "D3061", msg: "invalid power operation"}
	}
	base, baseOK := strictNumeric(collapse(args[0]))
	exponent, exponentOK := strictNumeric(collapse(args[1]))
	if !baseOK || !exponentOK {
		return nil, scalarNumberTypeError()
	}
	result := math.Pow(base, exponent)
	if math.IsNaN(result) || math.IsInf(result, 0) {
		return nil, runtimeError{code: "D3061", msg: "invalid power operation"}
	}
	return result, nil
}

func builtinRound(_ state, args []any) (any, error) {
	if len(args) == 0 || isUndefinedValue(args[0]) {
		return undefinedValue(), nil
	}
	number, ok := strictNumeric(collapse(args[0]))
	if !ok {
		return nil, scalarNumberTypeError()
	}
	precision := 0.0
	if len(args) > 1 && !isUndefinedValue(args[1]) {
		var precisionOK bool
		precision, precisionOK = strictNumeric(collapse(args[1]))
		if !precisionOK {
			return nil, scalarNumberTypeError()
		}
	}
	if math.Trunc(precision) != precision {
		return nil, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	if math.IsNaN(precision) || math.IsInf(precision, 0) {
		return nil, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	if precision > 1000 || precision < -1000 {
		return finiteResult(number)
	}
	result, ok := roundDecimal(number, int(precision))
	if !ok {
		return finiteResult(number)
	}
	return finiteResult(result)
}

func builtinSqrt(_ state, args []any) (any, error) {
	if len(args) == 0 || isUndefinedValue(args[0]) {
		return undefinedValue(), nil
	}
	number, ok := strictNumeric(collapse(args[0]))
	if !ok {
		return nil, scalarNumberTypeError()
	}
	result := math.Sqrt(number)
	if math.IsNaN(result) {
		return nil, runtimeError{code: "D3060", msg: "square root of negative number"}
	}
	return finiteResult(result)
}

type scalarNumber struct {
	number    float64
	valid     bool
	undefined bool
}

func scalarNumberArgument(args []any) scalarNumber {
	if len(args) == 0 || isUndefinedValue(args[0]) {
		return scalarNumber{undefined: true}
	}
	number, ok := strictNumeric(collapse(args[0]))
	return scalarNumber{number: number, valid: ok}
}

func scalarUnaryNumber(args []any, operation func(float64) float64) (any, error) {
	argument := scalarNumberArgument(args)
	if argument.undefined {
		return undefinedValue(), nil
	}
	if !argument.valid {
		return nil, scalarNumberTypeError()
	}
	return finiteResult(operation(argument.number))
}

func scalarNumberTypeError() error {
	return runtimeError{code: "T0410", msg: "function argument does not match its signature"}
}

func scalarBooleanValue(input any) bool {
	input = collapse(input)
	if isUndefinedValue(input) || input == nil {
		return false
	}
	if _, ok := callable(input); ok {
		return false
	}
	switch current := input.(type) {
	case value.Array:
		for _, item := range current.Items {
			if scalarBooleanValue(item) {
				return true
			}
		}
		return false
	case []any:
		for _, item := range current {
			if scalarBooleanValue(item) {
				return true
			}
		}
		return false
	case map[string]any:
		return len(current) != 0
	case value.OrderedObject:
		return len(current.Fields) != 0
	case string:
		return current != ""
	case bool:
		return current
	}
	if number, ok := numeric(input); ok {
		return number != 0 && !math.IsNaN(number)
	}
	return true
}

func undefinedValue() any {
	return value.Undefined
}

func isUndefinedValue(input any) bool {
	return value.IsUndefined(collapse(input))
}

func isFiniteNumber(input any) bool {
	number, ok := input.(float64)
	return ok && !math.IsNaN(number) && !math.IsInf(number, 0)
}

func roundDecimal(number float64, precision int) (float64, bool) {
	text := strconv.FormatFloat(number, 'f', -1, 64)
	rational, ok := new(big.Rat).SetString(text)
	if !ok {
		return 0, false
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scalarAbsInt(precision))), nil)
	if precision >= 0 {
		rational.Mul(rational, new(big.Rat).SetInt(scale))
	} else {
		rational.Quo(rational, new(big.Rat).SetInt(scale))
	}
	quotient := new(big.Int)
	remainder := new(big.Int)
	quotient.QuoRem(rational.Num(), rational.Denom(), remainder)
	doubled := new(big.Int).Abs(remainder)
	doubled.Lsh(doubled, 1)
	if doubled.Cmp(rational.Denom()) > 0 || (doubled.Cmp(rational.Denom()) == 0 && quotient.Bit(0) != 0) {
		if rational.Num().Sign() < 0 {
			quotient.Sub(quotient, big.NewInt(1))
		} else {
			quotient.Add(quotient, big.NewInt(1))
		}
	}
	if precision >= 0 {
		rational.SetFrac(quotient, scale)
	} else {
		rational.SetInt(quotient)
		rational.Mul(rational, new(big.Rat).SetInt(scale))
	}
	result, _ := rational.Float64()
	return result, true
}

func scalarAbsInt(input int) int {
	if input < 0 {
		return -input
	}
	return input
}
