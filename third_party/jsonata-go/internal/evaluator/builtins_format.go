package evaluator

import (
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// formatBuiltinSpecs is kept separate from the central registry while the
// picture-string families are developed independently.
var formatBuiltinSpecs = []builtinSpec{
	{name: "formatBase", signature: "<n-n?:s>", implementation: builtinFormatBase},
	{name: "formatInteger", signature: "<n-s:s>", implementation: builtinFormatInteger},
	{name: "formatNumber", signature: "<n-sj?:s>", implementation: builtinFormatNumber},
	{name: "parseInteger", signature: "<s-s:n>", implementation: builtinParseInteger},
}

func builtinFormatBase(st state, args []any) (any, error) {
	if err := checkFormatRuntime(st); err != nil {
		return nil, err
	}
	if len(args) == 0 || value.IsUndefined(collapse(args[0])) {
		return value.Undefined, nil
	}
	number, ok := strictNumeric(collapse(args[0]))
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return nil, runtimeError{code: "T0410", msg: "expected a number"}
	}
	radix := 10.0
	if len(args) > 1 && !value.IsUndefined(collapse(args[1])) {
		radix, ok = strictNumeric(collapse(args[1]))
		if !ok || math.IsNaN(radix) || math.IsInf(radix, 0) {
			return nil, runtimeError{code: "D3100", msg: "radix must be between 2 and 36"}
		}
	}
	radix = roundPictureNumber(radix)
	if radix < 2 || radix > 36 {
		return nil, runtimeError{code: "D3100", msg: "radix must be between 2 and 36"}
	}
	number = roundPictureNumber(number)
	negative := number < 0
	if negative {
		number = -number
	}
	integer := new(big.Int)
	integer.SetString(strconv.FormatFloat(number, 'f', 0, 64), 10)
	result := integer.Text(int(radix))
	if negative && result != "0" {
		result = "-" + result
	}
	return result, nil
}

func roundPictureNumber(number float64) float64 {
	floor := math.Floor(number)
	frac := number - floor
	if frac > 0.5 || (frac == 0.5 && math.Mod(floor, 2) != 0) {
		floor++
	}
	return floor
}

func pictureNumberInteger(number float64) (*big.Int, bool) {
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return nil, false
	}
	abs := math.Abs(math.Trunc(number))
	text := strconv.FormatFloat(abs, 'f', 0, 64)
	if abs >= 1 {
		exponent := int(math.Round(math.Log10(abs)))
		if exponent >= 12 && exponent <= 300 {
			power := math.Pow10(exponent)
			if math.Abs(abs-power) <= power*1e-15 {
				return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil), true
			}
		}
	}
	integer, ok := new(big.Int).SetString(text, 10)
	return integer, ok
}

func formatPictureError(code string) error {
	return runtimeError{code: code, msg: "invalid picture string"}
}

func formatStringOption(options any, name, fallback string) string {
	if options == nil || value.IsUndefined(collapse(options)) {
		return fallback
	}
	if fields, ok := collapse(options).(map[string]any); ok {
		if raw, exists := fields[name]; exists {
			if text, ok := collapse(raw).(string); ok && text != "" {
				return text
			}
		}
	}
	return fallback
}

func formatOptions(args []any) any {
	if len(args) > 2 {
		return args[2]
	}
	return nil
}

func formatDigitsFamily(zero string) ([]rune, bool) {
	runes := []rune(zero)
	if len(runes) != 1 {
		return nil, false
	}
	family := make([]rune, 10)
	for i := range family {
		family[i] = runes[0] + rune(i)
	}
	return family, true
}

func mapPictureDigits(text string, family []rune) string {
	if len(family) != 10 {
		return text
	}
	var out strings.Builder
	for _, char := range text {
		if char >= '0' && char <= '9' {
			out.WriteRune(family[char-'0'])
		} else {
			out.WriteRune(char)
		}
	}
	return out.String()
}
