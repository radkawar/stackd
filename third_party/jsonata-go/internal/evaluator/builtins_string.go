package evaluator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

type orderedJSONMap struct {
	value map[string]any
	order []string
}

func (m orderedJSONMap) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	for _, key := range m.order {
		item, ok := m.value[key]
		if !ok {
			continue
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		encodedValue, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(encodedKey)
		out.WriteByte(':')
		out.Write(encodedValue)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func isObjectValue(v any) bool {
	switch collapse(v).(type) {
	case map[string]any:
		return true
	case value.OrderedObject:
		return true
	default:
		return false
	}
}

type nonFiniteNumber struct{ value float64 }

var (
	jsonataLowercase = cases.Lower(language.Und)
	jsonataUppercase = cases.Upper(language.Und)
)

// JSONata casing follows the tables selected by golang.org/x/text v0.39.0:
// supported Go 1.26 builds use Unicode 15.0.0 and supported Go 1.27 builds use
// Unicode 17.0.0. ECMAScript delegates casing to its host runtime, so changes
// to either runtime require an oracle comparison.

var stringBuiltinSpecs = []builtinSpec{
	{name: "string", signature: "<x?b?:s>", implementation: builtinString},
	{name: "substring", signature: "<s-nn?:s>", implementation: builtinSubstring},
	{name: "substringBefore", signature: "<s-s:s>", implementation: builtinSubstringBefore},
	{name: "substringAfter", signature: "<s-s:s>", implementation: builtinSubstringAfter},
	{name: "lowercase", signature: "<s-:s>", implementation: builtinLowercase},
	{name: "uppercase", signature: "<s-:s>", implementation: builtinUppercase},
	{name: "pad", signature: "<s-ns?:s>", implementation: builtinPad},
	{name: "trim", signature: "<s-:s>", implementation: builtinTrim},
	{name: "base64encode", signature: "<s-:s>", implementation: builtinBase64Encode},
	{name: "base64decode", signature: "<s-:s>", implementation: builtinBase64Decode},
	{name: "encodeUrl", signature: "<s-:s>", implementation: builtinEncodeURL},
	{name: "decodeUrl", signature: "<s-:s>", implementation: builtinDecodeURL},
	{name: "encodeUrlComponent", signature: "<s-:s>", implementation: builtinEncodeURLComponent},
	{name: "decodeUrlComponent", signature: "<s-:s>", implementation: builtinDecodeURLComponent},
}

func builtinString(st state, args []any) (any, error) {
	if len(args) == 0 {
		if value.IsUndefined(st.current) || st.current == nil {
			return value.Undefined, nil
		}
		args = []any{st.current}
	}
	if len(args) < 1 || len(args) > 2 {
		return nil, functionArityError("$string", 1, len(args))
	}
	if value.IsUndefined(args[0]) && st.current != nil {
		if !isObjectValue(st.current) {
			args[0] = st.current
		}
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	pretty := false
	if len(args) == 2 && !value.IsUndefined(args[1]) {
		pretty, _ = args[1].(bool)
	}
	return stringifyJSONata(st, args[0], pretty)
}

func stringifyJSONata(st state, v any, pretty bool) (string, error) {
	if _, ok := callable(v); ok {
		return "", nil
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	if _, ok := collapse(v).(nonFiniteNumber); ok {
		return "", runtimeError{code: "D3001", msg: "numeric value is not finite"}
	}
	if b, ok := v.([]byte); ok {
		return string(b), nil
	}
	if n, ok := numeric(collapse(v)); ok {
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return "", runtimeError{code: "D1001", msg: "numeric result is not finite"}
		}
	}
	jsonValue, ok, conversionErr := jsonataStringValue(st, v)
	if conversionErr != nil {
		return "", conversionErr
	}
	if !ok {
		return "", runtimeError{code: "T0412", msg: "argument to function $string is not JSON-compatible"}
	}
	var data []byte
	var err error
	if pretty {
		data, err = json.MarshalIndent(jsonValue, "", "  ")
	} else {
		data, err = json.Marshal(jsonValue)
	}
	if err != nil {
		return "", runtimeError{code: "T0412", msg: "argument to function $string is not JSON-compatible", cause: err}
	}
	return string(data), nil
}

func jsonataStringValue(st state, v any) (any, bool, error) {
	if err := stringRuntimeCheck(st); err != nil {
		return nil, false, err
	}
	if value.IsUndefined(v) {
		return nil, false, nil
	}
	if _, ok := callable(v); ok {
		return "", true, nil
	}
	switch x := v.(type) {
	case contextual:
		return jsonataStringValue(st, x.v)
	case bound:
		return jsonataStringValue(st, x.v)
	case sortedSequence:
		return jsonataStringValue(st, x.values)
	case sequence:
		out := make([]any, 0, len(x))
		for _, item := range x {
			converted, ok, err := jsonataStringValue(st, item)
			if err != nil {
				return nil, false, err
			}
			if ok {
				out = append(out, converted)
			}
		}
		return out, true, nil
	case value.Array:
		out := make([]any, 0, len(x.Items))
		for _, item := range x.Items {
			converted, ok, err := jsonataStringValue(st, item)
			if err != nil {
				return nil, false, err
			}
			if ok {
				out = append(out, converted)
			}
		}
		return out, true, nil
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			converted, ok, err := jsonataStringValue(st, item)
			if err != nil {
				return nil, false, err
			}
			if ok {
				out = append(out, converted)
			}
		}
		return out, true, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, item := range x {
			converted, ok, err := jsonataStringValue(st, item)
			if err != nil {
				return nil, false, err
			}
			if ok {
				out[key] = converted
			}
		}
		return out, true, nil
	case value.OrderedObject:
		out := make(map[string]any, len(x.Fields))
		for _, key := range x.Order {
			item, exists := x.Fields[key]
			if !exists {
				continue
			}
			converted, ok, err := jsonataStringValue(st, item)
			if err != nil {
				return nil, false, err
			}
			if ok {
				out[key] = converted
			}
		}
		return orderedJSONMap{value: out, order: append([]string(nil), x.Order...)}, true, nil
	case nonFiniteNumber:
		return nil, false, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	case float64:
		return jsonataStringNumber(x), true, nil
	case float32:
		return jsonataStringNumber(float64(x)), true, nil
	case nil, bool, string, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, json.Number:
		return v, true, nil
	default:
		return nil, false, runtimeError{code: "T0412", msg: "argument to function $string is not JSON-compatible"}
	}
}

func stringRuntimeCheck(st state) error {
	if st.runtime == nil {
		return nil
	}
	return st.runtime.check()
}

func jsonataStringNumber(n float64) json.Number {
	return json.Number(formatJSONataNumber(n))
}

func builtinSubstring(st state, args []any) (any, error) {
	if len(args) < 2 || len(args) > 3 {
		return nil, functionArityError("$substring", 2, len(args))
	}
	text := collapse(args[0])
	if value.IsUndefined(text) {
		return value.Undefined, nil
	}
	s, _ := text.(string)
	start, _ := numeric(collapse(args[1]))
	if len(args) == 2 {
		return substringRunes(st, s, int(start), 0, false)
	}
	lengthArg := collapse(args[2])
	if value.IsUndefined(lengthArg) {
		return substringRunes(st, s, int(start), 0, false)
	}
	length, _ := numeric(lengthArg)
	return substringRunes(st, s, int(start), int(length), true)
}

func substringRunes(st state, s string, start, length int, hasLength bool) (string, error) {
	if hasLength && length <= 0 {
		return "", nil
	}
	if start >= 0 {
		startByte, err := runeOffset(st, s, start)
		if err != nil {
			return "", err
		}
		if startByte >= len(s) {
			return "", nil
		}
		if !hasLength {
			return s[startByte:], nil
		}
		lengthByte, err := runeOffset(st, s[startByte:], length)
		if err != nil {
			return "", err
		}
		return s[startByte : startByte+lengthByte], nil
	}
	total, err := runeCount(st, s)
	if err != nil {
		return "", err
	}
	if start < 0 {
		start += total
	}
	if start < 0 {
		start = 0
	}
	if start >= total {
		return "", nil
	}
	startByte, err := runeOffset(st, s, start)
	if err != nil {
		return "", err
	}
	if !hasLength {
		return s[startByte:], nil
	}
	end := total
	if length < total-start {
		end = start + length
	}
	endByte, err := runeOffset(st, s, end)
	if err != nil {
		return "", err
	}
	return s[startByte:endByte], nil
}

func runeOffset(st state, s string, runes int) (int, error) {
	if runes <= 0 {
		return 0, nil
	}
	offset := 0
	for count := 0; count < runes && offset < len(s); count++ {
		if err := stringRuntimeCheck(st); err != nil {
			return 0, err
		}
		_, size := utf8.DecodeRuneInString(s[offset:])
		offset += size
	}
	return offset, nil
}

func runeCount(st state, s string) (int, error) {
	count := 0
	for offset := 0; offset < len(s); count++ {
		if err := stringRuntimeCheck(st); err != nil {
			return 0, err
		}
		_, size := utf8.DecodeRuneInString(s[offset:])
		offset += size
	}
	return count, nil
}

func builtinSubstringBefore(_ state, args []any) (any, error) {
	if len(args) != 2 {
		return nil, functionArityError("$substringBefore", 2, len(args))
	}
	text := collapse(args[0])
	if value.IsUndefined(text) {
		return value.Undefined, nil
	}
	s, _ := text.(string)
	substr, _ := collapse(args[1]).(string)
	if index := strings.Index(s, substr); index >= 0 {
		return s[:index], nil
	}
	return s, nil
}

func builtinSubstringAfter(_ state, args []any) (any, error) {
	if len(args) != 2 {
		return nil, functionArityError("$substringAfter", 2, len(args))
	}
	text := collapse(args[0])
	if value.IsUndefined(text) {
		return value.Undefined, nil
	}
	s, _ := text.(string)
	substr, _ := collapse(args[1]).(string)
	if index := strings.Index(s, substr); index >= 0 {
		return s[index+len(substr):], nil
	}
	return s, nil
}

func builtinLowercase(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$lowercase", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	text, ok := collapse(args[0]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "argument to function $lowercase must be a string"}
	}
	return caseJSONataString(st, text, jsonataLowercase)
}

func builtinUppercase(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$uppercase", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	text, ok := collapse(args[0]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "argument to function $uppercase must be a string"}
	}
	return caseJSONataString(st, text, jsonataUppercase)
}

func caseJSONataString(st state, input string, caser cases.Caser) (string, error) {
	if !utf8.ValidString(input) {
		return "", stringRepresentationError("case-conversion input contains invalid UTF-8")
	}
	if err := stringWorkPreflight(st, stringWorkSize(len(input), 4)); err != nil {
		return "", err
	}
	for range input {
		if err := stringRuntimeCheck(st); err != nil {
			return "", err
		}
	}
	return caser.String(input), nil
}

func builtinPad(st state, args []any) (any, error) {
	if len(args) < 2 || len(args) > 3 {
		return nil, functionArityError("$pad", 2, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	s, _ := args[0].(string)
	widthValue, _ := numeric(args[1])
	if math.IsNaN(widthValue) || math.IsInf(widthValue, 0) {
		return nil, runtimeError{code: "T0410", msg: "padding width must be finite"}
	}
	maxInt := int(^uint(0) >> 1)
	if math.Abs(widthValue) >= float64(maxInt) {
		return nil, runtimeError{code: "U1001", msg: "padding width exceeds evaluation limits"}
	}
	width := int(math.Trunc(widthValue))
	chars := " "
	if len(args) == 3 && !value.IsUndefined(args[2]) {
		chars, _ = args[2].(string)
		if chars == "" {
			chars = " "
		}
	}
	padding := scalarAbsInt(width) - utf8.RuneCountInString(s)
	if padding <= 0 {
		return s, nil
	}
	const maxPadding = 1 << 20
	if padding > maxPadding {
		return nil, runtimeError{code: "U1001", msg: "padding width exceeds evaluation limits"}
	}
	// Padding materializes a character sequence. Honor the same per-evaluation
	// allocation bound as other sequence-producing expressions.
	if err := st.runtime.checkSequenceLength(padding); err != nil {
		return nil, err
	}
	for remaining := padding; remaining > 0; remaining-- {
		if err := stringRuntimeCheck(st); err != nil {
			return nil, err
		}
	}
	padded := strings.Repeat(chars, padding)
	paddedRunes := []rune(padded)
	if len(paddedRunes) > padding {
		padded = string(paddedRunes[:padding])
	}
	if width < 0 {
		return padded + s, nil
	}
	return s + padded, nil
}

func builtinTrim(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$trim", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	return trimJSONata(st, args[0].(string))
}

func trimJSONata(st state, input string) (string, error) {
	if !utf8.ValidString(input) {
		return "", stringRepresentationError("trim input contains invalid UTF-8")
	}
	if err := stringWorkPreflight(st, len(input)+1); err != nil {
		return "", err
	}
	var result strings.Builder
	result.Grow(len(input))
	inWhitespace := false
	for index := 0; index < len(input); index++ {
		if err := stringRuntimeCheck(st); err != nil {
			return "", err
		}
		whitespace := input[index] == ' ' || input[index] == '\t' || input[index] == '\n' || input[index] == '\r'
		if whitespace {
			if !inWhitespace {
				result.WriteByte(' ')
				inWhitespace = true
			}
			continue
		}
		result.WriteByte(input[index])
		inWhitespace = false
	}
	trimmed := result.String()
	if strings.HasPrefix(trimmed, " ") {
		trimmed = trimmed[1:]
	}
	if strings.HasSuffix(trimmed, " ") {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed, nil
}

func builtinBase64Encode(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$base64encode", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	return base64EncodeBinary(st, args[0].(string))
}

func builtinBase64Decode(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$base64decode", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	decoded, err := base64DecodeBinary(st, args[0].(string))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		var coded interface{ JSONataCode() string }
		if errors.As(err, &coded) && coded.JSONataCode() == "U1001" {
			return nil, err
		}
		return nil, runtimeError{code: "D3050", msg: err.Error(), cause: err}
	}
	return decoded, nil
}

func base64EncodeBinary(st state, input string) (string, error) {
	if !utf8.ValidString(input) {
		return "", stringRepresentationError("base64 input contains invalid UTF-8")
	}
	unitCount := 0
	for _, char := range input {
		if char > 0xffff {
			unitCount += 2
		} else {
			unitCount++
		}
	}
	if err := stringWorkPreflight(st, stringWorkSize(len(input)+unitCount, 2)); err != nil {
		return "", err
	}
	encoded := make([]byte, 0, unitCount)
	for _, char := range input {
		if err := stringRuntimeCheck(st); err != nil {
			return "", err
		}
		if char <= 0xffff {
			encoded = append(encoded, byte(char))
			continue
		}
		high, low := utf16.EncodeRune(char)
		encoded = append(encoded, byte(high), byte(low))
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func base64DecodeBinary(st state, input string) (string, error) {
	if !utf8.ValidString(input) {
		return "", stringRepresentationError("base64 input contains invalid UTF-8")
	}
	if err := stringWorkPreflight(st, stringWorkSize(len(input)+1, 3)); err != nil {
		return "", err
	}
	filtered := make([]byte, 0, len(input))
	for index := 0; index < len(input); index++ {
		if err := stringRuntimeCheck(st); err != nil {
			return "", err
		}
		char := input[index]
		switch {
		case char == '=':
			index = len(input)
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '+', char == '/':
			filtered = append(filtered, char)
		case char == '-':
			filtered = append(filtered, '+')
		case char == '_':
			filtered = append(filtered, '/')
		}
	}
	if remainder := len(filtered) % 4; remainder == 1 {
		filtered = filtered[:len(filtered)-1]
	}
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(filtered)))
	decodedLength, err := base64.RawStdEncoding.Decode(decoded, filtered)
	if err != nil {
		return "", err
	}
	decoded = decoded[:decodedLength]
	if err := stringWorkPreflight(st, stringWorkSize(len(decoded)+1, 2)); err != nil {
		return "", err
	}
	var result strings.Builder
	result.Grow(len(decoded) * 2)
	for _, byteValue := range decoded {
		if err := stringRuntimeCheck(st); err != nil {
			return "", err
		}
		result.WriteRune(rune(byteValue))
	}
	return result.String(), nil
}

func builtinEncodeURL(st state, args []any) (any, error) {
	return encodeURL(st, args, "encodeUrl")
}

func builtinDecodeURL(st state, args []any) (any, error) {
	return decodeURL(st, args, "decodeUrl")
}

func builtinEncodeURLComponent(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$encodeUrlComponent", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	s := args[0].(string)
	encoded, err := encodeURIValue(st, s, false)
	if err != nil {
		return nil, classifyURIError("encodeUrlComponent", s, err)
	}
	return encoded, nil
}

func encodeURLComponentValue(s string) string {
	encoded, _ := encodeURIValue(state{}, s, false)
	return encoded
}

func encodeURIValue(st state, input string, uri bool) (string, error) {
	if !utf8.ValidString(input) {
		return "", stringRepresentationError("URI input contains invalid UTF-8")
	}
	if err := stringWorkPreflight(st, stringWorkSize(len(input)+1, 3)); err != nil {
		return "", err
	}
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	encoded.Grow(stringWorkSize(len(input), 3))
	for _, char := range input {
		if err := stringRuntimeCheck(st); err != nil {
			return "", err
		}
		if isURIUnescaped(char, uri) {
			encoded.WriteRune(char)
			continue
		}
		if char <= 0x7f {
			encoded.WriteByte('%')
			encoded.WriteByte(hex[byte(char)>>4])
			encoded.WriteByte(hex[byte(char)&0x0f])
			continue
		}
		var bytes [utf8.UTFMax]byte
		count := utf8.EncodeRune(bytes[:], char)
		for index := 0; index < count; index++ {
			encoded.WriteByte('%')
			encoded.WriteByte(hex[bytes[index]>>4])
			encoded.WriteByte(hex[bytes[index]&0x0f])
		}
	}
	return encoded.String(), nil
}

func isURIUnescaped(char rune, uri bool) bool {
	if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
		return true
	}
	if strings.ContainsRune("-_.!~*'()", char) {
		return true
	}
	return uri && strings.ContainsRune(";/?:@&=+$,#", char)
}

func decodeURIValue(st state, input string, uri bool) (string, error) {
	if !utf8.ValidString(input) {
		return "", stringRepresentationError("URI input contains invalid UTF-8")
	}
	if err := stringWorkPreflight(st, stringWorkSize(len(input)+1, 2)); err != nil {
		return "", err
	}
	var decoded strings.Builder
	decoded.Grow(len(input))
	bytes := make([]byte, 0, len(input)/3+1)
	for index := 0; index < len(input); {
		if err := stringRuntimeCheck(st); err != nil {
			return "", err
		}
		if input[index] != '%' {
			decoded.WriteByte(input[index])
			index++
			continue
		}
		bytes = bytes[:0]
		for index < len(input) && input[index] == '%' {
			if err := stringRuntimeCheck(st); err != nil {
				return "", err
			}
			if index+2 >= len(input) {
				return "", fmt.Errorf("invalid percent escape")
			}
			high, okHigh := fromHex(input[index+1])
			low, okLow := fromHex(input[index+2])
			if !okHigh || !okLow {
				return "", fmt.Errorf("invalid percent escape")
			}
			byteValue := byte(high<<4 | low)
			if uri && isURIReservedByte(byteValue) {
				if len(bytes) > 0 {
					if err := appendDecodedUTF8(&decoded, bytes); err != nil {
						return "", err
					}
					bytes = nil
				}
				decoded.WriteString(input[index : index+3])
				index += 3
				continue
			}
			bytes = append(bytes, byteValue)
			index += 3
		}
		if err := appendDecodedUTF8(&decoded, bytes); err != nil {
			return "", err
		}
	}
	return decoded.String(), nil
}

func appendDecodedUTF8(output *strings.Builder, bytes []byte) error {
	if len(bytes) == 0 {
		return nil
	}
	if !utf8.Valid(bytes) {
		return fmt.Errorf("invalid UTF-8 escape sequence")
	}
	output.Write(bytes)
	return nil
}

func isURIReservedByte(value byte) bool {
	return strings.ContainsRune(";/?:@&=+$,#", rune(value))
}

func fromHex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func stringRepresentationError(message string) error {
	return runtimeError{code: "U1002", msg: message}
}

func builtinDecodeURLComponent(st state, args []any) (any, error) {
	return decodeURL(st, args, "decodeUrlComponent")
}

func encodeURL(st state, args []any, name string) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$"+name, 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	s := args[0].(string)
	encoded, err := encodeURIValue(st, s, name == "encodeUrl")
	if err != nil {
		return nil, classifyURIError(name, s, err)
	}
	return encoded, nil
}

func decodeURL(st state, args []any, name string) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$"+name, 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	decoded, err := decodeURIValue(st, args[0].(string), name == "decodeUrl")
	if err != nil {
		return nil, classifyURIError(name, args[0].(string), err)
	}
	return decoded, nil
}

func malformedURL(name, input string) error {
	return runtimeError{
		code: "D3140",
		msg:  fmt.Sprintf("Malformed URL passed to $%s(): %q", name, input),
	}
}

func classifyURIError(name, input string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var coded interface{ JSONataCode() string }
	if errors.As(err, &coded) && (coded.JSONataCode() == "U1001" || coded.JSONataCode() == "U1002") {
		return err
	}
	return malformedURL(name, input)
}

func stringWorkPreflight(st state, work int) error {
	if st.runtime == nil {
		return nil
	}
	if err := st.runtime.check(); err != nil {
		return err
	}
	if work < 0 || int64(work) > st.runtime.budget {
		return runtimeError{code: "U1001", msg: "string operation exceeds evaluation limits"}
	}
	return nil
}

func stringWorkSize(size, multiplier int) int {
	if size <= 0 || multiplier <= 0 {
		return 0
	}
	maximum := int(^uint(0) >> 1)
	if size > maximum/multiplier {
		return maximum
	}
	return size * multiplier
}
