package evaluator

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// EvalStaticFilterProjectBytes evaluates a decoded-input static plan after
// validating and decoding the complete JSON document. The raw scalar plans
// have a more direct representation and remain separate from this bridge.
func EvalStaticFilterProjectBytes(plan *StaticFilterProjectPlan, data []byte) ([]byte, bool) {
	if plan == nil {
		return nil, false
	}
	return evalStaticPlanBytes(data, func(input any) (any, bool) {
		return evalStaticFilterProjectValidated(plan, input)
	})
}

// EvalStaticSumBytes evaluates a decoded-input sum plan over a validated JSON
// document.
func EvalStaticSumBytes(plan *StaticSumPlan, data []byte) ([]byte, bool) {
	if plan == nil {
		return nil, false
	}
	return evalStaticPlanBytes(data, func(input any) (any, bool) {
		return evalStaticSumValidated(plan, input)
	})
}

// EvalStaticMapBytes evaluates a decoded-input map plan over a validated JSON
// document.
func EvalStaticMapBytes(plan *StaticMapPlan, data []byte) ([]byte, bool) {
	if plan == nil {
		return nil, false
	}
	return evalStaticPlanBytes(data, func(input any) (any, bool) {
		return evalStaticMapValidated(plan, input)
	})
}

// EvalStaticDescendantSumBytes evaluates a decoded-input descendant sum plan
// over a validated JSON document.
func EvalStaticDescendantSumBytes(plan *StaticDescendantSumPlan, data []byte) ([]byte, bool) {
	if plan == nil {
		return nil, false
	}
	return evalStaticPlanBytes(data, func(input any) (any, bool) {
		return evalStaticDescendantSumValidated(plan, input)
	})
}

type staticPlanEvaluator func(any) (any, bool)

func evalStaticPlanBytes(data []byte, evaluate staticPlanEvaluator) ([]byte, bool) {
	input, ok := decodeStaticPlanDocument(data)
	if !ok {
		return nil, false
	}
	result, ok := evaluate(input)
	if !ok {
		return nil, false
	}
	public, ok := value.Public(result)
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(public)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

func decodeStaticPlanDocument(data []byte) (any, bool) {
	if !scanStaticDocument(data) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return decoded, true
}

// scanStaticDocument validates syntax and the complete document before a
// static plan can observe any selected field. This retains the normal parser's
// invalid/trailing-input behavior and bounds work and nesting independently of
// the selected plan.
func scanStaticDocument(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	scanner := staticRawScanner{
		data:      data,
		remaining: staticPathMaxWork,
		maxDepth:  defaultMaxCallDepth,
	}
	_, _, valid := scanner.value(1, nil)
	if !valid || scanner.failed {
		return false
	}
	scanner.skipSpace()
	return scanner.pos == len(data)
}

// EvalStaticContainsBytes evaluates a static contains plan over a validated
// JSON document. The scanner validates the full document, not just the
// selected path, before attempting the regex shortcut.
func EvalStaticContainsBytes(plan *StaticContainsPlan, data []byte) (bool, bool) {
	if plan == nil || len(plan.path) == 0 {
		return false, false
	}
	scalar, ok := scanStaticScalar(data, plan.path, true, false)
	if !ok || scalar.kind != rawString {
		return false, false
	}
	if len(scalar.text)+staticPathMaxWork+64 > defaultMaxOperations {
		return false, false
	}
	matched, err := plan.pattern.MatchStringStatic(scalar.text)
	if err != nil {
		return false, false
	}
	return matched, true
}

// EvalStaticPathBytes evaluates a static scalar path directly from a JSON
// document. It returns ok=false for any input whose result cannot be proven to
// have the same semantics as the normal decoder. Callers must then use the
// complete evaluator. The scanner validates the complete document, including
// members unrelated to the selected path.
func EvalStaticPathBytes(plan *StaticPathPlan, data []byte) (result []byte, ok bool) {
	if plan == nil || len(plan.fields) == 0 {
		return nil, false
	}
	scalar, ok := scanStaticScalar(data, plan.fields, false, true)
	if !ok {
		return nil, false
	}
	return scalar.json, true
}

// EvalStaticComparisonBytes evaluates the narrow scalar comparison plan on a
// raw JSON document. Missing, null, container, invalid, and ambiguous values
// all fall back to the complete evaluator so its sequence and error rules
// remain authoritative.
func EvalStaticComparisonBytes(plan *StaticComparisonPlan, data []byte) (result []byte, ok bool) {
	if plan == nil || len(plan.path) == 0 {
		return nil, false
	}
	scalar, ok := scanStaticScalar(data, plan.path, true, false)
	if !ok || scalar.kind == rawNull {
		return nil, false
	}
	if !rawScalarMatches(scalar, plan.literal) {
		return nil, false
	}
	matched := rawScalarEqual(scalar, plan.literal)
	if plan.operator == "!=" {
		matched = !matched
	}
	if matched {
		return []byte("true"), true
	}
	return []byte("false"), true
}

type rawScalarKind uint8

const (
	rawNull rawScalarKind = iota
	rawString
	rawNumber
	rawBoolean
)

type rawScalar struct {
	kind    rawScalarKind
	text    string
	number  float64
	boolean bool
	json    []byte
}

func scanStaticScalar(data []byte, fields []string, needText, needJSON bool) (rawScalar, bool) {
	if len(data) == 0 || len(fields) == 0 {
		return rawScalar{}, false
	}
	scanner := staticRawScanner{
		data:      data,
		remaining: defaultMaxOperations,
		maxDepth:  defaultMaxCallDepth,
		needText:  needText,
		needJSON:  needJSON,
	}
	scalar, ok, valid := scanner.value(1, fields)
	if !ok || !valid || scanner.failed {
		return rawScalar{}, false
	}
	scanner.skipSpace()
	if scanner.pos != len(data) {
		return rawScalar{}, false
	}
	return scalar, true
}

// staticRawScanner is intentionally a validator as well as a selector. A
// shortcut that only scans the selected branch would change error behavior for
// malformed or excessively deep unrelated branches.
type staticRawScanner struct {
	data      []byte
	pos       int
	remaining int64
	maxDepth  int
	needText  bool
	needJSON  bool
	failed    bool
}

func (s *staticRawScanner) value(depth int, fields []string) (rawScalar, bool, bool) {
	if !s.step() || s.maxDepth > 0 && depth > s.maxDepth {
		s.failed = true
		return rawScalar{}, false, false
	}
	s.skipSpace()
	if s.pos >= len(s.data) {
		return rawScalar{}, false, false
	}
	switch s.data[s.pos] {
	case '{':
		return s.object(depth, fields)
	case '[':
		return rawScalar{}, false, s.array(depth)
	case '"':
		raw, ok := s.string()
		if !ok {
			return rawScalar{}, false, false
		}
		if fields == nil || len(fields) != 0 {
			return rawScalar{}, false, true
		}
		if s.needJSON {
			if encoded, ok := canonicalRawString(raw); ok {
				var text string
				if s.needText {
					text = string(raw[1 : len(raw)-1])
				}
				return rawScalar{kind: rawString, text: text, json: encoded}, true, true
			}
		} else if rawStringIsSafeASCII(raw) {
			return rawScalar{kind: rawString, text: string(raw[1 : len(raw)-1])}, true, true
		}
		var decoded string
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return rawScalar{}, false, false
		}
		var encoded []byte
		if s.needJSON {
			var err error
			encoded, err = json.Marshal(decoded)
			if err != nil {
				return rawScalar{}, false, false
			}
		}
		return rawScalar{kind: rawString, text: decoded, json: encoded}, true, true
	case 't':
		if !s.literal("true") {
			return rawScalar{}, false, false
		}
		if fields == nil || len(fields) != 0 {
			return rawScalar{}, false, true
		}
		var encoded []byte
		if s.needJSON {
			encoded = []byte("true")
		}
		return rawScalar{kind: rawBoolean, boolean: true, json: encoded}, true, true
	case 'f':
		if !s.literal("false") {
			return rawScalar{}, false, false
		}
		if fields == nil || len(fields) != 0 {
			return rawScalar{}, false, true
		}
		var encoded []byte
		if s.needJSON {
			encoded = []byte("false")
		}
		return rawScalar{kind: rawBoolean, json: encoded}, true, true
	case 'n':
		if !s.literal("null") {
			return rawScalar{}, false, false
		}
		if fields == nil || len(fields) != 0 {
			return rawScalar{}, false, true
		}
		var encoded []byte
		if s.needJSON {
			encoded = []byte("null")
		}
		return rawScalar{kind: rawNull, json: encoded}, true, true
	default:
		if s.data[s.pos] == '-' || s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			raw, ok := s.number()
			if !ok {
				return rawScalar{}, false, false
			}
			if fields == nil || len(fields) != 0 {
				return rawScalar{}, false, true
			}
			number, err := strconv.ParseFloat(string(raw), 64)
			if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
				return rawScalar{}, false, false
			}
			var encoded []byte
			if s.needJSON {
				encoded = appendJSONFloat(nil, number)
			}
			return rawScalar{kind: rawNumber, number: number, json: encoded}, true, true
		}
		return rawScalar{}, false, false
	}
}

func (s *staticRawScanner) object(depth int, fields []string) (rawScalar, bool, bool) {
	s.pos++ // '{'
	s.skipSpace()
	var selected rawScalar
	selectedOK := false
	if s.consume('}') {
		return selected, selectedOK, true
	}
	for {
		if !s.step() {
			return rawScalar{}, false, false
		}
		s.skipSpace()
		keyRaw, ok := s.string()
		if !ok {
			return rawScalar{}, false, false
		}
		s.skipSpace()
		if !s.consume(':') {
			return rawScalar{}, false, false
		}
		s.skipSpace()
		keyMatches := false
		if len(fields) != 0 {
			keyMatches = rawJSONStringEquals(keyRaw, fields[0])
		}
		candidate, candidateOK, valid := s.value(depth+1, fieldsAfterMatch(fields, keyMatches))
		if !valid || s.failed {
			return rawScalar{}, false, false
		}
		if keyMatches {
			// Assignment is important: JSON object duplicate keys retain the
			// value from the last occurrence, including a later container or
			// missing nested field.
			selected, selectedOK = candidate, candidateOK
		}
		s.skipSpace()
		if s.consume('}') {
			return selected, selectedOK, true
		}
		if !s.consume(',') {
			return rawScalar{}, false, false
		}
		s.skipSpace()
	}
}

func fieldsAfterMatch(fields []string, match bool) []string {
	if !match {
		return nil
	}
	return fields[1:]
}

func (s *staticRawScanner) array(depth int) bool {
	s.pos++ // '['
	s.skipSpace()
	if s.consume(']') {
		return true
	}
	for {
		_, _, valid := s.value(depth+1, nil)
		if !valid || s.failed {
			return false
		}
		s.skipSpace()
		if s.consume(']') {
			return true
		}
		if !s.consume(',') {
			return false
		}
		s.skipSpace()
	}
}

func (s *staticRawScanner) string() ([]byte, bool) {
	if s.pos >= len(s.data) || s.data[s.pos] != '"' {
		return nil, false
	}
	start := s.pos
	s.pos++
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case '"':
			s.pos++
			return s.data[start:s.pos], true
		case '\\':
			s.pos++
			if s.pos >= len(s.data) {
				return nil, false
			}
			switch s.data[s.pos] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.pos++
			case 'u':
				if s.pos+4 >= len(s.data) {
					return nil, false
				}
				for index := s.pos + 1; index <= s.pos+4; index++ {
					if !isHexDigit(s.data[index]) {
						return nil, false
					}
				}
				s.pos += 5
			default:
				return nil, false
			}
		default:
			if s.data[s.pos] < 0x20 {
				return nil, false
			}
			s.pos++
		}
	}
	return nil, false
}

func isHexDigit(char byte) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F'
}

func (s *staticRawScanner) number() ([]byte, bool) {
	start := s.pos
	if s.data[s.pos] == '-' {
		s.pos++
		if s.pos >= len(s.data) {
			return nil, false
		}
	}
	if s.data[s.pos] == '0' {
		s.pos++
	} else {
		if s.data[s.pos] < '1' || s.data[s.pos] > '9' {
			return nil, false
		}
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			s.pos++
		}
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		fraction := s.pos
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			s.pos++
		}
		if fraction == s.pos {
			return nil, false
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		exponent := s.pos
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			s.pos++
		}
		if exponent == s.pos {
			return nil, false
		}
	}
	return s.data[start:s.pos], true
}

func (s *staticRawScanner) literal(literal string) bool {
	if len(s.data)-s.pos < len(literal) {
		return false
	}
	for index := range literal {
		if s.data[s.pos+index] != literal[index] {
			return false
		}
	}
	s.pos += len(literal)
	return true
}

func (s *staticRawScanner) step() bool {
	if s.remaining <= 0 {
		s.failed = true
		return false
	}
	s.remaining--
	return true
}

func (s *staticRawScanner) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\r', '\n':
			s.pos++
		default:
			return
		}
	}
}

func (s *staticRawScanner) consume(expected byte) bool {
	if s.pos >= len(s.data) || s.data[s.pos] != expected {
		return false
	}
	s.pos++
	return true
}

func rawJSONStringEquals(raw []byte, want string) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	if bytes.IndexByte(raw[1:len(raw)-1], '\\') < 0 {
		content := raw[1 : len(raw)-1]
		for _, char := range content {
			if char >= 0x80 {
				var decoded string
				return json.Unmarshal(raw, &decoded) == nil && decoded == want
			}
		}
		if len(content) != len(want) {
			return false
		}
		for index, char := range content {
			if char != want[index] {
				return false
			}
		}
		return true
	}
	var decoded string
	return json.Unmarshal(raw, &decoded) == nil && decoded == want
}

// canonicalRawString returns the same JSON string encoding as json.Marshal
// for the common case where the input contains only safe ASCII. The copy is
// intentional: callers may retain the result after the input buffer changes.
// Strings with escapes or non-ASCII bytes use encoding/json, which preserves
// its replacement and HTML-escaping rules for all edge cases.
func canonicalRawString(raw []byte) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	content := raw[1 : len(raw)-1]
	htmlEscapes := 0
	for _, char := range content {
		if char >= 0x80 || char == '\\' || char == '"' || char < 0x20 {
			return nil, false
		}
		switch char {
		case '<', '>', '&':
			htmlEscapes++
		}
	}
	if htmlEscapes == 0 {
		return append([]byte(nil), raw...), true
	}
	encoded := make([]byte, 0, len(raw)+htmlEscapes*5)
	encoded = append(encoded, '"')
	for _, char := range content {
		switch char {
		case '<':
			encoded = append(encoded, '\\', 'u', '0', '0', '3', 'c')
		case '>':
			encoded = append(encoded, '\\', 'u', '0', '0', '3', 'e')
		case '&':
			encoded = append(encoded, '\\', 'u', '0', '0', '2', '6')
		default:
			encoded = append(encoded, char)
		}
	}
	return append(encoded, '"'), true
}

func rawStringIsSafeASCII(raw []byte) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	for _, char := range raw[1 : len(raw)-1] {
		if char >= 0x80 || char == '\\' || char == '"' || char < 0x20 {
			return false
		}
	}
	return true
}

// appendJSONFloat mirrors encoding/json's float64 encoder. In particular,
// JSON uses fixed notation below 1e21 and at least 1e-6, and removes the zero
// from negative exponents. Using strconv.AppendFloat avoids the temporary
// interface and encoder state allocated by json.Marshal.
func appendJSONFloat(dst []byte, number float64) []byte {
	abs := math.Abs(number)
	format := byte('f')
	if abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		format = 'e'
	}
	dst = strconv.AppendFloat(dst, number, format, -1, 64)
	if format == 'e' {
		last := len(dst)
		if last >= 4 && dst[last-4] == 'e' && dst[last-3] == '-' && dst[last-2] == '0' {
			dst[last-2] = dst[last-1]
			dst = dst[:last-1]
		}
	}
	return dst
}

func rawScalarMatches(scalar rawScalar, literal any) bool {
	if literal == nil {
		return false
	}
	switch literal.(type) {
	case string:
		return scalar.kind == rawString
	case bool:
		return scalar.kind == rawBoolean
	}
	_, ok := numeric(literal)
	return ok && scalar.kind == rawNumber
}

func rawScalarEqual(scalar rawScalar, literal any) bool {
	switch expected := literal.(type) {
	case string:
		return scalar.text == expected
	case bool:
		return scalar.boolean == expected
	default:
		number, ok := numeric(literal)
		return ok && scalar.kind == rawNumber && scalar.number == number
	}
}
