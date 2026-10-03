package asl

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"unicode/utf8"
)

type intrinsicCall struct {
	name string
	args []intrinsicArgument
}
type intrinsicArgument struct {
	literal       any
	format        string
	stringLiteral bool
	path          *Path
	call          *intrinsicCall
}
type intrinsicParser struct {
	source string
	pos    int
	count  int
}

var intrinsicArity = map[string][2]int{
	"Format": {1, -1}, "StringToJson": {1, 1}, "JsonToString": {1, 1},
	"Array": {0, -1}, "ArrayPartition": {2, 2}, "ArrayContains": {2, 2},
	"ArrayRange": {3, 3}, "ArrayGetItem": {2, 2}, "ArrayLength": {1, 1}, "ArrayUnique": {1, 1},
	"Base64Encode": {1, 1}, "Base64Decode": {1, 1}, "Hash": {2, 2}, "JsonMerge": {3, 3},
	"MathRandom": {2, 3}, "MathAdd": {2, 2}, "StringSplit": {2, 2}, "UUID": {0, 0},
}

func compileIntrinsic(source string) (*intrinsicCall, error) {
	parser := intrinsicParser{source: source}
	call, err := parser.parseCall()
	if err != nil {
		return nil, err
	}
	parser.space()
	if parser.pos != len(source) {
		return nil, fmt.Errorf("unexpected intrinsic suffix at offset %d", parser.pos)
	}
	return call, nil
}

func (p *intrinsicParser) space() {
	for p.pos < len(p.source) && strings.ContainsRune(" \t\r\n", rune(p.source[p.pos])) {
		p.pos++
	}
}

func (p *intrinsicParser) parseCall() (*intrinsicCall, error) {
	p.count++
	if p.count > 10 {
		return nil, fmt.Errorf("a field may contain at most 10 intrinsic function calls")
	}
	start := p.pos
	for p.pos < len(p.source) {
		c := p.source[p.pos]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_') {
			break
		}
		p.pos++
	}
	name := p.source[start:p.pos]
	short := strings.TrimPrefix(name, "States.")
	arity, exists := intrinsicArity[short]
	if !exists || name == short {
		return nil, fmt.Errorf("unknown intrinsic %q", name)
	}
	if p.pos == len(p.source) || p.source[p.pos] != '(' {
		return nil, fmt.Errorf("intrinsic name must be followed by (")
	}
	p.pos++
	call := &intrinsicCall{name: short}
	p.space()
	if p.pos < len(p.source) && p.source[p.pos] != ')' {
		for {
			arg, err := p.parseArgument()
			if err != nil {
				return nil, err
			}
			call.args = append(call.args, arg)
			p.space()
			if p.pos == len(p.source) || p.source[p.pos] != ',' {
				break
			}
			p.pos++
			p.space()
		}
	}
	if p.pos == len(p.source) || p.source[p.pos] != ')' {
		return nil, fmt.Errorf("unterminated intrinsic %s", name)
	}
	p.pos++
	if len(call.args) < arity[0] || arity[1] >= 0 && len(call.args) > arity[1] {
		return nil, fmt.Errorf("invalid argument count for %s: %d", name, len(call.args))
	}
	return call, nil
}

func (p *intrinsicParser) parseArgument() (intrinsicArgument, error) {
	p.space()
	arg := intrinsicArgument{}
	if p.pos == len(p.source) {
		return arg, fmt.Errorf("missing intrinsic argument")
	}
	if strings.HasPrefix(p.source[p.pos:], "States.") {
		var err error
		arg.call, err = p.parseCall()
		return arg, err
	}
	if p.source[p.pos] == '\'' {
		p.pos++
		var literal, format strings.Builder
		for p.pos < len(p.source) {
			c := p.source[p.pos]
			p.pos++
			if c == '\'' {
				arg.literal, arg.format, arg.stringLiteral = literal.String(), format.String(), true
				return arg, nil
			}
			if c == '\\' {
				if p.pos == len(p.source) {
					return arg, fmt.Errorf("unfinished intrinsic escape")
				}
				c = p.source[p.pos]
				p.pos++
				if !strings.ContainsRune("'{}\\", rune(c)) {
					return arg, fmt.Errorf("invalid intrinsic escape \\%c", c)
				}
				literal.WriteByte(c)
				if c != '\'' {
					format.WriteByte('\\')
				}
				format.WriteByte(c)
			} else {
				literal.WriteByte(c)
				format.WriteByte(c)
			}
		}
		return arg, fmt.Errorf("unterminated intrinsic string")
	}
	start, depth, quote := p.pos, 0, byte(0)
	for p.pos < len(p.source) {
		c := p.source[p.pos]
		if quote != 0 {
			p.pos++
			if c == '\\' {
				if p.pos < len(p.source) {
					p.pos++
				}
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\\' {
			p.pos += 2
			if p.pos > len(p.source) {
				return arg, fmt.Errorf("unfinished path escape")
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			p.pos++
			continue
		}
		if c == '[' || c == '(' {
			depth++
		}
		if c == ']' {
			depth--
		}
		if c == ')' {
			if depth == 0 {
				break
			}
			depth--
		}
		if c == ',' && depth == 0 {
			break
		}
		p.pos++
	}
	text := strings.TrimSpace(p.source[start:p.pos])
	if strings.HasPrefix(text, "$") {
		var err error
		arg.path, err = CompilePath(text, false)
		return arg, err
	}
	if text == "null" {
		return arg, nil
	}
	if text == "true" || text == "false" {
		arg.literal = text == "true"
		return arg, nil
	}
	if !json.Valid([]byte(text)) {
		return arg, fmt.Errorf("invalid intrinsic argument %q", text)
	}
	number, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
		return arg, fmt.Errorf("invalid numeric intrinsic argument %q", text)
	}
	arg.literal = number
	return arg, nil
}

func (call *intrinsicCall) references() []string {
	var refs []string
	for _, arg := range call.args {
		if arg.path != nil {
			refs = append(refs, arg.path.References()...)
		}
		if arg.call != nil {
			refs = append(refs, arg.call.references()...)
		}
	}
	return uniqueReferences(refs)
}

func (call *intrinsicCall) evaluate(ctx context.Context, env Environment) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	args := make([]any, len(call.args))
	for i, arg := range call.args {
		var err error
		switch {
		case arg.call != nil:
			args[i], err = arg.call.evaluate(ctx, env)
		case arg.path != nil:
			var found bool
			args[i], found, err = arg.path.Lookup(env)
			if err == nil && !found {
				err = fmt.Errorf("path %q does not exist", arg.path.source)
			}
		default:
			args[i] = arg.literal
		}
		if err != nil {
			return nil, err
		}
	}
	if call.name == "Format" && call.args[0].stringLiteral {
		args[0] = call.args[0].format
	}
	return evaluateIntrinsic(call.name, args, env)
}

func evaluateIntrinsic(name string, args []any, env Environment) (any, error) {
	bad := func() (any, error) { return nil, fmt.Errorf("invalid arguments to States.%s", name) }
	switch name {
	case "Array":
		return args, nil
	case "Format":
		format, ok := args[0].(string)
		if !ok {
			return bad()
		}
		return intrinsicFormat(format, args[1:])
	case "StringToJson":
		text, ok := args[0].(string)
		if !ok {
			return bad()
		}
		return parseJSON(text)
	case "JsonToString":
		return jsonString(args[0])
	case "ArrayPartition":
		array, ok := args[0].([]any)
		if !ok {
			return bad()
		}
		size, ok := intrinsicInteger(args[1], false)
		if !ok || size <= 0 {
			return bad()
		}
		return partitionArray(array, size), nil
	case "ArrayContains":
		array, ok := args[0].([]any)
		if !ok {
			return bad()
		}
		for _, item := range array {
			if jsonEqual(item, args[1]) {
				return true, nil
			}
		}
		return false, nil
	case "ArrayRange":
		start, ok1 := intrinsicInteger(args[0], false)
		end, ok2 := intrinsicInteger(args[1], false)
		step, ok3 := intrinsicInteger(args[2], false)
		if !ok1 || !ok2 || !ok3 {
			return bad()
		}
		return numberRange(start, end, step)
	case "ArrayGetItem":
		array, ok := args[0].([]any)
		if !ok {
			return bad()
		}
		index, ok := numberValue(args[1])
		if !ok || math.Trunc(index) != index || index < 0 || index >= float64(len(array)) {
			return bad()
		}
		return array[int(index)], nil
	case "ArrayLength":
		array, ok := args[0].([]any)
		if !ok {
			return bad()
		}
		return float64(len(array)), nil
	case "ArrayUnique":
		array, ok := args[0].([]any)
		if !ok {
			return bad()
		}
		result := make([]any, 0, len(array))
		seen := make(map[string]bool, len(array))
		for _, item := range array {
			key, err := jsonString(item)
			if err != nil {
				return nil, err
			}
			if !seen[key] {
				seen[key] = true
				result = append(result, item)
			}
		}
		return result, nil
	case "Base64Encode", "Base64Decode":
		text, ok := args[0].(string)
		if !ok || utf8.RuneCountInString(text) > 10000 {
			return bad()
		}
		if name == "Base64Encode" {
			return base64.StdEncoding.EncodeToString([]byte(text)), nil
		}
		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, err
		}
		return strings.ToValidUTF8(string(decoded), "\ufffd"), nil
	case "Hash":
		algorithm, ok := args[1].(string)
		if !ok {
			return bad()
		}
		text, err := intrinsicString(args[0])
		if err != nil {
			return nil, err
		}
		if utf8.RuneCountInString(text) > 10000 {
			return bad()
		}
		return hashString(text, algorithm)
	case "JsonMerge":
		first, ok1 := args[0].(map[string]any)
		second, ok2 := args[1].(map[string]any)
		deep, ok3 := args[2].(bool)
		if !ok1 || !ok2 || !ok3 || deep {
			return bad()
		}
		merged := make(map[string]any, len(first)+len(second))
		for k, v := range first {
			merged[k] = v
		}
		for k, v := range second {
			merged[k] = v
		}
		return merged, nil
	case "MathAdd":
		a, ok1 := intrinsicInteger(args[0], false)
		b, ok2 := intrinsicInteger(args[1], false)
		if !ok1 || !ok2 || a+b < math.MinInt32 || a+b > math.MaxInt32 {
			return bad()
		}
		return float64(a + b), nil
	case "MathRandom":
		start, ok1 := intrinsicInteger(args[0], false)
		end, ok2 := intrinsicInteger(args[1], false)
		if !ok1 || !ok2 || end <= start {
			return bad()
		}
		if len(args) == 3 {
			seed, ok := seedValue(args[2])
			if !ok {
				return bad()
			}
			return float64(start + seededRandom(seed).Int64N(end-start)), nil
		}
		random, err := randomBelow(env.Random, uint64(end-start))
		if err != nil {
			return nil, err
		}
		return float64(start + int64(random)), nil
	case "StringSplit":
		text, ok1 := args[0].(string)
		delimiters, ok2 := args[1].(string)
		if !ok1 || !ok2 {
			return bad()
		}
		pieces := strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune(delimiters, r) })
		result := make([]any, len(pieces))
		for i, piece := range pieces {
			result[i] = piece
		}
		return result, nil
	case "UUID":
		return randomUUID(env.Random)
	default:
		return nil, fmt.Errorf("unknown intrinsic States.%s", name)
	}
}

func numberValue(value any) (float64, bool) {
	var n float64
	switch v := value.(type) {
	case float64:
		n = v
	case float32:
		n = float64(v)
	case int:
		n = float64(v)
	case int32:
		n = float64(v)
	case int64:
		n = float64(v)
	case uint64:
		n = float64(v)
	case json.Number:
		var err error
		n, err = v.Float64()
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return n, !math.IsNaN(n) && !math.IsInf(n, 0)
}

func seededRandom(seed int64) *rand.Rand {
	return rand.New(rand.NewPCG(uint64(seed), 0))
}

func intrinsicInteger(value any, floor bool) (int64, bool) {
	n, ok := numberValue(value)
	if !ok {
		return 0, false
	}
	if floor {
		n = math.Floor(n)
	} else {
		n = math.Floor(n + 0.5)
	}
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, false
	}
	return int64(n), true
}

func seedValue(value any) (int64, bool) {
	n, ok := numberValue(value)
	if !ok || n < math.MinInt64 || n >= math.MaxInt64 {
		return 0, false
	}
	return int64(math.Floor(n)), true
}

func partitionArray(array []any, size int64) []any {
	result := make([]any, 0, (int64(len(array))+size-1)/size)
	for start := int64(0); start < int64(len(array)); start += size {
		end := min(start+size, int64(len(array)))
		result = append(result, array[start:end])
	}
	return result
}

func numberRange(start, end, step int64) ([]any, error) {
	if step == 0 {
		return nil, fmt.Errorf("range increment must not be zero")
	}
	count := int64(0)
	if step > 0 && start <= end || step < 0 && start >= end {
		count = (end-start)/step + 1
	}
	if count > 1000 {
		return nil, fmt.Errorf("range must not contain more than 1000 elements")
	}
	result := make([]any, int(count))
	for i := range result {
		result[i] = float64(start + int64(i)*step)
	}
	return result, nil
}

func intrinsicFormat(format string, args []any) (string, error) {
	var out strings.Builder
	arg := 0
	for i := 0; i < len(format); i++ {
		switch format[i] {
		case '\\':
			i++
			if i == len(format) || !strings.ContainsRune("'{}\\", rune(format[i])) {
				return "", fmt.Errorf("invalid Format escape")
			}
			out.WriteByte(format[i])
		case '{':
			if i+1 == len(format) || format[i+1] != '}' || arg == len(args) {
				return "", fmt.Errorf("format placeholders do not match arguments")
			}
			text, err := intrinsicString(args[arg])
			if err != nil {
				return "", err
			}
			out.WriteString(text)
			arg++
			i++
		case '}':
			return "", fmt.Errorf("unescaped closing brace in Format")
		default:
			out.WriteByte(format[i])
		}
	}
	if arg != len(args) {
		return "", fmt.Errorf("format placeholders do not match arguments")
	}
	return out.String(), nil
}

func parseJSON(text string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(text))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected one JSON value")
	}
	return value, nil
}

func jsonString(value any) (string, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func intrinsicString(value any) (string, error) {
	if text, ok := value.(string); ok {
		return text, nil
	}
	return jsonString(value)
}

func jsonEqual(a, b any) bool {
	if x, ok := numberValue(a); ok {
		y, ok := numberValue(b)
		return ok && x == y
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

func hashString(text, algorithm string) (string, error) {
	data := []byte(text)
	switch algorithm {
	case "MD5":
		sum := md5.Sum(data)
		return hex.EncodeToString(sum[:]), nil
	case "SHA-1":
		sum := sha1.Sum(data)
		return hex.EncodeToString(sum[:]), nil
	case "SHA-256":
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	case "SHA-384":
		sum := sha512.Sum384(data)
		return hex.EncodeToString(sum[:]), nil
	case "SHA-512":
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm %q", algorithm)
	}
}

func randomBelow(reader io.Reader, limit uint64) (uint64, error) {
	if reader == nil {
		return 0, fmt.Errorf("evaluation random source is unavailable")
	}
	// Rejection avoids modulo bias for non-power-of-two bounds.
	threshold := -limit % limit
	var bytes [8]byte
	for {
		if _, err := io.ReadFull(reader, bytes[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint64(bytes[:])
		if n >= threshold {
			return n % limit, nil
		}
	}
}

func randomUnit(reader io.Reader) (float64, error) {
	if reader == nil {
		return 0, fmt.Errorf("evaluation random source is unavailable")
	}
	var bytes [8]byte
	if _, err := io.ReadFull(reader, bytes[:]); err != nil {
		return 0, err
	}
	return float64(binary.BigEndian.Uint64(bytes[:])>>11) / (1 << 53), nil
}

func randomUUID(reader io.Reader) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("evaluation random source is unavailable")
	}
	var uuid [16]byte
	if _, err := io.ReadFull(reader, uuid[:]); err != nil {
		return "", err
	}
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}
