package rdsdata

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/rdsdata"
)

type boundStatement struct {
	sql            string
	args           []any
	rows, mutation bool
}
type parameter struct {
	value any
	cast  string
}

// bindSQL only translates lexical parameter tokens to driver bind slots. It
// never interpolates values or evaluates SQL. The native engine parses and runs
// the original statement; casts are fixed type annotations on bind slots only.
func bindSQL(text, engine string, parameters api.SqlParametersList) (boundStatement, error) {
	pg := engine == "aurora-postgresql"
	values := make(map[string]parameter, len(parameters))
	for _, p := range parameters {
		name := value(p.Name)
		if name == "" {
			return boundStatement{}, failure("BadRequestException", "Every parameter must have a name.")
		}
		if _, exists := values[name]; exists {
			return boundStatement{}, failure("BadRequestException", "Duplicate parameter name.")
		}
		v, err := parameterValue(p, pg)
		if err != nil {
			return boundStatement{}, err
		}
		values[name] = v
	}
	var out strings.Builder
	out.Grow(len(text))
	args := make([]any, 0, len(parameters))
	used := map[string]int{}
	tokens := []string{}
	depth := 0
	statementDepth := 0
	terminated := false
	hasSQL := false
	for i := 0; i < len(text); {
		start := i
		c := text[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			out.WriteByte(c)
			i++
			continue
		}
		lineComment := c == '-' && i+1 < len(text) && text[i+1] == '-' && (pg || i+2 == len(text) || text[i+2] <= ' ')
		if lineComment || (!pg && c == '#') {
			for i < len(text) && text[i] != '\n' {
				i++
			}
			out.WriteString(text[start:i])
			continue
		}
		if c == '/' && i+1 < len(text) && text[i+1] == '*' {
			if !pg && i+2 < len(text) && text[i+2] == '!' {
				return boundStatement{}, failure("BadRequestException", "Executable MySQL comments are not supported.")
			}
			i += 2
			nesting := 1
			for i < len(text) && nesting > 0 {
				if pg && i+1 < len(text) && text[i:i+2] == "/*" {
					nesting++
					i += 2
				} else if i+1 < len(text) && text[i:i+2] == "*/" {
					nesting--
					i += 2
				} else {
					i++
				}
			}
			if nesting != 0 {
				return boundStatement{}, failure("BadRequestException", "Unterminated SQL comment.")
			}
			out.WriteString(text[start:i])
			continue
		}
		if terminated {
			return boundStatement{}, failure("BadRequestException", "Multi-statements are not supported.")
		}
		if c == ';' {
			terminated = true
			out.WriteByte(c)
			i++
			continue
		}
		hasSQL = true
		if c == '\'' || c == '"' || (!pg && c == '`') {
			escape := !pg || (c == '\'' && i > 0 && (text[i-1] == 'E' || text[i-1] == 'e') && (i < 2 || !identifier(text[i-2])))
			i++
			closed := false
			for i < len(text) {
				if escape && text[i] == '\\' {
					i += 2
					if i > len(text) {
						i = len(text)
					}
					continue
				}
				if text[i] == c {
					i++
					if i < len(text) && text[i] == c {
						i++
						continue
					}
					closed = true
					break
				}
				i++
			}
			if !closed {
				return boundStatement{}, failure("BadRequestException", "Unterminated SQL quoted value.")
			}
			out.WriteString(text[start:i])
			continue
		}
		if pg && c == '$' && (i == 0 || !identifier(text[i-1])) {
			end := i + 1
			if end < len(text) && nameStart(text[end]) {
				end++
				for end < len(text) && identifier(text[end]) && text[end] != '$' {
					end++
				}
			}
			if end < len(text) && text[end] == '$' {
				delimiter := text[i : end+1]
				closeAt := strings.Index(text[end+1:], delimiter)
				if closeAt < 0 {
					return boundStatement{}, failure("BadRequestException", "Unterminated SQL dollar quote.")
				}
				i = end + 1 + closeAt + len(delimiter)
				out.WriteString(text[start:i])
				continue
			}
			if end < len(text) && text[end] >= '0' && text[end] <= '9' {
				return boundStatement{}, failure("BadRequestException", "Use named Data API parameters, not native positional parameters.")
			}
		}
		if !pg && c == '?' {
			return boundStatement{}, failure("BadRequestException", "Use named Data API parameters, not native positional parameters.")
		}
		if c == ':' && i+1 < len(text) && text[i+1] == ':' {
			out.WriteString("::")
			i += 2
			continue
		}
		if c == ':' && i+1 < len(text) && nameStart(text[i+1]) {
			i += 2
			for i < len(text) && (nameStart(text[i]) || text[i] >= '0' && text[i] <= '9') {
				i++
			}
			name := text[start+1 : i]
			v, exists := values[name]
			if !exists {
				return boundStatement{}, failure("BadRequestException", "A SQL parameter has no supplied value: "+name)
			}
			slot, exists := used[name]
			if !exists || !pg {
				args = append(args, v.value)
				slot = len(args)
				used[name] = slot
			}
			placeholder := "?"
			if pg {
				placeholder = "$" + strconv.Itoa(slot)
			}
			if v.cast != "" {
				out.WriteString("CAST(")
				out.WriteString(placeholder)
				out.WriteString(" AS ")
				out.WriteString(v.cast)
				out.WriteByte(')')
			} else {
				out.WriteString(placeholder)
			}
			continue
		}
		if nameStart(c) {
			i++
			for i < len(text) && identifier(text[i]) {
				i++
			}
			if len(tokens) == 0 {
				statementDepth = depth
			}
			if depth <= statementDepth {
				tokens = append(tokens, strings.ToUpper(text[start:i]))
			}
			out.WriteString(text[start:i])
			continue
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
		}
		out.WriteByte(c)
		i++
	}
	if !hasSQL {
		return boundStatement{}, failure("BadRequestException", "SQL must not be empty.")
	}
	for name := range values {
		if _, ok := used[name]; !ok {
			return boundStatement{}, failure("BadRequestException", "A supplied parameter is not used by the SQL statement: "+name)
		}
	}
	first := ""
	if len(tokens) > 0 {
		first = tokens[0]
	}
	if first == "WITH" {
		for _, token := range tokens[1:] {
			if token == "SELECT" || token == "VALUES" || token == "TABLE" || token == "INSERT" || token == "UPDATE" || token == "DELETE" || token == "MERGE" {
				first = token
				break
			}
		}
	}
	switch first {
	case "BEGIN", "START", "COMMIT", "ROLLBACK", "END", "ABORT", "USE":
		return boundStatement{}, failure("BadRequestException", "Use the Data API transaction and database parameters to control the session.")
	}
	rows := first == "SELECT" || first == "VALUES" || first == "TABLE" || first == "SHOW" || first == "EXPLAIN" || first == "DESCRIBE" || first == "DESC" || first == "CALL"
	mutation := first == "INSERT" || first == "UPDATE" || first == "DELETE" || first == "MERGE" || first == "REPLACE"
	if mutation {
		for _, token := range tokens {
			if token == "RETURNING" {
				rows = true
			}
		}
	}
	return boundStatement{out.String(), args, rows, mutation}, nil
}
func nameStart(c byte) bool  { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }
func identifier(c byte) bool { return nameStart(c) || c >= '0' && c <= '9' || c == '$' || c >= 128 }
func parameterValue(p api.SqlParameter, pg bool) (parameter, error) {
	var out parameter
	if p.Value == nil {
		return out, failure("BadRequestException", "Parameter value is required.")
	}
	f := p.Value
	count := 0
	if f.ArrayValue != nil {
		return out, failure("BadRequestException", "Array parameters are not supported.")
	}
	if f.IsNull != nil {
		count++
		if !bool(*f.IsNull) {
			return out, failure("BadRequestException", "isNull must be true.")
		}
	}
	if f.BlobValue != nil {
		count++
		out.value = []byte(f.BlobValue)
		if pg {
			out.cast = "bytea"
		}
	}
	if f.BooleanValue != nil {
		count++
		out.value = bool(*f.BooleanValue)
		if pg {
			out.cast = "boolean"
		}
	}
	if f.LongValue != nil {
		count++
		out.value = int64(*f.LongValue)
		if pg {
			out.cast = "bigint"
		}
	}
	if f.DoubleValue != nil {
		count++
		v := float64(*f.DoubleValue)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return out, failure("BadRequestException", "Floating point parameter must be finite.")
		}
		out.value = v
		if pg {
			out.cast = "double precision"
		}
	}
	if f.StringValue != nil {
		count++
		out.value = string(*f.StringValue)
	}
	if count != 1 {
		return out, failure("BadRequestException", "Parameter value must contain exactly one field.")
	}
	hint := value(p.TypeHint)
	if hint != "" && f.StringValue == nil && f.IsNull == nil {
		return out, failure("BadRequestException", "Type hints require a string or null parameter.")
	}
	switch hint {
	case "":
	case "DATE":
		out.cast = "date"
	case "TIME":
		out.cast = "time"
		if !pg {
			out.cast = "time(6)"
		}
	case "TIMESTAMP":
		out.cast = "timestamp"
		if !pg {
			out.cast = "datetime(6)"
		}
	case "JSON":
		out.cast = "json"
	case "UUID":
		if pg {
			out.cast = "uuid"
		}
	case "DECIMAL":
		out.cast = "numeric"
		if !pg {
			cast, err := mysqlDecimalCast(value(f.StringValue))
			if err != nil {
				return out, err
			}
			out.cast = cast
		}
	default:
		return out, failure("BadRequestException", "Unsupported parameter type hint.")
	}
	return out, nil
}

// MySQL requires explicit scale on DECIMAL casts. Infer only that type annotation
// from a validated numeric string; the actual value remains a driver argument.
func mysqlDecimalCast(v string) (string, error) {
	if v == "" {
		return "decimal(65,30)", nil
	}
	mantissa, expText, hasExp := strings.Cut(strings.ToLower(v), "e")
	exponent := 0
	if hasExp {
		n, err := strconv.Atoi(expText)
		if err != nil || n > 65 || n < -65 {
			return "", failure("BadRequestException", "Decimal is outside the native MySQL precision range.")
		}
		exponent = n
	}
	mantissa = strings.TrimPrefix(strings.TrimPrefix(mantissa, "-"), "+")
	integer, fraction, _ := strings.Cut(mantissa, ".")
	digits := integer + fraction
	if digits == "" {
		return "", failure("BadRequestException", "Invalid decimal parameter.")
	}
	for i := range digits {
		if digits[i] < '0' || digits[i] > '9' {
			return "", failure("BadRequestException", "Invalid decimal parameter.")
		}
	}
	scale := len(fraction) - exponent
	if scale < 0 {
		scale = 0
	}
	whole := len(strings.TrimLeft(integer, "0")) + exponent
	if whole < 0 {
		whole = 0
	}
	precision := whole + scale
	if precision == 0 {
		precision = 1
	}
	if precision > 65 || scale > 30 {
		return "", failure("BadRequestException", "Decimal is outside the native MySQL precision range.")
	}
	return fmt.Sprintf("decimal(%d,%d)", precision, scale), nil
}
