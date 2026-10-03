package apigatewayv2

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/ohler55/ojg/jp"
)

// Selection expressions interpolate variables once, with optional braces and
// escaped dollar signs. JSONPath evaluation is delegated to the same library
// used by the Step Functions expression engine.
type webSocketSelectionPart struct {
	literal  string
	query    jp.Expr
	multiple bool
}

func compileWebSocketSelection(source string) ([]webSocketSelectionPart, error) {
	if source == "" {
		return nil, bad("RouteSelectionExpression is required for WebSocket APIs")
	}
	var parts []webSocketSelectionPart
	var literal strings.Builder
	flush := func() {
		if literal.Len() != 0 {
			parts = append(parts, webSocketSelectionPart{literal: literal.String()})
			literal.Reset()
		}
	}
	for i := 0; i < len(source); {
		if source[i] == '\\' && i+1 < len(source) && source[i+1] == '$' {
			literal.WriteByte('$')
			i += 2
			continue
		}
		if source[i] != '$' {
			literal.WriteByte(source[i])
			i++
			continue
		}
		flush()
		i++
		wrapped := i < len(source) && source[i] == '{'
		if wrapped {
			i++
		}
		start := i
		depth := 0
		var quote byte
		for i < len(source) {
			c := source[i]
			if quote != 0 {
				if c == '\\' && i+1 < len(source) {
					i += 2
					continue
				}
				if c == quote {
					quote = 0
				}
			} else if depth > 0 && (c == '\'' || c == '"') {
				quote = c
			} else if c == '[' {
				depth++
			} else if c == ']' {
				depth--
			} else if depth == 0 && (wrapped && c == '}' || !wrapped && strings.ContainsRune(" /\\$\t\r\n{}", rune(c))) {
				break
			}
			i++
		}
		variable := source[start:i]
		if wrapped {
			if i == len(source) || source[i] != '}' {
				return nil, bad("Unterminated variable in RouteSelectionExpression")
			}
			i++
		}
		path, ok := strings.CutPrefix(variable, "request.body")
		if !ok || path != "" && path[0] != '.' && path[0] != '[' {
			return nil, bad("WebSocket route selection variables must reference request.body")
		}
		query, err := jp.ParseString("$" + path)
		if err != nil {
			return nil, bad("Invalid JSONPath in RouteSelectionExpression: " + variable)
		}
		part := webSocketSelectionPart{query: query}
		for _, fragment := range query {
			switch fragment.(type) {
			case jp.Root, jp.Child, jp.Nth:
			case jp.Wildcard, jp.Descent, jp.Union, jp.Slice, *jp.Filter:
				part.multiple = true
			default:
				return nil, unsupported("Unsupported JSONPath operation in RouteSelectionExpression")
			}
		}
		parts = append(parts, part)
	}
	flush()
	return parts, nil
}

func selectWebSocketRoute(expression string, body []byte) (string, error) {
	// API Gateway sends non-JSON messages directly to $default, even for a
	// static expression. Missing variables in otherwise valid JSON become "".
	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return "$default", nil
	}
	parts, err := compileWebSocketSelection(expression)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, part := range parts {
		if part.query == nil {
			out.WriteString(part.literal)
			continue
		}
		values := part.query.Get(document)
		if len(values) == 0 {
			continue
		}
		if part.multiple {
			out.WriteString(webSocketSelectionValue(values))
		} else {
			out.WriteString(webSocketSelectionValue(values[0]))
		}
	}
	return out.String(), nil
}

func webSocketSelectionValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		var out strings.Builder
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteString(", ")
			}
			out.WriteString(webSocketSelectionValue(item))
		}
		out.WriteByte(']')
		return out.String()
	default:
		encoded, _ := json.Marshal(v) // Values originate in a decoded JSON document.
		return string(encoded)
	}
}
