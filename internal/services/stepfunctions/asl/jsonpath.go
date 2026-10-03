package asl

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ohler55/ojg/jp"
)

// Path is a compiled ASL path. A definite path can select null without being
// confused with a missing value; an indefinite path always selects an array.
type Path struct {
	source    string
	query     jp.Expr
	variable  string
	context   bool
	multiple  bool
	reference bool
}

func CompilePath(source string, reference bool) (*Path, error) {
	if source == "" || source[0] != '$' {
		return nil, fmt.Errorf("path must start with $: %q", source)
	}
	p := &Path{source: source, reference: reference}
	query := source
	if strings.HasPrefix(query, "$$") {
		p.context = true
		query = query[1:]
	} else if len(query) > 1 && query[1] != '.' && query[1] != '[' {
		end := 1
		for end < len(query) {
			r, size := utf8.DecodeRuneInString(query[end:])
			if !(unicode.IsLetter(r) || r == '_' || end > 1 && (unicode.IsDigit(r) || unicode.IsMark(r))) {
				break
			}
			end += size
		}
		if end == 1 {
			return nil, fmt.Errorf("invalid variable path %q", source)
		}
		p.variable = query[1:end]
		query = "$" + query[end:]
	}
	if len(query) > 1 && query[1] != '.' && query[1] != '[' {
		return nil, fmt.Errorf("invalid path %q", source)
	}
	normalized, err := normalizePath(query)
	if err != nil {
		return nil, err
	}
	p.query, err = jp.ParseString(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid path %q: %w", source, err)
	}
	for i, fragment := range p.query {
		switch fragment.(type) {
		case jp.Root:
			if i != 0 {
				return nil, fmt.Errorf("root inside path %q", source)
			}
		case jp.Child, jp.Nth:
		case jp.Wildcard, jp.Descent, jp.Union, jp.Slice, *jp.Filter:
			p.multiple = true
		default:
			return nil, fmt.Errorf("unsupported path operation in %q", source)
		}
	}
	if reference && p.multiple {
		return nil, fmt.Errorf("reference path must identify one value: %q", source)
	}
	return p, nil
}

// normalizePath converts ASL escaped dot-member syntax into quoted members.
// Bracket expressions (including filters) are left for the JSONPath parser.
func normalizePath(source string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(source); {
		if source[i] == '[' {
			start, depth, quote := i, 0, byte(0)
			for ; i < len(source); i++ {
				c := source[i]
				if quote != 0 {
					if c == '\\' {
						i++
						continue
					}
					if c == quote {
						quote = 0
					}
					continue
				}
				if c == '\'' || c == '"' {
					quote = c
					continue
				}
				if c == '[' {
					depth++
				}
				if c == ']' {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
			}
			if depth != 0 || quote != 0 {
				return "", fmt.Errorf("unterminated bracket in %q", source)
			}
			out.WriteString(source[start:i])
			continue
		}
		if source[i] != '.' {
			out.WriteByte(source[i])
			i++
			continue
		}
		i++
		if i == len(source) {
			return "", fmt.Errorf("unfinished path %q", source)
		}
		if source[i] == '.' {
			out.WriteString("..")
			i++
			if i == len(source) {
				return "", fmt.Errorf("unfinished recursive descent in %q", source)
			}
			if source[i] == '*' {
				out.WriteByte('*')
				i++
				continue
			}
		} else if source[i] == '*' {
			out.WriteString(".*")
			i++
			continue
		}
		// ASL permits a dot before a bracketed member.
		if source[i] == '[' {
			continue
		}
		var member strings.Builder
		for i < len(source) && source[i] != '.' && source[i] != '[' {
			c := source[i]
			if c == '\\' {
				i++
				if i == len(source) {
					return "", fmt.Errorf("unfinished escape in %q", source)
				}
				if source[i] == 'u' {
					start := i - 1
					if i+5 > len(source) {
						return "", fmt.Errorf("unfinished Unicode escape in %q", source)
					}
					i += 5
					if i+6 <= len(source) && source[i:i+2] == "\\u" {
						i += 6
					}
					var decoded string
					if err := json.Unmarshal([]byte("\""+source[start:i]+"\""), &decoded); err != nil {
						return "", err
					}
					member.WriteString(decoded)
					continue
				}
				member.WriteByte(source[i])
				i++
				continue
			}
			if c < 0x80 && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '&') {
				return "", fmt.Errorf("member must use bracket notation in %q", source)
			}
			member.WriteByte(c)
			i++
		}
		if member.Len() == 0 {
			return "", fmt.Errorf("empty path member in %q", source)
		}
		out.WriteByte('[')
		out.WriteString(strconv.Quote(member.String()))
		out.WriteByte(']')
	}
	return out.String(), nil
}

func (p *Path) Lookup(env Environment) (value any, found bool, err error) {
	if p == nil {
		return nil, false, runtimeError("nil path")
	}
	root := env.Input
	if p.context {
		root = env.ContextObject
	}
	if p.variable != "" {
		root, found = env.Variables[p.variable]
		if !found {
			return nil, false, nil
		}
	}
	values := p.query.Get(root)
	if p.multiple {
		if values == nil {
			values = []any{}
		}
		return values, true, nil
	}
	if len(values) == 0 {
		return nil, false, nil
	}
	return values[0], true, nil
}

// Store replaces only the addressed branch. Unchanged subtrees remain shared;
// the original state input remains available through the evaluation environment.
func (p *Path) Store(input, value any) (any, error) {
	if p == nil || p.context || p.variable != "" || p.multiple || !p.reference {
		return nil, &EvaluationError{Name: "States.ResultPathMatchFailure", Cause: "ResultPath must be an input-root reference path"}
	}
	result, err := storePath(input, p.query[1:], value)
	if err != nil {
		return nil, &EvaluationError{Name: "States.ReferencePathConflict", Cause: fmt.Sprintf("cannot apply ResultPath %q: %v", p.source, err)}
	}
	return result, nil
}

func storePath(input any, fragments jp.Expr, value any) (any, error) {
	if len(fragments) == 0 {
		return value, nil
	}
	switch fragment := fragments[0].(type) {
	case jp.Child:
		object, ok := input.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected an object, got %T", input)
		}
		child, exists := object[string(fragment)]
		if !exists && len(fragments) > 1 {
			child = map[string]any{}
		}
		updated, err := storePath(child, fragments[1:], value)
		if err != nil {
			return nil, err
		}
		result := make(map[string]any, len(object)+1)
		for k, v := range object {
			result[k] = v
		}
		result[string(fragment)] = updated
		return result, nil
	case jp.Nth:
		array, ok := input.([]any)
		if !ok {
			return nil, fmt.Errorf("expected an array, got %T", input)
		}
		index := int(fragment)
		if index < 0 {
			index += len(array)
		}
		if index < 0 || index >= len(array) {
			return nil, fmt.Errorf("array index out of bounds")
		}
		updated, err := storePath(array[index], fragments[1:], value)
		if err != nil {
			return nil, err
		}
		result := append([]any(nil), array...)
		result[index] = updated
		return result, nil
	default:
		return nil, fmt.Errorf("not a reference path")
	}
}

func (p *Path) References() []string {
	if p != nil && p.variable != "" {
		return []string{"$" + p.variable}
	}
	return nil
}
