package policy

import (
	"fmt"
	"strings"
	"unicode"
)

type templatePart struct {
	text      string
	key       string
	sourceKey string
	fallback  *string
	literal   bool
}

// valueTemplate separates policy-written wildcard syntax from values supplied
// by a caller. Substitution never reparses context text as wildcard syntax or
// as another variable, including the predefined ${*}, ${?} and ${$} values.
type valueTemplate struct{ parts []templatePart }

func compileTemplate(text string, variables bool) (valueTemplate, error) {
	if !variables {
		return valueTemplate{parts: []templatePart{{text: text}}}, nil
	}
	var result valueTemplate
	for text != "" {
		start := strings.Index(text, "${")
		if start < 0 {
			result.parts = append(result.parts, templatePart{text: text})
			break
		}
		if start > 0 {
			result.parts = append(result.parts, templatePart{text: text[:start]})
		}
		expression := text[start+2:]
		quoted := false
		end := -1
		for i, ch := range expression {
			if ch == '\'' {
				quoted = !quoted
			}
			if ch == '}' && !quoted {
				end = i
				break
			}
		}
		if end < 0 {
			return valueTemplate{}, fmt.Errorf("%w: unterminated policy variable", ErrInvalidPolicy)
		}
		body := strings.TrimSpace(expression[:end])
		text = expression[end+1:]
		if body == "*" || body == "?" || body == "$" {
			result.parts = append(result.parts, templatePart{text: body, literal: true})
			continue
		}
		name, rawDefault, hasDefault := strings.Cut(body, ",")
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "${}'\",*?") {
			return valueTemplate{}, fmt.Errorf("%w: invalid policy variable name", ErrInvalidPolicy)
		}
		for _, r := range name {
			if unicode.IsControl(r) {
				return valueTemplate{}, fmt.Errorf("%w: invalid policy variable name", ErrInvalidPolicy)
			}
		}
		part := templatePart{key: strings.ToLower(name), sourceKey: name}
		if hasDefault {
			rawDefault = strings.TrimSpace(rawDefault)
			if len(rawDefault) < 2 || rawDefault[0] != '\'' || rawDefault[len(rawDefault)-1] != '\'' || strings.ContainsRune(rawDefault[1:len(rawDefault)-1], '\'') {
				return valueTemplate{}, fmt.Errorf("%w: policy variable default must be a single-quoted literal", ErrInvalidPolicy)
			}
			fallback := rawDefault[1 : len(rawDefault)-1]
			part.fallback = &fallback
		}
		result.parts = append(result.parts, part)
	}
	return result, nil
}
func (t valueTemplate) expand(context evaluationContext) (string, []patternToken, bool) {
	var text strings.Builder
	var tokens []patternToken
	for _, part := range t.parts {
		value := part.text
		literal := part.literal
		if part.key != "" {
			values := context.values[part.key]
			if len(values) != 0 && context.multivalued(part.key) {
				return "", nil, false
			}
			if len(values) == 0 {
				if part.fallback == nil {
					return "", nil, false
				}
				value = *part.fallback
			} else {
				value = values[0]
			}
			literal = true
		}
		text.WriteString(value)
		tokens = append(tokens, patternTokens(value, literal)...)
	}
	return text.String(), tokens, true
}
func resourceTemplate(text string, variables bool) (valueTemplate, error) {
	if variables && strings.Contains(text, "${") {
		// Real IAM evaluates variables in any ARN component and even an entire
		// resource value. Unlike static ARNs, short dynamic ARNs are not padded
		// with wildcard components. Preserve the template until evaluation.
		return compileTemplate(text, true)
	}
	normalized, err := normalizeResource(text)
	if err != nil {
		return valueTemplate{}, err
	}
	return compileTemplate(normalized, variables)
}
func expandCondition(c condition, context evaluationContext) condition {
	expanded := c
	expanded.values = make([]conditionValue, len(c.values))
	for i, value := range c.values {
		if value.template == nil {
			expanded.values[i] = value
			continue
		}
		text, tokens, present := value.template.expand(context)
		if !present {
			expanded.values[i] = conditionValue{absent: true}
			continue
		}
		value, err := compileValue(c.op.kind, text, true)
		if err != nil {
			value.invalid = true
		}
		value.pattern = tokens
		expanded.values[i] = value
	}
	return expanded
}
