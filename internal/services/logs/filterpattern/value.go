package filterpattern

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

type valuePattern struct {
	text    string
	quoted  bool
	regex   *regexp.Regexp
	number  float64
	numeric bool
}

func compileRegex(source string) (*regexp.Regexp, error) {
	var normalized strings.Builder
	copied := 0
	inClass := false
	for i := 0; i < len(source); i++ {
		c := source[i]
		if c == '\\' {
			i++
			if i == len(source) {
				return nil, fmt.Errorf("unterminated regular expression escape")
			}
			c = source[i]
			if !strings.ContainsRune("dDsSwWtnrfv^$?[]{}|\\*+.-", rune(c)) && c != 'x' {
				return nil, fmt.Errorf("unsupported regular expression escape")
			}
			if c == 'x' {
				if i+2 >= len(source) {
					return nil, fmt.Errorf("invalid hexadecimal regular expression escape")
				}
				if _, err := strconv.ParseUint(source[i+1:i+3], 16, 8); err != nil {
					return nil, fmt.Errorf("invalid hexadecimal regular expression escape")
				}
				i += 2
			}
			continue
		}
		if !isName(rune(c)) && !strings.ContainsRune(":#=@/;,^$?[]{}|*+.", rune(c)) {
			return nil, fmt.Errorf("unsupported regular expression character %q", c)
		}
		if c == '[' {
			inClass = true
		} else if c == ']' {
			inClass = false
		} else if c == '{' && !inClass && i+1 < len(source) && source[i+1] == ',' {
			normalized.WriteString(source[copied : i+1])
			normalized.WriteByte('0')
			copied = i + 1
		}
	}
	// CloudWatch permits an omitted lower repetition bound; RE2 spells it zero.
	if copied != 0 {
		normalized.WriteString(source[copied:])
		source = normalized.String()
	}
	compiled, err := regexp.Compile(source)
	if err != nil {
		return nil, fmt.Errorf("invalid regular expression: %w", err)
	}
	return compiled, nil
}

func (v valuePattern) matchText(text string) bool {
	if v.regex != nil {
		return v.regex.MatchString(text)
	}
	return wildcardMatch(v.text, text)
}

// Only '*' is a wildcard; '?' remains literal. This does not allocate or turn
// string patterns into regular expressions.
func wildcardMatch(pattern, text string) bool {
	star, retry := -1, 0
	p, t := 0, 0
	for t < len(text) {
		if p < len(pattern) && pattern[p] == '*' {
			star, retry = p, t
			p++
		} else if p < len(pattern) && pattern[p] == text[t] {
			p++
			t++
		} else if star >= 0 {
			retry++
			t, p = retry, star+1
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

type comparison struct {
	op    string
	value valuePattern
}

func (p *parser) comparison() (comparison, error) {
	var c comparison
	for _, op := range []string{"!=", ">=", "<=", "=", ">", "<"} {
		if p.take(op) {
			c.op = op
			break
		}
	}
	if c.op == "" {
		if p.field != "" {
			return c, p.invalid()
		}
		keyword := p.name()
		if keyword == "IS" {
			kind := p.name()
			if kind != "NULL" && kind != "TRUE" && kind != "FALSE" {
				return c, p.invalid()
			}
			c.op = "IS " + kind
			return c, nil
		}
		if keyword == "NOT" && p.name() == "EXISTS" {
			c.op = "NOT EXISTS"
			return c, nil
		}
		return c, p.invalid()
	}
	value, err := p.readValue()
	if err != nil {
		return c, err
	}
	if !value.quoted && value.regex == nil {
		if value.text == "null" && p.field == "" {
			return c, p.invalid()
		}
		for _, ch := range value.text {
			if !isName(ch) && ch != '*' && ch != '.' && ch != '+' {
				return c, p.invalid()
			}
		}
		value.number, err = strconv.ParseFloat(value.text, 64)
		value.numeric = err == nil && !math.IsInf(value.number, 0) && !math.IsNaN(value.number)
	}
	if c.op != "=" && c.op != "!=" && !value.numeric {
		return c, p.invalid()
	}
	c.value = value
	return c, nil
}

func (c comparison) match(value any) bool {
	switch c.op {
	case "NOT EXISTS":
		return false // Missing-path handling belongs to the selector.
	case "IS NULL":
		if value == nil {
			return true
		}
		// Native IS NULL observes a null member of an array-valued property,
		// unlike ordinary equality, which never coerces an array to a scalar.
		if values, ok := value.([]any); ok {
			for _, item := range values {
				if item == nil {
					return true
				}
			}
		}
		return false
	case "IS TRUE", "IS FALSE":
		b, ok := value.(bool)
		return ok && b == (c.op == "IS TRUE")
	}
	var equal bool
	switch value := value.(type) {
	case json.Number:
		if c.value.numeric {
			n, err := value.Float64()
			if err != nil {
				return false
			}
			switch c.op {
			case ">":
				return n > c.value.number
			case "<":
				return n < c.value.number
			case ">=":
				return n >= c.value.number
			case "<=":
				return n <= c.value.number
			}
			equal = n == c.value.number
		} else {
			equal = c.value.matchText(string(value))
		}
	case string:
		if c.op != "=" && c.op != "!=" {
			return false
		}
		// Unquoted numeric equality is numeric only for JSON numbers. Strings
		// compare to the original pattern lexeme, including exponent spelling.
		equal = c.value.matchText(value)
	default:
		return false
	}
	if c.op == "!=" {
		return !equal
	}
	return equal
}
