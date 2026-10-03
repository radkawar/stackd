package filterpattern

import (
	"fmt"
	"strconv"
	"strings"
)

type parser struct {
	source     string
	pos        int
	regexCount int
	wildcards  int
	field      string // Nonempty only while parsing a delimited field's predicates.
}

func (p *parser) invalid() error {
	return fmt.Errorf("invalid filter pattern at character %d", p.pos+1)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func isName(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func (p *parser) skipSpace() {
	for p.pos < len(p.source) && isSpace(p.source[p.pos]) {
		p.pos++
	}
}

func (p *parser) end() bool {
	p.skipSpace()
	return p.pos == len(p.source)
}

func (p *parser) take(text string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.source[p.pos:], text) {
		p.pos += len(text)
		return true
	}
	return false
}

func (p *parser) name() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.source) && isName(rune(p.source[p.pos])) {
		p.pos++
	}
	return p.source[start:p.pos]
}

func (p *parser) quoted(quote byte) (string, error) {
	p.pos++
	start := p.pos
	for p.pos < len(p.source) {
		if p.source[p.pos] == quote {
			text := p.source[start:p.pos]
			p.pos++
			if !strings.ContainsRune(text, '\\') {
				return text, nil
			}
			if quote == '"' {
				decoded, err := strconv.Unquote("\"" + text + "\"")
				if err != nil {
					return "", p.invalid()
				}
				return decoded, nil
			}
			// Single quotes delimit selector keys, not Go character literals.
			var decoded strings.Builder
			for i := 0; i < len(text); i++ {
				if text[i] == '\\' {
					i++
					if i == len(text) || text[i] != '\\' && text[i] != '\'' {
						return "", p.invalid()
					}
				}
				decoded.WriteByte(text[i])
			}
			return decoded.String(), nil
		}
		if p.source[p.pos] == '\\' {
			p.pos++
		}
		p.pos++
	}
	return "", p.invalid()
}

func (p *parser) readValue() (valuePattern, error) {
	p.skipSpace()
	var value valuePattern
	if p.pos == len(p.source) {
		return value, p.invalid()
	}
	if p.source[p.pos] == '"' {
		text, err := p.quoted('"')
		value.text, value.quoted = text, true
		return value, err
	}
	if p.source[p.pos] == '%' {
		p.pos++
		start := p.pos
		for p.pos < len(p.source) && p.source[p.pos] != '%' {
			p.pos++
		}
		if p.pos == len(p.source) {
			return value, p.invalid()
		}
		text := p.source[start:p.pos]
		p.pos++
		p.regexCount++
		if p.regexCount > 2 {
			return value, fmt.Errorf("filter pattern exceeds the maximum of 2 regular expressions")
		}
		compiled, err := compileRegex(text)
		value.regex = compiled
		return value, err
	}
	start := p.pos
	for p.pos < len(p.source) {
		c := p.source[p.pos]
		if isSpace(c) || strings.ContainsRune(",]}()&|=<>!", rune(c)) {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return value, p.invalid()
	}
	value.text = p.source[start:p.pos]
	return value, nil
}
