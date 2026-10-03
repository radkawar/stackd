// Package filterpattern compiles CloudWatch Logs filter patterns.
package filterpattern

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Pattern is an immutable compiled filter, safe for concurrent matching.
// Its zero value matches every message.
type Pattern struct {
	terms      []term
	optional   bool
	json       *expression
	space      *delimited
	regexCount int
}

// Compile validates a native CloudWatch Logs filter pattern once.
func Compile(source string) (*Pattern, error) {
	if !utf8.ValidString(source) || utf8.RuneCountInString(source) > 1024 {
		return nil, fmt.Errorf("filter pattern must contain at most 1024 valid characters")
	}
	source = strings.TrimSpace(source)
	p := &Pattern{}
	if source == "" {
		return p, nil
	}
	parser := parser{source: source}
	var err error
	switch source[0] {
	case '{':
		parser.pos++
		p.json, err = parser.parseOr()
		if err == nil && (!parser.take("}") || !parser.end()) {
			err = parser.invalid()
		}
	case '[':
		p.space, err = parser.parseDelimited()
	default:
		p.terms, p.optional, err = parser.parseTerms()
	}
	if err != nil {
		return nil, err
	}
	p.regexCount = parser.regexCount
	return p, nil
}

// Match reports whether message satisfies the compiled filter. Malformed JSON
// messages do not match JSON filters; they remain valid unstructured messages.
func (p *Pattern) Match(message string) bool {
	_, matched := p.Evaluate(message)
	return matched
}

// RegexCount reports actual parsed regular expressions, not percent characters
// inside quoted literals.
func (p *Pattern) RegexCount() int { return p.regexCount }

// Evaluate matches and retains the already-parsed fields for metric extraction.
// Ordinary Match calls use the same parser without allocating a capture map.
func (p *Pattern) Evaluate(message string) (MatchResult, bool) {
	if p.json != nil {
		decoder := json.NewDecoder(strings.NewReader(message))
		decoder.UseNumber() // Quoted comparisons preserve numeric spelling.
		var object map[string]any
		if decoder.Decode(&object) != nil || object == nil {
			return MatchResult{}, false
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			return MatchResult{}, false
		}
		// encoding/json implements the native last-duplicate-key-wins rule.
		return MatchResult{object: object}, p.json.match(object)
	}
	if p.space != nil {
		fields, matched := p.space.evaluate(message)
		return MatchResult{fields: fields}, matched
	}
	for _, term := range p.terms {
		matched := term.match(message)
		if p.optional && matched {
			return MatchResult{}, true
		}
		if !p.optional && matched == term.excluded {
			return MatchResult{}, false
		}
	}
	return MatchResult{}, !p.optional
}

type term struct {
	value    valuePattern
	excluded bool
}

func (t term) match(message string) bool {
	if t.value.regex != nil {
		return t.value.regex.MatchString(message)
	}
	return strings.Contains(message, t.value.text)
}

func (p *parser) parseTerms() ([]term, bool, error) {
	var required, optional []term
	for !p.end() {
		mode := byte(0)
		if p.source[p.pos] == '?' || p.source[p.pos] == '-' {
			mode = p.source[p.pos]
			p.pos++
		}
		if p.pos == len(p.source) || isSpace(p.source[p.pos]) {
			return nil, false, p.invalid()
		}
		value, err := p.readValue()
		if err != nil {
			return nil, false, err
		}
		if !value.quoted && value.regex == nil {
			for _, c := range value.text {
				if !isName(c) {
					return nil, false, p.invalid()
				}
			}
		}
		if p.pos < len(p.source) && !isSpace(p.source[p.pos]) {
			return nil, false, p.invalid()
		}
		t := term{value: value, excluded: mode == '-'}
		if mode == '?' {
			optional = append(optional, t)
		} else {
			required = append(required, t)
		}
	}
	// Native optional terms are ignored whenever any required/excluded term exists.
	if len(required) != 0 {
		return required, false, nil
	}
	return optional, len(optional) != 0, nil
}
