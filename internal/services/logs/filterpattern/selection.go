package filterpattern

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Selection is an immutable predicate over subscription system fields. It does
// not reinterpret the customer's message or duplicate log filter matching.
type Selection struct{ root *selectionNode }
type selectionNode struct {
	left, right *selectionNode
	or          bool
	field       string
	values      []string
	negate      bool
}

func (n *selectionNode) match(account, region string) bool {
	if n == nil {
		return true
	}
	if n.field == "" {
		if n.or {
			return n.left.match(account, region) || n.right.match(account, region)
		}
		return n.left.match(account, region) && n.right.match(account, region)
	}
	value := account
	if n.field == "@aws.region" {
		value = region
	}
	found := false
	for _, v := range n.values {
		if value == v {
			found = true
			break
		}
	}
	return found != n.negate
}
func (s *Selection) Match(account, region string) bool { return s.root.match(account, region) }

// CompileSelection parses the documented system-field equality, membership and
// boolean operators used by CloudWatch Logs subscription field selection.
func CompileSelection(source string) (*Selection, error) {
	if !utf8.ValidString(source) || utf8.RuneCountInString(source) > 2000 {
		return nil, fmt.Errorf("invalid field selection criteria length")
	}
	p := selectionParser{source: source}
	p.space()
	if p.pos == len(source) {
		return &Selection{}, nil
	}
	root, err := p.expression(false)
	p.space()
	if err != nil {
		return nil, err
	}
	if p.pos != len(source) {
		return nil, p.invalid()
	}
	return &Selection{root}, nil
}

type selectionParser struct {
	source string
	pos    int
}

func (p *selectionParser) space() {
	for p.pos < len(p.source) && isSpace(p.source[p.pos]) {
		p.pos++
	}
}
func (p *selectionParser) invalid() error {
	return fmt.Errorf("invalid field selection criteria at character %d", p.pos+1)
}
func (p *selectionParser) take(t string) bool {
	p.space()
	if len(p.source)-p.pos < len(t) {
		return false
	}
	keyword := t[0] >= 'A' && t[0] <= 'Z'
	token := p.source[p.pos : p.pos+len(t)]
	if keyword {
		if !strings.EqualFold(token, t) {
			return false
		}
	} else if token != t {
		return false
	}
	end := p.pos + len(t)
	if t[0] >= 'A' && t[0] <= 'Z' && end < len(p.source) && isName(rune(p.source[end])) {
		return false
	}
	p.pos = end
	return true
}
func (p *selectionParser) expression(and bool) (*selectionNode, error) {
	var left *selectionNode
	var err error
	if and {
		left, err = p.atom()
	} else {
		left, err = p.expression(true)
	}
	if err != nil {
		return nil, err
	}
	op := "OR"
	if and {
		op = "AND"
	}
	for p.take(op) {
		var right *selectionNode
		if and {
			right, err = p.atom()
		} else {
			right, err = p.expression(true)
		}
		if err != nil {
			return nil, err
		}
		left = &selectionNode{left: left, right: right, or: !and}
	}
	return left, nil
}
func (p *selectionParser) atom() (*selectionNode, error) {
	if p.take("(") {
		n, err := p.expression(false)
		if err != nil {
			return nil, err
		}
		if !p.take(")") {
			return nil, p.invalid()
		}
		return n, nil
	}
	p.space()
	n := &selectionNode{}
	for _, field := range []string{"@aws.account", "@aws.region"} {
		if p.take(field) {
			n.field = field
			break
		}
	}
	if n.field == "" {
		return nil, p.invalid()
	}
	list := false
	switch {
	case p.take("!="):
		n.negate = true
	case p.take("="):
	case p.take("NOT"):
		n.negate = true
		if !p.take("IN") {
			return nil, p.invalid()
		}
		list = true
	case p.take("IN"):
		list = true
	default:
		return nil, p.invalid()
	}
	// Native membership lists use parentheses; the API documentation's square
	// bracket examples are rejected by the live service.
	if list && !p.take("(") {
		return nil, p.invalid()
	}
	for {
		v, err := p.quoted()
		if err != nil {
			return nil, err
		}
		n.values = append(n.values, v)
		if !list || !p.take(",") {
			break
		}
	}
	if list && !p.take(")") {
		return nil, p.invalid()
	}
	return n, nil
}
func (p *selectionParser) quoted() (string, error) {
	p.space()
	if p.pos >= len(p.source) || (p.source[p.pos] != '"' && p.source[p.pos] != '\'') {
		return "", p.invalid()
	}
	text := parser{source: p.source, pos: p.pos}
	value, err := text.quoted(p.source[p.pos])
	p.pos = text.pos
	if err != nil {
		return "", p.invalid()
	}
	return value, nil
}
