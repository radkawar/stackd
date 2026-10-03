package filterpattern

import "strconv"

type expression struct {
	left, right *expression
	or          bool
	path        selector
	comparison  comparison
}

func (e *expression) match(value any) bool {
	if e.left != nil {
		if e.or {
			return e.left.match(value) || e.right.match(value)
		}
		return e.left.match(value) && e.right.match(value)
	}
	if e.comparison.op == "NOT EXISTS" {
		return !e.path.match(value, e.comparison, true)
	}
	return e.path.match(value, e.comparison, false)
}

func (p *parser) parseOr() (*expression, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.take("||") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &expression{left: left, right: right, or: true}
	}
	return left, nil
}

func (p *parser) parseAnd() (*expression, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for p.take("&&") {
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		left = &expression{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parsePrimary() (*expression, error) {
	if p.take("(") {
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.take(")") {
			return nil, p.invalid()
		}
		return expr, nil
	}
	expr := &expression{}
	if p.field != "" {
		if p.name() != p.field {
			return nil, p.invalid()
		}
	} else {
		path, err := p.selector()
		if err != nil {
			return nil, err
		}
		expr.path = path
	}
	cmp, err := p.comparison()
	if err != nil {
		return nil, err
	}
	expr.comparison = cmp
	return expr, nil
}

type selector []pathStep

type pathStep struct {
	key        string
	index      int
	arrayIndex bool
	wildcard   bool
}

func (p *parser) selector() (selector, error) {
	if !p.take("$.") {
		return nil, p.invalid()
	}
	var path selector
	wildcards := 0
	for {
		if p.pos == len(p.source) {
			return nil, p.invalid()
		}
		var step pathStep
		if p.source[p.pos] == '[' {
			p.pos++
			if p.pos == len(p.source) {
				return nil, p.invalid()
			}
			switch p.source[p.pos] {
			case '\'', '"':
				key, err := p.quoted(p.source[p.pos])
				if err != nil {
					return nil, err
				}
				step.key = key
			case '*':
				step.wildcard = true
				p.pos++
			default:
				start := p.pos
				for p.pos < len(p.source) && p.source[p.pos] >= '0' && p.source[p.pos] <= '9' {
					p.pos++
				}
				index, err := strconv.Atoi(p.source[start:p.pos])
				if err != nil {
					return nil, p.invalid()
				}
				step.index, step.arrayIndex = index, true
			}
			if p.pos == len(p.source) || p.source[p.pos] != ']' {
				return nil, p.invalid()
			}
			p.pos++
		} else if p.source[p.pos] == '*' {
			step.wildcard = true
			p.pos++
		} else {
			start := p.pos
			for p.pos < len(p.source) && isName(rune(p.source[p.pos])) {
				p.pos++
			}
			if start == p.pos {
				return nil, p.invalid()
			}
			step.key = p.source[start:p.pos]
		}
		if step.wildcard {
			wildcards++
			p.wildcards++
			if wildcards > 1 || p.wildcards > 3 {
				return nil, p.invalid()
			}
		}
		path = append(path, step)
		if p.pos < len(p.source) && p.source[p.pos] == '.' {
			p.pos++
			continue
		}
		if p.pos < len(p.source) && p.source[p.pos] == '[' {
			continue
		}
		return path, nil
	}
}

// Each condition independently searches its selector, so conjunctions may be
// satisfied by different array members. No candidate slices are allocated.
func (s selector) match(value any, c comparison, existence bool) bool {
	if len(s) == 0 {
		return existence || c.match(value)
	}
	step := s[0]
	if step.wildcard {
		switch value := value.(type) {
		case []any:
			for _, child := range value {
				if s[1:].match(child, c, existence) {
					return true
				}
			}
		case map[string]any:
			for _, child := range value {
				if s[1:].match(child, c, existence) {
					return true
				}
			}
		}
		return false
	}
	child, present := step.child(value)
	return present && s[1:].match(child, c, existence)
}

// child resolves one exact selector step for both matching and extraction.
func (s pathStep) child(value any) (any, bool) {
	if s.arrayIndex {
		array, ok := value.([]any)
		if !ok || s.index >= len(array) {
			return nil, false
		}
		return array[s.index], true
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	child, present := object[s.key]
	return child, present
}
