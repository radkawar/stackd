// Package partiql identifies DynamoDB PartiQL resources and IAM access facts.
// It does not evaluate expressions or execute statements. Grammar references:
// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.html
package partiql

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type token struct {
	kind       string
	text       string
	start, end int
	ordinal    int
}

func (t token) keyword(s string) bool { return t.kind == "word" && strings.EqualFold(t.text, s) }
func (t token) identifier() bool      { return t.kind == "word" || t.kind == "identifier" }

type expression struct {
	kind, value string
	ordinal     int
	start, end  int
	children    []*expression
	fields      []field
	nested      bool
}

type field struct {
	name       string
	start, end int
	value      *expression
}

// Statement retains the source text so rewriting cannot alter literals or paths.
// Statements are immutable after parsing and may be analyzed concurrently.
type Statement struct {
	text                 string
	table                token
	index                string
	action               string
	parameters           int
	reads                []*expression
	where                *expression
	item                 *expression
	exists               bool
	projections          int
	orderTerms           []orderTerm
	tokens               []token
	orderStart, orderEnd int
}

func (s *Statement) Table() string  { return s.table.text }
func (s *Statement) Index() string  { return s.index }
func (s *Statement) Action() string { return s.action }

// ConditionCheck distinguishes EXISTS from an ordinary transactional SELECT.
func (s *Statement) ConditionCheck() bool { return s.exists }

// RewriteTable changes only the source table identifier, preserving every other
// byte, including comments, whitespace, index identifiers and parameter order.
func (s *Statement) RewriteTable(physical string) string {
	return s.text[:s.table.start] + `"` + strings.ReplaceAll(physical, `"`, `""`) + `"` + s.text[s.table.end:]
}

// UnorderedRead removes a parsed ORDER BY clause when Query owns traversal.
// Projection and predicates remain unchanged for native expression validation.
func (s *Statement) UnorderedRead(physical string) string {
	if s.orderEnd == 0 {
		return s.RewriteTable(physical)
	}
	return s.text[:s.table.start] + quoteIdentifier(physical) + s.text[s.table.end:s.orderStart] + s.text[s.orderEnd:]
}

type parser struct {
	tokens     []token
	pos, depth int
	statement  *Statement
}

// Parse identifies exactly one DynamoDB statement and its expression structure.
// Engine-specific type checking, function validation and expression evaluation
// remain the engine's responsibility. Joins, aliases and nested SELECT sources
// are deliberately rejected rather than authorizing an ambiguous resource.
func Parse(text string) (*Statement, error) {
	tokens, count, err := lex(text)
	if err != nil {
		return nil, err
	}
	s := &Statement{text: text, parameters: count, tokens: tokens}
	p := parser{tokens: tokens, statement: s}
	exists := p.takeKeyword("EXISTS")
	s.exists = exists
	if exists {
		if err := p.expect("("); err != nil {
			return nil, err
		}
		if !p.peek().keyword("SELECT") {
			return nil, p.errorf("EXISTS requires a SELECT statement")
		}
	}
	if err := p.parseStatement(); err != nil {
		return nil, err
	}
	if exists {
		if err := p.expect(")"); err != nil {
			return nil, err
		}
	}
	p.take(";")
	if p.peek().kind != "eof" {
		return nil, p.errorf("unexpected token %q after statement", p.peek().text)
	}
	return s, nil
}

func (p *parser) peek() token { return p.tokens[p.pos] }
func (p *parser) take(s string) bool {
	if p.peek().kind == s {
		p.pos++
		return true
	}
	return false
}
func (p *parser) takeKeyword(s string) bool {
	if p.peek().keyword(s) {
		p.pos++
		return true
	}
	return false
}
func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("PartiQL at byte %d: %s", p.peek().start, fmt.Sprintf(format, args...))
}
func (p *parser) expect(s string) error {
	if !p.take(s) {
		return p.errorf("expected %s, found %q", s, p.peek().text)
	}
	return nil
}
func (p *parser) expectKeyword(s string) error {
	if !p.takeKeyword(s) {
		return p.errorf("expected %s, found %q", s, p.peek().text)
	}
	return nil
}
func (p *parser) source(index bool) error {
	t := p.peek()
	if !t.identifier() || t.text == "" {
		return p.errorf("expected table identifier")
	}
	if t.kind == "word" {
		switch strings.ToUpper(t.text) {
		case "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "INTO", "WHERE", "VALUE", "SET", "REMOVE", "RETURNING", "ORDER", "BY", "AS", "JOIN", "UNION":
			return p.errorf("reserved table name %q must be double-quoted", t.text)
		}
	}
	p.statement.table = t
	p.pos++
	if p.take(".") {
		if !index {
			return p.errorf("only SELECT supports an index source")
		}
		i := p.peek()
		if t.kind != "identifier" || i.kind != "identifier" || i.text == "" {
			return p.errorf("table and index names must both be double-quoted")
		}
		p.statement.index = i.text
		p.pos++
	}
	return nil
}

func (p *parser) parseStatement() error {
	s := p.statement
	switch {
	case p.takeKeyword("SELECT"):
		s.action = "PartiQLSelect"
		for {
			x, err := p.expr(0)
			if err != nil {
				return err
			}
			s.reads = append(s.reads, x)
			if !p.take(",") {
				break
			}
		}
		s.projections = len(s.reads)
		if err := p.expectKeyword("FROM"); err != nil {
			return err
		}
		if err := p.source(true); err != nil {
			return err
		}
		if p.takeKeyword("WHERE") {
			x, err := p.expr(0)
			if err != nil {
				return err
			}
			s.where = x
		}
		if p.takeKeyword("ORDER") {
			if s.where == nil {
				return p.errorf("ORDER BY requires a WHERE clause")
			}
			start := p.tokens[p.pos-1].start
			if err := p.expectKeyword("BY"); err != nil {
				return err
			}
			for {
				x, err := p.expr(0)
				if err != nil {
					return err
				}
				s.reads = append(s.reads, x)
				desc := false
				if !p.takeKeyword("ASC") {
					desc = p.takeKeyword("DESC")
				}
				s.orderTerms = append(s.orderTerms, orderTerm{path: x, descending: desc})
				if !p.take(",") {
					break
				}
			}
			s.orderStart, s.orderEnd = start, p.tokens[p.pos-1].end
		}
	case p.takeKeyword("INSERT"):
		s.action = "PartiQLInsert"
		if err := p.expectKeyword("INTO"); err != nil {
			return err
		}
		if err := p.source(false); err != nil {
			return err
		}
		if err := p.expectKeyword("VALUE"); err != nil {
			return err
		}
		x, err := p.expr(0)
		if err != nil {
			return err
		}
		if x.kind != "map" && x.kind != "parameter" {
			return p.errorf("INSERT VALUE requires an item tuple or parameter")
		}
		s.item = x
	case p.takeKeyword("UPDATE"):
		s.action = "PartiQLUpdate"
		if err := p.source(false); err != nil {
			return err
		}
		changed := false
		for p.peek().keyword("SET") || p.peek().keyword("REMOVE") {
			set := p.takeKeyword("SET")
			if !set {
				p.pos++
			}
			for {
				x, err := p.primary()
				if err != nil {
					return err
				}
				if x.kind != "path" {
					return p.errorf("expected attribute path in update")
				}
				s.reads = append(s.reads, x)
				if set {
					if err := p.expect("="); err != nil {
						return err
					}
					x, err = p.expr(0)
					if err != nil {
						return err
					}
					s.reads = append(s.reads, x)
				}
				changed = true
				if !p.take(",") {
					break
				}
			}
		}
		if !changed {
			return p.errorf("UPDATE requires SET or REMOVE")
		}
		if err := p.mutationWhere(); err != nil {
			return err
		}
	case p.takeKeyword("DELETE"):
		s.action = "PartiQLDelete"
		if err := p.expectKeyword("FROM"); err != nil {
			return err
		}
		if err := p.source(false); err != nil {
			return err
		}
		if err := p.mutationWhere(); err != nil {
			return err
		}
	default:
		return p.errorf("expected SELECT, INSERT, UPDATE, DELETE or EXISTS")
	}
	return nil
}

func (p *parser) mutationWhere() error {
	if err := p.expectKeyword("WHERE"); err != nil {
		return err
	}
	x, err := p.expr(0)
	if err != nil {
		return err
	}
	p.statement.where = x
	if p.takeKeyword("RETURNING") {
		all := p.takeKeyword("ALL")
		if !all {
			if p.statement.action == "PartiQLDelete" {
				return p.errorf("DELETE RETURNING requires ALL OLD *")
			}
			if err := p.expectKeyword("MODIFIED"); err != nil {
				return err
			}
		}
		if !p.takeKeyword("OLD") {
			if p.statement.action == "PartiQLDelete" {
				return p.errorf("DELETE RETURNING requires ALL OLD *")
			}
			if err := p.expectKeyword("NEW"); err != nil {
				return err
			}
		}
		if err := p.expect("*"); err != nil {
			return err
		}
	}
	return nil
}

// Binding powers keep BETWEEN's AND separate from boolean AND. The tree is used
// only to prove access bounds, never to decide whether an item matches.
func operator(t token) (string, int) {
	if t.keyword("OR") {
		return "OR", 1
	}
	if t.keyword("AND") {
		return "AND", 2
	}
	for _, op := range []string{"IN", "BETWEEN", "IS"} {
		if t.keyword(op) {
			return op, 4
		}
	}
	switch t.kind {
	case "=", "<>", "!=", "<", ">", "<=", ">=":
		return t.kind, 4
	case "+", "-":
		return t.kind, 5
	case "*", "/", "%":
		return t.kind, 6
	}
	return "", 0
}

func (p *parser) expr(min int) (*expression, error) {
	start := p.peek().start
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		return nil, p.errorf("expression nesting exceeds 128 levels")
	}
	var left *expression
	var err error
	if p.takeKeyword("NOT") {
		x, e := p.expr(3)
		if e != nil {
			return nil, e
		}
		left = &expression{kind: "NOT", children: []*expression{x}}
	} else if p.peek().kind == "+" || p.peek().kind == "-" {
		op := p.peek().kind
		p.pos++
		x, e := p.expr(7)
		if e != nil {
			return nil, e
		}
		left = &expression{kind: "unary" + op, children: []*expression{x}}
	} else {
		left, err = p.primary()
		if err != nil {
			return nil, err
		}
	}
	left.start, left.end = start, p.tokens[p.pos-1].end
	for {
		op, power := operator(p.peek())
		negated := p.peek().keyword("NOT") && (p.tokens[p.pos+1].keyword("IN") || p.tokens[p.pos+1].keyword("BETWEEN"))
		if negated {
			op, power = operator(p.tokens[p.pos+1])
		}
		if power == 0 || power < min {
			break
		}
		p.pos++
		if negated {
			p.pos++
		}
		if op == "IS" {
			not := p.takeKeyword("NOT")
			t := p.peek()
			if !t.identifier() {
				return nil, p.errorf("expected type after IS")
			}
			p.pos++
			left = &expression{kind: "IS", value: t.text, children: []*expression{left}}
			if not {
				left = &expression{kind: "NOT", children: []*expression{left}}
			}
			left.start, left.end = start, p.tokens[p.pos-1].end
			continue
		}
		right, e := p.expr(power + 1)
		if e != nil {
			return nil, e
		}
		left = &expression{kind: op, children: []*expression{left, right}}
		if op == "BETWEEN" {
			if err := p.expectKeyword("AND"); err != nil {
				return nil, err
			}
			hi, e := p.expr(power + 1)
			if e != nil {
				return nil, e
			}
			left.children = append(left.children, hi)
		}
		if negated {
			left = &expression{kind: "NOT", children: []*expression{left}}
		}
		left.start, left.end = start, p.tokens[p.pos-1].end
	}
	return left, nil
}

func (p *parser) primary() (*expression, error) {
	t := p.peek()
	var x *expression
	switch t.kind {
	case "string", "number", "ion":
		p.pos++
		x = &expression{kind: t.kind, value: t.text, start: t.start, end: t.end}
	case "parameter":
		p.pos++
		x = &expression{kind: "parameter", ordinal: t.ordinal}
	case "*":
		p.pos++
		x = &expression{kind: "wildcard"}
	case "(":
		p.pos++
		var err error
		x, err = p.expr(0)
		if err != nil {
			return nil, err
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
	case "[", "<<":
		p.pos++
		close := "]"
		if t.kind == "<<" {
			close = ">>"
		}
		x = &expression{kind: "list"}
		if !p.take(close) {
			for {
				e, err := p.expr(0)
				if err != nil {
					return nil, err
				}
				x.children = append(x.children, e)
				if !p.take(",") {
					break
				}
			}
			if err := p.expect(close); err != nil {
				return nil, err
			}
		}
	case "{":
		p.pos++
		x = &expression{kind: "map"}
		if !p.take("}") {
			for {
				key := p.peek()
				if key.kind != "string" && !key.identifier() {
					return nil, p.errorf("expected tuple attribute name")
				}
				p.pos++
				if err := p.expect(":"); err != nil {
					return nil, err
				}
				e, err := p.expr(0)
				if err != nil {
					return nil, err
				}
				x.fields = append(x.fields, field{name: key.text, start: key.start, end: key.end, value: e})
				if !p.take(",") {
					break
				}
			}
			if err := p.expect("}"); err != nil {
				return nil, err
			}
		}
	case "word", "identifier":
		if t.keyword("SELECT") || t.keyword("FROM") || t.keyword("WHERE") || t.keyword("RETURNING") || t.keyword("SET") || t.keyword("REMOVE") || t.keyword("ORDER") || t.keyword("AND") || t.keyword("OR") {
			return nil, p.errorf("expected expression, found %q", t.text)
		}
		p.pos++
		x = &expression{kind: "path", value: t.text, start: t.start, end: t.end}
		if t.keyword("NULL") || t.keyword("MISSING") || t.keyword("TRUE") || t.keyword("FALSE") {
			x.kind = "constant"
		}
		if p.take("(") {
			x.kind = "function"
			if !p.take(")") {
				for {
					e, err := p.expr(0)
					if err != nil {
						return nil, err
					}
					x.children = append(x.children, e)
					if !p.take(",") {
						break
					}
				}
				if err := p.expect(")"); err != nil {
					return nil, err
				}
			}
		}
	default:
		return nil, p.errorf("expected expression, found %q", t.text)
	}
	for p.peek().kind == "." || p.peek().kind == "[" {
		if p.take(".") {
			next := p.peek()
			if !next.identifier() && next.kind != "*" {
				return nil, p.errorf("expected document path member")
			}
			p.pos++
		} else {
			p.pos++
			i, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			x.children = append(x.children, i)
		}
		x.nested = true
	}
	return x, nil
}

func lex(text string) ([]token, int, error) {
	var tokens []token
	parameters := 0
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 1 {
			return nil, 0, fmt.Errorf("PartiQL at byte %d: invalid UTF-8", i)
		}
		if unicode.IsSpace(r) {
			i += size
			continue
		}
		if strings.HasPrefix(text[i:], "--") {
			for i < len(text) && text[i] != '\n' && text[i] != '\r' {
				i++
			}
			continue
		}
		if strings.HasPrefix(text[i:], "/*") {
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				return nil, 0, fmt.Errorf("PartiQL at byte %d: unterminated comment", i)
			}
			i += end + 4
			continue
		}
		start := i
		if r == '\'' || r == '"' || r == '`' {
			quote := byte(r)
			i++
			var value strings.Builder
			closed := false
			for i < len(text) {
				if text[i] == quote {
					if i+1 < len(text) && text[i+1] == quote {
						value.WriteByte(quote)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				value.WriteByte(text[i])
				i++
			}
			if !closed {
				return nil, 0, fmt.Errorf("PartiQL at byte %d: unterminated quoted token", start)
			}
			kind := "string"
			if quote == '"' {
				kind = "identifier"
			}
			if quote == '`' {
				kind = "ion"
			}
			tokens = append(tokens, token{kind: kind, text: value.String(), start: start, end: i})
			continue
		}
		if unicode.IsLetter(r) || r == '_' {
			i += size
			for i < len(text) {
				r, size = utf8.DecodeRuneInString(text[i:])
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
					break
				}
				i += size
			}
			tokens = append(tokens, token{kind: "word", text: text[start:i], start: start, end: i})
			continue
		}
		if r >= '0' && r <= '9' || r == '.' && i+1 < len(text) && text[i+1] >= '0' && text[i+1] <= '9' {
			for i < len(text) && text[i] >= '0' && text[i] <= '9' {
				i++
			}
			if i < len(text) && text[i] == '.' {
				i++
				for i < len(text) && text[i] >= '0' && text[i] <= '9' {
					i++
				}
			}
			if i < len(text) && (text[i] == 'e' || text[i] == 'E') {
				i++
				if i < len(text) && (text[i] == '+' || text[i] == '-') {
					i++
				}
				digits := i
				for i < len(text) && text[i] >= '0' && text[i] <= '9' {
					i++
				}
				if digits == i {
					return nil, 0, fmt.Errorf("PartiQL at byte %d: missing exponent digits", start)
				}
			}
			tokens = append(tokens, token{kind: "number", text: text[start:i], start: start, end: i})
			continue
		}
		if r == '?' {
			tokens = append(tokens, token{kind: "parameter", text: "?", start: i, end: i + 1, ordinal: parameters})
			parameters++
			i++
			continue
		}
		kind := ""
		if i+1 < len(text) {
			switch text[i : i+2] {
			case "<<", ">>", "<=", ">=", "!=", "<>":
				kind = text[i : i+2]
			}
		}
		if kind == "" && strings.ContainsRune("()[]{}.,:;=<>+-*/%", r) {
			kind = string(r)
		}
		if kind == "" {
			return nil, 0, fmt.Errorf("PartiQL at byte %d: unexpected character %q", i, r)
		}
		i += len(kind)
		tokens = append(tokens, token{kind: kind, text: kind, start: start, end: i})
	}
	tokens = append(tokens, token{kind: "eof", start: len(text), end: len(text)})
	return tokens, parameters, nil
}
