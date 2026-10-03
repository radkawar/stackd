// Package syntax implements the immutable JSONata syntax tree and parser.
package syntax

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	jsonregex "github.com/tiaanduplessis/jsonata-go/internal/regex"
)

type Position struct{ Offset, Byte, Line, Column int }
type TokenKind uint8

const (
	EOF TokenKind = iota
	Identifier
	String
	Number
	Regex
	True
	False
	Null
	Operator
	LBracket
	RBracket
	LBrace
	RBrace
	LParen
	RParen
	Comma
	Colon
	Semicolon
	Dollar
	Invalid
)

type Token struct {
	Kind    TokenKind
	Text    string
	Pos     Position
	Literal any
	// The number value is stored inline because boxing a float64 in Literal
	// adds an allocation to every numeric token. Regex products use Literal
	// below because their representation is substantially larger.
	NumberValue  float64
	NumberParsed bool
}

// UTF16String retains a JSONata string literal containing an unpaired UTF-16
// surrogate. Go strings cannot represent that value without information loss.
// The evaluator must reject it before the public value boundary.
type UTF16String struct {
	Units []uint16
}
type Lexer struct {
	source                          string
	bytePos, utf16Pos, line, column int
}

func Lex(source string) ([]Token, *ParseError) {
	l := Lexer{source: source, line: 1, column: 1}
	out := make([]Token, 0, len(source)/2+1)
	for {
		t, err := l.next()
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		if t.Kind == EOF {
			return out, nil
		}
	}
}
func (l *Lexer) pos() Position { return Position{l.utf16Pos, l.bytePos, l.line, l.column} }
func (l *Lexer) peek() rune {
	if l.bytePos >= len(l.source) {
		return utf8.RuneError
	}
	r, _ := utf8.DecodeRuneInString(l.source[l.bytePos:])
	return r
}
func (l *Lexer) advance() rune {
	if l.bytePos >= len(l.source) {
		return utf8.RuneError
	}
	r, n := utf8.DecodeRuneInString(l.source[l.bytePos:])
	l.bytePos += n
	if r > 0xffff {
		l.utf16Pos += 2
	} else {
		l.utf16Pos++
	}
	if r == '\n' {
		l.line++
		l.column = 1
	} else {
		l.column++
	}
	return r
}
func (l *Lexer) error(code, token, message string, p Position) *ParseError {
	return &ParseError{Code: code, Token: token, Value: token, Position: p.Offset, Message: message}
}
func (l *Lexer) next() (Token, *ParseError) {
	for {
		r := l.peek()
		if r == utf8.RuneError && l.bytePos >= len(l.source) {
			return Token{Kind: EOF, Pos: l.pos()}, nil
		}
		if unicode.IsSpace(r) {
			l.advance()
			continue
		}
		if r == '/' && l.bytePos+1 < len(l.source) && l.source[l.bytePos+1] == '*' {
			start := l.pos()
			l.advance()
			l.advance()
			closed := false
			for l.bytePos < len(l.source) {
				if l.peek() == '*' && l.bytePos+1 < len(l.source) && l.source[l.bytePos+1] == '/' {
					l.advance()
					l.advance()
					closed = true
					break
				}
				l.advance()
			}
			if !closed {
				return Token{}, l.error("S0106", "", "unterminated comment", start)
			}
			continue
		}
		break
	}
	start := l.pos()
	r := l.peek()
	if r == utf8.RuneError && l.bytePos >= len(l.source) {
		return Token{Kind: EOF, Pos: start}, nil
	}
	if unicode.IsLetter(r) || r == '_' {
		return l.word(start)
	}
	if unicode.IsDigit(r) {
		return l.number(start)
	}
	if r == '\'' || r == '"' {
		if start.Byte > 0 {
			previous := l.source[start.Byte-1]
			if unicode.IsLetter(rune(previous)) || unicode.IsDigit(rune(previous)) {
				l.advance()
				return Token{Kind: String, Pos: start}, nil
			}
		}
		return l.stringToken(start, false)
	}
	if r == '/' && regexStart(l.source, l.bytePos) {
		// A slash-delimited pattern is a token only when a closing slash is
		// present. This keeps ordinary arithmetic division unambiguous.
		end := l.bytePos + 1
		depth := 0
		for end < len(l.source) {
			char := l.source[end]
			if char == '/' && depth == 0 && regexDelimiterUnescaped(l.source, end) {
				for l.bytePos <= end {
					l.advance()
				}
				for l.peek() == 'i' || l.peek() == 'm' {
					l.advance()
				}
				literal := l.source[start.Byte:l.bytePos]
				pattern, err := validateRegexLiteral(literal, start)
				if err != nil {
					return Token{}, err
				}
				// Literal carries the immutable compiled product for regex tokens.
				// String tokens use this field for UTF-16 values, so the parser
				// dispatches by token kind before asserting the cached type.
				return Token{Kind: Regex, Text: literal, Pos: start, Literal: pattern}, nil
			}
			if end == 0 || l.source[end-1] != '\\' {
				switch char {
				case '(', '[', '{':
					depth++
				case ')', ']', '}':
					depth--
				}
			}
			_, n := utf8.DecodeRuneInString(l.source[end:])
			end += n
		}
		position := len(utf16.Encode([]rune(l.source[:end])))
		return Token{}, &ParseError{Code: "S0302", Position: position, Message: "unterminated regular expression literal"}
	}
	if r == '`' {
		return l.stringToken(start, true)
	}
	if r == '$' {
		l.advance()
		if l.peek() == '$' {
			l.advance()
			return Token{Kind: Identifier, Text: "$$", Pos: start}, nil
		}
		return Token{Kind: Dollar, Text: "$", Pos: start}, nil
	}
	for _, op := range []string{"!=", "<=", ">=", "??", ":=", "?:", "~>", "..", "**"} {
		if strings.HasPrefix(l.source[l.bytePos:], op) {
			for range op {
				l.advance()
			}
			return Token{Kind: Operator, Text: op, Pos: start}, nil
		}
	}
	switch r {
	case '[':
		l.advance()
		return Token{Kind: LBracket, Text: "[", Pos: start}, nil
	case ']':
		l.advance()
		return Token{Kind: RBracket, Text: "]", Pos: start}, nil
	case '{':
		l.advance()
		return Token{Kind: LBrace, Text: "{", Pos: start}, nil
	case '}':
		l.advance()
		return Token{Kind: RBrace, Text: "}", Pos: start}, nil
	case '(':
		l.advance()
		return Token{Kind: LParen, Text: "(", Pos: start}, nil
	case ')':
		l.advance()
		return Token{Kind: RParen, Text: ")", Pos: start}, nil
	case ',':
		l.advance()
		return Token{Kind: Comma, Text: ",", Pos: start}, nil
	case ':':
		l.advance()
		return Token{Kind: Colon, Text: ":", Pos: start}, nil
	case ';':
		l.advance()
		return Token{Kind: Semicolon, Text: ";", Pos: start}, nil
	case '!', '-', '.', '+', '*', '/', '%', '^', '=', '<', '>', '&', '|', '@', '#', '?':
		l.advance()
		return Token{Kind: Operator, Text: string(r), Pos: start}, nil
	}
	l.advance()
	return Token{}, l.error("S0201", string(r), fmt.Sprintf("unexpected token %q", r), start)
}

func regexDelimiterUnescaped(source string, position int) bool {
	backslashes := 0
	for index := position - 1; index >= 0 && source[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 0
}

func validateRegexLiteral(literal string, start Position) (jsonregex.Pattern, *ParseError) {
	pattern, err := jsonregex.CompileLiteral(literal)
	if err != nil {
		code := "S0302"
		message := err.Error()
		if compileErr, ok := err.(*jsonregex.CompileError); ok {
			code = compileErr.Code
			message = compileErr.Message
		}
		return jsonregex.Pattern{}, &ParseError{Code: code, Token: literal, Value: literal, Position: start.Offset + 1, Message: message}
	}
	return pattern, nil
}

func regexStart(source string, at int) bool {
	for at > 0 {
		at--
		r := rune(source[at])
		if unicode.IsSpace(r) {
			continue
		}
		return strings.ContainsRune("([{,:;=!?&|~>", r)
	}
	return true
}
func (l *Lexer) word(start Position) (Token, *ParseError) {
	b := l.bytePos
	for {
		r := l.peek()
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$') {
			break
		}
		l.advance()
	}
	s := l.source[b:l.bytePos]
	switch s {
	case "true":
		return Token{Kind: True, Text: s, Pos: start}, nil
	case "false":
		return Token{Kind: False, Text: s, Pos: start}, nil
	case "null":
		return Token{Kind: Null, Text: s, Pos: start}, nil
	case "and", "or", "in":
		return Token{Kind: Operator, Text: s, Pos: start}, nil
	}
	return Token{Kind: Identifier, Text: s, Pos: start}, nil
}
func (l *Lexer) number(start Position) (Token, *ParseError) {
	b := l.bytePos
	if l.peek() == '-' {
		l.advance()
	}
	if l.peek() == '0' && l.bytePos+1 < len(l.source) {
		prefix := l.source[l.bytePos : l.bytePos+2]
		if strings.Contains("xXbBoO", prefix[1:]) {
			l.advance()
			l.advance()
			digits := l.bytePos
			for {
				r := l.peek()
				valid := unicode.IsDigit(r) || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
				if prefix[1] == 'b' || prefix[1] == 'B' {
					valid = r == '0' || r == '1'
				}
				if prefix[1] == 'o' || prefix[1] == 'O' {
					valid = r >= '0' && r <= '7'
				}
				if !valid {
					break
				}
				l.advance()
			}
			if digits == l.bytePos {
				return Token{}, l.error("S0101", l.source[b:l.bytePos], "invalid number literal", start)
			}
			literal := l.source[b:l.bytePos]
			value, err := parseNumberLiteral(literal)
			if err != nil {
				// Non-decimal literals historically defer overflow handling to
				// evaluation. Keep that behavior while caching valid values.
				return Token{Kind: Number, Text: literal, Pos: start}, nil
			}
			return Token{Kind: Number, Text: literal, Pos: start, NumberValue: value, NumberParsed: true}, nil
		}
	}
	if l.peek() == '0' {
		l.advance()
	} else if unicode.IsDigit(l.peek()) {
		for unicode.IsDigit(l.peek()) {
			l.advance()
		}
	} else {
		return Token{}, l.error("S0201", l.source[b:l.bytePos], "invalid number literal", start)
	}
	if l.peek() == '.' && !(l.bytePos+1 < len(l.source) && l.source[l.bytePos+1] == '.') {
		l.advance()
		if !unicode.IsDigit(l.peek()) {
			return Token{}, l.error("S0201", l.source[b:l.bytePos], "invalid number literal", start)
		}
		for unicode.IsDigit(l.peek()) {
			l.advance()
		}
	}
	if r := l.peek(); r == 'e' || r == 'E' {
		l.advance()
		if r = l.peek(); r == '+' || r == '-' {
			l.advance()
		}
		if !unicode.IsDigit(l.peek()) {
			return Token{}, l.error("S0201", l.source[b:l.bytePos], "invalid exponent", start)
		}
		for unicode.IsDigit(l.peek()) {
			l.advance()
		}
	}
	s := l.source[b:l.bytePos]
	value, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return Token{}, l.error("S0102", s, "number out of range", start)
	}
	return Token{Kind: Number, Text: s, Pos: start, NumberValue: value, NumberParsed: true}, nil
}

func parseNumberLiteral(s string) (float64, error) {
	sign := int64(1)
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = s[1:]
	}
	base := 10
	if len(s) > 2 && s[0] == '0' {
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'b', 'B':
			base = 2
		case 'o', 'O':
			base = 8
		}
	}
	if base != 10 {
		n, err := strconv.ParseInt(s[2:], base, 64)
		return float64(sign * n), err
	}
	n, err := strconv.ParseFloat(s, 64)
	return float64(sign) * n, err
}
func (l *Lexer) stringToken(start Position, backtick bool) (Token, *ParseError) {
	quote := l.advance()
	b := l.bytePos
	escaped := false
	for {
		r := l.peek()
		if r == utf8.RuneError && l.bytePos >= len(l.source) {
			if backtick {
				return Token{}, l.error("S0105", "", "unterminated quoted property name", l.pos())
			}
			if start.Byte > 0 {
				previous := l.source[start.Byte-1]
				if unicode.IsLetter(rune(previous)) || unicode.IsDigit(rune(previous)) {
					return Token{Kind: String, Pos: start}, nil
				}
			}
			return Token{}, l.error("S0101", "", "unterminated string literal", l.pos())
		}
		l.advance()
		if backtick {
			if r == '`' {
				return Token{Kind: Identifier, Text: l.source[b : l.bytePos-1], Pos: start}, nil
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == quote {
			content := l.source[b : l.bytePos-1]
			var s any
			var err error
			if quote == '\'' {
				s, err = decodeSingleQuoted(content)
			} else {
				s, err = decodeDoubleQuoted(content)
			}
			if err != nil {
				code := "S0103"
				if strings.Contains(content, `\u`) {
					code = "S0104"
				}
				return Token{}, l.error(code, string(quote)+content+string(quote), "invalid string escape", start)
			}
			if text, ok := s.(string); ok {
				return Token{Kind: String, Text: text, Pos: start}, nil
			}
			return Token{Kind: String, Pos: start, Literal: s}, nil
		}
	}
}

func decodeSingleQuoted(content string) (any, error) {
	return decodeQuotedString(content)
}

func decodeDoubleQuoted(content string) (any, error) {
	return decodeQuotedString(content)
}

func decodeQuotedString(content string) (any, error) {
	units := make([]uint16, 0, len(content))
	for i := 0; i < len(content); i++ {
		if content[i] != '\\' {
			r, size := utf8.DecodeRuneInString(content[i:])
			if r == utf8.RuneError && size == 1 {
				return nil, strconv.ErrSyntax
			}
			units = appendRuneUnits(units, r)
			i += size - 1
			continue
		}
		if i+1 >= len(content) {
			return "", strconv.ErrSyntax
		}
		i++
		switch content[i] {
		case '\\', '/', '\'', '"':
			units = append(units, uint16(content[i]))
		case 'b':
			units = append(units, '\b')
		case 'f':
			units = append(units, '\f')
		case 'n':
			units = append(units, '\n')
		case 'r':
			units = append(units, '\r')
		case 't':
			units = append(units, '\t')
		case 'u':
			if i+4 >= len(content) {
				return nil, strconv.ErrSyntax
			}
			code, parseErr := strconv.ParseUint(content[i+1:i+5], 16, 16)
			if parseErr != nil {
				return nil, parseErr
			}
			units = append(units, uint16(code))
			i += 4
		default:
			return nil, strconv.ErrSyntax
		}
	}
	if hasUnpairedSurrogate(units) {
		return UTF16String{Units: units}, nil
	}
	return string(utf16.Decode(units)), nil
}

func appendRuneUnits(units []uint16, r rune) []uint16 {
	if r <= 0xffff {
		return append(units, uint16(r))
	}
	high, low := utf16.EncodeRune(r)
	return append(units, uint16(high), uint16(low))
}

func hasUnpairedSurrogate(units []uint16) bool {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return true
			}
			index++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return true
		}
	}
	return false
}

type ParseError struct {
	Code, Token, Value, Message string
	Position                    int
}

func (e *ParseError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

type Node interface{ node() }
type Literal struct {
	Kind         TokenKind
	Value        any
	Pos          Position
	NumberValue  float64
	NumberParsed bool
	RegexValue   jsonregex.Pattern
	RegexParsed  bool
}

func (Literal) node() {}

type Name struct {
	Value string
	Pos   Position
}

func (Name) node() {}

type VariableKind uint8

const (
	VariableNamed VariableKind = iota
	VariableFocus
	VariableRoot
)

type Variable struct {
	Name string
	Kind VariableKind
	Pos  Position
}

func (Variable) node() {}

type Path struct {
	Base   Node
	Fields []Name
	Pos    Position
}

func (Path) node() {}

type Array struct {
	Items         []Node
	Pos           Position
	FlattenInPath bool
}

func (Array) node() {}

type Block struct {
	Expressions []Node
	Pos         Position
}

func (Block) node() {}

type Pair struct {
	Key     string
	KeyExpr Node
	Value   Node
	Pos     Position
}
type Object struct {
	Pairs []Pair
	Pos   Position
}

func (Object) node() {}

type Binary struct {
	Op          string
	Left, Right Node
	Pos         Position
}

func (Binary) node() {}

type Bind struct {
	Variable Variable
	Value    Node
	Pos      Position
}

func (Bind) node() {}

type Apply struct {
	Left, Right Node
	Pos         Position
}

func (Apply) node() {}

type Unary struct {
	Op   string
	Expr Node
	Pos  Position
}

func (Unary) node() {}

type Selector struct {
	Base, Index Node
	Pos         Position
}

func (Selector) node() {}

type Wildcard struct {
	Recursive bool
	Pos       Position
}

func (Wildcard) node() {}

type Parent struct{ Pos Position }

func (Parent) node() {}

type Transform struct {
	Path, Update, Delete Node
	Pos                  Position
}

func (Transform) node() {}

type Call struct {
	Function         Node
	Args             []Node
	Partial          bool
	ProcedureGrouped bool
	Pos              Position
}

func (Call) node() {}

type Placeholder struct{ Pos Position }

func (Placeholder) node() {}

type Lambda struct {
	Params    []Variable
	Signature string
	Body      Node
	Pos       Position
}

func (Lambda) node() {}

type Parser struct {
	tokens              []Token
	index, depth        int
	allowParentOperator bool
	source              string
}

func Parse(source string) (Node, *ParseError) {
	ts, err := Lex(source)
	if err != nil {
		return nil, err
	}
	p := &Parser{tokens: ts, source: source}
	n, e := p.expression(0)
	if e != nil {
		return nil, e
	}
	if p.peek().Kind != EOF {
		return nil, p.error("S0201", p.peek(), "unexpected token")
	}
	return n, nil
}
func (p *Parser) peek() Token {
	if p.index >= len(p.tokens) {
		return Token{Kind: EOF}
	}
	return p.tokens[p.index]
}
func (p *Parser) take() Token {
	t := p.peek()
	if p.index < len(p.tokens) {
		p.index++
	}
	return t
}

func variableKind(value string) VariableKind {
	switch value {
	case "$":
		return VariableFocus
	case "$$":
		return VariableRoot
	default:
		return VariableNamed
	}
}

func nameNode(value string, pos Position) Name {
	return Name{Value: value, Pos: pos}
}

func variableNode(value string, pos Position) Variable {
	return Variable{Name: value, Kind: variableKind(value), Pos: pos}
}
func (p *Parser) error(code string, t Token, msg string) *ParseError {
	if code == "S0207" && t.Kind == EOF {
		return &ParseError{Code: code, Token: "(end)", Value: "(end)", Position: t.Pos.Offset, Message: msg}
	}
	position := t.Pos.Offset + 1
	return &ParseError{Code: code, Token: t.Text, Value: t.Text, Position: position, Message: msg}
}
func precedence(op string) (int, bool) {
	switch op {
	case ";":
		return 1, false
	case ":=":
		return 1, true
	case "?", "?:":
		return 2, true
	case "??":
		return 3, true
	case "or":
		return 5, false
	case "and":
		return 6, false
	case "=", "!=", "<", "<=", ">", ">=", "in", "~>":
		return 7, false
	case "&":
		return 8, false
	case "..":
		return 9, false
	case "+", "-":
		return 10, false
	case "*", "/", "%":
		return 11, false
	case "^":
		return 12, true
	case "@":
		return 13, false
	}
	return -1, false
}
func (p *Parser) expression(min int) (Node, *ParseError) {
	p.depth++
	if p.depth > 512 {
		p.depth--
		return nil, p.error("S1001", p.peek(), "maximum nesting depth exceeded")
	}
	defer func() { p.depth-- }()
	left, err := p.prefix()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.Kind == Operator && t.Text == "?" {
			if 2 < min {
				break
			}
			p.take()
			yes, e := p.expression(0)
			if e != nil {
				return nil, e
			}
			if p.peek().Kind == Colon {
				p.take()
				no, e := p.expression(2)
				if e != nil {
					return nil, e
				}
				left = Binary{"?", left, Binary{":", yes, no, t.Pos}, t.Pos}
			} else {
				left = Binary{"?", left, yes, t.Pos}
			}
			continue
		}
		if t.Kind == LBrace {
			if groupingStep(left) {
				return nil, p.error("S0210", t, "each step can only have one grouping expression")
			}
			right, e := p.object()
			if e != nil {
				return nil, e
			}
			left = Binary{".", left, right, t.Pos}
			left, err = p.postfix(left)
			if err != nil {
				return nil, err
			}
			continue
		}
		if t.Kind != Operator {
			break
		}
		if t.Text == "." {
			if 14 <= min {
				break
			}
			p.take()
			if p.peek().Kind == Number && (p.index+1 >= len(p.tokens) || p.tokens[p.index+1].Kind != Identifier) {
				number := p.peek()
				return nil, p.error("S0213", number, "literal value cannot be used as a path step")
			}
			rightStart := p.peek()
			if p.peek().Kind == Operator && p.peek().Text == "%" {
				count := 0
				for p.index+count < len(p.tokens) && p.tokens[p.index+count].Kind == Operator && p.tokens[p.index+count].Text == "%" {
					count++
				}
				if count == 2 {
					return nil, p.error("S0207", p.tokens[p.index+1], "unexpected end of expression")
				}
				if count > 2 {
					return nil, p.error("S0217", p.peek(), "parent operator cannot be used here")
				}
			}
			parentAllowed := p.allowParentOperator
			p.allowParentOperator = true
			right, e := p.expression(15)
			p.allowParentOperator = parentAllowed
			if e != nil {
				return nil, e
			}
			if _, parent := right.(Parent); parent && !parentAllowed && !containsParent(left) && !emptyGrouping(left) {
				return nil, p.error("S0217", rightStart, "parent operator cannot be used here")
			}
			left = Binary{".", left, right, t.Pos}
			continue
		}
		if (t.Text == "@" || t.Text == "#") && t.Kind == Operator {
			if t.Text == "@" {
				if b, ok := left.(Binary); ok && b.Op == "^" {
					return nil, p.error("S0216", t, "binding cannot follow a sort")
				}
				if selector, ok := left.(Selector); ok {
					if _, simpleIndex := selector.Index.(Literal); simpleIndex {
						return nil, p.error("S0215", t, "binding cannot follow an array filter")
					}
				}
			}
			n, e := p.binding(left, t)
			if e != nil {
				return nil, e
			}
			left = n
			continue
		}
		prec, assoc := precedence(t.Text)
		if prec < min {
			break
		}
		if t.Text == ";" {
			if p.index+1 < len(p.tokens) && p.tokens[p.index+1].Kind == RParen {
				break
			}
			if p.index+1 >= len(p.tokens) || p.tokens[p.index+1].Kind == EOF {
				p.take()
				return nil, p.error("S0201", t, "unexpected token")
			}
		}
		p.take()
		next := prec + 1
		if assoc {
			next = prec
		}
		if t.Text == "^" {
			// A sort key is followed by the outer path (for example
			// `items^($key).name`). Keep that path outside the key expression.
			next = 14
		}
		right, e := p.expression(next)
		if e != nil {
			return nil, e
		}
		switch t.Text {
		case ":=":
			if !assignable(left) {
				return nil, p.assignmentError(left)
			}
			name := left.(Variable)
			left = Bind{Variable: name, Value: right, Pos: t.Pos}
		case "~>":
			left = Apply{Left: left, Right: right, Pos: t.Pos}
		default:
			left = Binary{t.Text, left, right, t.Pos}
		}
	}
	return left, nil
}
func (p *Parser) prefix() (Node, *ParseError) {
	t := p.take()
	if t.Kind == EOF {
		return nil, p.error("S0207", t, "unexpected end of expression")
	}
	switch t.Kind {
	case String:
		literal := any(t.Text)
		if t.Literal != nil {
			literal = t.Literal
		}
		return p.postfix(Literal{Kind: String, Value: literal, Pos: t.Pos})
	case Number:
		return p.postfix(Literal{Kind: Number, Value: t.Text, Pos: t.Pos, NumberValue: t.NumberValue, NumberParsed: t.NumberParsed})
	case Regex:
		regex := Literal{Kind: Regex, Value: t.Text, Pos: t.Pos}
		if pattern, ok := t.Literal.(jsonregex.Pattern); ok {
			regex.RegexValue, regex.RegexParsed = pattern, true
		}
		return p.postfix(regex)
	case True, False:
		return p.postfix(Literal{Kind: t.Kind, Value: t.Kind == True, Pos: t.Pos})
	case Null:
		return p.postfix(Literal{Kind: Null, Pos: t.Pos})
	case Identifier:
		if t.Text == "$$" {
			return p.postfix(variableNode(t.Text, t.Pos))
		}
		return p.postfix(nameNode(t.Text, t.Pos))
	case Dollar:
		if p.peek().Kind == Identifier {
			name := p.take()
			return p.postfix(variableNode("$"+name.Text, t.Pos))
		}
		return p.postfix(variableNode("$", t.Pos))
	case LParen:
		if p.peek().Kind == RParen {
			p.take()
			return p.postfix(Block{Pos: t.Pos})
		}
		if p.peek().Kind == Operator && p.peek().Text == "%" {
			count := 0
			for p.index+count < len(p.tokens) && p.tokens[p.index+count].Kind == Operator && p.tokens[p.index+count].Text == "%" {
				count++
			}
			if p.index+count < len(p.tokens) && p.tokens[p.index+count].Kind == RParen {
				if count == 1 {
					return nil, p.error("S0217", p.peek(), "parent operator cannot be used here")
				}
				if count == 2 {
					return nil, p.error("S0211", p.tokens[p.index+1], "operator cannot be used as a unary operator")
				}
				var n Node
				for i := 0; i < count; i++ {
					part := p.take()
					if n == nil {
						n = Parent{part.Pos}
					} else {
						n = Binary{"%", n, Parent{part.Pos}, part.Pos}
					}
				}
				p.take()
				return p.postfix(n)
			}
		}
		parentAllowed := p.allowParentOperator
		p.allowParentOperator = true
		n, e := p.expression(0)
		if e != nil {
			p.allowParentOperator = parentAllowed
			return nil, e
		}
		if p.peek().Kind == Comma {
			items := []Node{n}
			for p.peek().Kind == Comma {
				p.take()
				item, itemErr := p.expression(0)
				if itemErr != nil {
					p.allowParentOperator = parentAllowed
					return nil, itemErr
				}
				items = append(items, item)
			}
			n = Array{Items: items, Pos: t.Pos}
		} else if p.peek().Kind == Semicolon {
			expressions := []Node{n}
			for p.peek().Kind == Semicolon {
				p.take()
				if p.peek().Kind == RParen {
					break
				}
				item, itemErr := p.expression(0)
				if itemErr != nil {
					p.allowParentOperator = parentAllowed
					return nil, itemErr
				}
				expressions = append(expressions, item)
			}
			n = Block{Expressions: expressions, Pos: t.Pos}
		} else if _, binding := n.(Bind); binding {
			n = Block{Expressions: []Node{n}, Pos: t.Pos}
		}
		if array, ok := n.(Array); ok {
			array.FlattenInPath = true
			n = array
		}
		p.allowParentOperator = parentAllowed
		if _, e = p.expect(RParen); e != nil {
			return nil, e
		}
		return p.postfixNode(n, true)
	case LBracket:
		p.index--
		n, e := p.array()
		if e != nil {
			return nil, e
		}
		return p.postfix(n)
	case LBrace:
		p.index--
		n, e := p.object()
		if e != nil {
			return nil, e
		}
		return p.postfix(n)
	case Operator:
		// These words are both operators and valid unquoted field names.
		// At expression start they are names (for example `and=1`).
		if t.Text == "and" || t.Text == "or" || t.Text == "in" {
			return p.postfix(nameNode(t.Text, t.Pos))
		}
		if t.Text == "#" {
			return p.postfix(nameNode("#", t.Pos))
		}
		if t.Text == "!" {
			return nil, p.error("S0204", t, "unknown operator")
		}
		if t.Text == "@" || t.Text == ":" || (t.Text == ">" && p.index >= 2 && p.tokens[p.index-2].Text == "=") {
			return nil, p.error("S0211", t, "operator cannot be used as a unary operator")
		}
		if t.Text == "?" {
			return nil, p.error("S0211", t, "operator cannot be used as a unary operator")
		}
		if t.Text == "-" || t.Text == "+" || t.Text == "not" {
			n, e := p.expression(13)
			if e != nil {
				return nil, e
			}
			return p.postfix(Unary{t.Text, n, t.Pos})
		}
		if t.Text == "<" || t.Text == ">" {
			n, e := p.expression(13)
			if e != nil {
				return nil, e
			}
			return p.postfix(Unary{t.Text, n, t.Pos})
		}
		if t.Text == "*" {
			return p.postfix(Wildcard{false, t.Pos})
		}
		if t.Text == "**" {
			return p.postfix(Wildcard{true, t.Pos})
		}
		if t.Text == "|" {
			return p.transform(t)
		}
		if t.Text == "%" {
			if !p.allowParentOperator && p.peek().Kind != LParen && !(p.peek().Kind == Operator && p.peek().Text == "%") {
				return nil, p.error("S0217", t, "parent operator cannot be used here")
			}
			return p.postfix(Parent{t.Pos})
		}
	case Colon:
		return nil, p.error("S0211", t, "operator cannot be used as a unary operator")
	}
	return nil, p.error("S0201", t, "unexpected token")
}

func (p *Parser) transform(open Token) (Node, *ParseError) {
	path, err := p.expression(0)
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != Operator || p.peek().Text != "|" {
		return nil, p.error("S0202", p.peek(), "expected transform path terminator")
	}
	p.take()
	update, err := p.expression(0)
	if err != nil {
		return nil, err
	}
	var deleteExpr Node
	if p.peek().Kind == Comma {
		p.take()
		deleteExpr, err = p.expression(0)
		if err != nil {
			return nil, err
		}
	}
	if p.peek().Kind != Operator || p.peek().Text != "|" {
		return nil, p.error("S0202", p.peek(), "expected transform update terminator")
	}
	p.take()
	return p.postfix(Transform{Path: path, Update: update, Delete: deleteExpr, Pos: open.Pos})
}

func (p *Parser) postfix(n Node) (Node, *ParseError) {
	return p.postfixNode(n, false)
}

func (p *Parser) postfixNode(n Node, procedureGrouped bool) (Node, *ParseError) {
	for {
		t := p.peek()
		grouped := procedureGrouped
		procedureGrouped = false
		switch t.Kind {
		case LParen:
			p.take()
			args := make([]Node, 0, 1)
			partial := false
			if p.peek().Kind != RParen {
				for {
					var arg Node
					var e *ParseError
					if p.peek().Kind == Operator && p.peek().Text == "?" {
						placeholder := p.take()
						arg = Placeholder{Pos: placeholder.Pos}
						partial = true
					} else {
						arg, e = p.expression(0)
					}
					if e != nil {
						return nil, e
					}
					args = append(args, arg)
					if p.peek().Kind != Comma {
						if p.peek().Kind == Identifier && p.index+2 < len(p.tokens) && p.tokens[p.index+1].Kind == String && p.tokens[p.index+2].Kind == RParen {
							bad := p.peek()
							close := p.tokens[p.index+2]
							return nil, &ParseError{Code: "S0202", Token: bad.Text + "\"", Value: close.Text, Position: close.Pos.Offset, Message: "unexpected token"}
						}
						break
					}
					p.take()
				}
			}
			if _, e := p.expect(RParen); e != nil {
				return nil, e
			}
			if function, ok := n.(Name); ok && (function.Value == "function" || function.Value == "λ") {
				lambda, e := p.lambda(function, args, t.Pos)
				if e != nil {
					return nil, e
				}
				n = lambda
			} else {
				n = Call{Function: n, Args: args, Partial: partial, ProcedureGrouped: grouped, Pos: t.Pos}
			}
		case LBracket:
			open := t
			p.take()
			var idx Node
			var e *ParseError
			if p.peek().Kind != RBracket {
				parentAllowed := p.allowParentOperator
				p.allowParentOperator = true
				idx, e = p.expression(0)
				p.allowParentOperator = parentAllowed
				if e != nil {
					return nil, e
				}
			}
			if _, e = p.expect(RBracket); e != nil {
				return nil, e
			}
			if groupingStep(n) && idx != nil {
				return nil, p.error("S0209", open, "a predicate cannot follow a grouping expression in a step")
			}
			n = Selector{n, idx, t.Pos}
		case Operator:
			if t.Text == "@" || t.Text == "#" {
				p.take()
				if t.Text == "@" {
					if unary, ok := n.(Unary); ok && (unary.Op == "<" || unary.Op == ">") {
						return nil, p.error("S0216", t, "binding cannot follow a sort")
					}
				}
				if selector, invalidFilter := n.(Selector); invalidFilter {
					if _, simpleIndex := selector.Index.(Literal); simpleIndex {
						return nil, p.error("S0215", t, "binding cannot follow an array filter")
					}
				}
				var e *ParseError
				n, e = p.binding(n, t)
				if e != nil {
					return nil, e
				}
				continue
			}
			return n, nil
		default:
			return n, nil
		}
	}
}

func (p *Parser) binding(left Node, operator Token) (Node, *ParseError) {
	name := p.peek()
	if name.Kind != Dollar {
		return nil, p.error("S0214", operator, "binding name must start with $")
	}
	p.take()
	name = p.take()
	if name.Kind != Identifier {
		return nil, p.error("S0214", name, "expected binding name")
	}
	return Binary{operator.Text, left, variableNode("$"+name.Text, name.Pos), operator.Pos}, nil
}

func (p *Parser) lambda(function Name, args []Node, pos Position) (Lambda, *ParseError) {
	params := make([]Variable, len(args))
	for i, arg := range args {
		name, ok := arg.(Variable)
		if !ok || !strings.HasPrefix(name.Name, "$") || name.Name == "$" || name.Name == "$$" {
			value := ""
			argPos := pos
			if name, ok := arg.(Variable); ok {
				value = name.Name
				argPos = name.Pos
			} else if name, ok := arg.(Name); ok {
				value = name.Value
				argPos = name.Pos
			} else if literal, ok := arg.(Literal); ok {
				value = fmt.Sprint(literal.Value)
				argPos = literal.Pos
			}
			return Lambda{}, &ParseError{Code: "S0208", Token: value, Value: strconv.Itoa(i + 1), Position: argPos.Offset + 1, Message: "parameter must be a variable name"}
		}
		params[i] = name
	}

	signature := ""
	if p.peek().Kind == Operator && p.peek().Text == "<" {
		var err *ParseError
		signature, err = p.readSignature()
		if err != nil {
			return Lambda{}, err
		}
	}
	if _, err := p.expect(LBrace); err != nil {
		return Lambda{}, err
	}
	body, err := p.expression(0)
	if err != nil {
		return Lambda{}, err
	}
	if _, err = p.expect(RBrace); err != nil {
		return Lambda{}, err
	}
	return Lambda{Params: params, Signature: signature, Body: body, Pos: pos}, nil
}

func (p *Parser) readSignature() (string, *ParseError) {
	open := p.take()
	depth := 1
	close := open
	for depth > 0 {
		t := p.peek()
		if t.Kind == EOF {
			return "", p.error("S0202", t, "unexpected end of signature")
		}
		p.take()
		close = t
		if t.Kind == Operator && t.Text == "<" {
			depth++
		} else if t.Kind == Operator && t.Text == ">" {
			depth--
		}
	}
	start := open.Pos.Byte
	end := close.Pos.Byte + len(close.Text)
	if start < 0 || end > len(p.source) || start > end {
		return "", p.error("S0202", close, "invalid signature")
	}
	raw := p.source[start:end]
	if err := validateSignature(raw, open.Pos); err != nil {
		return "", err
	}
	return raw, nil
}

func validateSignature(raw string, start Position) *ParseError {
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '(':
			end := matchingSignatureDelimiter(raw, i, '(', ')')
			if end < 0 {
				return nil
			}
			choice := raw[i+1 : end]
			if strings.Contains(choice, "<") {
				return &ParseError{Code: "S0402", Value: choice, Position: start.Offset + i + 1, Message: "choice groups containing parameterized types are not supported"}
			}
		case '<':
			if i == 0 {
				continue
			}
			j := i - 1
			for j >= 0 && (raw[j] == ' ' || raw[j] == '\t') {
				j--
			}
			if j < 0 || (raw[j] != 'a' && raw[j] != 'f') {
				value := ""
				if j >= 0 {
					value = string(raw[j])
				}
				return &ParseError{Code: "S0401", Value: value, Position: start.Offset + i + 1, Message: "type parameters can only be applied to functions and arrays"}
			}
		}
	}
	return nil
}

func matchingSignatureDelimiter(raw string, start int, open, close byte) int {
	depth := 1
	for i := start + 1; i < len(raw); i++ {
		switch raw[i] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func assignable(n Node) bool {
	name, ok := n.(Variable)
	return ok && name.Kind == VariableNamed && name.Name != ""
}

func (p *Parser) assignmentError(n Node) *ParseError {
	pos := Position{}
	token := ""
	switch x := n.(type) {
	case Variable:
		pos, token = x.Pos, x.Name
	case Name:
		pos, token = x.Pos, x.Value
	case Literal:
		pos = x.Pos
		token = fmt.Sprint(x.Value)
	case Selector:
		pos, token = x.Pos, "["
	case Binary:
		pos, token = x.Pos, x.Op
	default:
		return p.error("S0212", p.peek(), "the left side of := must be a variable name")
	}
	return &ParseError{Code: "S0212", Token: token, Position: pos.Offset + 1, Message: "the left side of := must be a variable name"}
}

func (p *Parser) parentExpression(min int) (Node, *ParseError) {
	parentAllowed := p.allowParentOperator
	p.allowParentOperator = true
	n, err := p.expression(min)
	p.allowParentOperator = parentAllowed
	return n, err
}

func containsParent(n Node) bool {
	switch x := n.(type) {
	case Parent:
		return true
	case Binary:
		return containsParent(x.Left) || containsParent(x.Right)
	case Selector:
		return containsParent(x.Base) || containsParent(x.Index)
	case Array:
		for _, item := range x.Items {
			if containsParent(item) {
				return true
			}
		}
	case Block:
		for _, item := range x.Expressions {
			if containsParent(item) {
				return true
			}
		}
	case Object:
		for _, pair := range x.Pairs {
			if containsParent(pair.KeyExpr) || containsParent(pair.Value) {
				return true
			}
		}
	case Unary:
		return containsParent(x.Expr)
	case Call:
		if containsParent(x.Function) {
			return true
		}
		for _, arg := range x.Args {
			if containsParent(arg) {
				return true
			}
		}
	case Lambda:
		return containsParent(x.Body)
	case Apply:
		return containsParent(x.Left) || containsParent(x.Right)
	case Bind:
		return containsParent(x.Value)
	}
	return false
}

func emptyGrouping(n Node) bool {
	binary, ok := n.(Binary)
	if !ok || binary.Op != "." {
		return false
	}
	block, ok := binary.Right.(Block)
	return ok && len(block.Expressions) == 0
}

func groupingStep(n Node) bool {
	binary, ok := n.(Binary)
	if !ok || binary.Op != "." {
		return false
	}
	if _, object := binary.Right.(Object); object {
		return true
	}
	return groupingStep(binary.Left) || groupingStep(binary.Right)
}
func (p *Parser) expect(k TokenKind) (Token, *ParseError) {
	t := p.peek()
	if t.Kind != k {
		if t.Kind == EOF {
			return Token{}, p.error("S0203", t, "unexpected end of expression")
		}
		return Token{}, p.error("S0202", t, "unexpected token")
	}
	return p.take(), nil
}
func (p *Parser) array() (Node, *ParseError) {
	open := p.take()
	a := Array{Pos: open.Pos}
	if p.peek().Kind == RBracket {
		p.take()
		return a, nil
	}
	for {
		n, e := p.parentExpression(0)
		if e != nil {
			return nil, e
		}
		a.Items = append(a.Items, n)
		if p.peek().Kind == RBracket {
			p.take()
			return a, nil
		}
		if p.peek().Kind != Comma {
			if p.peek().Kind == Operator && p.peek().Text == "!" {
				return nil, p.error("S0204", p.peek(), "unknown operator")
			}
			return nil, p.error("S0202", p.peek(), "expected comma or closing bracket")
		}
		p.take()
		if p.peek().Kind == RBracket {
			return nil, p.error("S0201", p.peek(), "trailing comma")
		}
	}
}
func (p *Parser) object() (Node, *ParseError) {
	open := p.take()
	o := Object{Pos: open.Pos}
	if p.peek().Kind == RBrace {
		p.take()
		return o, nil
	}
	for {
		k := p.peek()
		var keyExpr Node
		if k.Kind == String && p.index+1 < len(p.tokens) && p.tokens[p.index+1].Kind == Colon {
			p.take()
			literal := any(k.Text)
			if k.Literal != nil {
				literal = k.Literal
			}
			keyExpr = Literal{Kind: String, Value: literal, Pos: k.Pos}
		} else {
			var e *ParseError
			keyExpr, e = p.parentExpression(0)
			if e != nil {
				return nil, e
			}
		}
		if _, e := p.expect(Colon); e != nil {
			return nil, e
		}
		v, e := p.parentExpression(0)
		if e != nil {
			return nil, e
		}
		pair := Pair{Value: v, Pos: k.Pos}
		if name, ok := keyExpr.(Name); ok {
			pair.Key = name.Value
		} else {
			pair.KeyExpr = keyExpr
		}
		o.Pairs = append(o.Pairs, pair)
		if p.peek().Kind == RBrace {
			p.take()
			return o, nil
		}
		if p.peek().Kind != Comma {
			return nil, p.error("S0202", p.peek(), "expected comma or closing brace")
		}
		p.take()
		if p.peek().Kind == RBrace {
			return nil, p.error("S0201", p.peek(), "trailing comma")
		}
	}
}
