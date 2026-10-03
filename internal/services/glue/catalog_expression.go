package glue

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode"

	api "stackd/internal/awsapi/glue"
)

type partitionPredicate func(api.ValueStringList) (bool, error)
type partitionTruth int8

const (
	partitionUnknown partitionTruth = -1
	partitionFalse   partitionTruth = 0
	partitionTrue    partitionTruth = 1
)

type partitionExpr func(api.ValueStringList) partitionTruth
type partitionToken struct {
	text       string
	quoted     bool
	identifier bool
}
type partitionParser struct {
	tokens  []partitionToken
	pos     int
	columns api.ColumnList
}

func compilePartitionExpression(expression string, columns api.ColumnList) (partitionPredicate, error) {
	if strings.TrimSpace(expression) == "" {
		return func(api.ValueStringList) (bool, error) { return true, nil }, nil
	}
	tokens, err := partitionLex(expression)
	if err != nil {
		return nil, failure("InvalidInputException", err.Error())
	}
	p := partitionParser{tokens: tokens, columns: columns}
	node, err := p.disjunction()
	if err == nil && p.pos != len(tokens) {
		err = fmt.Errorf("unexpected partition expression token %q", tokens[p.pos].text)
	}
	if err != nil {
		return nil, failure("InvalidInputException", err.Error())
	}
	return func(values api.ValueStringList) (bool, error) { return node(values) == partitionTrue, nil }, nil
}
func partitionLex(input string) ([]partitionToken, error) {
	var out []partitionToken
	for i := 0; i < len(input); {
		r := rune(input[i])
		if unicode.IsSpace(r) {
			i++
			continue
		}
		if input[i] == '\'' || input[i] == '"' || input[i] == '`' {
			quote := input[i]
			i++
			var text strings.Builder
			closed := false
			for i < len(input) {
				if input[i] == quote {
					if i+1 < len(input) && input[i+1] == quote {
						text.WriteByte(quote)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				text.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted partition expression")
			}
			out = append(out, partitionToken{text: text.String(), quoted: quote == '\'', identifier: quote != '\''})
			continue
		}
		if strings.ContainsRune("(),=<>!", r) {
			start := i
			i++
			if i < len(input) && ((input[start] == '<' && (input[i] == '=' || input[i] == '>')) || (input[start] == '>' && input[i] == '=') || (input[start] == '!' && input[i] == '=')) {
				i++
			}
			out = append(out, partitionToken{text: input[start:i]})
			continue
		}
		start := i
		for i < len(input) && !unicode.IsSpace(rune(input[i])) && !strings.ContainsRune("(),=<>!'\"`", rune(input[i])) {
			i++
		}
		if i == start {
			return nil, fmt.Errorf("invalid partition expression character")
		}
		out = append(out, partitionToken{text: input[start:i]})
	}
	return out, nil
}
func (p *partitionParser) take(keyword string) bool {
	if p.pos < len(p.tokens) && !p.tokens[p.pos].quoted && !p.tokens[p.pos].identifier && strings.EqualFold(p.tokens[p.pos].text, keyword) {
		p.pos++
		return true
	}
	return false
}
func (p *partitionParser) require(keyword string) error {
	if !p.take(keyword) {
		return fmt.Errorf("expected %s in partition expression", keyword)
	}
	return nil
}
func (p *partitionParser) disjunction() (partitionExpr, error) {
	left, err := p.conjunction()
	if err != nil {
		return nil, err
	}
	for p.take("OR") {
		right, err := p.conjunction()
		if err != nil {
			return nil, err
		}
		a, b := left, right
		left = func(v api.ValueStringList) partitionTruth {
			x, y := a(v), b(v)
			if x == partitionTrue || y == partitionTrue {
				return partitionTrue
			}
			if x == partitionUnknown || y == partitionUnknown {
				return partitionUnknown
			}
			return partitionFalse
		}
	}
	return left, nil
}
func (p *partitionParser) conjunction() (partitionExpr, error) {
	left, err := p.atom()
	if err != nil {
		return nil, err
	}
	for p.take("AND") {
		right, err := p.atom()
		if err != nil {
			return nil, err
		}
		a, b := left, right
		left = func(v api.ValueStringList) partitionTruth {
			x, y := a(v), b(v)
			if x == partitionFalse || y == partitionFalse {
				return partitionFalse
			}
			if x == partitionUnknown || y == partitionUnknown {
				return partitionUnknown
			}
			return partitionTrue
		}
	}
	return left, nil
}
func partitionNegate(node partitionExpr) partitionExpr {
	return func(v api.ValueStringList) partitionTruth {
		result := node(v)
		if result == partitionUnknown {
			return result
		}
		return partitionTrue - result
	}
}
func (p *partitionParser) literal() (partitionToken, error) {
	if p.pos >= len(p.tokens) {
		return partitionToken{}, fmt.Errorf("missing partition expression value")
	}
	v := p.tokens[p.pos]
	if v.identifier || !v.quoted && strings.ContainsAny(v.text, "(),=<>!") {
		return partitionToken{}, fmt.Errorf("expected partition expression literal")
	}
	p.pos++
	return v, nil
}
func (p *partitionParser) atom() (partitionExpr, error) {
	if p.take("NOT") {
		node, err := p.atom()
		if err != nil {
			return nil, err
		}
		return partitionNegate(node), nil
	}
	if p.take("(") {
		node, err := p.disjunction()
		if err != nil {
			return nil, err
		}
		if err := p.require(")"); err != nil {
			return nil, err
		}
		return node, nil
	}
	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("incomplete partition expression")
	}
	column := p.tokens[p.pos]
	p.pos++
	index := -1
	var typ string
	for i, key := range p.columns {
		if strings.EqualFold(value(key.Name), column.text) {
			index = i
			typ = strings.ToLower(value(key.Type))
			break
		}
	}
	if index < 0 {
		return nil, fmt.Errorf("unknown partition key %q", column.text)
	}
	null := func(v api.ValueStringList) bool { return index >= len(v) || v[index] == "__HIVE_DEFAULT_PARTITION__" }
	if p.take("IS") {
		negated := p.take("NOT")
		if err := p.require("NULL"); err != nil {
			return nil, err
		}
		node := partitionExpr(func(v api.ValueStringList) partitionTruth {
			if null(v) {
				return partitionTrue
			}
			return partitionFalse
		})
		if negated {
			node = partitionNegate(node)
		}
		return node, nil
	}
	negated := p.take("NOT")
	var node partitionExpr
	if p.take("IN") {
		if err := p.require("("); err != nil {
			return nil, err
		}
		var comparisons []func(string) (int, bool)
		for {
			literal, err := p.literal()
			if err != nil {
				return nil, err
			}
			comparison, err := partitionComparator(typ, literal)
			if err != nil {
				return nil, err
			}
			comparisons = append(comparisons, comparison)
			if !p.take(",") {
				break
			}
		}
		if err := p.require(")"); err != nil {
			return nil, err
		}
		node = func(v api.ValueStringList) partitionTruth {
			if null(v) {
				return partitionUnknown
			}
			unknown := false
			for _, compare := range comparisons {
				c, ok := compare(string(v[index]))
				if !ok {
					unknown = true
				} else if c == 0 {
					return partitionTrue
				}
			}
			if unknown {
				return partitionUnknown
			}
			return partitionFalse
		}
	} else if p.take("BETWEEN") {
		lo, err := p.literal()
		if err != nil {
			return nil, err
		}
		if err := p.require("AND"); err != nil {
			return nil, err
		}
		hi, err := p.literal()
		if err != nil {
			return nil, err
		}
		lower, err := partitionComparator(typ, lo)
		if err != nil {
			return nil, err
		}
		upper, err := partitionComparator(typ, hi)
		if err != nil {
			return nil, err
		}
		node = func(v api.ValueStringList) partitionTruth {
			if null(v) {
				return partitionUnknown
			}
			a, okA := lower(string(v[index]))
			b, okB := upper(string(v[index]))
			if !okA || !okB {
				return partitionUnknown
			}
			if a >= 0 && b <= 0 {
				return partitionTrue
			}
			return partitionFalse
		}
	} else if p.take("LIKE") {
		literal, err := p.literal()
		if err != nil {
			return nil, err
		}
		var pattern strings.Builder
		pattern.WriteString("(?s)^")
		escaped := false
		for _, r := range literal.text {
			if escaped {
				pattern.WriteString(regexp.QuoteMeta(string(r)))
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '%':
				pattern.WriteString(".*")
			case '_':
				pattern.WriteByte('.')
			default:
				pattern.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		if escaped {
			pattern.WriteString("\\\\")
		}
		pattern.WriteByte('$')
		compiled, err := regexp.Compile(pattern.String())
		if err != nil {
			return nil, err
		}
		node = func(v api.ValueStringList) partitionTruth {
			if null(v) {
				return partitionUnknown
			}
			if compiled.MatchString(string(v[index])) {
				return partitionTrue
			}
			return partitionFalse
		}
	} else {
		if negated {
			return nil, fmt.Errorf("NOT must precede IN, BETWEEN, or LIKE")
		}
		if p.pos >= len(p.tokens) {
			return nil, fmt.Errorf("missing partition comparison operator")
		}
		op := p.tokens[p.pos].text
		p.pos++
		switch op {
		case "=", "!=", "<>", "<", ">", "<=", ">=":
		default:
			return nil, fmt.Errorf("invalid partition comparison operator %q", op)
		}
		literal, err := p.literal()
		if err != nil {
			return nil, err
		}
		compare, err := partitionComparator(typ, literal)
		if err != nil {
			return nil, err
		}
		node = func(v api.ValueStringList) partitionTruth {
			if null(v) {
				return partitionUnknown
			}
			c, ok := compare(string(v[index]))
			if !ok {
				return partitionUnknown
			}
			matches := op == "=" && c == 0 || (op == "!=" || op == "<>") && c != 0 || op == "<" && c < 0 || op == ">" && c > 0 || op == "<=" && c <= 0 || op == ">=" && c >= 0
			if matches {
				return partitionTrue
			}
			return partitionFalse
		}
	}
	if negated {
		node = partitionNegate(node)
	}
	return node, nil
}
func partitionComparator(typ string, literal partitionToken) (func(string) (int, bool), error) {
	if !literal.quoted && strings.EqualFold(literal.text, "NULL") {
		return func(string) (int, bool) { return 0, false }, nil
	}
	numeric := typ == "tinyint" || typ == "smallint" || typ == "int" || typ == "bigint" || typ == "long" || typ == "float" || typ == "double" || strings.HasPrefix(typ, "decimal")
	if numeric {
		expected, ok := new(big.Rat).SetString(literal.text)
		if !ok {
			return nil, fmt.Errorf("invalid numeric partition expression literal %q", literal.text)
		}
		return func(value string) (int, bool) {
			actual, ok := new(big.Rat).SetString(value)
			if !ok {
				return 0, false
			}
			return actual.Cmp(expected), true
		}, nil
	}
	return func(value string) (int, bool) { return strings.Compare(value, literal.text), true }, nil
}
