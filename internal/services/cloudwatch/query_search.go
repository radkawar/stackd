package cloudwatch

import (
	"math"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"stackd/internal/awswire"
)

type metricSearch struct {
	namespace string
	schema    []string
	term      *metricSearchNode
	statistic statisticSpec
	period    int64
}

type metricSearchKind uint8

const (
	metricSearchTerm metricSearchKind = iota
	metricSearchAnd
	metricSearchOr
	metricSearchNot
)

type metricSearchNode struct {
	kind        metricSearchKind
	field, text string
	exact       bool
	tokens      []string
	left, right *metricSearchNode
}

type metricSearchParser struct {
	input string
	at    int
	text  string
	exact bool
	end   bool
	err   *awswire.Error
}

func compileMetricSearch(node *mathNode, inheritedPeriod int64) (*metricSearch, *awswire.Error) {
	bad := func() *awswire.Error { return mathValidation("Invalid arguments for SEARCH.") }
	if len(node.args) < 2 || len(node.args) > 3 || node.args[0].kind != "string" || node.args[1].kind != "string" {
		return nil, bad()
	}
	statistic, ok := parseStatistic(node.args[1].text)
	if !ok {
		return nil, mathValidation("Invalid statistic in SEARCH expression.")
	}
	period := inheritedPeriod
	if len(node.args) == 3 {
		constant := mathEnvironment{
			resolve: func(string) (mathValue, *awswire.Error) { return mathValue{}, bad() },
			metrics: func(string) (mathValue, *awswire.Error) { return mathValue{}, bad() },
			search:  func(*mathNode) (mathValue, *awswire.Error) { return mathValue{}, bad() },
		}
		value, w := constant.evaluate(node.args[2])
		if w != nil {
			return nil, w
		}
		if value.scalar == nil || math.IsNaN(*value.scalar) || math.IsInf(*value.scalar, 0) || *value.scalar >= math.MaxInt64 || *value.scalar < 0 {
			return nil, bad()
		}
		period = int64(*value.scalar)
	} else if period == 0 {
		return nil, mathValidation("Period is a required field when using SEARCH function within an expression")
	}
	if !validPeriod(period) {
		return nil, mathValidation("Invalid Period in SEARCH expression.")
	}
	body := node.args[0].text
	if utf8.RuneCountInString(body) > 1024 {
		return nil, mathValidation("SEARCH expression exceeds 1024 characters.")
	}
	p := metricSearchParser{input: body}
	p.next()
	query := &metricSearch{statistic: statistic, period: period}
	if p.take("{") {
		query.namespace = p.name()
		query.schema = []string{}
		for p.take(",") {
			query.schema = append(query.schema, p.name())
		}
		p.expect("}")
		slices.Sort(query.schema)
		query.schema = slices.Compact(query.schema)
	}
	if !p.end {
		query.term = p.expression(1, "")
	}
	if !p.end && p.err == nil {
		p.err = mathValidation("Unexpected token in SEARCH expression: " + p.text)
	}
	if p.err != nil {
		return nil, p.err
	}
	return query, nil
}

func (p *metricSearchParser) expression(minimum int, field string) *metricSearchNode {
	if p.err != nil {
		return nil
	}
	var left *metricSearchNode
	switch {
	case p.take("NOT"):
		left = &metricSearchNode{kind: metricSearchNot, left: p.expression(3, field)}
	case p.take("("):
		left = p.expression(1, field)
		p.expect(")")
	default:
		if p.end || !p.exact && strings.ContainsAny(p.text, "{}(),=") || !p.exact && (p.text == "AND" || p.text == "OR") {
			p.err = mathValidation("Expected a term in SEARCH expression.")
			return nil
		}
		left = &metricSearchNode{field: field, text: p.text, exact: p.exact}
		p.next()
		if p.take("=") {
			if field != "" {
				p.err = mathValidation("Unexpected nested property in SEARCH expression.")
				return nil
			}
			property := left.text
			if p.take("(") {
				left = p.expression(1, property)
				p.expect(")")
			} else {
				if p.end || !p.exact && strings.ContainsAny(p.text, "{}(),=") {
					p.err = mathValidation("Expected a property value in SEARCH expression.")
					return nil
				}
				left.field, left.text, left.exact = property, p.text, p.exact
				p.next()
			}
		}
		if left != nil && left.kind == metricSearchTerm && !left.exact {
			left.tokens = metricSearchTokens(left.text)
		}
	}
	for p.err == nil && !p.end && (p.exact || p.text != ")") {
		kind, precedence := metricSearchAnd, 2
		explicit := !p.exact && (p.text == "AND" || p.text == "OR")
		if !p.exact && p.text == "OR" {
			kind, precedence = metricSearchOr, 1
		}
		if precedence < minimum {
			break
		}
		if explicit {
			p.next()
		}
		left = &metricSearchNode{kind: kind, left: left, right: p.expression(precedence+1, field)}
	}
	return left
}

func (p *metricSearchParser) take(text string) bool {
	if p.err != nil || p.end || p.exact || p.text != text {
		return false
	}
	p.next()
	return true
}

func (p *metricSearchParser) expect(text string) {
	if !p.take(text) && p.err == nil {
		p.err = mathValidation("Expected " + text + " in SEARCH expression.")
	}
}

func (p *metricSearchParser) name() string {
	if p.end || !p.exact && strings.ContainsAny(p.text, "{}(),=") || p.text == "" {
		p.err = mathValidation("Invalid metric schema in SEARCH expression.")
		return ""
	}
	name := p.text
	p.next()
	return name
}

func (p *metricSearchParser) next() {
	if p.err != nil {
		return
	}
	for p.at < len(p.input) && unicode.IsSpace(rune(p.input[p.at])) {
		p.at++
	}
	p.exact, p.end, p.text = false, p.at == len(p.input), ""
	if p.end {
		return
	}
	c := p.input[p.at]
	p.at++
	if strings.ContainsRune("{}(),=", rune(c)) {
		p.text = string(c)
		return
	}
	var text strings.Builder
	if c == '"' {
		p.exact = true
	} else {
		p.at--
	}
	for p.at < len(p.input) {
		v := p.input[p.at]
		if p.exact && v == '"' {
			p.at++
			p.text = text.String()
			return
		}
		if !p.exact && (unicode.IsSpace(rune(v)) || strings.ContainsRune("{}(),=", rune(v))) {
			break
		}
		p.at++
		if v == '\\' && p.at < len(p.input) {
			v = p.input[p.at]
			p.at++
		}
		text.WriteByte(v)
	}
	p.text = text.String()
	if p.exact {
		p.err = mathValidation("Unterminated quoted value in SEARCH expression.")
	}
}

// Token boundaries are meaningful in both operands. A query token may span
// adjacent identity tokens, but cannot split one: customcount matches
// CustomCount1 while couNT does not match Count.
func metricSearchTokens(text string) []string {
	var tokens []string
	start := -1
	var previous rune
	for at, r := range text {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			if start >= 0 {
				tokens = append(tokens, text[start:at])
			}
			start, previous = -1, 0
			continue
		}
		if start < 0 {
			start = at
		} else {
			next, _ := utf8.DecodeRuneInString(text[at+utf8.RuneLen(r):])
			if unicode.IsDigit(previous) != unicode.IsDigit(r) || unicode.IsLower(previous) && unicode.IsUpper(r) || unicode.IsUpper(previous) && unicode.IsUpper(r) && unicode.IsLower(next) {
				tokens = append(tokens, text[start:at])
				start = at
			}
		}
		previous = r
	}
	if start >= 0 {
		tokens = append(tokens, text[start:])
	}
	return tokens
}

func (n *metricSearchNode) matchesText(text string) bool {
	if n.exact {
		return text == n.text
	}
	if len(n.tokens) == 0 {
		return false
	}
	candidate := metricSearchTokens(text)
	for start := range candidate {
		at := start
		matched := true
		for _, token := range n.tokens {
			remaining := token
			for at < len(candidate) && len(remaining) > 0 {
				part := candidate[at]
				if len(part) > len(remaining) || !strings.EqualFold(part, remaining[:len(part)]) {
					break
				}
				remaining = remaining[len(part):]
				at++
			}
			if remaining != "" {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func (n *metricSearchNode) matches(record MetricRecord) bool {
	if n == nil {
		return true
	}
	switch n.kind {
	case metricSearchAnd:
		return n.left.matches(record) && n.right.matches(record)
	case metricSearchOr:
		return n.left.matches(record) || n.right.matches(record)
	case metricSearchNot:
		return !n.left.matches(record)
	}
	switch n.field {
	case "Namespace":
		return n.matchesText(record.Key.Namespace)
	case "MetricName":
		return n.matchesText(record.Key.Name)
	case ":aws.AccountId":
		return n.text == "LOCAL" || n.text == record.Key.AccountID
	case "":
		if n.matchesText(record.Key.Namespace) || n.matchesText(record.Key.Name) {
			return true
		}
		for _, dimension := range record.Dimensions {
			if n.matchesText(dimension.Name) || n.matchesText(dimension.Value) {
				return true
			}
		}
	default:
		for _, dimension := range record.Dimensions {
			if dimension.Name == n.field {
				return n.matchesText(dimension.Value)
			}
		}
	}
	return false
}

func (q *metricSearch) matches(record MetricRecord) bool {
	if q.schema != nil {
		if q.namespace != record.Key.Namespace || len(q.schema) != len(record.Dimensions) {
			return false
		}
		for i, name := range q.schema {
			if record.Dimensions[i].Name != name {
				return false
			}
		}
	}
	return q.term.matches(record)
}

func compileMetricSearches(node *mathNode, period int64, searches *[]*mathNode) *awswire.Error {
	for _, child := range node.args {
		if w := compileMetricSearches(child, period, searches); w != nil {
			return w
		}
	}
	if node.kind == "call" && node.text == "SEARCH" {
		search, w := compileMetricSearch(node, period)
		if w != nil {
			return w
		}
		node.search = search
		*searches = append(*searches, node)
	}
	return nil
}

func (n *metricSearchNode) exactProperty(field string) string {
	if n == nil {
		return ""
	}
	if n.kind == metricSearchTerm && n.field == field && n.exact {
		return n.text
	}
	if n.kind == metricSearchAnd {
		if found := n.left.exactProperty(field); found != "" {
			return found
		}
		return n.right.exactProperty(field)
	}
	return ""
}
