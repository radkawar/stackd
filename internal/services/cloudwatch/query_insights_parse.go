package cloudwatch

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"stackd/internal/awswire"
)

type insightsPredicate struct {
	field, value   string
	notEqual       bool
	currentAccount bool
}

type insightsQuery struct {
	namespace, metric string
	statistic         statisticSpec
	// A nil schema permits any dimension set; an empty schema selects none.
	schema     []string
	predicates []insightsPredicate
	group      []string
	order      string
	descending bool
	limit      int
}

type insightsTokenKind uint8

const (
	insightsEnd insightsTokenKind = iota
	insightsWord
	insightsIdentifier
	insightsString
	insightsNumber
	insightsPunctuation
)

type insightsParser struct {
	input     string
	at, start int
	text      string
	kind      insightsTokenKind
	err       *awswire.Error
}

func isInsightsExpression(input string) bool {
	text := strings.TrimSpace(input)
	return len(text) >= 6 && strings.EqualFold(text[:6], "SELECT") && (len(text) == 6 || unicode.IsSpace(rune(text[6])))
}

func parseInsights(input string) (*insightsQuery, *awswire.Error) {
	p := insightsParser{input: input}
	p.next()
	p.expect("SELECT")
	aggregate := p.aggregate()
	p.expect("(")
	metric := p.identifier()
	p.expect(")")
	p.expect("FROM")
	query := &insightsQuery{metric: metric, statistic: aggregate, limit: 500}
	if p.take("SCHEMA") {
		p.expect("(")
		query.namespace = p.identifier()
		query.schema = []string{}
		for p.take(",") {
			query.schema = append(query.schema, p.identifier())
		}
		p.expect(")")
		slices.Sort(query.schema)
		query.schema = slices.Compact(query.schema)
	} else {
		query.namespace = p.identifier()
	}
	if p.take("WHERE") {
		for p.err == nil {
			predicate := insightsPredicate{field: p.identifier()}
			if p.take("!=") {
				predicate.notEqual = true
			} else {
				p.expect("=")
			}
			switch {
			case p.kind == insightsString:
				predicate.value = p.text
				p.next()
			case p.take("CURRENT_ACCOUNT_ID"):
				p.expect("(")
				p.expect(")")
				predicate.currentAccount = true
			default:
				if p.kind == insightsWord || p.kind == insightsIdentifier {
					p.fail("Invalid syntax. Comparing identifiers is not supported. Values must be surrounded by single quotes")
				} else {
					p.syntax()
				}
			}
			query.predicates = append(query.predicates, predicate)
			if !p.take("AND") {
				break
			}
		}
	}
	if p.take("GROUP") {
		p.expect("BY")
		query.group = append(query.group, p.identifier())
		for p.take(",") {
			query.group = append(query.group, p.identifier())
		}
	}
	if p.take("ORDER") {
		p.expect("BY")
		query.order = p.aggregate().kind
		p.expect("(")
		p.expect(")")
		query.descending = p.take("DESC")
		if !query.descending {
			p.take("ASC")
		}
	}
	if p.take("LIMIT") {
		limit, err := strconv.ParseUint(p.text, 10, 64)
		if p.kind != insightsNumber || err != nil || limit == 0 {
			p.syntax()
		} else {
			query.limit = int(min(limit, 500))
			p.next()
		}
	}
	if p.kind != insightsEnd {
		p.syntax()
	}
	if p.err != nil {
		return nil, p.err
	}
	return query, nil
}

func (p *insightsParser) aggregate() statisticSpec {
	name := strings.ToUpper(p.text)
	kind := ""
	switch name {
	case "AVG":
		kind = "Average"
	case "COUNT":
		kind = "SampleCount"
	case "MIN":
		kind = "Minimum"
	case "MAX":
		kind = "Maximum"
	case "SUM":
		kind = "Sum"
	default:
		p.fail(fmt.Sprintf("Invalid syntax. '%s' is not a valid aggregate function", p.text))
	}
	if p.kind != insightsWord {
		p.syntax()
	}
	p.next()
	return statisticSpec{name: kind, kind: kind}
}

func (p *insightsParser) identifier() string {
	name := p.text
	if p.kind != insightsWord && p.kind != insightsIdentifier {
		p.syntax()
		return ""
	}
	if p.kind == insightsWord && insightsReservedIdentifier(name) {
		p.fail(fmt.Sprintf("Invalid syntax. Reserved keyword '%s' must be surrounded by double quotes", name))
		return ""
	}
	if p.kind == insightsWord && strings.HasSuffix(name, ".") {
		p.next()
		return name + p.identifier()
	}
	p.next()
	return name
}

func (p *insightsParser) take(text string) bool {
	if p.err != nil || p.kind != insightsWord && p.kind != insightsPunctuation || !strings.EqualFold(p.text, text) {
		return false
	}
	p.next()
	return true
}

func (p *insightsParser) expect(text string) {
	if !p.take(text) {
		p.syntax()
	}
}

func (p *insightsParser) fail(message string) {
	if p.err == nil {
		p.err = mathValidation(message)
	}
}

func (p *insightsParser) syntax() {
	near := p.input[p.start:]
	if len(near) > 30 {
		near = near[:27] + "..."
	}
	p.fail("Invalid syntax near '" + near + "'")
}

func insightsLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func (p *insightsParser) next() {
	if p.err != nil {
		return
	}
	for p.at < len(p.input) && unicode.IsSpace(rune(p.input[p.at])) {
		p.at++
	}
	p.start = p.at
	if p.at == len(p.input) {
		p.kind, p.text = insightsEnd, ""
		return
	}
	c := p.input[p.at]
	p.at++
	switch {
	case c == '\'' || c == '"':
		var text strings.Builder
		for p.at < len(p.input) {
			v := p.input[p.at]
			p.at++
			if v == c {
				p.kind = insightsString
				if c == '"' {
					p.kind = insightsIdentifier
				}
				p.text = text.String()
				return
			}
			// Insights escapes the matching delimiter, not arbitrary backslashes.
			// Doubling a literal backslash changes the value being compared.
			if v == '\\' && p.at < len(p.input) && p.input[p.at] == c {
				v = c
				p.at++
			}
			text.WriteByte(v)
		}
		p.syntax()
	case insightsLetter(c):
		for p.at < len(p.input) {
			v := p.input[p.at]
			if !insightsLetter(v) && !(v >= '0' && v <= '9') && v != '.' {
				break
			}
			p.at++
		}
		p.kind, p.text = insightsWord, p.input[p.start:p.at]
	case c >= '0' && c <= '9':
		for p.at < len(p.input) && p.input[p.at] >= '0' && p.input[p.at] <= '9' {
			p.at++
		}
		p.kind, p.text = insightsNumber, p.input[p.start:p.at]
	default:
		if c == '!' && p.at < len(p.input) && p.input[p.at] == '=' {
			p.at++
		}
		p.kind, p.text = insightsPunctuation, p.input[p.start:p.at]
	}
}
