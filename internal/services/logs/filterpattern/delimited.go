package filterpattern

import (
	"encoding/json"
	"strconv"
	"strings"
)

type delimited struct {
	fields   []delimitedField
	ellipsis int
}

type delimitedField struct {
	name      string
	predicate *expression
}

func (p *parser) parseDelimited() (*delimited, error) {
	p.pos++
	d := &delimited{ellipsis: -1}
	if p.take("]") {
		if !p.end() {
			return nil, p.invalid()
		}
		return d, nil
	}
	names := make(map[string]bool)
	for {
		p.skipSpace()
		start := p.pos
		if p.take("...") {
			if d.ellipsis >= 0 {
				return nil, p.invalid()
			}
			d.ellipsis = len(d.fields)
			d.fields = append(d.fields, delimitedField{})
		} else {
			name := p.name()
			if name == "" || names[name] {
				return nil, p.invalid()
			}
			names[name] = true
			p.skipSpace()
			var expr *expression
			if p.pos < len(p.source) && p.source[p.pos] != ',' && p.source[p.pos] != ']' {
				p.pos, p.field = start, name
				var err error
				expr, err = p.parseOr()
				if err != nil {
					return nil, err
				}
				p.field = ""
			}
			d.fields = append(d.fields, delimitedField{name: name, predicate: expr})
		}
		if p.take("]") {
			if !p.end() {
				return nil, p.invalid()
			}
			return d, nil
		}
		if !p.take(",") {
			return nil, p.invalid()
		}
	}
}

type logField struct {
	name  string
	start int
	value string
}

// Bracketed timestamps and double-quoted requests are each one field. Native
// unclosed quotes remain ordinary token text instead of rejecting the event.
func splitFields(message string) []logField {
	var fields []logField
	for pos := 0; pos < len(message); {
		if isSpace(message[pos]) {
			pos++
			continue
		}
		start := pos
		close := byte(0)
		if message[pos] == '[' {
			close = ']'
		} else if message[pos] == '"' {
			close = '"'
		}
		if close != 0 {
			end := pos + 1
			for end < len(message) {
				if message[end] == '\\' && end+1 < len(message) {
					end += 2
					continue
				}
				if message[end] == close {
					break
				}
				end++
			}
			if end < len(message) && (end+1 == len(message) || isSpace(message[end+1])) {
				fields = append(fields, logField{start: start, value: message[pos+1 : end]})
				pos = end + 1
				continue
			}
		}
		for pos < len(message) && !isSpace(message[pos]) {
			pos++
		}
		fields = append(fields, logField{start: start, value: message[start:pos]})
	}
	return fields
}

func (d *delimited) evaluate(message string) ([]logField, bool) {
	values := splitFields(message)
	minimum := len(d.fields)
	if d.ellipsis >= 0 {
		minimum--
	}
	if len(values) < minimum || len(values) == 0 {
		return nil, false
	}
	for i, field := range d.fields {
		if i == d.ellipsis {
			continue
		}
		index := i
		if d.ellipsis >= 0 && i > d.ellipsis {
			index = len(values) - (len(d.fields) - i)
		}
		values[index].name = field.name
		value := values[index].value
		if d.ellipsis < 0 && i == len(d.fields)-1 && len(values) > len(d.fields) {
			value = strings.TrimRight(message[values[index].start:], " \t\r\n")
			values[index].value = value
			values = values[:index+1]
		}
		if field.predicate == nil {
			continue
		}
		var scalar any = value
		if _, err := strconv.ParseFloat(value, 64); err == nil {
			scalar = json.Number(value)
		}
		if !field.predicate.match(scalar) {
			return nil, false
		}
	}
	return values, true
}
