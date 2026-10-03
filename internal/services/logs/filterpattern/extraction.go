package filterpattern

import (
	"encoding/json"
	"fmt"
	"iter"
	"strconv"
	"strings"
)

// MatchResult retains only the message's parsed representation. JSON fields are
// available to metric selectors but are not exposed by TestMetricFilter.
type MatchResult struct {
	object map[string]any
	fields []logField
}

func (m MatchResult) ExtractedValues() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for i, field := range m.fields {
			name := field.name
			if name == "" {
				name = strconv.Itoa(i + 1)
			}
			if !yield("$"+name, field.value) {
				return
			}
		}
	}
}

// Extractor is a compiled scalar selector, reusable across matched messages.
type Extractor struct {
	path  selector
	field string
	index int
}

func (p *Pattern) Extractor(source string) (*Extractor, error) {
	if p.json != nil {
		parser := parser{source: source}
		path, err := parser.selector()
		if err != nil {
			return nil, err
		}
		if !parser.end() {
			return nil, parser.invalid()
		}
		for _, step := range path {
			if step.wildcard {
				return nil, fmt.Errorf("metric extraction requires a single property selector")
			}
		}
		return &Extractor{path: path}, nil
	}
	if p.space == nil || !strings.HasPrefix(source, "$") || len(source) == 1 {
		return nil, fmt.Errorf("metric extraction requires a JSON or space-delimited field selector")
	}
	name := source[1:]
	for _, c := range name {
		if !isName(c) {
			return nil, fmt.Errorf("invalid metric field selector")
		}
	}
	index, _ := strconv.Atoi(name)
	return &Extractor{field: name, index: index}, nil
}

// Value returns an extracted scalar without reparsing the original log message.
// Missing, null and compound values cannot produce a metric value or dimension.
func (e *Extractor) Value(m MatchResult) (string, bool) {
	if e.path != nil {
		var value any = m.object
		for _, step := range e.path {
			child, ok := step.child(value)
			if !ok {
				return "", false
			}
			value = child
		}
		switch value := value.(type) {
		case string:
			return value, true
		case json.Number:
			return string(value), true
		case bool:
			return strconv.FormatBool(value), true
		default:
			return "", false
		}
	}
	for _, field := range m.fields {
		if field.name == e.field {
			return field.value, true
		}
	}
	if e.index > 0 && e.index <= len(m.fields) && m.fields[e.index-1].name == "" {
		return m.fields[e.index-1].value, true
	}
	return "", false
}
