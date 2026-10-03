package partiql

import (
	"sort"
	"strings"
)

// Redacted preserves the original statement except for sensitive literal value
// spans. Placeholders are untouched: their values are omitted separately by the
// audit caller. Native CloudTrail retains INSERT's primary key values, unlike
// the older documentation example; nested tuple field names are sensitive.
// Callers must replace the entire text when Parse fails, never log unparsed SQL.
func (s *Statement) Redacted(keyNames []string) string {
	type span struct{ start, end int }
	var spans []span
	isKey := func(x *expression) bool {
		if x == nil || x.kind != "path" || x.nested {
			return false
		}
		for _, name := range keyNames {
			if x.value == name {
				return true
			}
		}
		return false
	}
	var visit func(*expression, bool)
	visit = func(x *expression, predicate bool) {
		if x == nil {
			return
		}
		switch x.kind {
		case "path", "parameter":
			// Document subscripts are part of an attribute path, not item values.
			return
		case "string", "number", "ion", "constant":
			spans = append(spans, span{x.start, x.end})
			return
		}
		if predicate {
			switch x.kind {
			case "=", "<>", "!=", "<", ">", "<=", ">=", "IN", "BETWEEN":
				if isKey(x.children[0]) {
					for _, child := range x.children[1:] {
						if !redactionKeyValue(child) {
							visit(child, false)
						}
					}
					return
				}
				if len(x.children) == 2 && isKey(x.children[1]) && redactionKeyValue(x.children[0]) {
					return
				}
			case "function":
				if strings.EqualFold(x.value, "begins_with") && len(x.children) == 2 && isKey(x.children[0]) && redactionKeyValue(x.children[1]) {
					return
				}
			}
		}
		for _, child := range x.children {
			visit(child, predicate && (x.kind == "AND" || x.kind == "OR" || x.kind == "NOT"))
		}
		for _, field := range x.fields {
			spans = append(spans, span{field.start, field.end})
			visit(field.value, false)
		}
	}
	for _, x := range s.reads {
		visit(x, false)
	}
	if s.item != nil {
		if s.item.kind == "map" {
			for _, field := range s.item.fields {
				key := false
				for _, name := range keyNames {
					if name == field.name {
						key = true
						break
					}
				}
				if !key || !redactionKeyValue(field.value) {
					visit(field.value, false)
				}
			}
		} else {
			visit(s.item, false)
		}
	}
	visit(s.where, true)
	if len(spans) == 0 {
		return s.text
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out strings.Builder
	out.Grow(len(s.text))
	start := 0
	for _, span := range spans {
		out.WriteString(s.text[start:span.start])
		out.WriteString("***(Redacted)")
		start = span.end
	}
	out.WriteString(s.text[start:])
	return out.String()
}

// Only direct key values may remain public. Arithmetic or other computed
// expressions can contain non-key payloads and must not inherit key status.
func redactionKeyValue(x *expression) bool {
	if x.nested {
		return false
	}
	switch x.kind {
	case "string", "number", "ion", "parameter":
		return true
	case "unary+", "unary-":
		return x.children[0].kind == "number" && !x.children[0].nested
	case "list":
		for _, child := range x.children {
			if !redactionKeyValue(child) {
				return false
			}
		}
		return true
	}
	return false
}
