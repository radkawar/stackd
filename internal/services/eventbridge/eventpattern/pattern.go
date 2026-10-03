// Package eventpattern compiles EventBridge event patterns for API validation
// and repeated matching of events against rules.
package eventpattern

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Pattern is an immutable compiled event pattern, safe for concurrent matches.
type Pattern struct {
	clauses []clause
}

type clause []field

type field struct {
	path      string
	terms     []term
	admission []complexityTerm
}

type term struct {
	absent bool
	match  func(value) bool
}

// Compile validates an EventBridge event pattern and compiles its alternatives.
func Compile(data []byte) (*Pattern, error) {
	root, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("invalid event pattern: %w", err)
	}
	clauses, err := compileObject(root, nil, []clause{{}}, false)
	if err != nil {
		return nil, err
	}
	if err := checkComplexity(clauses); err != nil {
		return nil, err
	}
	for i := range clauses {
		for j := range clauses[i] {
			clauses[i][j].admission = nil
		}
	}
	return &Pattern{clauses: clauses}, nil
}

func compileObject(object value, prefix []string, clauses []clause, inOr bool) ([]clause, error) {
	if len(object.members) == 0 {
		return nil, fmt.Errorf("empty objects are not allowed")
	}
	for _, member := range object.members {
		if inOr && reserved(member.name) {
			return nil, fmt.Errorf("reserved operator %q cannot be a field inside $or", member.name)
		}
		child := member.value
		if member.name == "$or" {
			if child.kind != arrayValue || len(child.items) < 2 {
				return nil, fmt.Errorf("$or must contain at least two objects")
			}
			var expanded []clause
			for _, branch := range child.items {
				if branch.kind != objectValue {
					return nil, fmt.Errorf("$or branches must be objects")
				}
				copies := make([]clause, len(clauses))
				for i, old := range clauses {
					copies[i] = slices.Clone(old)
				}
				compiled, err := compileObject(branch, prefix, copies, true)
				if err != nil {
					return nil, err
				}
				expanded = append(expanded, compiled...)
				if len(expanded) > 1000 {
					return nil, fmt.Errorf("event pattern has more than 1000 $or combinations")
				}
			}
			clauses = expanded
			continue
		}
		path := append(slices.Clone(prefix), member.name)
		if child.kind == objectValue {
			var err error
			clauses, err = compileObject(child, path, clauses, inOr)
			if err != nil {
				return nil, err
			}
			continue
		}
		if child.kind != arrayValue || len(child.items) == 0 {
			return nil, fmt.Errorf("field %q must contain a nonempty array or object", path)
		}
		compiled := field{path: strings.Join(path, ".")}
		for _, item := range child.items {
			predicate, err := compileTerm(item)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", path, err)
			}
			compiled.terms = append(compiled.terms, predicate)
			compiled.admission = append(compiled.admission, describeComplexity(item))
		}
		for i := range clauses {
			clauses[i] = setField(clauses[i], compiled)
		}
	}
	return clauses, nil
}

func reserved(name string) bool {
	switch name {
	case "exactly", "prefix", "suffix", "anything-but", "numeric", "exists", "cidr", "equals-ignore-case", "wildcard",
		"=", "<", "<=", ">", ">=", "regex", "not-wildcard", "not-equals-ignore-case", "date-after", "date-on-or-after", "date-before", "date-on-or-before", "in-date-range", "ip-address-in-range", "ip-address-not-in-range":
		return true
	}
	return false
}

func setField(fields clause, replacement field) clause {
	for i, field := range fields {
		if field.path == replacement.path {
			fields[i] = replacement
			return fields
		}
	}
	return append(fields, replacement)
}

type position struct {
	array int
	index int
}

type eventField struct {
	value value
	trail []position
}

// Match matches a JSON event object. The provider owns envelope requirements
// such as source, detail-type and event timestamps.
func (p *Pattern) Match(data []byte) (bool, error) {
	root, err := parse(data)
	if err != nil {
		return false, fmt.Errorf("invalid event: %w", err)
	}
	event := make(map[string][]eventField)
	array := 0
	flatten(root, nil, nil, event, &array)
	for _, clause := range p.clauses {
		if matchClause(clause, event) {
			return true, nil
		}
	}
	return false, nil
}

func flatten(current value, path []string, trail []position, event map[string][]eventField, array *int) {
	switch current.kind {
	case objectValue:
		for _, member := range current.members {
			name := append(slices.Clone(path), member.name)
			flatten(member.value, name, trail, event, array)
		}
	case arrayValue:
		*array++
		id := *array
		for index, item := range current.items {
			flatten(item, path, append(slices.Clone(trail), position{array: id, index: index}), event, array)
		}
	default:
		if current.kind == numberValue {
			current.text = eventNumber(current.text)
		}
		key := strings.Join(path, ".")
		event[key] = append(event[key], eventField{value: current, trail: trail})
	}
}

// Each candidate already satisfies a field's value predicates. Its array trail
// is retained so joining fields cannot combine different elements of one array.
type fieldCandidates struct {
	path   string
	values []eventField
	absent bool
}

func (f fieldCandidates) alternatives() int {
	if f.absent {
		return len(f.values) + 1
	}
	return len(f.values)
}

func matchClause(required clause, event map[string][]eventField) bool {
	prepared := make([]fieldCandidates, 0, len(required))
	for _, field := range required {
		candidates := fieldCandidates{path: field.path}
		for _, term := range field.terms {
			candidates.absent = candidates.absent || term.absent
		}
		for _, candidate := range event[field.path] {
			for _, term := range field.terms {
				if !term.absent && term.match(candidate.value) {
					candidates.values = append(candidates.values, candidate)
					break
				}
			}
		}
		if candidates.alternatives() == 0 {
			return false
		}
		prepared = append(prepared, candidates)
	}
	// Rejecting impossible fields before the join avoids enumerating unrelated
	// matching arrays. Start with the most selective remaining field.
	slices.SortStableFunc(prepared, func(a, b fieldCandidates) int {
		return cmp.Compare(a.alternatives(), b.alternatives())
	})
	return matchFields(prepared, event, nil, nil)
}

func matchFields(required []fieldCandidates, event map[string][]eventField, trail []position, absent []string) bool {
	if len(required) == 0 {
		// Native absence is global unless positive fields bound an array
		// element. Deferring it also makes JSON field ordering irrelevant.
		for _, path := range absent {
			for _, candidate := range event[path] {
				if compatible(trail, candidate.trail) {
					return false
				}
			}
		}
		return true
	}
	field := required[0]
	if field.absent {
		if matchFields(required[1:], event, trail, append(slices.Clone(absent), field.path)) {
			return true
		}
	}
	for _, candidate := range field.values {
		if compatible(trail, candidate.trail) {
			joined := append(slices.Clone(trail), candidate.trail...)
			if matchFields(required[1:], event, joined, absent) {
				return true
			}
		}
	}
	return false
}

func compatible(left, right []position) bool {
	for _, l := range left {
		for _, r := range right {
			if l.array == r.array && l.index != r.index {
				return false
			}
		}
	}
	return true
}
