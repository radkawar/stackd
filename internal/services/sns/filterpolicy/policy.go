// Package filterpolicy implements the SNS subscription filter language.
package filterpolicy

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	snsapi "stackd/internal/awsapi/sns"
)

const (
	maxPolicyBytes    = 256 * 1024
	maxCombinations   = 150
	maxKeys           = 5
	maxWildcardPoints = 100
)

// Policy is immutable after compilation and safe for concurrent matching.
// Its zero value, like an empty filter policy, accepts every message.
type Policy struct {
	body     bool
	branches []object
}

// MatchResult preserves the native distinction between a policy mismatch and a
// message whose selected filtering scope is absent or malformed.
type MatchResult uint8

const (
	Matched MatchResult = iota
	FilteredAttributes
	FilteredBody
	NoMessageAttributes
	InvalidMessageBody
	InvalidAttributes
	MatchResultCount
)

type object struct {
	fields []field
}

type field struct {
	name   string
	child  *object
	groups [][]predicate
}

type requirement struct {
	path  []string
	terms []predicate
}

type branch struct {
	requirements []requirement
	complexity   int
}

type compiler struct {
	body           bool
	keys           int
	wildcardPoints int
}

// Compile validates and retains a subscription policy. An empty scope selects
// MessageAttributes; an empty document or object disables filtering.
func Compile(document, scope string) (*Policy, error) {
	if scope == "" {
		scope = "MessageAttributes"
	}
	if scope != "MessageAttributes" && scope != "MessageBody" {
		return nil, fmt.Errorf("invalid FilterPolicyScope %q", scope)
	}
	if len(document) > maxPolicyBytes {
		return nil, fmt.Errorf("FilterPolicy exceeds 256 KB")
	}
	p := &Policy{body: scope == "MessageBody"}
	if document == "" {
		return p, nil
	}
	input, err := decode(document)
	if err != nil {
		return nil, fmt.Errorf("invalid FilterPolicy JSON: %w", err)
	}
	root, ok := input.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("FilterPolicy must be an object")
	}
	if len(root) == 0 {
		return p, nil
	}
	c := compiler{body: p.body}
	branches, err := c.compileObject(root, nil, false)
	if err != nil {
		return nil, fmt.Errorf("invalid FilterPolicy: %w", err)
	}
	for _, b := range branches {
		var root object
		for _, r := range b.requirements {
			if err := root.insert(r.path, r.terms); err != nil {
				return nil, fmt.Errorf("invalid FilterPolicy: %w", err)
			}
		}
		p.branches = append(p.branches, root)
	}
	return p, nil
}

func decode(document string) (any, error) {
	if !utf8.ValidString(document) {
		return nil, fmt.Errorf("JSON must be valid UTF-8")
	}
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.UseNumber()
	var result any
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	return result, nil
}

func (c *compiler) compileObject(input map[string]any, path []string, inOr bool) ([]branch, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("nested objects and $or branches must not be empty")
	}
	if len(path) >= maxCombinations {
		return nil, fmt.Errorf("policy exceeds 150 combinations")
	}
	// Stable ordering makes validation deterministic despite JSON object maps.
	names := make([]string, 0, len(input))
	for name := range input {
		names = append(names, name)
	}
	sort.Strings(names)
	result := []branch{{complexity: 1}}
	for _, name := range names {
		value := input[name]
		if inOr && reserved(name) {
			return nil, fmt.Errorf("reserved operator %q cannot be a field inside $or", name)
		}
		var alternatives []branch
		if name == "$or" {
			items, ok := value.([]any)
			if !ok || len(items) < 2 {
				return nil, fmt.Errorf("$or requires at least two objects")
			}
			for _, item := range items {
				object, ok := item.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("$or branches must be objects")
				}
				branches, err := c.compileObject(object, path, true)
				if err != nil {
					return nil, err
				}
				alternatives = append(alternatives, branches...)
				if complexity(alternatives) > maxCombinations {
					return nil, fmt.Errorf("policy exceeds 150 combinations")
				}
			}
		} else {
			childPath := append(append([]string(nil), path...), name)
			switch child := value.(type) {
			case map[string]any:
				if !c.body {
					return nil, fmt.Errorf("nested policies require MessageBody scope")
				}
				var err error
				alternatives, err = c.compileObject(child, childPath, false)
				if err != nil {
					return nil, err
				}
			case []any:
				if len(child) == 0 {
					return nil, fmt.Errorf("field %q requires a nonempty match array", name)
				}
				// Repeated leaf names in separate $or branches still count as keys.
				c.keys++
				if c.keys > maxKeys {
					return nil, fmt.Errorf("policy exceeds five leaf keys")
				}
				cost := len(child) * len(childPath)
				if cost > maxCombinations {
					return nil, fmt.Errorf("policy exceeds 150 combinations")
				}
				terms := make([]predicate, 0, len(child))
				points := 0
				for _, item := range child {
					term, score, err := compilePredicate(item)
					if err != nil {
						return nil, fmt.Errorf("field %q: %w", name, err)
					}
					terms = append(terms, term)
					points += score
				}
				c.wildcardPoints += points * len(child)
				if c.wildcardPoints > maxWildcardPoints {
					return nil, fmt.Errorf("policy exceeds 100 wildcard complexity points")
				}
				alternatives = []branch{{requirements: []requirement{{path: childPath, terms: terms}}, complexity: cost}}
			default:
				return nil, fmt.Errorf("field %q requires a match array or nested object", name)
			}
		}
		if complexity(result)*complexity(alternatives) > maxCombinations {
			return nil, fmt.Errorf("policy exceeds 150 combinations")
		}
		joined := make([]branch, 0, len(result)*len(alternatives))
		for _, left := range result {
			for _, right := range alternatives {
				requirements := make([]requirement, 0, len(left.requirements)+len(right.requirements))
				requirements = append(requirements, left.requirements...)
				requirements = append(requirements, right.requirements...)
				joined = append(joined, branch{requirements: requirements, complexity: left.complexity * right.complexity})
			}
		}
		result = joined
	}
	return result, nil
}

func complexity(branches []branch) int {
	result := 0
	for _, b := range branches {
		result += b.complexity
	}
	return result
}

func reserved(name string) bool {
	switch name {
	case "prefix", "suffix", "anything-but", "numeric", "exists", "cidr", "equals-ignore-case", "wildcard", "=", "<", "<=", ">", ">=":
		return true
	}
	return false
}

func (o *object) insert(path []string, terms []predicate) error {
	index := -1
	for i := range o.fields {
		if o.fields[i].name == path[0] {
			index = i
			break
		}
	}
	if index < 0 {
		o.fields = append(o.fields, field{name: path[0]})
		index = len(o.fields) - 1
	}
	f := &o.fields[index]
	if len(path) == 1 {
		if f.child != nil {
			return fmt.Errorf("field %q cannot be both a leaf and a nested object", path[0])
		}
		f.groups = append(f.groups, terms)
		return nil
	}
	if len(f.groups) != 0 {
		return fmt.Errorf("field %q cannot be both a leaf and a nested object", path[0])
	}
	if f.child == nil {
		f.child = &object{}
	}
	return f.child.insert(path[1:], terms)
}

// Match evaluates the configured scope using publication-admitted attributes.
// An unfiltered policy never parses the body or attribute values.
func (p *Policy) Match(body string, attributes snsapi.MessageAttributeMap) MatchResult {
	if len(p.branches) == 0 {
		return Matched
	}
	if p.body {
		input, err := decode(body)
		if err != nil {
			return InvalidMessageBody
		}
		root, ok := input.(map[string]any)
		if !ok {
			return InvalidMessageBody
		}
		if len(root) == 0 {
			return FilteredBody
		}
		for _, branch := range p.branches {
			if branch.matchObject(root) {
				return Matched
			}
		}
		return FilteredBody
	}
	if len(attributes) == 0 {
		return NoMessageAttributes
	}
	// Native attribute filtering rejects a malformed value even when no policy
	// field references it. Decode every value once before considering branches.
	values := make(map[string]any, len(attributes))
	for name, attribute := range attributes {
		value, valid := attributeValue(attribute)
		if !valid {
			return InvalidAttributes
		}
		values[string(name)] = value
	}
	for _, branch := range p.branches {
		if branch.matchObject(values) {
			return Matched
		}
	}
	return FilteredAttributes
}

// ignoredValue retains Binary key presence without permitting it to masquerade
// as null, a string, or a number.
type ignoredValue struct{}

// Attribute filtering compares the escaped string representation: SNS requires
// policy strings containing quotes and backslashes to be double-escaped.
// MessageBody matching, by contrast, compares decoded JSON scalar strings.
var attributeEscapes = strings.NewReplacer("\\", "\\\\", "\"", "\\\"")

func attributeValue(attribute snsapi.MessageAttributeValue) (any, bool) {
	switch string(*attribute.DataType) {
	case "String":
		return attributeEscapes.Replace(string(*attribute.StringValue)), true
	case "Number":
		number, valid := parseDecimal(string(*attribute.StringValue))
		return number, valid
	case "String.Array":
		value, err := decode(string(*attribute.StringValue))
		if err != nil {
			return nil, false
		}
		items, valid := value.([]any)
		if !valid {
			return nil, false
		}
		for i, item := range items {
			switch value := item.(type) {
			case string:
				items[i] = attributeEscapes.Replace(value)
			case map[string]any, []any:
				return nil, false
			}
		}
		return items, true
	default:
		return ignoredValue{}, true
	}
}

func (o *object) matchObject(input map[string]any) bool {
	for _, f := range o.fields {
		value, present := input[f.name]
		if !f.match(value, present) {
			return false
		}
	}
	return true
}

func (f *field) match(value any, present bool) bool {
	if f.child != nil {
		if !present {
			return f.child.matchObject(nil)
		}
		return f.child.matchValue(value)
	}
	if !present {
		for _, group := range f.groups {
			matched := false
			for _, term := range group {
				matched = matched || term.kind == absentPredicate
			}
			if !matched {
				return false
			}
		}
		return true
	}
	if items, ok := value.([]any); ok {
		for _, item := range items {
			if f.match(item, true) {
				return true
			}
		}
		return false
	}
	if _, ok := value.(map[string]any); ok {
		return false // exists operates on leaves, not intermediate objects.
	}
	if _, ok := value.(ignoredValue); ok {
		return false
	}
	actual := makeScalar(value)
	for _, group := range f.groups {
		matched := false
		for _, term := range group {
			if term.match(actual) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (o *object) matchValue(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		return o.matchObject(v)
	case []any:
		// Evaluate the whole nested object at one array position. Matching each
		// field independently would incorrectly join different array objects.
		for _, item := range v {
			if o.matchValue(item) {
				return true
			}
		}
	}
	return false
}
