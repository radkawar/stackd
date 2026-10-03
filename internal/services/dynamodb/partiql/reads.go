package partiql

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

var errReadScan = errors.New("must have at least one non-optional hash key condition in WHERE clause when using ORDER BY clause")

type orderTerm struct {
	path       *expression
	descending bool
}

// ReadPlan describes native key traversal, not expression evaluation.
// Projection and residual predicates remain PartiQL evaluated by the engine.
type ReadPlan struct {
	Ranges  []ReadRange
	Forward bool
	Ordered bool
}

func (s *Statement) DirectReadItems(plan *ReadRange) bool {
	return s.index == "" && s.projections == 1 && s.reads[0].kind == "wildcard" && !plan.Filtered()
}

func (s *Statement) readPlan(schema api.KeySchema, parameters []api.AttributeValue) (*ReadPlan, error) {
	var hash, sort string
	for _, member := range schema {
		if *member.KeyType == "HASH" {
			hash = string(*member.AttributeName)
		} else {
			sort = string(*member.AttributeName)
		}
	}
	ranges, err := orderedRanges(s.where, schema, parameters)
	if err != nil {
		if errors.Is(err, errReadScan) && len(s.orderTerms) == 0 {
			return nil, nil
		}
		return nil, err
	}
	keys, err := prepareRanges(ranges, hash, sort)
	if err != nil {
		if errors.Is(err, errReadScan) && len(s.orderTerms) == 0 {
			return nil, nil
		}
		return nil, err
	}
	slices.SortFunc(keys, compareRanges)
	plan := &ReadPlan{Ranges: make([]ReadRange, len(keys)), Forward: len(s.orderTerms) == 0, Ordered: len(s.orderTerms) != 0}
	for i := range keys {
		plan.Ranges[i] = keys[i].ReadRange
	}
	var hashOrder, hashDescending, sortOrder bool
	for _, term := range s.orderTerms {
		switch {
		case isPartitionPath(term.path, hash) && !hashOrder:
			hashOrder, hashDescending = true, term.descending
		case sort != "" && isPartitionPath(term.path, sort) && !sortOrder:
			sortOrder, plan.Forward = true, !term.descending
		default:
			return plan, fmt.Errorf("order by must name each partition or sort key at most once")
		}
	}
	for i := 1; i < len(keys); i++ {
		previous, current := keys[i-1], keys[i]
		if previous.hash.compare(current.hash) != 0 {
			if !hashOrder && plan.Ordered {
				return plan, fmt.Errorf("must have hash key in ORDER BY clause when more than one hash key condition specified in WHERE clause")
			}
		} else if previous.overlaps(current) {
			return plan, fmt.Errorf("overlapping conditions with range keys are not supported in where clause")
		}
	}
	if hashDescending || !plan.Forward {
		slices.SortFunc(keys, func(a, b orderedRange) int {
			order := a.hash.compare(b.hash)
			if order != 0 {
				if hashDescending {
					return -order
				}
				return order
			}
			order = compareLower(a, b)
			if !plan.Forward {
				return -order
			}
			return order
		})
		for i := range keys {
			plan.Ranges[i] = keys[i].ReadRange
		}
	}
	return plan, nil
}

func quoteIdentifier(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

// fragment retains the original expression bytes and their parameter order.
func (s *Statement) fragment(start, end int, parameters []api.AttributeValue, into *api.PreparedStatementParameters) string {
	for _, token := range s.tokens {
		if token.start >= end {
			break
		}
		if token.start >= start && token.kind == "parameter" {
			*into = append(*into, parameters[token.ordinal])
		}
	}
	return s.text[start:end]
}

// PointStatement applies the original projection and residual filter to one
// evaluated physical item. Key predicates have already been enforced by Query.
// This deliberately does not implement a second PartiQL expression evaluator.
func (s *Statement) PointStatement(plan *ReadRange, physical string, schema, primary api.KeySchema, image api.AttributeMap, parameters []api.AttributeValue) (string, api.PreparedStatementParameters) {
	var bound api.PreparedStatementParameters
	var projections []string
	for _, x := range s.reads[:s.projections] {
		projections = append(projections, s.fragment(x.start, x.end, parameters, &bound))
	}
	text := "SELECT " + strings.Join(projections, ", ") + " FROM " + quoteIdentifier(physical)
	if s.index != "" {
		text += "." + quoteIdentifier(s.index)
	}
	var clauses []string
	seen := make(map[api.AttributeName]bool)
	for _, keys := range []api.KeySchema{schema, primary} {
		for _, member := range keys {
			name := api.AttributeName(*member.AttributeName)
			if seen[name] {
				continue
			}
			seen[name] = true
			clauses = append(clauses, quoteIdentifier(string(name))+" = ?")
			bound = append(bound, image[name])
		}
	}
	for _, x := range plan.residual {
		clauses = append(clauses, "("+s.fragment(x.start, x.end, parameters, &bound)+")")
	}
	return text + " WHERE " + strings.Join(clauses, " AND "), bound
}

// SingletonRead rewrites only AND-bound singleton IN key predicates on SELECT.
// Writes and OR expressions retain their original native validation contract.
func (s *Statement) SingletonRead(physical string, schema api.KeySchema, parameters []api.AttributeValue) (string, api.PreparedStatementParameters) {
	if s.action != "PartiQLSelect" {
		return s.RewriteTable(physical), parameters
	}
	type replacement struct {
		start, end int
		text       string
		value      *api.AttributeValue
	}
	replacements := []replacement{{start: s.table.start, end: s.table.end, text: quoteIdentifier(physical)}}
	var visit func(*expression)
	visit = func(x *expression) {
		if x == nil {
			return
		}
		if x.kind == "AND" {
			visit(x.children[0])
			visit(x.children[1])
			return
		}
		if x.kind != "IN" {
			return
		}
		for _, member := range schema {
			name := string(*member.AttributeName)
			condition, found, valid := capacityCondition(x, name, parameters)
			if found && valid && len(condition.AttributeValueList) == 1 {
				attribute := condition.AttributeValueList[0]
				if _, valid := attributeScalar(attribute); !valid {
					return
				}
				replacements = append(replacements, replacement{x.start, x.end, quoteIdentifier(name) + " = ?", &attribute})
				return
			}
		}
	}
	visit(s.where)
	if len(replacements) == 1 {
		return s.RewriteTable(physical), parameters
	}
	var text strings.Builder
	var bound api.PreparedStatementParameters
	start := 0
	for _, replacement := range replacements {
		text.WriteString(s.fragment(start, replacement.start, parameters, &bound))
		text.WriteString(replacement.text)
		if replacement.value != nil {
			bound = append(bound, *replacement.value)
		}
		start = replacement.end
	}
	text.WriteString(s.fragment(start, len(s.text), parameters, &bound))
	return text.String(), bound
}
