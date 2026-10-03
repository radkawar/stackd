package partiql

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/messageattribute"
)

// ReadRange is one native Query and its remaining engine-evaluated predicates.
// Point denotes equality on every key of the queried table or index.
type ReadRange struct {
	Conditions api.KeyConditions
	Point      bool
	residual   []*expression
}

func (r *ReadRange) Filtered() bool { return len(r.residual) != 0 }

// orderedRanges distributes key alternatives, not ordinary filter alternatives.
// Branch-local filters stay with their key range; they are never Go-evaluated.
func orderedRanges(x *expression, schema api.KeySchema, parameters []api.AttributeValue) ([]ReadRange, error) {
	if x == nil {
		return []ReadRange{{Conditions: make(api.KeyConditions)}}, nil
	}
	if x.kind == "AND" || x.kind == "OR" {
		a, err := orderedRanges(x.children[0], schema, parameters)
		if err != nil {
			return nil, err
		}
		b, err := orderedRanges(x.children[1], schema, parameters)
		if err != nil {
			return nil, err
		}
		if x.kind == "OR" {
			branches := append(a, b...)
			if len(a) == 1 && len(b) == 1 && len(a[0].Conditions) == 0 && len(b[0].Conditions) == 0 {
				return []ReadRange{{Conditions: make(api.KeyConditions), residual: []*expression{x}}}, nil
			}
			return branches, nil
		}
		out := make([]ReadRange, 0, len(a)*len(b))
		for _, left := range a {
			for _, right := range b {
				conditions := maps.Clone(left.Conditions)
				for name, condition := range right.Conditions {
					if previous, exists := conditions[name]; exists && !sameKeyCondition(previous, condition) {
						return nil, errReadScan
					}
					conditions[name] = condition
				}
				out = append(out, ReadRange{Conditions: conditions, residual: append(slices.Clone(left.residual), right.residual...)})
			}
		}
		return out, nil
	}
	for _, member := range schema {
		condition, found, valid := capacityCondition(x, string(*member.AttributeName), parameters)
		if !valid {
			return nil, errReadScan
		}
		if !found {
			continue
		}
		name := api.AttributeName(*member.AttributeName)
		if *condition.ComparisonOperator != "IN" {
			return []ReadRange{{Conditions: api.KeyConditions{name: condition}}}, nil
		}
		if x.children[1].kind != "list" {
			return nil, fmt.Errorf("the right hand side of IN must be a list")
		}
		out := make([]ReadRange, 0, len(condition.AttributeValueList))
		for _, attribute := range condition.AttributeValueList {
			out = append(out, ReadRange{Conditions: api.KeyConditions{name: {ComparisonOperator: new(api.ComparisonOperator("EQ")), AttributeValueList: api.AttributeValueList{attribute}}}})
		}
		return out, nil
	}
	return []ReadRange{{Conditions: make(api.KeyConditions), residual: []*expression{x}}}, nil
}

// orderedScalar caches parsed decimals once per bound rather than during sort.
type orderedScalar struct {
	attribute api.AttributeValue
	number    messageattribute.Number
}

func scalarOrder(attribute api.AttributeValue) (orderedScalar, error) {
	out := orderedScalar{attribute: attribute}
	if _, ok := attributeScalar(attribute); !ok {
		return out, fmt.Errorf("key values must be scalar")
	}
	if attribute.N != nil {
		var err error
		out.number, err = messageattribute.ParseNumber(string(*attribute.N), -130)
		return out, err
	}
	return out, nil
}

func (a orderedScalar) compare(b orderedScalar) int {
	switch {
	case a.attribute.N != nil:
		return a.number.Compare(b.number)
	case a.attribute.S != nil:
		return strings.Compare(string(*a.attribute.S), string(*b.attribute.S))
	default:
		return bytes.Compare(a.attribute.B, b.attribute.B)
	}
}

func sameScalarType(a, b api.AttributeValue) bool {
	return (a.S != nil) == (b.S != nil) && (a.N != nil) == (b.N != nil) && (a.B != nil) == (b.B != nil)
}

type orderedRange struct {
	ReadRange
	hash                           orderedScalar
	lower, upper                   *orderedScalar
	lowerInclusive, upperInclusive bool
}

func prepareRanges(ranges []ReadRange, hash, sort string) ([]orderedRange, error) {
	out := make([]orderedRange, 0, len(ranges))
	var hashType, sortType *api.AttributeValue
	for _, query := range ranges {
		partition, ok := query.Conditions[api.AttributeName(hash)]
		if !ok || *partition.ComparisonOperator != "EQ" {
			return nil, errReadScan
		}
		key, err := scalarOrder(partition.AttributeValueList[0])
		if err != nil {
			return nil, err
		}
		if hashType != nil && !sameScalarType(*hashType, key.attribute) {
			return nil, fmt.Errorf("partition key values must have the same type")
		}
		hashType = &key.attribute
		r := orderedRange{ReadRange: query, hash: key}
		condition, hasSort := query.Conditions[api.AttributeName(sort)]
		r.Point = sort == "" || hasSort && *condition.ComparisonOperator == "EQ"
		if hasSort {
			bounds := make([]orderedScalar, len(condition.AttributeValueList))
			for i, attribute := range condition.AttributeValueList {
				bounds[i], err = scalarOrder(attribute)
				if err != nil {
					return nil, err
				}
				if sortType != nil && !sameScalarType(*sortType, attribute) {
					return nil, fmt.Errorf("sort key values must have the same type")
				}
				sortType = &bounds[i].attribute
			}
			switch *condition.ComparisonOperator {
			case "EQ":
				r.lower, r.upper, r.lowerInclusive, r.upperInclusive = &bounds[0], &bounds[0], true, true
			case "GT", "GE":
				r.lower, r.lowerInclusive = &bounds[0], *condition.ComparisonOperator == "GE"
			case "LT", "LE":
				r.upper, r.upperInclusive = &bounds[0], *condition.ComparisonOperator == "LE"
			case "BETWEEN":
				r.lower, r.upper, r.lowerInclusive, r.upperInclusive = &bounds[0], &bounds[1], true, true
			case "BEGINS_WITH":
				r.lower, r.lowerInclusive = &bounds[0], true
				var prefix []byte
				if bounds[0].attribute.S != nil {
					prefix = []byte(*bounds[0].attribute.S)
				} else {
					prefix = slices.Clone(bounds[0].attribute.B)
				}
				for i := len(prefix) - 1; i >= 0; i-- {
					if prefix[i] == 255 {
						continue
					}
					prefix[i]++
					next := api.AttributeValue{B: prefix[:i+1]}
					if bounds[0].attribute.S != nil {
						next = api.AttributeValue{S: new(api.StringAttributeValue(string(prefix[:i+1])))}
					}
					upper, err := scalarOrder(next)
					if err != nil {
						return nil, err
					}
					r.upper = &upper
					break
				}
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func compareLower(a, b orderedRange) int {
	if a.lower == nil {
		if b.lower == nil {
			return 0
		}
		return -1
	}
	if b.lower == nil {
		return 1
	}
	if order := a.lower.compare(*b.lower); order != 0 {
		return order
	}
	if a.lowerInclusive != b.lowerInclusive {
		if a.lowerInclusive {
			return -1
		}
		return 1
	}
	return 0
}

func compareRanges(a, b orderedRange) int {
	if order := a.hash.compare(b.hash); order != 0 {
		return order
	}
	return compareLower(a, b)
}

func (a orderedRange) overlaps(b orderedRange) bool {
	if a.upper == nil || b.lower == nil {
		return true
	}
	order := a.upper.compare(*b.lower)
	return order > 0 || order == 0 && a.upperInclusive && b.lowerInclusive
}
