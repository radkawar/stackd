package partiql

import (
	"encoding/base64"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

// CapacityKey identifies the singleton affected by a mutation or point read.
// It never evaluates a condition; execution and validation remain native.
func (s *Statement) CapacityKey(schema api.KeySchema, parameters []api.AttributeValue) (api.Key, bool) {
	key := make(api.Key, len(schema))
	for _, member := range schema {
		name := string(*member.AttributeName)
		var attribute api.AttributeValue
		var ok bool
		if s.item != nil {
			if s.item.kind == "map" {
				for _, f := range s.item.fields {
					if f.name == name {
						attribute, ok = capacityLiteral(f.value, parameters)
					}
				}
			} else if s.item.kind == "parameter" && s.item.ordinal < len(parameters) {
				attribute, ok = parameters[s.item.ordinal].M[api.AttributeName(name)]
			}
		} else if s.action == "PartiQLSelect" {
			condition, found, valid := capacityCondition(s.where, name, parameters)
			if found && valid && len(condition.AttributeValueList) == 1 && (*condition.ComparisonOperator == "EQ" || *condition.ComparisonOperator == "IN") {
				attribute, ok = condition.AttributeValueList[0], true
			}
		} else {
			attribute, ok = capacityEquality(s.where, name, parameters)
		}
		if !ok {
			return nil, false
		}
		key[api.AttributeName(name)] = attribute
	}
	return key, true
}

func capacityEquality(x *expression, name string, parameters []api.AttributeValue) (api.AttributeValue, bool) {
	if x == nil {
		return api.AttributeValue{}, false
	}
	if x.kind == "AND" {
		if v, ok := capacityEquality(x.children[0], name, parameters); ok {
			return v, true
		}
		return capacityEquality(x.children[1], name, parameters)
	}
	if x.kind == "=" {
		if isPartitionPath(x.children[0], name) {
			return capacityLiteral(x.children[1], parameters)
		}
		if isPartitionPath(x.children[1], name) {
			return capacityLiteral(x.children[0], parameters)
		}
	}
	return api.AttributeValue{}, false
}

func capacityLiteral(x *expression, parameters []api.AttributeValue) (api.AttributeValue, bool) {
	if x == nil || x.nested {
		return api.AttributeValue{}, false
	}
	switch x.kind {
	case "parameter":
		if x.ordinal < len(parameters) {
			v := parameters[x.ordinal]
			_, ok := attributeScalar(v)
			return v, ok
		}
	case "string":
		return api.AttributeValue{S: new(api.StringAttributeValue(x.value))}, true
	case "number":
		return api.AttributeValue{N: new(api.NumberAttributeValue(x.value))}, true
	case "unary+", "unary-":
		if text, ok := scalar(x, parameters); ok {
			return api.AttributeValue{N: new(api.NumberAttributeValue(text))}, true
		}
	case "ion":
		// DynamoDB's binary literal is an Ion blob, not an evaluated expression.
		text := strings.TrimSpace(x.value)
		if strings.HasPrefix(text, "{{") && strings.HasSuffix(text, "}}") {
			text = strings.Join(strings.Fields(text[2:len(text)-2]), "")
			if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
				return api.AttributeValue{B: api.BinaryAttributeValue(decoded)}, true
			}
		}
	}
	return api.AttributeValue{}, false
}

// CapacityConditions mirrors the native key extractor's AND-only query access
// path. A nil result denotes a scan, not an unevaluated filter approximation.
// Conditions unrelated to keys remain native filters and are omitted here so
// measurement observes every evaluated item before filtering or projection.
func (s *Statement) CapacityConditions(schema api.KeySchema, parameters []api.AttributeValue) api.KeyConditions {
	conditions := make(api.KeyConditions)
	var partition string
	for _, member := range schema {
		name := string(*member.AttributeName)
		if string(*member.KeyType) == "HASH" {
			partition = name
		}
		condition, found, valid := capacityCondition(s.where, name, parameters)
		if !valid {
			return nil
		}
		if found {
			conditions[api.AttributeName(name)] = condition
		}
	}
	hash, ok := conditions[api.AttributeName(partition)]
	if !ok || hash.ComparisonOperator == nil || (*hash.ComparisonOperator != "EQ" && *hash.ComparisonOperator != "IN") {
		return nil
	}
	return conditions
}

func capacityCondition(x *expression, name string, parameters []api.AttributeValue) (api.Condition, bool, bool) {
	if x == nil {
		return api.Condition{}, false, true
	}
	if x.kind == "AND" {
		a, foundA, validA := capacityCondition(x.children[0], name, parameters)
		b, foundB, validB := capacityCondition(x.children[1], name, parameters)
		if !validA || !validB || foundA && foundB && !sameKeyCondition(a, b) {
			return api.Condition{}, false, false
		}
		if foundA {
			return a, true, true
		}
		return b, foundB, true
	}
	if x.kind == "OR" {
		return api.Condition{}, false, true
	}
	if x.kind == "NOT" {
		// Native SELECT leaves OR and compound negations as post-key
		// filters; only a directly negated key comparison invalidates its
		// query access path (KeyAndConditionExpressionExtractorBase).
		for _, operand := range x.children[0].children {
			if isPartitionPath(operand, name) {
				return api.Condition{}, false, false
			}
		}
		return api.Condition{}, false, true
	}
	var operator api.ComparisonOperator
	switch x.kind {
	case "=":
		operator = "EQ"
	case "<":
		operator = "LT"
	case "<=":
		operator = "LE"
	case ">":
		operator = "GT"
	case ">=":
		operator = "GE"
	case "BETWEEN":
		operator = "BETWEEN"
	case "IN":
		operator = "IN"
	}
	operands := x.children
	if x.kind == "function" && strings.EqualFold(x.value, "begins_with") {
		operator = "BEGINS_WITH"
	}
	if len(operands) < 2 {
		return api.Condition{}, false, true
	}
	var values []*expression
	if isPartitionPath(operands[0], name) {
		values = operands[1:]
	} else if len(operands) == 2 && isPartitionPath(operands[1], name) {
		values = operands[:1]
		switch operator {
		case "LT":
			operator = "GT"
		case "LE":
			operator = "GE"
		case "GT":
			operator = "LT"
		case "GE":
			operator = "LE"
		}
	} else {
		return api.Condition{}, false, true
	}
	if operator == "" {
		return api.Condition{}, false, false
	}
	var attributes api.AttributeValueList
	if operator == "IN" && len(values) == 1 {
		if values[0].kind == "list" {
			values = values[0].children
		} else if values[0].kind == "parameter" && values[0].ordinal < len(parameters) {
			attributes = api.AttributeValueList(parameters[values[0].ordinal].L)
			values = nil
		}
	}
	for _, x := range values {
		v, ok := capacityLiteral(x, parameters)
		if !ok {
			return api.Condition{}, false, false
		}
		attributes = append(attributes, v)
	}
	if len(attributes) == 0 {
		return api.Condition{}, false, false
	}
	return api.Condition{ComparisonOperator: &operator, AttributeValueList: attributes}, true, true
}

// sameKeyCondition follows native key extraction: numerically equivalent
// scalars and singleton IN/EQ are identical; intersecting lists are not queries.
func sameKeyCondition(a, b api.Condition) bool {
	operation := func(c api.Condition) api.ComparisonOperator {
		if *c.ComparisonOperator == "IN" && len(c.AttributeValueList) == 1 {
			return "EQ"
		}
		return *c.ComparisonOperator
	}
	op := operation(a)
	if op != operation(b) || op == "IN" || len(a.AttributeValueList) != len(b.AttributeValueList) {
		return false
	}
	for i, attribute := range a.AttributeValueList {
		other := b.AttributeValueList[i]
		if !sameScalarType(attribute, other) {
			return false
		}
		left, err := scalarOrder(attribute)
		if err != nil {
			return false
		}
		right, err := scalarOrder(other)
		if err != nil || left.compare(right) != 0 {
			return false
		}
	}
	return true
}

// CapacityReadStatement removes response projection and post-key filters while
// preserving the native key access path and parameter values.
func (s *Statement) CapacityReadStatement(physical string, schema api.KeySchema, conditions api.KeyConditions) (string, api.PreparedStatementParameters) {
	quote := func(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }
	text := "SELECT * FROM " + quote(physical)
	if s.index != "" {
		text += "." + quote(s.index)
	}
	var clauses []string
	var parameters api.PreparedStatementParameters
	for _, member := range schema {
		name := api.AttributeName(*member.AttributeName)
		condition, ok := conditions[name]
		if !ok {
			continue
		}
		path := quote(string(name))
		switch *condition.ComparisonOperator {
		case "IN":
			clauses = append(clauses, path+" IN ["+strings.TrimSuffix(strings.Repeat("?,", len(condition.AttributeValueList)), ",")+"]")
		case "BETWEEN":
			clauses = append(clauses, path+" BETWEEN ? AND ?")
		case "BEGINS_WITH":
			clauses = append(clauses, "begins_with("+path+", ?)")
		default:
			var operator string
			switch *condition.ComparisonOperator {
			case "EQ":
				operator = "="
			case "LT":
				operator = "<"
			case "LE":
				operator = "<="
			case "GT":
				operator = ">"
			case "GE":
				operator = ">="
			}
			clauses = append(clauses, path+" "+operator+" ?")
		}
		parameters = append(parameters, condition.AttributeValueList...)
	}
	if len(clauses) != 0 {
		text += " WHERE " + strings.Join(clauses, " AND ")
	}
	if s.orderEnd != 0 {
		text += " " + s.text[s.orderStart:s.orderEnd]
	}
	return text, parameters
}
