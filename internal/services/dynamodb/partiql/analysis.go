package partiql

import (
	"encoding/base64"
	"fmt"
	"sort"

	api "stackd/internal/awsapi/dynamodb"
)

// Access describes facts proven by a statement, not its evaluated result.
// Nil LeadingKeys means no finite key bound was proven. Attributes contains
// explicitly requested top-level names, not the attributes an item may return.
// FullTableScan is absent when a read cannot reach query/scan execution.
type Access struct {
	LeadingKeys         []string
	Attributes          []string
	ProjectedAttributes []string
	FullTableScan       *bool
	ReadPlan            *ReadPlan
	// ReadError is reported after authorization; invalid plans can omit IAM context.
	ReadError error
}

// Analyze resolves positional parameters against the original statement order.
// schema is the queried table's (or index's) key schema.
// This function deliberately does not evaluate arithmetic, functions or item
// conditions. Unproven access is reported conservatively instead.
func (s *Statement) Analyze(schema api.KeySchema, parameters []api.AttributeValue) (Access, error) {
	if len(parameters) != s.parameters {
		return Access{}, fmt.Errorf("PartiQL expected %d parameters, received %d", s.parameters, len(parameters))
	}
	var partitionKey string
	for _, member := range schema {
		if *member.KeyType == "HASH" {
			partitionKey = string(*member.AttributeName)
		}
	}
	attributes := make(map[string]struct{})
	var access Access
	for i, x := range s.reads {
		collectAttributes(x, attributes)
		if i+1 == s.projections {
			access.ProjectedAttributes = attributeNames(attributes)
		}
	}
	collectAttributes(s.where, attributes)
	var keys []string
	var boundedKeys bool
	if s.item != nil {
		switch s.item.kind {
		case "map":
			seen := make(map[string]struct{}, len(s.item.fields))
			for _, f := range s.item.fields {
				// Duplicate fields are ambiguous until validated by the engine.
				if _, duplicate := seen[f.name]; duplicate {
					return Access{}, fmt.Errorf("PartiQL INSERT contains duplicate attribute %q", f.name)
				}
				seen[f.name] = struct{}{}
				attributes[f.name] = struct{}{}
				collectAttributes(f.value, attributes)
				if f.name == partitionKey {
					if key, ok := scalar(f.value, parameters); ok {
						keys, boundedKeys = []string{key}, true
					}
				}
			}
		case "parameter":
			item := parameters[s.item.ordinal].M
			for name, value := range item {
				attributes[string(name)] = struct{}{}
				if string(name) == partitionKey {
					if key, ok := attributeScalar(value); ok {
						keys, boundedKeys = []string{key}, true
					}
				}
			}
		}
	} else if s.action == "PartiQLSelect" {
		access.ReadPlan, access.ReadError = s.readPlan(schema, parameters)
		if access.ReadError == nil {
			access.FullTableScan = new(access.ReadPlan == nil)
		}
		if access.ReadPlan != nil {
			boundedKeys = true
			for _, r := range access.ReadPlan.Ranges {
				key, _ := attributeScalar(r.Conditions[api.AttributeName(partitionKey)].AttributeValueList[0])
				keys = append(keys, key)
			}
		}
	} else {
		keys, boundedKeys = keyBounds(s.where, partitionKey, parameters, false)
	}
	if boundedKeys {
		access.LeadingKeys = unique(keys)
	}
	access.Attributes = attributeNames(attributes)
	return access, nil
}

func attributeNames(attributes map[string]struct{}) []string {
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func collectAttributes(x *expression, into map[string]struct{}) {
	if x == nil {
		return
	}
	if x.kind == "path" {
		into[x.value] = struct{}{}
	}
	for _, child := range x.children {
		collectAttributes(child, into)
	}
	for _, f := range x.fields {
		collectAttributes(f.value, into)
	}
}

// Bounds are a superset of possible partition keys. AND may inherit either
// bound; OR needs both. Negation is pushed through boolean operators (including
// double NOT) but never turns an inequality into a fictitious finite key bound.
func keyBounds(x *expression, partitionKey string, parameters []api.AttributeValue, negative bool) ([]string, bool) {
	if x == nil || partitionKey == "" {
		return nil, false
	}
	if x.kind == "NOT" {
		return keyBounds(x.children[0], partitionKey, parameters, !negative)
	}
	if x.kind == "AND" || x.kind == "OR" {
		left, leftOK := keyBounds(x.children[0], partitionKey, parameters, negative)
		right, rightOK := keyBounds(x.children[1], partitionKey, parameters, negative)
		and := x.kind == "AND"
		if negative {
			and = !and
		}
		if and {
			if leftOK {
				return left, true
			}
			return right, rightOK
		}
		if !leftOK || !rightOK {
			return nil, false
		}
		return append(left, right...), true
	}
	if negative {
		return nil, false
	}
	if x.kind == "=" {
		if isPartitionPath(x.children[0], partitionKey) {
			if key, ok := scalar(x.children[1], parameters); ok {
				return []string{key}, true
			}
		}
		if isPartitionPath(x.children[1], partitionKey) {
			if key, ok := scalar(x.children[0], parameters); ok {
				return []string{key}, true
			}
		}
	}
	if x.kind == "IN" && isPartitionPath(x.children[0], partitionKey) {
		return scalarList(x.children[1], parameters)
	}
	return nil, false
}

func isPartitionPath(x *expression, name string) bool {
	return x.kind == "path" && !x.nested && x.value == name
}

func scalar(x *expression, parameters []api.AttributeValue) (string, bool) {
	if x.nested {
		return "", false
	}
	switch x.kind {
	case "string", "number":
		return x.value, true
	case "parameter":
		return attributeScalar(parameters[x.ordinal])
	case "unary+", "unary-":
		// A sign on a numeric literal is a literal, not computed key arithmetic.
		child := x.children[0]
		if child.kind == "number" && !child.nested {
			if x.kind == "unary-" {
				return "-" + child.value, true
			}
			return child.value, true
		}
	}
	return "", false
}

func attributeScalar(value api.AttributeValue) (string, bool) {
	// AttributeValue is a generated struct, not a tagged union. Refuse malformed
	// multi-type values instead of selecting a convenient key for authorization.
	kinds := 0
	if value.S != nil {
		kinds++
	}
	if value.N != nil {
		kinds++
	}
	if value.B != nil {
		kinds++
	}
	if value.BOOL != nil {
		kinds++
	}
	if value.NULL != nil {
		kinds++
	}
	if value.M != nil {
		kinds++
	}
	if value.L != nil {
		kinds++
	}
	if value.SS != nil {
		kinds++
	}
	if value.NS != nil {
		kinds++
	}
	if value.BS != nil {
		kinds++
	}
	if kinds != 1 {
		return "", false
	}
	if value.S != nil {
		return string(*value.S), true
	}
	if value.N != nil {
		return string(*value.N), true
	}
	if value.B != nil {
		return base64.StdEncoding.EncodeToString(value.B), true
	}
	return "", false
}

func scalarList(x *expression, parameters []api.AttributeValue) ([]string, bool) {
	if x.nested {
		return nil, false
	}
	if x.kind == "list" {
		if len(x.children) == 0 {
			return nil, false
		}
		keys := make([]string, 0, len(x.children))
		for _, child := range x.children {
			key, ok := scalar(child, parameters)
			if !ok {
				return nil, false
			}
			keys = append(keys, key)
		}
		return keys, true
	}
	if x.kind == "parameter" {
		value := parameters[x.ordinal]
		// Lists supplied to IN are not evaluated; only scalar members establish
		// bounds. Other DynamoDB collection types remain engine-validated.
		if len(value.L) == 0 || value.S != nil || value.N != nil || value.B != nil || value.BOOL != nil || value.NULL != nil || value.M != nil || value.SS != nil || value.NS != nil || value.BS != nil {
			return nil, false
		}
		keys := make([]string, 0, len(value.L))
		for _, child := range value.L {
			key, ok := attributeScalar(child)
			if !ok {
				return nil, false
			}
			keys = append(keys, key)
		}
		return keys, true
	}
	return nil, false
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}
