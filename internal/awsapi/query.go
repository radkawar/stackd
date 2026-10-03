package awsapi

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/awscatalog"
)

func queryValue(service awscatalog.Service, id awscatalog.ShapeID, path string, query url.Values, flattened bool) (json.RawMessage, bool, error) {
	shape, ok := service.Shape(id)
	if !ok {
		return nil, false, fmt.Errorf("missing generated shape %s", id)
	}
	switch shape.Kind {
	case "structure", "union":
		object := map[string]json.RawMessage{}
		for _, member := range shape.Members {
			wireName := member.XMLName
			if service.Protocol == awscatalog.EC2Query {
				wireName = member.EC2QueryName
			} else if wireName == "" {
				wireName = member.Name
			}
			childPath := joinPath(path, wireName)
			value, present, err := queryValue(service, member.Target, childPath, query, member.XMLFlattened)
			if err != nil {
				return nil, false, err
			}
			if !present {
				continue
			}
			jsonName := member.JSONName
			if jsonName == "" {
				jsonName = member.Name
			}
			object[jsonName] = value
		}
		value, err := json.Marshal(object)
		return value, len(object) > 0 || path == "", err
	case "list", "set":
		prefix := path
		if service.Protocol != awscatalog.EC2Query && !flattened && !shape.XMLFlattened {
			name := shape.Member.XMLName
			if name == "" {
				name = "member"
			}
			prefix = joinPath(prefix, name)
		}
		elements, err := queryElements(query, prefix, service.Protocol == awscatalog.EC2Query)
		if err != nil {
			return nil, false, err
		}
		values := make([]json.RawMessage, 0, len(elements))
		for _, element := range elements {
			if element == nil {
				values = append(values, json.RawMessage("null"))
				continue
			}
			value, present, err := queryValue(service, shape.Member.Target, "", element, false)
			if err != nil {
				return nil, false, err
			}
			if !present && service.Protocol == awscatalog.EC2Query {
				member, _ := service.Shape(shape.Member.Target)
				if member.Kind == "string" || member.Kind == "enum" {
					value, present = json.RawMessage(`""`), true
				}
			}
			if !present {
				return nil, false, &ValidationError{Path: path, Reason: "unexpected nested collection member", Constraint: "query"}
			}
			values = append(values, value)
		}
		if len(elements) == 0 {
			if _, present := query[path]; present {
				if service.Protocol == awscatalog.EC2Query {
					value, _, err := queryValue(service, shape.Member.Target, path, query, false)
					if err != nil {
						return nil, false, err
					}
					return json.RawMessage(append(append([]byte{'['}, value...), ']')), true, nil
				}
				if query.Get(path) != "" {
					return nil, false, &ValidationError{Path: path, Reason: "expected indexed query list"}
				}
				return json.RawMessage("[]"), true, nil
			}
			return nil, false, nil
		}
		value, err := json.Marshal(values)
		return value, true, err
	case "map":
		prefix := path
		if !flattened && !shape.XMLFlattened {
			prefix = joinPath(prefix, "entry")
		}
		elements, err := queryElements(query, prefix, false)
		if err != nil {
			return nil, false, err
		}
		values := map[string]json.RawMessage{}
		for _, element := range elements {
			keyName, valueName := shape.Key.XMLName, shape.Value.XMLName
			if keyName == "" {
				keyName = "key"
			}
			if valueName == "" {
				valueName = "value"
			}
			key, ok := element[keyName]
			if !ok || len(key) != 1 {
				return nil, false, &ValidationError{Path: path, Reason: "map entry key is required"}
			}
			if _, exists := values[key[0]]; exists {
				return nil, false, &ValidationError{Path: path, Reason: "duplicate map key"}
			}
			value, present, err := queryValue(service, shape.Value.Target, valueName, element, false)
			if err != nil {
				return nil, false, err
			}
			if !present {
				return nil, false, &ValidationError{Path: path, Reason: "map entry value is required"}
			}
			values[key[0]] = value
		}
		if len(elements) == 0 {
			return nil, false, nil
		}
		value, err := json.Marshal(values)
		return value, true, err
	default:
		values, present := query[path]
		if !present {
			return nil, false, nil
		}
		if len(values) != 1 {
			return nil, false, &ValidationError{Path: path, Reason: "query parameter must occur exactly once"}
		}
		switch shape.Kind {
		case "boolean":
			switch values[0] {
			case "true", "1":
				return json.RawMessage("true"), true, nil
			case "false", "0":
				return json.RawMessage("false"), true, nil
			default:
				return nil, false, &ValidationError{Path: path, Reason: "expected true, false, 1 or 0", Constraint: "query"}
			}
		case "byte", "short", "integer", "long", "intEnum":
			// Query integers accept a leading sign and zeroes, unlike JSON.
			// Generated normalization owns the modeled type and value bounds.
			value, ok := new(big.Int).SetString(values[0], 10)
			if !ok {
				return nil, false, &ValidationError{Path: path, Reason: "expected a decimal integer", Constraint: "query"}
			}
			return json.RawMessage(value.String()), true, nil
		case "float", "double":
			value := json.RawMessage(values[0])
			if !json.Valid(value) {
				return nil, false, &ValidationError{Path: path, Reason: "invalid " + string(shape.Kind) + " query value", Constraint: "query"}
			}
			return value, true, nil
		default:
			value, err := json.Marshal(values[0])
			return value, true, err
		}
	}
}

// queryElements groups wire fields by numeric position. AWS Query retains gaps
// for modeled validation; EC2 Query compacts supplied positions, including zero.
func queryElements(query url.Values, prefix string, compact bool) ([]url.Values, error) {
	groups := make(map[int]url.Values)
	for _, key := range slices.Sorted(maps.Keys(query)) {
		if !strings.HasPrefix(key, prefix+".") {
			continue
		}
		tail := strings.TrimPrefix(key, prefix+".")
		indexText, field, _ := strings.Cut(tail, ".")
		if strings.HasPrefix(indexText, "-") {
			return nil, &ValidationError{Path: key, Reason: "negative collection index", Constraint: "query"}
		}
		index := 1
		if decimalIndex(indexText) {
			var err error
			index, err = strconv.Atoi(indexText)
			if err != nil || (index == 0 && !compact) {
				return nil, &ValidationError{Path: key, Reason: "invalid collection index", Constraint: "query"}
			}
			next, _, _ := strings.Cut(field, ".")
			if !compact && decimalIndex(next) {
				return nil, &ValidationError{Path: key, Reason: "consecutive collection indices", Constraint: "query"}
			}
		} else {
			// Non-index keys belong to an unindexed member. Structure validation
			// handles its missing modeled fields; primitive members reject nesting.
			field = tail
		}
		if groups[index] == nil {
			groups[index] = make(url.Values)
		}
		groups[index][field] = append(groups[index][field], query[key]...)
	}
	if len(groups) == 0 {
		return nil, nil
	}
	if compact {
		elements := make([]url.Values, 0, len(groups))
		for _, index := range slices.Sorted(maps.Keys(groups)) {
			elements = append(elements, groups[index])
		}
		return elements, nil
	}
	// AWS starts the collection at position one, then permits each supplied
	// position to extend it by at most ten. Thus 11 is admitted as a first
	// position, while 12 is malformed even when position one is also supplied.
	elements := make([]url.Values, 1)
	for _, index := range slices.Sorted(maps.Keys(groups)) {
		if index-len(elements) > 10 {
			return nil, &ValidationError{Path: prefix, Reason: "excessively sparse collection", Constraint: "query"}
		}
		for len(elements) < index {
			elements = append(elements, nil)
		}
		elements[index-1] = groups[index]
	}
	return elements, nil
}

func decimalIndex(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func joinPath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}
