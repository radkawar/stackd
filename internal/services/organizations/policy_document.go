package organizations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type policyOperators uint8

const (
	policyAssign policyOperators = 1 << iota
	policyAppend
	policyRemove
	policyAll = policyAssign | policyAppend | policyRemove
)

// managementNode represents the inheritance grammar shared by management
// policies. Service-owned settings remain JSON values, not IAM statements.
type managementNode struct {
	children         map[string]*managementNode
	assign           any
	assigned         bool
	priorAssignments []any
	append           []any
	remove           []any
	allowed          policyOperators
}

func managementObject(n *managementNode) bool {
	return !n.assigned && n.append == nil && n.remove == nil
}

func parseManagementPolicy(data []byte, kind string) (*managementNode, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	// Preserve numeric spelling until the service validator interprets it.
	// AWS distinguishes integer 60 from decimal 60.0 in backup settings.
	decoder.UseNumber()
	n, err := decodeManagementNode(decoder, kind, true)
	if err == nil && kind == "CHATBOT_POLICY" {
		normalizeChatFields(n)
	}
	return n, err
}

func decodeManagementNode(decoder *json.Decoder, kind string, root bool) (*managementNode, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("management policy settings must be objects")
	}
	n := &managementNode{allowed: policyAll}
	keys := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		canonical := key
		if kind == "CHATBOT_POLICY" {
			canonical = strings.ToLower(key)
			if strings.HasPrefix(key, "@@") {
				key = canonical
			}
		}
		if kind == "S3_POLICY" {
			key = strings.ToLower(key)
			// S3 rejects duplicate field names after folding, but admits distinct
			// case spellings of an operator and validates each supplied value.
			if !strings.HasPrefix(key, "@@") {
				canonical = key
			}
		}
		if !ok || keys[canonical] {
			return nil, fmt.Errorf("invalid or duplicate management policy key")
		}
		keys[canonical] = true
		if root && (kind == "AISERVICES_OPT_OUT_POLICY" || kind == "CHATBOT_POLICY") && (key == "@@assign" || key == "@@append" || key == "@@remove") {
			// AI and chat policies admit unused scalar and scalar-list root operators.
			var value any
			if err := decoder.Decode(&value); err != nil || !managementRootOperatorValue(value) {
				return nil, fmt.Errorf("invalid management policy root operator")
			}
			continue
		}
		switch key {
		case "@@assign":
			if n.assigned {
				n.priorAssignments = append(n.priorAssignments, n.assign)
			}
			if err := decoder.Decode(&n.assign); err != nil || n.assign == nil {
				return nil, fmt.Errorf("invalid assignment")
			}
			n.assigned = true
		case "@@append", "@@remove":
			var values []any
			if err := decoder.Decode(&values); err != nil || values == nil {
				return nil, fmt.Errorf("%s requires an array", key)
			}
			if key == "@@append" {
				n.append = values
			} else {
				n.remove = values
			}
		case "@@operators_allowed_for_child_policies":
			var allowed []string
			if err := decoder.Decode(&allowed); err != nil || len(allowed) == 0 {
				return nil, fmt.Errorf("invalid child operators")
			}
			n.allowed = 0
			seen := make(map[string]bool)
			for _, operator := range allowed {
				if seen[operator] {
					return nil, fmt.Errorf("duplicate child operator")
				}
				seen[operator] = true
				if kind == "CHATBOT_POLICY" || kind == "S3_POLICY" {
					operator = strings.ToLower(operator)
				}
				if operator == "@@none" && len(allowed) != 1 {
					return nil, fmt.Errorf("invalid child operator combination")
				}
				switch operator {
				case "@@all":
					n.allowed |= policyAll
				case "@@none":
				case "@@assign":
					n.allowed |= policyAssign
				case "@@append":
					n.allowed |= policyAppend
				case "@@remove":
					n.allowed |= policyRemove
				default:
					return nil, fmt.Errorf("unknown child operator %q", operator)
				}
			}
		default:
			if strings.HasPrefix(key, "@@") {
				return nil, fmt.Errorf("unknown inheritance operator %q", key)
			}
			child, err := decodeManagementNode(decoder, kind, false)
			if err != nil {
				return nil, err
			}
			if n.children == nil {
				n.children = make(map[string]*managementNode)
			}
			n.children[key] = child
		}
	}
	if len(keys) == 0 {
		n.children = make(map[string]*managementNode)
	}
	_, err = decoder.Token() // Consume the closing object delimiter.
	return n, err
}

// managementScalar follows the primitive-to-string conversion used by AWS
// management policies. Containers are never coerced into scalar policy fields.
func managementScalar(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case json.Number:
		return value.String(), true
	case bool:
		return strconv.FormatBool(value), true
	case nil:
		return "null", true
	default:
		return "", false
	}
}

func managementScalarSetting(n *managementNode, valid func(string) bool) bool {
	if len(n.children) != 0 || n.append != nil || n.remove != nil {
		return false
	}
	if !n.assigned {
		return true
	}
	matches := func(raw any) bool {
		value, ok := managementScalar(raw)
		return ok && valid(value)
	}
	if !matches(n.assign) {
		return false
	}
	for _, prior := range n.priorAssignments {
		if !matches(prior) {
			return false
		}
	}
	return true
}

func managementStringList(n *managementNode, valid func(string) bool, nonempty bool) bool {
	if len(n.children) != 0 {
		return false
	}
	assigned, ok := n.assign.([]any)
	if n.assigned && (!ok || nonempty && len(assigned) == 0) {
		return false
	}
	for _, values := range [][]any{assigned, n.append, n.remove} {
		if nonempty && values != nil && len(values) == 0 {
			return false
		}
		for _, raw := range values {
			value, ok := managementScalar(raw)
			if !ok || !valid(value) {
				return false
			}
		}
	}
	return true
}

func managementRootOperatorValue(value any) bool {
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if _, ok := managementScalar(item); !ok {
				return false
			}
		}
		return true
	}
	_, ok := managementScalar(value)
	return ok
}
