package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ContextKeys reports keys referenced by one policy, preserving their spelling
// and removing exact duplicates within that document. AWS's introspection API
// accepts incomplete policy statements and values that cannot be evaluated.
// This validates the introspection grammar only; never use it to authorize or
// validate a policy for storage. Parse performs enforcement validation.
func ContextKeys(data []byte) ([]string, error) {
	if err := validateJSON(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	obj, err := object(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if err := onlyFields(obj, "Version", "Id", "Statement"); err != nil {
		return nil, err
	}
	variables := false
	if raw, ok := obj["Version"]; ok {
		version, err := stringValue(raw)
		if err != nil || (version != "2008-10-17" && version != "2012-10-17") {
			return nil, fmt.Errorf("%w: invalid policy language version", ErrInvalidPolicy)
		}
		variables = version == "2012-10-17"
	}
	if raw, ok := obj["Id"]; ok {
		if _, err := stringValue(raw); err != nil {
			return nil, fmt.Errorf("%w: invalid policy Id", ErrInvalidPolicy)
		}
	}
	keys := make(map[string]bool)
	if raw, ok := obj["Statement"]; ok {
		statements, err := scalarOrArray(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid statements", ErrInvalidPolicy)
		}
		for _, raw := range statements {
			if err := statementContextKeys(raw, variables, keys); err != nil {
				return nil, err
			}
		}
	}
	return sortedKeys(keys), nil
}

// ConditionKeys returns the unique condition key names in a compiled policy,
// preserving their original spelling. Resource variables are not condition keys.
func (d *Document) ConditionKeys() []string {
	var keys []string
	for _, statement := range d.statements {
		for _, condition := range statement.conditions {
			keys = append(keys, condition.sourceKey)
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

func statementContextKeys(raw json.RawMessage, variables bool, keys map[string]bool) error {
	obj, err := object(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid statement", ErrInvalidPolicy)
	}
	if err := onlyFields(obj, "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal", "Condition"); err != nil {
		return err
	}
	effect, err := stringValue(obj["Effect"])
	if err != nil || (effect != "Allow" && effect != "Deny") {
		return fmt.Errorf("%w: Effect must be Allow or Deny", ErrInvalidPolicy)
	}
	if raw, ok := obj["Sid"]; ok {
		if _, err := stringValue(raw); err != nil {
			return fmt.Errorf("%w: invalid Sid", ErrInvalidPolicy)
		}
	}
	for _, field := range []string{"Action", "NotAction", "Resource", "NotResource"} {
		if raw, ok := obj[field]; ok {
			values, err := contextKeyStrings(raw)
			if err != nil {
				return err
			}
			if strings.HasSuffix(field, "Resource") {
				for _, value := range values {
					if err := templateContextKeys(value, variables, keys); err != nil {
						return err
					}
				}
			}
		}
	}
	for _, field := range []string{"Principal", "NotPrincipal"} {
		if raw, ok := obj[field]; ok {
			if principals, err := object(raw); err == nil {
				for _, raw := range principals {
					if _, err := contextKeyStrings(raw); err != nil {
						return err
					}
				}
			} else if _, err := contextKeyStrings(raw); err != nil {
				return err
			}
		}
	}
	if raw, ok := obj["Condition"]; ok {
		conditions, err := object(raw)
		if err != nil {
			return fmt.Errorf("%w: invalid Condition", ErrInvalidPolicy)
		}
		for name, raw := range conditions {
			if _, err := parseOperator(name); err != nil {
				return err
			}
			conditions, err := object(raw)
			if err != nil {
				return fmt.Errorf("%w: invalid condition keys", ErrInvalidPolicy)
			}
			for key, raw := range conditions {
				keys[key] = true
				values, err := scalarOrArray(raw)
				if err != nil {
					return fmt.Errorf("%w: invalid condition values", ErrInvalidPolicy)
				}
				for _, raw := range values {
					value, err := conditionScalar(raw)
					if err != nil {
						return fmt.Errorf("%w: invalid condition value", ErrInvalidPolicy)
					}
					if err := templateContextKeys(value, variables, keys); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func contextKeyStrings(raw json.RawMessage) ([]string, error) {
	values, err := scalarOrArray(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid string list", ErrInvalidPolicy)
	}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value, err := stringValue(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid string", ErrInvalidPolicy)
		}
		result = append(result, value)
	}
	return result, nil
}

func templateContextKeys(value string, variables bool, keys map[string]bool) error {
	template, err := compileTemplate(value, variables)
	if err != nil {
		return err
	}
	for _, part := range template.parts {
		if part.sourceKey != "" {
			keys[part.sourceKey] = true
		} else if part.literal {
			// AWS includes the three predefined literal variable names too.
			keys[part.text] = true
		}
	}
	return nil
}
