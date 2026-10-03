package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// TrustResourcePolicy validates a role trust policy and gives its statements
// the implicit resource they have when attached to a role. The returned copy is
// for evaluation only; IAM stores and returns the original trust document.
func TrustResourcePolicy(data []byte) ([]byte, error) {
	if err := validateJSON(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	document, err := object(data)
	if err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(document["Statement"])
	statements, err := scalarOrArray(raw)
	if err != nil {
		return nil, err
	}
	for i, statement := range statements {
		fields, err := object(statement)
		if err != nil {
			return nil, err
		}
		if principal, err := stringValue(fields["Principal"]); err == nil && principal == "*" {
			return nil, fmt.Errorf("%w: role trust policies cannot use a scalar wildcard Principal", ErrInvalidPolicy)
		}
		if _, exists := fields["Resource"]; exists {
			return nil, fmt.Errorf("%w: trust policies must not contain Resource", ErrInvalidPolicy)
		}
		if _, exists := fields["NotResource"]; exists {
			return nil, fmt.Errorf("%w: trust policies must not contain NotResource", ErrInvalidPolicy)
		}
		fields["Resource"] = json.RawMessage(`"*"`)
		statements[i], _ = json.Marshal(fields)
	}
	if len(raw) > 0 && raw[0] == '[' {
		document["Statement"], _ = json.Marshal(statements)
	} else if len(statements) == 1 {
		document["Statement"] = statements[0]
	}
	result, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseResource(result)
	if err != nil {
		return nil, err
	}
	for _, statement := range parsed.statements {
		for _, principal := range statement.principals {
			if principal.kind == "Federated" && !validPrincipalPattern(principal.kind, principal.value) {
				return nil, fmt.Errorf("%w: invalid Federated trust principal", ErrInvalidPolicy)
			}
		}
	}
	return result, nil
}
