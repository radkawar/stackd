package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// AWSPrincipals returns a sorted copy of AWS principal references in a resource
// policy. Service principals and values appearing only in conditions are absent.
func (d *Document) AWSPrincipals() []string {
	var references []string
	for _, statement := range d.statements {
		for _, principal := range statement.principals {
			if principal.kind == "AWS" {
				references = append(references, principal.value)
			}
		}
	}
	slices.Sort(references)
	return slices.Compact(references)
}

// FederatedPrincipals returns the unique literal federated principal selectors.
func (d *Document) FederatedPrincipals() []string {
	var references []string
	for _, statement := range d.statements {
		for _, principal := range statement.principals {
			if principal.kind == "Federated" {
				references = append(references, principal.value)
			}
		}
	}
	slices.Sort(references)
	return slices.Compact(references)
}

// RewriteResourcePrincipals replaces only AWS principal references. In
// particular, conditions and resource names are never rewritten. It preserves
// scalar-versus-array policy structure and emits deterministic JSON.
func RewriteResourcePrincipals(data []byte, replacements map[string]string) ([]byte, error) {
	if _, err := ParseResource(data); err != nil {
		return nil, err
	}
	return rewritePrincipals(data, replacements)
}

// RewriteTrustPrincipals is the trust-policy counterpart of
// RewriteResourcePrincipals, preserving the absence of Resource elements.
func RewriteTrustPrincipals(data []byte, replacements map[string]string) ([]byte, error) {
	if _, err := TrustResourcePolicy(data); err != nil {
		return nil, err
	}
	return rewritePrincipals(data, replacements)
}

func rewritePrincipals(data []byte, replacements map[string]string) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	rawStatements := bytes.TrimSpace(document["Statement"])
	statements, err := scalarOrArray(rawStatements)
	if err != nil {
		return nil, err
	}
	for i, raw := range statements {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(raw, &statement); err != nil {
			return nil, err
		}
		for _, field := range []string{"Principal", "NotPrincipal"} {
			raw, exists := statement[field]
			if !exists {
				continue
			}
			if wildcard, _ := stringValue(raw); wildcard == "*" {
				continue
			}
			var principal map[string]json.RawMessage
			if err := json.Unmarshal(raw, &principal); err != nil {
				return nil, err
			}
			aws, exists := principal["AWS"]
			if !exists {
				continue
			}
			aws = bytes.TrimSpace(aws)
			values, err := scalarOrArray(aws)
			if err != nil {
				return nil, err
			}
			for i, raw := range values {
				reference, _ := stringValue(raw)
				if replacement, ok := replacements[reference]; ok {
					if !validPrincipalPattern("AWS", replacement) {
						return nil, fmt.Errorf("%w: invalid principal replacement", ErrInvalidPolicy)
					}
					values[i], _ = json.Marshal(replacement)
				}
			}
			if len(aws) != 0 && aws[0] == '[' {
				principal["AWS"], _ = json.Marshal(values)
			} else {
				principal["AWS"] = values[0]
			}
			statement[field], _ = json.Marshal(principal)
		}
		statements[i], _ = json.Marshal(statement)
	}
	if len(rawStatements) != 0 && rawStatements[0] == '[' {
		document["Statement"], _ = json.Marshal(statements)
	} else {
		document["Statement"] = statements[0]
	}
	return json.Marshal(document)
}
