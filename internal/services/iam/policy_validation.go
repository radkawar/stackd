package iam

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	iampolicy "stackd/iam/policy"
	"stackd/internal/awswire"
)

type policyDocument struct {
	Version   string
	Id        string
	Statement json.RawMessage
}

type policyStatement struct {
	Sid          string
	Effect       string
	Principal    json.RawMessage
	NotPrincipal json.RawMessage
	Action       json.RawMessage
	NotAction    json.RawMessage
	Resource     json.RawMessage
	NotResource  json.RawMessage
	Condition    json.RawMessage
}

func malformed(message string) *awswire.Error {
	return &awswire.Error{Code: "MalformedPolicyDocument", Message: message, StatusCode: 400}
}

// IAM owns document size and storage-specific structure checks. Condition
// syntax and literal validation are shared with the policy compiler.
func validateDocument(v string, trust bool) *awswire.Error {
	if len(v) == 0 || len(v) > 131072 {
		return malformed("Policy document must contain 1-131072 characters.")
	}
	for _, r := range v {
		if r > 0xff || (r < 0x20 && r != '\n' && r != '\r' && r != '\t') {
			return malformed("Policy document contains invalid characters.")
		}
	}
	if !json.Valid([]byte(v)) {
		return malformed("Invalid JSON policy document.")
	}
	if err := uniqueJSONKeys(json.NewDecoder(strings.NewReader(v))); err != nil {
		return malformed(err.Error())
	}
	var d policyDocument
	if err := exactJSONObject([]byte(v), &d, "Version", "Id", "Statement"); err != nil {
		return malformed(err.Error())
	}
	if d.Version != "" && d.Version != "2012-10-17" && d.Version != "2008-10-17" {
		return malformed("Invalid policy language version.")
	}
	if !trust && d.Id != "" {
		return malformed("Identity policies must not contain Id.")
	}
	var rawStatements []json.RawMessage
	if len(d.Statement) != 0 && d.Statement[0] == '{' {
		rawStatements = []json.RawMessage{d.Statement}
	} else if json.Unmarshal(d.Statement, &rawStatements) != nil {
		return malformed("Invalid policy statements.")
	}
	if len(rawStatements) == 0 {
		return malformed("Policy must include at least one statement.")
	}
	for _, raw := range rawStatements {
		var statement policyStatement
		if err := exactJSONObject(raw, &statement, "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition"); err != nil {
			return malformed(err.Error())
		}
		if err := validateStatement(statement, trust, d.Version == "2012-10-17"); err != nil {
			return err
		}
	}
	return nil
}

func validateStatement(s policyStatement, trust, variables bool) *awswire.Error {
	if s.Effect != "Allow" && s.Effect != "Deny" {
		return malformed("Statement Effect must be Allow or Deny.")
	}
	if (len(s.Action) == 0) == (len(s.NotAction) == 0) {
		return malformed("Statement must specify exactly one Action or NotAction.")
	}
	for _, raw := range []json.RawMessage{s.Action, s.NotAction} {
		if len(raw) == 0 {
			continue
		}
		actions, ok := stringList(raw)
		if !ok {
			return malformed("Actions must be strings or nonempty string lists.")
		}
		for _, action := range actions {
			if action != "*" && !strings.Contains(action, ":") {
				return malformed("Actions require a service prefix.")
			}
			if action != "*" {
				prefix, _, _ := strings.Cut(action, ":")
				if strings.ContainsAny(prefix, "*?") {
					return malformed("Action service prefixes must not contain wildcards.")
				}
			}
		}
	}
	if trust {
		if len(s.Resource) != 0 || len(s.NotResource) != 0 {
			return malformed("Trust policies must not include Resource or NotResource.")
		}
		if (len(s.Principal) == 0) == (len(s.NotPrincipal) == 0) {
			return malformed("Trust statements require exactly one Principal or NotPrincipal.")
		}
		principal := s.Principal
		if len(principal) == 0 {
			principal = s.NotPrincipal
		}
		if err := validatePrincipal(principal); err != nil {
			return err
		}
	} else {
		if len(s.Principal) != 0 || len(s.NotPrincipal) != 0 {
			return malformed("Identity policies must not specify Principal or NotPrincipal.")
		}
		if (len(s.Resource) == 0) == (len(s.NotResource) == 0) {
			return malformed("Statement must specify exactly one Resource or NotResource.")
		}
		for _, raw := range []json.RawMessage{s.Resource, s.NotResource} {
			if len(raw) == 0 {
				continue
			}
			resources, ok := stringList(raw)
			if !ok {
				return malformed("Resources must be strings or nonempty string lists.")
			}
			for _, resource := range resources {
				if resource != "*" && !strings.HasPrefix(resource, "arn:") {
					return malformed("Resources must be ARNs or *.")
				}
			}
		}
	}
	if len(s.Condition) != 0 {
		if err := iampolicy.ValidateStoredConditions(s.Condition, variables); err != nil {
			return malformed(err.Error())
		}
	}
	return nil
}

func validatePrincipal(raw json.RawMessage) *awswire.Error {
	var wildcard string
	if json.Unmarshal(raw, &wildcard) == nil && wildcard == "*" {
		return nil
	}
	var principal map[string]json.RawMessage
	if json.Unmarshal(raw, &principal) != nil || len(principal) == 0 {
		return malformed("Invalid principal in trust policy.")
	}
	for kind, values := range principal {
		if kind != "AWS" && kind != "Service" && kind != "Federated" && kind != "CanonicalUser" {
			return malformed("Invalid principal type.")
		}
		if _, ok := stringList(values); !ok {
			return malformed("Invalid principal value.")
		}
	}
	return nil
}

func stringList(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 {
		return nil, false
	}
	for _, value := range many {
		if value == "" {
			return nil, false
		}
	}
	return many, true
}

func exactJSONObject(raw []byte, target any, allowed ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
		return fmt.Errorf("expected a nonempty policy object")
	}
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("unrecognized policy element %q", key)
		}
	}
	return json.Unmarshal(raw, target)
}

// uniqueJSONKeys rejects ambiguous documents before decoding into typed models.
func uniqueJSONKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate policy element %q", key)
			}
			seen[key] = struct{}{}
			if err := uniqueJSONKeys(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSONKeys(decoder); err != nil {
				return err
			}
		}
	}
	_, err = decoder.Token()
	return err
}
