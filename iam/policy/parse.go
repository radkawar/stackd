package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

var (
	actionPattern = regexp.MustCompile(`^[A-Za-z0-9-]+:[A-Za-z0-9*?]+$`)
	sidPattern    = regexp.MustCompile(`^[A-Za-z0-9]*$`)
)

// Parse validates and compiles an IAM identity policy. Statement, Action,
// Resource, and condition values accept their documented scalar or array forms.
// Both policy language versions are accepted. Unknown fields, duplicate JSON
// members, resource-policy principals, and unsupported features return errors.
func Parse(data []byte) (*Document, error) {
	return parseDocument(data, identityDocument)
}

type documentKind uint8

const (
	identityDocument documentKind = iota
	resourceDocument
	simulationDocument
	sessionDocument
	simulationResourceDocument
)

func (k documentKind) resourcePolicy() bool {
	return k == resourceDocument || k == simulationResourceDocument
}

func (k documentKind) simulation() bool {
	return k == simulationDocument || k == simulationResourceDocument
}

// ParseSession accepts STS inline session policies. STS permits numeric, date,
// IP and ARN literals that IAM policy storage rejects; their comparison behavior
// is retained for authorization. An empty Condition object adds no restrictions.
// Structural and binary-value validation remains.
func ParseSession(data []byte) (*Document, error) {
	return parseDocument(data, sessionDocument)
}

func parseDocument(data []byte, kind documentKind) (*Document, error) {
	resourcePolicy := kind.resourcePolicy()
	allowID := resourcePolicy || kind.simulation()
	if err := validateJSON(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	obj, err := object(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	fields := []string{"Version", "Statement"}
	if allowID {
		fields = append(fields, "Id")
	}
	if err := onlyFields(obj, fields...); err != nil {
		return nil, err
	}
	if id, ok := obj["Id"]; ok {
		if _, err := stringValue(id); err != nil {
			return nil, fmt.Errorf("%w: Id must be a string", ErrInvalidPolicy)
		}
	}
	variables := false
	if value, ok := obj["Version"]; ok {
		version, err := stringValue(value)
		if err != nil || (version != "2008-10-17" && version != "2012-10-17") {
			return nil, fmt.Errorf("%w: Version must be 2008-10-17 or 2012-10-17", ErrInvalidPolicy)
		}
		variables = version == "2012-10-17"
	}
	raw, ok := obj["Statement"]
	if !ok {
		return nil, fmt.Errorf("%w: Statement is required", ErrInvalidPolicy)
	}
	statements, err := scalarOrArray(raw)
	if err != nil || len(statements) == 0 {
		return nil, fmt.Errorf("%w: Statement must contain at least one statement", ErrInvalidPolicy)
	}
	positions, err := statementPositions(data)
	if err != nil || len(positions) != len(statements) {
		return nil, fmt.Errorf("%w: cannot locate policy statements", ErrInvalidPolicy)
	}
	doc := &Document{resourcePolicy: resourcePolicy}
	sids := make(map[string]bool)
	for i, raw := range statements {
		st, err := parseStatement(raw, kind, variables)
		if err != nil {
			return nil, fmt.Errorf("statement[%d]: %w", i, err)
		}
		st.start, st.end = positions[i].start, positions[i].end
		if st.sid != "" {
			if sids[st.sid] {
				return nil, fmt.Errorf("%w: duplicate Sid %q", ErrInvalidPolicy, st.sid)
			}
			sids[st.sid] = true
		}
		doc.statements = append(doc.statements, st)
	}
	return doc, nil
}

func parseStatement(raw json.RawMessage, kind documentKind, variables bool) (statement, error) {
	resourcePolicy := kind.resourcePolicy()
	var st statement
	obj, err := object(raw)
	if err != nil {
		return st, fmt.Errorf("%w: statement must be an object", ErrInvalidPolicy)
	}
	fields := []string{"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"}
	if resourcePolicy {
		fields = append(fields, "Principal", "NotPrincipal")
	}
	if err := onlyFields(obj, fields...); err != nil {
		return st, err
	}
	if raw, ok := obj["Sid"]; ok {
		st.sid, err = stringValue(raw)
		if err != nil || (!resourcePolicy && !sidPattern.MatchString(st.sid)) {
			return st, fmt.Errorf("%w: Sid must contain only ASCII letters and digits", ErrInvalidPolicy)
		}
	}
	effect, err := stringValue(obj["Effect"])
	if err != nil || (effect != "Allow" && effect != "Deny") {
		return st, fmt.Errorf("%w: Effect must be Allow or Deny", ErrInvalidPolicy)
	}
	st.effect = Allow
	if effect == "Deny" {
		st.effect = ExplicitDeny
	}
	st.actions, st.notAction, err = alternatives(obj, "Action", "NotAction")
	if err != nil {
		return st, err
	}
	for _, action := range st.actions {
		if action != "*" && !actionPattern.MatchString(action) {
			return st, fmt.Errorf("%w: invalid action %q", ErrInvalidPolicy, action)
		}
	}
	var resources []string
	resources, st.notResource, err = alternatives(obj, "Resource", "NotResource")
	if err != nil {
		return st, err
	}
	st.resourcePatterns = resources
	for _, resource := range resources {
		template, err := resourceTemplate(resource, variables)
		if err != nil {
			return st, err
		}
		st.resources = append(st.resources, template)
	}

	if raw, ok := obj["Condition"]; ok {
		st.conditions, err = parseConditions(raw, kind, variables)
	}
	if err == nil && resourcePolicy {
		st.principals, st.notPrincipal, err = parsePrincipals(obj)
	}
	return st, err
}

func alternatives(obj map[string]json.RawMessage, positive, negative string) ([]string, bool, error) {
	p, pOK := obj[positive]
	n, nOK := obj[negative]
	if pOK == nOK {
		return nil, false, fmt.Errorf("%w: exactly one of %s and %s is required", ErrInvalidPolicy, positive, negative)
	}
	if nOK {
		p = n
	}
	raw, err := scalarOrArray(p)
	if err != nil || len(raw) == 0 {
		return nil, false, fmt.Errorf("%w: %s/%s must contain a nonempty string or array", ErrInvalidPolicy, positive, negative)
	}
	values := make([]string, len(raw))
	for i, v := range raw {
		values[i], err = stringValue(v)
		if err != nil || values[i] == "" {
			return nil, false, fmt.Errorf("%w: %s/%s values must be nonempty strings", ErrInvalidPolicy, positive, negative)
		}
	}
	return values, nOK, nil
}

func normalizeResource(value string) (string, error) {
	if value == "*" {
		return value, nil
	}
	parts := strings.SplitN(value, ":", 6)
	if len(parts) < 3 || parts[0] != "arn" || parts[1] == "" || parts[2] == "" || strings.ContainsAny(parts[2], "*?") {
		return "", fmt.Errorf("%w: Resource must be an ARN or *", ErrInvalidPolicy)
	}
	// Identity policies complete missing ARN components with wildcards.
	for len(parts) < 6 {
		parts = append(parts, "*")
	}
	return strings.Join(parts, ":"), nil
}

func onlyFields(obj map[string]json.RawMessage, names ...string) error {
	for _, key := range sortedKeys(obj) {
		if !slices.Contains(names, key) {
			return fmt.Errorf("%w: unexpected field %q in identity policy", ErrInvalidPolicy, key)
		}
	}
	return nil
}

func object(raw []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	return obj, nil
}

func scalarOrArray(raw json.RawMessage) ([]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, fmt.Errorf("expected value or array")
	}
	if raw[0] != '[' {
		return []json.RawMessage{raw}, nil
	}
	var values []json.RawMessage
	err := json.Unmarshal(raw, &values)
	return values, err
}

func stringValue(raw json.RawMessage) (string, error) {
	var value string
	if len(raw) == 0 || raw[0] != '"' {
		return "", fmt.Errorf("expected string")
	}
	err := json.Unmarshal(raw, &value)
	return value, err
}

func sortedKeys[V any](obj map[string]V) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// validateJSON prevents the default decoder's last-value-wins handling of
// duplicate object members from silently discarding an authorization rule.
func validateJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanJSON(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("unexpected content after policy document")
	}
	return nil
}

func scanJSON(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("expected object key")
			}
			if seen[key] {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = true
			if err := scanJSON(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := scanJSON(dec); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	_, err = dec.Token()
	return err
}
