package eventbridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"stackd/iam/policy"
)

// EventBridge bus-policy admission supports a subset of the service's IAM
// actions. Smithy/SAR do not describe it; the action_admission native fixture
// checks every published IAM events action, including rejected administration.
var permissionActions = [...]string{
	"events:DeleteRule",
	"events:DescribeEventBus",
	"events:DescribeRule",
	"events:DisableRule",
	"events:EnableRule",
	"events:ListRuleNamesByTarget",
	"events:ListRules",
	"events:ListTagsForResource",
	"events:ListTargetsByRule",
	"events:PutEvents",
	"events:PutRule",
	"events:PutTargets",
	"events:RemoveTargets",
	"events:TagResource",
	"events:UntagResource",
}

// permissionPolicy is the stored presentation and statement-editing shape.
// IAM's parser and binder own the language, evaluation and immutable principals.
type permissionPolicy struct {
	Version    string            `json:"Version"`
	ID         *string           `json:"Id,omitempty"`
	Statements []json.RawMessage `json:"Statement"`
	Principals []string          `json:"-"`
}

func readPermissionPolicy(document string) (permissionPolicy, error) {
	if document == "" {
		return permissionPolicy{Version: "2012-10-17"}, nil
	}
	var raw struct {
		Version   string
		ID        *string `json:"Id"`
		Statement json.RawMessage
	}
	if err := json.Unmarshal([]byte(document), &raw); err != nil {
		return permissionPolicy{}, err
	}
	out := permissionPolicy{Version: raw.Version, ID: raw.ID}
	if bytes.HasPrefix(bytes.TrimSpace(raw.Statement), []byte("[")) {
		if err := json.Unmarshal(raw.Statement, &out.Statements); err != nil {
			return permissionPolicy{}, err
		}
	} else {
		out.Statements = []json.RawMessage{raw.Statement}
	}
	return out, nil
}

func permissionSID(statement json.RawMessage) string {
	var fields struct{ Sid string }
	_ = json.Unmarshal(statement, &fields)
	return fields.Sid
}

func validatePermissionPolicy(document string, key BusKey) (permissionPolicy, error) {
	parsed, err := policy.ParseResource([]byte(document))
	if err != nil {
		return permissionPolicy{}, failure("ValidationException", err.Error())
	}
	replacements := map[string]string{}
	for _, principal := range parsed.AWSPrincipals() {
		if len(principal) == 12 && strings.Trim(principal, "0123456789") == "" {
			replacements[principal] = "arn:" + key.Partition + ":iam::" + principal + ":root"
		}
	}
	canonical, err := policy.RewriteResourcePrincipals([]byte(document), replacements)
	if err != nil {
		return permissionPolicy{}, err
	}
	out, err := readPermissionPolicy(string(canonical))
	if err != nil {
		return permissionPolicy{}, err
	}
	if out.Version == "" {
		return permissionPolicy{}, failure("ValidationException", "Missing required field Version")
	}
	for _, principal := range parsed.AWSPrincipals() {
		if normalized, ok := replacements[principal]; ok {
			principal = normalized
		}
		out.Principals = append(out.Principals, principal)
	}
	for _, raw := range out.Statements {
		var statement struct {
			Sid                                  *string
			Action, Resource                     json.RawMessage
			NotAction, NotResource, NotPrincipal json.RawMessage
		}
		if err := json.Unmarshal(raw, &statement); err != nil {
			return permissionPolicy{}, err
		}
		if statement.Sid == nil || *statement.Sid == "" {
			return permissionPolicy{}, failure("ValidationException", "Missing required field Sid")
		}
		for _, negative := range []struct {
			name string
			raw  json.RawMessage
		}{{"NotAction", statement.NotAction}, {"NotResource", statement.NotResource}, {"NotPrincipal", statement.NotPrincipal}} {
			if negative.raw != nil {
				return permissionPolicy{}, failure("ValidationException", "Has prohibited field "+negative.name)
			}
		}
		actions := permissionStrings(statement.Action)
		for _, action := range actions {
			if action == "*" {
				continue
			}
			if !strings.HasPrefix(strings.ToLower(action), "events:") {
				return permissionPolicy{}, failure("ValidationException", "Action field includes AWS services that are inconsistent with specified vendor")
			}
			matched := false
			for _, known := range permissionActions {
				if match, _ := path.Match(strings.ToLower(action), strings.ToLower(known)); match {
					matched = true
					break
				}
			}
			if !matched {
				return permissionPolicy{}, failure("ValidationException", fmt.Sprintf("The following action names are invalid: %q", action))
			}
		}
		for _, resource := range permissionStrings(statement.Resource) {
			if err := validatePermissionResource(resource, key); err != nil {
				return permissionPolicy{}, err
			}
		}
	}
	return out, nil
}

// The shared IAM parser has already established scalar-or-array string shapes.
func permissionStrings(raw json.RawMessage) []string {
	var scalar string
	if json.Unmarshal(raw, &scalar) == nil {
		return []string{scalar}
	}
	var values []string
	_ = json.Unmarshal(raw, &values)
	return values
}

func validatePermissionResource(resource string, key BusKey) error {
	if resource == "*" {
		return nil
	}
	parts := strings.SplitN(resource, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "events" {
		return failure("ValidationException", "Resource must identify an EventBridge event bus or rule.")
	}
	if parts[4] != key.Account {
		return failure("ValidationException", fmt.Sprintf("The namespace %q is invalid for ARN %q", parts[4], resource))
	}
	rulePrefix := "rule/"
	if key.Name != "default" {
		rulePrefix += key.Name + "/"
	}
	relative := parts[5]
	if relative == "event-bus/"+key.Name || strings.HasPrefix(relative, rulePrefix) && len(relative) > len(rulePrefix) {
		return nil
	}
	return failure("ValidationException", fmt.Sprintf("The relative-id %q is invalid for ARN %q", relative, resource))
}
