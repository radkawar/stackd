package iam

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awswire"
)

type renderedRoleTemplate struct {
	create iamapi.CreateRoleInput
	inline map[string]string
}

type roleTemplateParameters struct {
	values map[string][]string
	lists  map[string]bool
}

var roleTemplatePlaceholder = regexp.MustCompile(`@\{([^}]+)\}`)

func templateParameters(version *iamapi.RoleTemplateVersion, replacements map[string][]string) (roleTemplateParameters, *awswire.Error) {
	p := roleTemplateParameters{values: make(map[string][]string), lists: make(map[string]bool)}
	for _, definition := range version.ParametersDefinition {
		name := string(*definition.Name)
		p.lists[name] = *definition.Type == "StringList"
		if value, ok := replacements[name]; ok {
			if !p.lists[name] && len(value) != 1 {
				return p, invalid(fmt.Sprintf("%s replacement value must contain exactly one value, got %d", name, len(value)))
			}
			p.values[name] = value
		} else if definition.DefaultValue != nil {
			p.values[name] = []string{string(*definition.DefaultValue)}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(replacements)) {
		if _, ok := p.lists[name]; !ok {
			return p, invalidInput("Failed to render template: Unrecognized parameter: " + name)
		}
	}
	return p, nil
}

func (p roleTemplateParameters) text(pattern string) (string, *awswire.Error) {
	var renderErr *awswire.Error
	result := roleTemplatePlaceholder.ReplaceAllStringFunc(pattern, func(match string) string {
		name := match[2 : len(match)-1]
		values, ok := p.values[name]
		if !ok {
			renderErr = invalidInput("Failed to render template: Parameter '" + name + "' not found.")
			return ""
		}
		if len(values) != 1 {
			renderErr = invalidInput("Failed to render template: Parameter '" + name + "' must have one value in a string pattern.")
			return ""
		}
		return values[0]
	})
	return result, renderErr
}

// node substitutes JSON values structurally: user text cannot inject policy
// syntax, and StringList parameters remain arrays. Disabled statements are
// removed before resolving their parameters, even when marked IsRequired.
func (p roleTemplateParameters) node(value any) (any, *awswire.Error) {
	switch value := value.(type) {
	case string:
		if match := roleTemplatePlaceholder.FindStringSubmatch(value); match != nil && match[0] == value && p.lists[match[1]] {
			if values, ok := p.values[match[1]]; ok {
				return values, nil
			}
		}
		return p.text(value)
	case []any:
		out := make([]any, 0, len(value))
		for _, item := range value {
			rendered, err := p.node(item)
			if err != nil {
				return nil, err
			}
			if rendered != nil {
				out = append(out, rendered)
			}
		}
		return out, nil
	case map[string]any:
		if enabled, ok := value["@Enabled"].(string); ok {
			values := p.values[enabled]
			if len(values) != 1 || !strings.EqualFold(values[0], "true") {
				return nil, nil
			}
		}
		out := make(map[string]any, len(value))
		for _, key := range slices.Sorted(maps.Keys(value)) {
			if key == "@Enabled" {
				continue
			}
			rendered, err := p.node(value[key])
			if err != nil {
				return nil, err
			}
			out[key] = rendered
		}
		return out, nil
	default:
		return value, nil
	}
}

func (p roleTemplateParameters) policy(document string) (string, *awswire.Error) {
	var value map[string]any
	if err := json.Unmarshal([]byte(document), &value); err != nil {
		return "", malformed(err.Error())
	}
	rendered, err := p.node(value)
	if err != nil {
		return "", err
	}
	if statements, ok := rendered.(map[string]any)["Statement"].([]any); ok && len(statements) == 0 {
		return "", nil
	}
	encoded, marshalErr := json.Marshal(rendered)
	if marshalErr != nil {
		return "", malformed(marshalErr.Error())
	}
	return string(encoded), nil
}

func renderRoleTemplate(version *iamapi.RoleTemplateVersion, replacements map[string][]string) (renderedRoleTemplate, *awswire.Error) {
	result := renderedRoleTemplate{inline: make(map[string]string)}
	parameters, err := templateParameters(version, replacements)
	if err != nil {
		return result, err
	}
	name, err := parameters.text(string(*version.RoleNamePattern))
	if err != nil {
		return result, err
	}
	description, err := parameters.text(inputString(version.RoleDescriptionPattern))
	if err != nil {
		return result, err
	}
	path, err := parameters.text(inputString(version.RolePathPattern))
	if err != nil {
		return result, err
	}
	trust, err := parameters.policy(string(*version.AssumeRolePolicyDocumentTemplate))
	if err != nil {
		return result, err
	}
	result.create = iamapi.CreateRoleInput{RoleName: wirePointer(iamapi.RoleNameType(name)), Path: wirePointer(iamapi.PathType(defaultPath(path))),
		Description: wirePointer(iamapi.RoleDescriptionType(description)), AssumeRolePolicyDocument: wirePointer(iamapi.PolicyDocumentType(trust)),
		MaxSessionDuration: version.MaxSessionDuration, PermissionsBoundary: version.PermissionBoundaryArn}
	for _, policy := range version.InlinePolicyTemplates {
		document, err := parameters.policy(string(*policy.PolicyDocument))
		if err != nil {
			return result, err
		}
		if document != "" {
			result.inline[string(*policy.PolicyName)] = document
		}
	}
	return result, nil
}
