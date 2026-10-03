package organizations

import (
	"fmt"
	"maps"
	"slices"
	"time"
)

// validateEffectiveBackup reports invalid inherited plans so the publisher can
// retain the last valid document when any plan is invalid.
func validateEffectiveBackup(root *inheritedSetting, now time.Time) []EffectivePolicyError {
	plans := root.children["plans"]
	if plans == nil {
		return nil
	}
	var errors []EffectivePolicyError
	for _, name := range slices.Sorted(maps.Keys(plans.children)) {
		plan := plans.children[name]
		validation := backupValidation{}
		path := "plans/" + name
		validation.required(plan, path, "rules", "regions", "selections")
		if regions := plan.children["regions"]; regions != nil {
			validation.elements(regions, path+"/regions", "regions", 1, 0)
		}
		if rules := plan.children["rules"]; rules != nil {
			validation.elements(rules, path+"/rules", "rules", 1, 10)
			for _, name := range slices.Sorted(maps.Keys(rules.children)) {
				rule := rules.children[name]
				validation.required(rule, path+"/rules/"+name, "target_backup_vault_name")
				validation.rule(rule, path+"/rules/"+name, name, now)
				if rule.children["scan_actions"] != nil && plan.children["scan_settings"] == nil {
					validation.add("CROSS_ATTRIBUTE_VALIDATION", fmt.Sprintf("Dependent fields scan_actions(undefined),scan_settings(undefined) in policy block %s are invalid when used together", name), path+"/rules/"+name, rule.children["scan_actions"])
				}
			}
		}
		if selections := plan.children["selections"]; selections != nil {
			validation.elements(selections, path+"/selections", "selections", 1, 0)
			for _, kind := range []string{"tags", "resources"} {
				if group := selections.children[kind]; group != nil {
					for _, name := range slices.Sorted(maps.Keys(group.children)) {
						selection := group.children[name]
						selectedPath := path + "/selections/" + kind + "/" + name
						validation.required(selection, selectedPath, "iam_role_arn")
						if kind == "tags" {
							validation.required(selection, selectedPath, "tag_key", "tag_value")
						}
						if kind == "resources" && selection.children["conditions"] == nil {
							validation.required(selection, selectedPath, "resource_types")
						}
						if values := selection.children["tag_value"]; values != nil {
							validation.elements(values, selectedPath+"/tag_value", "tag_value", 1, 0)
						}
						if values := selection.children["resource_types"]; values != nil {
							validation.elements(values, selectedPath+"/resource_types", "resource_types", 1, 0)
						}
					}
				}
			}
		}
		if len(validation.errors) > 0 {
			errors = append(errors, validation.errors...)
		}
	}
	return errors
}

func (v *backupValidation) required(n *inheritedSetting, path string, fields ...string) {
	for _, field := range fields {
		if n.children[field] == nil {
			v.add("KEY_REQUIRED", fmt.Sprintf("'%s' is missing", field), path, n)
		}
	}
}

func (v *backupValidation) elements(n *inheritedSetting, path, field string, minimum, maximum int) {
	count := len(n.children)
	if values, ok := n.value.([]any); ok {
		count = len(values)
	}
	if count < minimum {
		v.add("ELEMENTS_TOO_FEW", fmt.Sprintf("'%s' is less than the allowed minimum limit %d", field, minimum), path, n)
	}
	if maximum > 0 && count > maximum {
		v.add("ELEMENTS_TOO_MANY", fmt.Sprintf("'%s' exceeds the allowed maximum limit %d", field, maximum), path, n)
	}
}

func (v *backupValidation) add(code, message, path string, settings ...*inheritedSetting) {
	var sources []string
	for _, setting := range settings {
		if setting != nil {
			sources = append(sources, setting.contributingPolicies()...)
		}
	}
	// Native reports coalesce identical rule diagnostics from multiple copy
	// actions. Keep that identity authoritative before storage and pagination.
	for i := range v.errors {
		e := &v.errors[i]
		if e.Code == code && e.Message == message && e.Path == path {
			sources = append(sources, e.ContributingPolicies...)
			slices.Sort(sources)
			e.ContributingPolicies = slices.Compact(sources)
			return
		}
	}
	slices.Sort(sources)
	v.errors = append(v.errors, EffectivePolicyError{Code: code, Message: message, Path: path, ContributingPolicies: slices.Compact(sources)})
}
