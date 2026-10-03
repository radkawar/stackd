package organizations

import "strings"

func backupSelections(n *managementNode) bool {
	if !managementObject(n) {
		return false
	}
	for kind, selections := range n.children {
		if (kind != "tags" && kind != "resources") || !managementObject(selections) {
			return false
		}
		for name, selection := range selections.children {
			if !backupName.MatchString(name) || !managementObject(selection) {
				return false
			}
			if kind == "tags" && (selection.children["tag_key"] == nil || selection.children["tag_value"] == nil) {
				return false
			}
			if kind == "resources" && selection.children["resource_types"] == nil && selection.children["conditions"] == nil {
				return false
			}
			for field, setting := range selection.children {
				valid := false
				switch field {
				case "iam_role_arn":
					valid = managementScalarSetting(setting, backupRoleARN.MatchString)
				case "tag_key":
					valid = kind == "tags" && managementScalarSetting(setting, backupLength(1, 128))
				case "tag_value":
					valid = kind == "tags" && managementStringList(setting, backupLength(0, 256), true)
				case "resource_types", "not_resource_types":
					valid = kind == "resources" && managementStringList(setting, backupResourceType, true)
				case "conditions":
					valid = backupConditions(setting)
				}
				if !valid {
					return false
				}
			}
		}
	}
	return true
}

func backupResourceType(value string) bool {
	if value == "*" {
		return true
	}
	for _, partition := range []string{"aws-us-gov", "aws-cn"} {
		value = strings.Replace(value, "arn:"+partition+":", "arn:aws:", 1)
	}
	return backupResourceTypes[value]
}

func backupConditions(n *managementNode) bool {
	if !managementObject(n) {
		return false
	}
	for operator, conditions := range n.children {
		if !backupEnum("string_equals", "string_not_equals", "string_like", "string_not_like")(operator) || !managementObject(conditions) {
			return false
		}
		for name, condition := range conditions.children {
			if !backupName.MatchString(name) || !managementObject(condition) || len(condition.children) != 2 || condition.children["condition_key"] == nil || condition.children["condition_value"] == nil {
				return false
			}
			if !managementScalarSetting(condition.children["condition_key"], backupLength(1, 128)) || !managementScalarSetting(condition.children["condition_value"], backupLength(0, 256)) {
				return false
			}
		}
	}
	return true
}
