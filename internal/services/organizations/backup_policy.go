package organizations

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stackd/internal/awscatalog"
)

var backupName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,50}$`)
var backupVaultName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,50}$`)
var backupDigits = regexp.MustCompile(`^[0-9]+$`)
var backupRoleARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::\$account:role/[A-Za-z0-9_+=,.@/\-]+$`)
var backupCopyARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):backup:[a-z0-9-]+:(\$account|[0-9]{12}):backup-vault:[A-Za-z0-9_-]{1,50}$`)
var backupAirGapARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):backup:\$region:\$account:backup-vault:[A-Za-z0-9_-]{1,50}$`)

func backupPolicy(n *managementNode, now time.Time) error {
	if !managementObject(n) || len(n.children) != 1 || n.children["plans"] == nil {
		return fmt.Errorf("backup policies require plans")
	}
	plans := n.children["plans"]
	if !managementObject(plans) {
		return fmt.Errorf("backup plans must be objects")
	}
	for name, plan := range plans.children {
		if !backupName.MatchString(name) || !managementObject(plan) {
			return fmt.Errorf("invalid backup plan")
		}
		for field, setting := range plan.children {
			valid := false
			switch field {
			case "regions":
				valid = managementStringList(setting, backupRegion, false)
			case "rules":
				valid = managementObject(setting)
				for name, rule := range setting.children {
					valid = valid && backupName.MatchString(name) && backupRule(rule, now)
				}
			case "selections":
				valid = backupSelections(setting)
			case "backup_plan_tags":
				valid = backupTags(setting)
			case "advanced_backup_settings":
				valid = backupAdvanced(setting)
			case "scan_settings":
				valid = backupScans(setting, false)
			}
			if !valid {
				return fmt.Errorf("invalid backup plan field %q", field)
			}
		}
	}
	return nil
}

func backupRegion(value string) bool {
	return slices.ContainsFunc(awscatalog.CommercialRegions(), func(r awscatalog.CommercialRegion) bool { return r.Name == value })
}

func backupLength(minimum, maximum int) func(string) bool {
	return func(value string) bool { n := utf8.RuneCountInString(value); return n >= minimum && n <= maximum }
}

func backupEnum(values ...string) func(string) bool {
	return func(value string) bool { return slices.Contains(values, value) }
}

func backupInteger(minimum uint64) func(string) bool {
	return func(value string) bool {
		if !backupDigits.MatchString(value) {
			return false
		}
		n, err := strconv.ParseUint(value, 10, 64)
		return err == nil && n >= minimum && n <= 9_999_999_999_999_999
	}
}

func backupAssigned(n *managementNode, field string) string {
	if child := n.children[field]; child != nil && child.assigned {
		value, _ := managementScalar(child.assign)
		return value
	}
	return ""
}

func backupTags(n *managementNode) bool {
	if !managementObject(n) {
		return false
	}
	for key, tag := range n.children {
		if !managementObject(tag) || len(tag.children) != 2 || tag.children["tag_key"] == nil || tag.children["tag_value"] == nil {
			return false
		}
		if !managementScalarSetting(tag.children["tag_key"], func(value string) bool { return backupLength(1, 128)(value) && strings.EqualFold(key, value) }) || !managementScalarSetting(tag.children["tag_value"], backupLength(0, 256)) {
			return false
		}
	}
	return true
}

func backupAdvanced(n *managementNode) bool {
	if !managementObject(n) {
		return false
	}
	for resource, settings := range n.children {
		if !managementObject(settings) || resource != "ec2" && resource != "s3" {
			return false
		}
		for field, setting := range settings.children {
			if !(resource == "ec2" && field == "windows_vss" || resource == "s3" && (field == "backup_acls" || field == "backup_object_tags")) || !managementScalarSetting(setting, backupEnum("enabled", "disabled")) {
				return false
			}
		}
	}
	return true
}

func backupScans(n *managementNode, action bool) bool {
	if !managementObject(n) {
		return false
	}
	for scanner, settings := range n.children {
		if scanner != "GUARDDUTY" || !managementObject(settings) {
			return false
		}
		for field, setting := range settings.children {
			switch {
			case action && field == "scan_mode":
				if !managementScalarSetting(setting, backupEnum("INCREMENTAL_SCAN", "FULL_SCAN")) {
					return false
				}
			case !action && field == "resource_types":
				if !managementStringList(setting, backupEnum("EBS", "EC2", "S3", "ALL"), true) {
					return false
				}
			case !action && field == "scanner_role_arn":
				if !managementScalarSetting(setting, backupRoleARN.MatchString) {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
