package organizations

import (
	"strconv"
	"time"
)

func backupRule(n *managementNode, now time.Time) bool {
	if !managementObject(n) {
		return false
	}
	var interval time.Duration
	archive := false
	for field, setting := range n.children {
		valid := false
		switch field {
		case "schedule_expression":
			valid = managementScalarSetting(setting, func(expression string) bool {
				var ok bool
				interval, ok = backupScheduleInterval(expression, now)
				return ok && interval >= time.Hour
			})
		case "target_backup_vault_name":
			valid = managementScalarSetting(setting, backupVaultName.MatchString)
		case "target_logically_air_gapped_backup_vault_arn":
			valid = managementScalarSetting(setting, backupAirGapARN.MatchString)
		case "start_backup_window_minutes", "complete_backup_window_minutes":
			valid = managementScalarSetting(setting, backupInteger(60))
		case "enable_continuous_backup":
			valid = managementScalarSetting(setting, backupEnum("true", "false"))
		case "lifecycle":
			valid = backupLifecycle(setting)
			archive = archive || backupAssigned(setting, "opt_in_to_archive_for_supported_resources") == "true"
		case "copy_actions":
			valid = managementObject(setting)
			for vault, action := range setting.children {
				if !backupCopyARN.MatchString(vault) || !managementObject(action) || action.children["target_backup_vault_arn"] == nil {
					return false
				}
				for field, child := range action.children {
					switch field {
					case "target_backup_vault_arn":
						valid = valid && managementScalarSetting(child, backupCopyARN.MatchString)
					case "lifecycle":
						valid = valid && backupLifecycle(child)
						archive = archive || backupAssigned(child, "opt_in_to_archive_for_supported_resources") == "true"
					default:
						return false
					}
				}
			}
		case "recovery_point_tags":
			valid = backupTags(setting)
		case "index_actions":
			valid = managementObject(setting)
			for field, child := range setting.children {
				valid = valid && field == "resource_types" && managementStringList(child, backupEnum("EBS", "S3"), true)
			}
		case "scan_actions":
			valid = backupScans(setting, true)
		}
		if !valid {
			return false
		}
	}
	if backupAssigned(n, "enable_continuous_backup") == "true" {
		lifecycle := n.children["lifecycle"]
		if lifecycle == nil {
			return false
		}
		days, err := strconv.ParseUint(backupAssigned(lifecycle, "delete_after_days"), 10, 64)
		if err != nil || days > 35 || backupAssigned(lifecycle, "move_to_cold_storage_after_days") != "" {
			return false
		}
	}
	return !archive || interval >= 28*24*time.Hour
}

func backupLifecycle(n *managementNode) bool {
	if !managementObject(n) {
		return false
	}
	for field, setting := range n.children {
		switch field {
		case "move_to_cold_storage_after_days", "delete_after_days":
			if !managementScalarSetting(setting, backupInteger(1)) {
				return false
			}
		case "opt_in_to_archive_for_supported_resources":
			if !managementScalarSetting(setting, backupEnum("true", "false")) {
				return false
			}
		default:
			return false
		}
	}
	if backupAssigned(n, "opt_in_to_archive_for_supported_resources") == "true" {
		// Native admission requires an explicit compatible deletion interval.
		cold, coldErr := strconv.ParseUint(backupAssigned(n, "move_to_cold_storage_after_days"), 10, 64)
		expires, expirationErr := strconv.ParseUint(backupAssigned(n, "delete_after_days"), 10, 64)
		return coldErr == nil && expirationErr == nil && expires >= cold && expires-cold >= 90
	}
	return true
}
