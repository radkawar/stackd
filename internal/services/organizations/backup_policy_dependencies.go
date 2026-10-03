package organizations

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

func inheritedBackupValue(n *inheritedSetting, name string) string {
	if n != nil {
		if child := n.children[name]; child != nil {
			value, _ := child.value.(string)
			return value
		}
	}
	return "undefined"
}

func (v *backupValidation) rule(rule *inheritedSetting, path, name string, now time.Time) {
	lifecycle := rule.children["lifecycle"]
	continuous := inheritedBackupValue(rule, "enable_continuous_backup")
	expiration := inheritedBackupValue(lifecycle, "delete_after_days")
	if continuous == "true" {
		days, err := strconv.ParseUint(expiration, 10, 64)
		if err != nil || days > 35 {
			v.dependencies(path, name, []string{"enable_continuous_backup=" + continuous, "delete_after_days=" + expiration}, rule.children["enable_continuous_backup"], childSetting(lifecycle, "delete_after_days"))
		}
	}
	v.archive(rule, lifecycle, path, name, now)
	if copies := rule.children["copy_actions"]; copies != nil {
		for _, target := range slices.Sorted(maps.Keys(copies.children)) {
			copy := copies.children[target]
			v.archive(rule, copy.children["lifecycle"], path, name, now)
		}
	}
}

func childSetting(n *inheritedSetting, field string) *inheritedSetting {
	if n == nil {
		return nil
	}
	return n.children[field]
}

func (v *backupValidation) archive(rule, lifecycle *inheritedSetting, path, name string, now time.Time) {
	if inheritedBackupValue(lifecycle, "opt_in_to_archive_for_supported_resources") != "true" {
		return
	}
	archive := lifecycle.children["opt_in_to_archive_for_supported_resources"]
	schedule := inheritedBackupValue(rule, "schedule_expression")
	interval, ok := backupScheduleInterval(schedule, now)
	if !ok || interval < 28*24*time.Hour {
		v.dependencies(path, name, []string{"opt_in_to_archive_for_supported_resources=true", "schedule_expression=" + schedule}, archive, rule.children["schedule_expression"])
	}
	expiration := inheritedBackupValue(lifecycle, "delete_after_days")
	transition := inheritedBackupValue(lifecycle, "move_to_cold_storage_after_days")
	expires, expiresErr := strconv.ParseUint(expiration, 10, 64)
	cold, coldErr := strconv.ParseUint(transition, 10, 64)
	if expiresErr != nil || coldErr != nil || expires < cold || expires-cold < 90 {
		v.dependencies(path, name, []string{"opt_in_to_archive_for_supported_resources=true", "delete_after_days=" + expiration, "move_to_cold_storage_after_days=" + transition}, archive, lifecycle.children["delete_after_days"], lifecycle.children["move_to_cold_storage_after_days"])
	}
}

func (v *backupValidation) dependencies(path, name string, fields []string, settings ...*inheritedSetting) {
	v.add("CROSS_ATTRIBUTE_VALIDATION", fmt.Sprintf("Dependent fields %s in policy block %s are invalid when used together", strings.Join(fields, ","), name), path, settings...)
}
