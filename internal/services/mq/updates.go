package mq

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/mq"
	"strings"
	"time"
)

func (s *Service) updateBroker(ctx context.Context, t Transaction, in *api.UpdateBrokerInput) (*api.UpdateBrokerOutput, error) {
	v, e := s.load(ctx, t, value(in.BrokerId), "UpdateBroker")
	if e != nil {
		return nil, e
	}
	if v.State != "RUNNING" {
		return nil, failure("ConflictException", "Broker must be running before update", 409)
	}
	// TODO: Comeback implement version/capacity rollouts, LDAP, native encrypted storage,
	// private network attachments and replication through real owners.
	if in.LdapServerMetadata != nil || in.DataReplicationMode != nil || len(in.ResourceShareArns) > 0 || len(in.SecurityGroups) > 0 || in.StorageSize != nil || in.AuthenticationStrategy != nil && value(in.AuthenticationStrategy) != "SIMPLE" || truth(in.AutoMinorVersionUpgrade) || in.EngineVersion != nil && value(in.EngineVersion) != v.EngineVersion || in.HostInstanceType != nil && value(in.HostInstanceType) != v.InstanceType {
		return nil, invalid("Requested update requires an unavailable native broker dependency")
	}
	o := &api.UpdateBrokerOutput{}
	text(&o.BrokerId, v.ID)
	if in.Configuration != nil {
		ref, e := s.resolveConfiguration(ctx, t, v, in.Configuration)
		if e != nil {
			return nil, e
		}
		v.PendingConfiguration = ref
		o.Configuration = configurationReference(ref)
	}
	if in.MaintenanceWindowStartTime != nil {
		previousDay, previousTime, previousZone := v.MaintenanceDay, v.MaintenanceTime, v.MaintenanceZone
		if e = setMaintenance(&v, in.MaintenanceWindowStartTime); e != nil {
			return nil, e
		}
		if v.MaintenanceAdjustments >= 4 {
			return nil, invalid("Maintenance window cannot be modified greater than 4 times. You will be able to modify your broker maintenance window after the next maintenance window has completed.")
		}
		if v.MaintenanceDay != previousDay || v.MaintenanceTime != previousTime || v.MaintenanceZone != previousZone {
			v.MaintenanceAdjustments++
			v.MaintenanceDue = time.Time{}
		}
		o.MaintenanceWindowStartTime = maintenanceOutput(v)
	}
	if in.AuthenticationStrategy != nil {
		text(&o.AuthenticationStrategy, "SIMPLE")
	}
	if in.AutoMinorVersionUpgrade != nil {
		boolean(&o.AutoMinorVersionUpgrade, false)
	}
	if in.EngineVersion != nil {
		text(&o.EngineVersion, v.EngineVersion)
	}
	if in.HostInstanceType != nil {
		text(&o.HostInstanceType, v.InstanceType)
	}
	if in.Logs != nil {
		settings, err := s.logSettings(v, in.Logs, true)
		if err != nil {
			return nil, err
		}
		if err = s.prepareLogGroups(ctx, &v, settings); err != nil {
			return nil, err
		}
		v.PendingLogs = nil
		if settings != v.Logs {
			v.PendingLogs = &settings
		}
		o.Logs = logsOutput(settings)
	}
	s.scheduleMaintenance(&v)
	return o, t.PutBroker(v)
}
func maintenanceOutput(v BrokerRecord) *api.WeeklyStartTime {
	if v.MaintenanceDay == "" {
		return nil
	}
	o := &api.WeeklyStartTime{}
	text(&o.DayOfWeek, v.MaintenanceDay)
	text(&o.TimeOfDay, v.MaintenanceTime)
	text(&o.TimeZone, v.MaintenanceZone)
	return o
}

var weekdays = map[string]time.Weekday{"SUNDAY": time.Sunday, "MONDAY": time.Monday, "TUESDAY": time.Tuesday, "WEDNESDAY": time.Wednesday, "THURSDAY": time.Thursday, "FRIDAY": time.Friday, "SATURDAY": time.Saturday}

func maintenanceLocation(zone string) (*time.Location, error) {
	if zone == "" || zone == "UTC" {
		return time.UTC, nil
	}
	if len(zone) == 6 && (zone[0] == '+' || zone[0] == '-') && zone[3] == ':' {
		var h, m int
		if _, e := fmt.Sscanf(zone[1:], "%02d:%02d", &h, &m); e != nil || h > 14 || m > 59 || h == 14 && m != 0 {
			return nil, invalid("Invalid maintenance time zone")
		}
		n := h*3600 + m*60
		if zone[0] == '-' {
			n = -n
		}
		return time.FixedZone(zone, n), nil
	}
	loc, e := time.LoadLocation(zone)
	if e != nil {
		return nil, invalid("Invalid maintenance time zone")
	}
	return loc, nil
}
func setMaintenance(v *BrokerRecord, in *api.WeeklyStartTime) error {
	day, clock, zone := value(in.DayOfWeek), value(in.TimeOfDay), value(in.TimeZone)
	if _, ok := weekdays[day]; !ok {
		return invalid("Invalid maintenance day")
	}
	if len(clock) != 5 {
		return invalid("Maintenance TimeOfDay must be HH:MM")
	}
	if _, e := time.Parse("15:04", clock); e != nil {
		return invalid("Invalid maintenance time")
	}
	if zone == "" {
		zone = "UTC"
	}
	if _, e := maintenanceLocation(zone); e != nil {
		return e
	}
	v.MaintenanceDay, v.MaintenanceTime, v.MaintenanceZone = day, clock, zone
	return nil
}

// TODO: Comeback calibrate AWS maintenance completion and DST edge semantics;
// the bounded native capture did not observe the scheduled quota reset.
func nextMaintenance(v BrokerRecord, now time.Time) time.Time {
	loc, e := maintenanceLocation(v.MaintenanceZone)
	if e != nil {
		return time.Time{}
	}
	clock, e := time.Parse("15:04", v.MaintenanceTime)
	if e != nil {
		return time.Time{}
	}
	local := now.In(loc)
	delta := (int(weekdays[v.MaintenanceDay]) - int(local.Weekday()) + 7) % 7
	candidate := time.Date(local.Year(), local.Month(), local.Day()+delta, clock.Hour(), clock.Minute(), 0, 0, loc)
	if !candidate.After(now) {
		candidate = candidate.AddDate(0, 0, 7)
	}
	return candidate.UTC()
}
func hasPending(v BrokerRecord) bool {
	if v.PendingConfiguration.ID != "" || v.PendingLogs != nil {
		return true
	}
	for _, u := range v.Users {
		if u.PendingChange != "" {
			return true
		}
	}
	return false
}
func (s *Service) scheduleMaintenance(v *BrokerRecord) {
	v.Version++
	if !hasPending(*v) && v.MaintenanceAdjustments == 0 {
		v.MaintenanceDue = time.Time{}
		return
	}
	if v.MaintenanceDay == "" {
		v.MaintenanceDay, v.MaintenanceTime, v.MaintenanceZone = "SUNDAY", "03:00", "UTC"
	}
	if v.MaintenanceDue.IsZero() {
		v.MaintenanceDue = nextMaintenance(*v, s.clock.Now())
	}
	if v.Due.IsZero() || v.MaintenanceDue.Before(v.Due) {
		v.Due = v.MaintenanceDue
	}
}
func (s *Service) describeSharedResources(ctx context.Context, t Transaction, in *api.DescribeSharedResourcesInput) (*api.DescribeSharedResourcesOutput, error) {
	v, e := s.load(ctx, t, value(in.BrokerId), "DescribeSharedResources")
	if e != nil {
		return nil, e
	}
	_, after, e := page(ctx, "shares:"+v.ID, in.MaxResults, value(in.NextToken))
	if e != nil {
		return nil, e
	}
	if after != "" {
		return nil, invalid("Invalid NextToken")
	}
	return &api.DescribeSharedResourcesOutput{}, nil
}
func (s *Service) promote(ctx context.Context, t Transaction, in *api.PromoteInput) (*api.PromoteOutput, error) {
	_, e := s.load(ctx, t, value(in.BrokerId), "Promote")
	if e != nil {
		return nil, e
	}
	// TODO: Comeback CRDR promotion needs replicated native journals and a fenced
	// role transition; a standalone broker cannot be promoted by changing metadata.
	return nil, invalid("Broker has no native cross-region replication counterpart")
}
func isConfigurationARN(arn string) bool { return strings.Contains(arn, ":configuration:") }
