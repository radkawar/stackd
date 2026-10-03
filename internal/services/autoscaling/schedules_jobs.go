package autoscaling

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type scheduleJobs struct{ s *Service }

func scheduleJobKey(r ScheduleRecord) string {
	return strings.Join([]string{r.Key.Partition, r.Key.AccountID, r.Key.Region, r.Key.GroupKey.Name, r.GroupID, r.Key.Name}, "\x00")
}
func nextScheduledAction(r Reader) (ScheduleRecord, bool, error) {
	rows, err := r.PendingSchedules()
	if err != nil {
		return ScheduleRecord{}, false, err
	}
	var selected ScheduleRecord
	found := false
	for _, row := range rows {
		if row.NextDue.IsZero() {
			continue
		}
		if !found || row.NextDue.Before(selected.NextDue) || row.NextDue.Equal(selected.NextDue) && scheduleJobKey(row) < scheduleJobKey(selected) {
			selected = row
			found = true
		}
	}
	return selected, found, nil
}
func (j scheduleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var row ScheduleRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; row, found, err = nextScheduledAction(r); return err })
	if err != nil || !found {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: scheduleJobKey(row), Due: row.NextDue}, true, nil
}
func (j scheduleJobs) Run(ctx context.Context, job scheduler.Job) error {
	var rejected error
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		row, found, err := nextScheduledAction(tx)
		if err != nil || !found {
			return err
		}
		now := j.s.clock.Now()
		if scheduleJobKey(row) != job.Key || !row.NextDue.Equal(job.Due) || job.Due.After(now) {
			return nil
		}
		g, err := tx.Group(row.Key.GroupKey)
		if errors.Is(err, ErrNotFound) || err == nil && g.ID != row.GroupID {
			return tx.DeleteSchedule(row.Key)
		}
		if err != nil {
			return err
		}
		if !g.Deleting && !processSuspended(g, "ScheduledActions") && (row.Data.EndTime == nil || !now.After(*row.Data.EndTime)) {
			rejected = j.s.repository.Attempt(tx.Context(), func(child Transaction) error { return j.s.applyScheduledAction(child, row, g) })
			if rejected != nil {
				var wire *awswire.Error
				if !errors.As(rejected, &wire) || wire.StatusCode >= 500 {
					return rejected
				}
				id := uuid.NewString()
				activity := ActivityRecord{Key: ActivityKey{Scope: g.Key.Scope, ID: id}, Group: g.Key, GroupID: g.ID, Kind: "ScheduledAction", OriginEventID: row.OriginEventID, Data: api.Activity{ActivityId: new(api.XmlString(id)), AutoScalingGroupName: new(api.XmlStringMaxLen255(g.Key.Name)), AutoScalingGroupARN: g.Data.AutoScalingGroupARN, StartTime: new(now), EndTime: new(now), Cause: new(api.XmlStringMaxLen1023("scheduled action " + row.Key.Name + " was triggered")), Description: new(api.XmlString("Applying scheduled capacity")), StatusCode: new(api.ScalingActivityStatusCode("Failed")), StatusMessage: new(api.XmlStringMaxLen255(wire.Message)), Progress: new(api.Progress(100))}}
				if err = tx.PutActivity(activity); err != nil {
					return err
				}
			}
		}
		if value(row.Data.Recurrence) == "" {
			return tx.DeleteSchedule(row.Key)
		}
		if err = advanceScheduledDeadline(&row, now); err != nil {
			return err
		}
		if row.NextDue.IsZero() {
			return tx.DeleteSchedule(row.Key)
		}
		return tx.PutSchedule(row)
	})
	if err != nil {
		return err
	}
	return rejected
}

func advanceScheduledDeadline(row *ScheduleRecord, now time.Time) error {
	parsed, err := parseRecurrence(value(row.Data.Recurrence), value(row.Data.TimeZone))
	if err != nil {
		return err
	}
	next, found := parsed.next(now)
	if !found || row.Data.EndTime != nil && next.After(*row.Data.EndTime) {
		row.NextDue = time.Time{}
	} else {
		row.NextDue = next
	}
	return nil
}

func (s *Service) applyScheduledAction(tx Transaction, row ScheduleRecord, g GroupRecord) error {
	ctx := awsctx.WithMetadata(tx.Context(), awsctx.Metadata{Partition: g.Key.Partition, AccountID: g.Key.AccountID, Region: g.Key.Region, ParentEventID: row.OriginEventID, InvokedBy: ServicePrincipal, SourceIP: ServicePrincipal, UserAgent: ServicePrincipal})
	if s.identity == nil {
		return unsupported("Auto Scaling execution identity is unavailable")
	}
	if _, err := s.identity.Context(ctx, g); err != nil {
		return err
	}
	if row.Data.MinSize != nil {
		g.Data.MinSize = row.Data.MinSize
	}
	if row.Data.MaxSize != nil {
		g.Data.MaxSize = row.Data.MaxSize
	}
	if int32(*g.Data.MinSize) > int32(*g.Data.MaxSize) {
		return invalid("Scheduled action minimum capacity exceeds maximum capacity")
	}
	desired := int32(*g.Data.DesiredCapacity)
	if row.Data.DesiredCapacity != nil {
		desired = int32(*row.Data.DesiredCapacity)
	} else {
		desired = min(max(desired, int32(*g.Data.MinSize)), int32(*g.Data.MaxSize))
	}
	if desired < int32(*g.Data.MinSize) || desired > int32(*g.Data.MaxSize) {
		return invalid("Scheduled action desired capacity is outside the group bounds")
	}
	g.OriginEventID = row.OriginEventID
	g.PendingInstanceWarmup = nil
	return s.changeDesired(tx, g, desired, "scheduled action "+row.Key.Name+" was triggered")
}

func processSuspended(g GroupRecord, name string) bool {
	for _, p := range g.Data.SuspendedProcesses {
		if value(p.ProcessName) == name {
			return true
		}
	}
	return false
}

// A resume must not replay occurrences that elapsed while scheduling was
// suspended, even if the driver had not reached those rows before the resume.
func (s *Service) skipSuspendedSchedules(tx Transaction, key GroupKey, now time.Time) error {
	rows, err := tx.Schedules(key)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.NextDue.IsZero() || row.NextDue.After(now) {
			continue
		}
		if value(row.Data.Recurrence) == "" {
			if err = tx.DeleteSchedule(row.Key); err != nil {
				return err
			}
			continue
		}
		if err = advanceScheduledDeadline(&row, now); err != nil {
			return err
		}
		if err = tx.PutSchedule(row); err != nil {
			return err
		}
	}
	return nil
}
