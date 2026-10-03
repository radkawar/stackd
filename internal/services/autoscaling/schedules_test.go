package autoscaling

import (
	"context"
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
)

func TestRecurringScheduleUnixCalendarAndDST(t *testing.T) {
	cases := []struct{ expression, zone, after, want string }{
		{"0 9 * * 0", "UTC", "2026-09-27T09:00:00Z", "2026-10-04T09:00:00Z"},
		{"0 9 * * 1-5", "UTC", "2026-09-25T09:00:00Z", "2026-09-28T09:00:00Z"},
		{"0 0 1 * 1", "UTC", "2026-09-27T00:00:00Z", "2026-09-28T00:00:00Z"},
		{"0 0 */2 * 1", "UTC", "2026-09-27T00:00:00Z", "2026-10-05T00:00:00Z"},
		{"0 9 * JUL WED", "UTC", "2026-06-30T00:00:00Z", "2026-07-01T09:00:00Z"},
		{"30 2 * * *", "America/New_York", "2026-03-08T00:00:00Z", "2026-03-09T06:30:00Z"},
		{"30 1 * * *", "America/New_York", "2026-11-01T05:30:00Z", "2026-11-02T06:30:00Z"},
	}
	for _, c := range cases {
		t.Run(c.expression+"/"+c.after, func(t *testing.T) {
			parsed, err := parseRecurrence(c.expression, c.zone)
			if err != nil {
				t.Fatal(err)
			}
			after, err := time.Parse(time.RFC3339, c.after)
			if err != nil {
				t.Fatal(err)
			}
			next, found := parsed.next(after)
			if !found || next.Format(time.RFC3339) != c.want {
				t.Fatalf("next=%s/%v want %s", next.Format(time.RFC3339), found, c.want)
			}
		})
	}
	for _, expression := range []string{"0 0 * * ? *", "61 * * * *", "0 0 * * 8", "0 0 L * *"} {
		if _, err := parseRecurrence(expression, "UTC"); err == nil {
			t.Fatalf("accepted invalid Unix recurrence %q", expression)
		}
	}
}

func TestScheduledBatchCommitsValidActionsAndCoalescesMissedRecurrences(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	first := source.Now().Add(time.Minute)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.batchPutScheduledUpdateGroupAction(ctx, tx, &api.BatchPutScheduledUpdateGroupActionInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ScheduledUpdateGroupActions: api.ScheduledUpdateGroupActionRequests{
			{ScheduledActionName: new(api.XmlStringMaxLen255("valid")), StartTime: &first, Recurrence: new(api.XmlStringMaxLen255("* * * * *")), MinSize: new(api.AutoScalingGroupMinSize(3)), MaxSize: new(api.AutoScalingGroupMaxSize(5))},
			{ScheduledActionName: new(api.XmlStringMaxLen255("invalid")), StartTime: &first, MinSize: new(api.AutoScalingGroupMinSize(8)), MaxSize: new(api.AutoScalingGroupMaxSize(4))},
		}})
		if err != nil {
			return err
		}
		if len(out.FailedScheduledUpdateGroupActions) != 1 || value(out.FailedScheduledUpdateGroupActions[0].ScheduledActionName) != "invalid" {
			t.Fatalf("batch failures=%+v", out.FailedScheduledUpdateGroupActions)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	jobs := scheduleJobs{s}
	stale, found, err := jobs.Next(ctx)
	if err != nil || !found {
		t.Fatalf("schedule selection=%v,%v", found, err)
	}
	if err = source.Advance(11*time.Minute + 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err = jobs.Run(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if err = s.repository.View(ctx, func(r Reader) error {
		actual, err := r.Group(g.Key)
		if err != nil {
			return err
		}
		if *actual.Data.MinSize != 3 || *actual.Data.MaxSize != 5 || *actual.Data.DesiredCapacity != 3 {
			t.Fatalf("scheduled bounds/desired=%d/%d/%d", *actual.Data.MinSize, *actual.Data.MaxSize, *actual.Data.DesiredCapacity)
		}
		if actual.ScaleUpVersion != 1 {
			t.Fatalf("scheduled minimum increase did not advance ownership exactly once: %d", actual.ScaleUpVersion)
		}
		rows, err := r.Schedules(g.Key)
		if err == nil && (len(rows) != 1 || !rows[0].NextDue.Equal(source.Now().Truncate(time.Minute).Add(time.Minute))) {
			t.Fatalf("missed recurrence was not coalesced: %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A stale selection cannot replay the occurrence after the persisted deadline
	// advanced, even if an unrelated command has since changed desired capacity.
	if err = s.repository.Update(ctx, func(tx Transaction) error {
		actual, err := tx.Group(g.Key)
		if err != nil {
			return err
		}
		actual.Data.DesiredCapacity = new(api.AutoScalingGroupDesiredCapacity(4))
		return tx.PutGroup(actual)
	}); err != nil {
		t.Fatal(err)
	}
	if err = jobs.Run(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if err = s.repository.View(ctx, func(r Reader) error {
		actual, err := r.Group(g.Key)
		if err == nil && *actual.Data.DesiredCapacity != 4 {
			t.Fatal("stale schedule selection reapplied bounds")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuspensionSkipsRatherThanReplays(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		g.Data.SuspendedProcesses = append(g.Data.SuspendedProcesses, api.SuspendedProcess{ProcessName: new(api.XmlStringMaxLen255("ScheduledActions"))})
		if err := tx.PutGroup(g); err != nil {
			return err
		}
		_, err := s.putScheduledUpdateGroupAction(ctx, tx, &api.PutScheduledUpdateGroupActionInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ScheduledActionName: new(api.XmlStringMaxLen255("once")), StartTime: new(source.Now().Add(time.Minute)), DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(5))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	jobs := scheduleJobs{s}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found {
		t.Fatalf("schedule selection=%v,%v", found, err)
	}
	if err = jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err = s.repository.View(context.Background(), func(r Reader) error {
		actual, err := r.Group(g.Key)
		if err != nil {
			return err
		}
		if *actual.Data.DesiredCapacity != 2 {
			t.Fatal("suspended scheduled action changed desired capacity")
		}
		_, exists, err := nextScheduledAction(r)
		if exists {
			t.Fatal("suspended occurrence remained queued for replay")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScheduledNamesOverrideTimeFiltersAndTimeAliasExecutes(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		for n, name := range []string{"a", "b"} {
			_, err := s.putScheduledUpdateGroupAction(ctx, tx, &api.PutScheduledUpdateGroupActionInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ScheduledActionName: new(api.XmlStringMaxLen255(name)), Time: new(source.Now().Add(time.Duration(n+1)*time.Minute + 123*time.Millisecond)), DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(0))})
			if err != nil {
				return err
			}
		}
		names := api.ScheduledActionNames{api.XmlStringMaxLen255("a"), api.XmlStringMaxLen255("b")}
		first, err := s.describeScheduledActions(ctx, tx, &api.DescribeScheduledActionsInput{ScheduledActionNames: names, StartTime: new(source.Now().Add(time.Hour)), EndTime: new(source.Now().Add(-time.Hour)), MaxRecords: new(api.MaxRecords(1))})
		if err != nil {
			return err
		}
		if len(first.ScheduledUpdateGroupActions) != 1 || value(first.ScheduledUpdateGroupActions[0].ScheduledActionName) != "a" || first.NextToken == nil {
			t.Fatalf("named first page=%+v", first)
		}
		second, err := s.describeScheduledActions(ctx, tx, &api.DescribeScheduledActionsInput{ScheduledActionNames: names, NextToken: first.NextToken})
		if err != nil {
			return err
		}
		if len(second.ScheduledUpdateGroupActions) != 1 || value(second.ScheduledUpdateGroupActions[0].ScheduledActionName) != "b" {
			t.Fatalf("named continuation=%+v", second)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	jobs := scheduleJobs{s}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found || !job.Due.Equal(source.Now()) {
		t.Fatalf("Time alias deadline=%+v/%v/%v", job, found, err)
	}
	if err = jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err = s.repository.View(ctx, func(r Reader) error {
		actual, err := r.Group(g.Key)
		if err == nil && *actual.Data.DesiredCapacity != 0 {
			t.Fatalf("Time-only action did not execute: desired=%d", *actual.Data.DesiredCapacity)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
