package mq

import (
	"context"
	"errors"
	"fmt"
	"stackd/clock"
	api "stackd/internal/awsapi/mq"
	"stackd/internal/awswire"
	"testing"
	"time"
)

func changeMaintenance(s *Service, ctx context.Context, id, at string) error {
	in := &api.UpdateBrokerInput{MaintenanceWindowStartTime: &api.WeeklyStartTime{}}
	text(&in.BrokerId, id)
	text(&in.MaintenanceWindowStartTime.DayOfWeek, "WEDNESDAY")
	text(&in.MaintenanceWindowStartTime.TimeOfDay, at)
	return s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.updateBroker(tx.Context(), tx, in)
		return err
	})
}

func TestMaintenanceAdjustmentBudgetRequiresCompletedMaintenance(t *testing.T) {
	s, ctx, v := controlFixture(t)
	if err := changeMaintenance(s, ctx, v.ID, "25:00"); err == nil {
		t.Fatal("invalid maintenance time admitted")
	}
	if got := storedBroker(t, s, v); got.MaintenanceAdjustments != 0 || got.MaintenanceTime != "00:01" {
		t.Fatal("invalid request changed maintenance budget or schedule")
	}
	for range 2 {
		if err := changeMaintenance(s, ctx, v.ID, "00:01"); err != nil {
			t.Fatal(err)
		}
	}
	if got := storedBroker(t, s, v); got.MaintenanceAdjustments != 0 {
		t.Fatal("unchanged request consumed an available adjustment budget")
	}
	for minute := 2; minute <= 5; minute++ {
		if err := changeMaintenance(s, ctx, v.ID, fmt.Sprintf("00:%02d", minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := changeMaintenance(s, ctx, v.ID, "00:06"); err == nil {
		t.Fatal("fifth maintenance adjustment admitted")
	}
	full := storedBroker(t, s, v)
	if full.MaintenanceAdjustments != 4 || full.MaintenanceTime != "00:05" || full.MaintenanceDue.IsZero() {
		t.Fatal("rejected adjustment changed the retained schedule or budget")
	}
	// Native AWS checks an exhausted budget even when the window is unchanged.
	if err := changeMaintenance(s, ctx, v.ID, "00:05"); err == nil {
		t.Fatal("unchanged window admitted after exhausting the budget")
	}
	if got := storedBroker(t, s, v); got.MaintenanceAdjustments != 4 || !got.MaintenanceDue.Equal(full.MaintenanceDue) {
		t.Fatal("unchanged schedule altered its adjustment budget or deadline")
	}
	run := func() {
		t.Helper()
		jobs := brokerJobs{s}
		job, found, err := jobs.Next(ctx)
		if err != nil || !found {
			t.Fatalf("next broker work: found=%v error=%v", found, err)
		}
		if err := jobs.Run(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	reboot := &api.RebootBrokerInput{}
	text(&reboot.BrokerId, v.ID)
	if err := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.rebootBroker(tx.Context(), tx, reboot)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	run()
	if got := storedBroker(t, s, v); got.MaintenanceAdjustments != 4 || !got.MaintenanceDue.Equal(full.MaintenanceDue) {
		t.Fatal("manual reboot reset the maintenance adjustment budget")
	}
	if err := changeMaintenance(s, ctx, v.ID, "00:06"); err == nil {
		t.Fatal("manual reboot allowed a fifth maintenance adjustment")
	}
	s.clock.(*clock.Manual).Advance(5 * time.Minute)
	run() // Claim due maintenance without resetting its budget.
	if got := storedBroker(t, s, v); got.MaintenanceAdjustments != 4 || got.State != "REBOOT_IN_PROGRESS" {
		t.Fatal("maintenance claim consumed the budget before native completion")
	}
	s.runtime = testRuntime{reboot: func(context.Context, BrokerRecord) (Endpoint, error) {
		return Endpoint{}, errors.New("native reboot failed")
	}}
	run()
	if got := storedBroker(t, s, v); got.MaintenanceAdjustments != 4 || got.State != "CRITICAL_ACTION_REQUIRED" {
		t.Fatal("failed native maintenance reset the adjustment budget")
	}
	s.runtime = testRuntime{}
	s.clock.(*clock.Manual).Advance(30 * time.Second)
	run()
	if got := storedBroker(t, s, v); got.MaintenanceAdjustments != 0 || got.State != "RUNNING" || !got.MaintenanceDue.IsZero() {
		t.Fatal("completed native maintenance did not reset its budget")
	}
	if err := changeMaintenance(s, ctx, v.ID, "00:07"); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceAdjustmentBudgetSerializesConcurrentAdmission(t *testing.T) {
	s, ctx, v := controlFixture(t)
	results := make(chan error, 8)
	for minute := 2; minute < 10; minute++ {
		go func() {
			results <- changeMaintenance(s, ctx, v.ID, fmt.Sprintf("00:%02d", minute))
		}()
	}
	accepted := 0
	for range 8 {
		err := <-results
		if err == nil {
			accepted++
			continue
		}
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != "BadRequestException" {
			t.Fatalf("unexpected admission failure: %v", err)
		}
	}
	if accepted != 4 || storedBroker(t, s, v).MaintenanceAdjustments != 4 {
		t.Fatalf("concurrent maintenance budget admitted %d requests", accepted)
	}
}
