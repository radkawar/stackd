package ssmcommands

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"stackd/internal/scheduler"
)

func setInvocationTerminal(inv *Invocation, status, details string, now time.Time) {
	inv.Status, inv.StatusDetails, inv.FinishedAt = status, details, now
	for i := range inv.Plugins {
		p := &inv.Plugins[i]
		if !terminal(p.Status) {
			p.Status, p.StatusDetails, p.FinishedAt = status, details, now
		}
	}
}
func aggregate(cmd *Command, invs []Invocation) {
	if cmd.AlarmPoll.TriggeredState != "" {
		cmd.Status, cmd.StatusDetails = "Failed", alarmFailureDetails(cmd.AlarmPoll.TriggeredState)
		return
	}
	if len(invs) == 0 {
		return
	}
	pending, active, cancelling, failed, timedout, cancelled, success := 0, 0, 0, 0, 0, 0, 0
	for _, inv := range invs {
		switch inv.Status {
		case "Pending", "Delayed":
			pending++
		case "InProgress":
			active++
		case "Cancelling":
			cancelling++
		case "Failed":
			failed++
		case "TimedOut":
			timedout++
			if inv.StatusDetails == "ExecutionTimedOut" {
				failed++
			}
		case "Cancelled":
			cancelled++
		case "Success":
			success++
		}
	}
	switch {
	case cancelling > 0:
		cmd.Status, cmd.StatusDetails = "Cancelling", "Cancelling"
	case active > 0 || (pending > 0 && pending != len(invs)):
		cmd.Status, cmd.StatusDetails = "InProgress", "InProgress"
	case pending > 0:
		cmd.Status, cmd.StatusDetails = "Pending", "Pending"
	case failed > cmd.ErrorBudget:
		cmd.Status, cmd.StatusDetails = "Failed", "Failed"
	case cancelled == len(invs):
		cmd.Status, cmd.StatusDetails = "Cancelled", "Cancelled"
	case timedout == len(invs):
		cmd.Status, cmd.StatusDetails = "TimedOut", "DeliveryTimedOut"
		for _, inv := range invs {
			if inv.StatusDetails == "ExecutionTimedOut" {
				cmd.StatusDetails = "ExecutionTimedOut"
				break
			}
		}
	case success > 0:
		cmd.Status, cmd.StatusDetails = "Success", "Success"
	default:
		cmd.Status, cmd.StatusDetails = "Failed", "Incomplete"
	}
}

type deadlineJobs struct{ s *Service }

func commandDeadline(cmd Command) time.Time {
	if !cmd.EmptyTargetReadyAt.IsZero() {
		return cmd.EmptyTargetReadyAt
	}
	return cmd.DeliveryDeadline
}

func (j deadlineJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var result scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		cmd, err := r.NextDeadline()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		key, err := json.Marshal(cmd.Key)
		if err != nil {
			return err
		}
		result = scheduler.Job{Key: string(key), Due: commandDeadline(cmd)}
		found = true
		return nil
	})
	return result, found, err
}
func (j deadlineJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key Key
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		cmd, err := tx.Command(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		due := commandDeadline(cmd)
		if terminal(cmd.Status) || !due.Equal(job.Due) || due.After(j.s.clock.Now()) {
			return nil
		}
		invs, err := tx.Invocations(key)
		if err != nil {
			return err
		}
		if len(invs) == 0 && !cmd.EmptyTargetReadyAt.IsZero() {
			cmd.Status, cmd.StatusDetails = "Success", "NoInstancesInTag"
			cmd.EmptyTargetReadyAt = time.Time{}
			return j.s.putCommand(tx, cmd)
		}
		// AWS waits for the terminal agent reply, not merely a delivery acknowledgment.
		// The agent alone reports Execution Timed Out; lost/offline replies expire as
		// Delivery Timed Out even when the process had started in the guest.
		for i := range invs {
			if !terminal(invs[i].Status) {
				setInvocationTerminal(&invs[i], "TimedOut", "DeliveryTimedOut", j.s.clock.Now())
				if err = j.s.putInvocation(tx, invs[i]); err != nil {
					return err
				}
			}
		}
		aggregate(&cmd, invs)
		return j.s.putCommand(tx, cmd)
	})
}
