package autoscaling

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

func retainOnAbandon(policy *api.InstanceLifecyclePolicy) bool {
	return policy != nil && policy.RetentionTriggers != nil && value(policy.RetentionTriggers.TerminateHookAbandon) == "retain"
}

// beginLifecycleHooks is called exactly at the launch/termination admission
// boundary. Pending:Proceed and Terminating:Proceed are completed barriers; the
// reconciler must not re-enter hooks for those states after a restart.
func (s *Service) beginLifecycleHooks(ctx context.Context, tx Transaction, g GroupRecord, instanceID, transition string) (bool, error) {
	instance, err := tx.Instance(g.Key.Scope, instanceID)
	if err != nil {
		return false, err
	}
	if instance.Group != g.Key || instance.GroupID != g.ID {
		return false, ErrNotFound
	}
	state := "Pending"
	eventType := "EC2 Instance-launch Lifecycle Action"
	if transition == terminateTransition {
		state = "Terminating"
		eventType = "EC2 Instance-terminate Lifecycle Action"
	} else if transition != launchTransition {
		return false, invalid("Invalid lifecycle transition")
	}
	kind := "launch"
	if transition == terminateTransition {
		kind = "terminate"
	}
	if instance.ActivityID != "" {
		activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: instance.ActivityID})
		if err != nil {
			return false, err
		}
		kind = activity.Kind
	}
	if warmMember(instance) {
		if kind == "warm-return" {
			state = "Warmed:Pending"
		} else {
			state = "Warmed:" + state
		}
	}
	origin, destination := lifecycleEndpoints(kind, value(instance.Data.LifecycleState))
	if value(instance.Data.LifecycleState) == state+":Proceed" {
		return false, nil
	}
	if value(instance.Data.LifecycleState) == state+":Wait" {
		return true, nil
	}
	if transition == terminateTransition {
		actions, err := tx.LifecycleActions(g.Key)
		if err != nil {
			return false, err
		}
		for _, a := range actions {
			if a.GroupID == g.ID && a.InstanceID == instanceID && a.Transition == launchTransition {
				if err = tx.DeleteLifecycleAction(g.Key, a.Token); err != nil {
					return false, err
				}
			}
		}
	}
	hooks, err := tx.Hooks(g.Key)
	if err != nil {
		return false, err
	}
	now := s.clock.Now()
	waiting := false
	var rejectedActions []LifecycleAction
	for _, hook := range hooks {
		if hook.GroupID != g.ID || value(hook.Data.LifecycleTransition) != transition {
			continue
		}
		if s.events == nil {
			return false, unsupported("Lifecycle event delivery is unavailable")
		}
		heartbeat := time.Duration(*hook.Data.HeartbeatTimeout) * time.Second
		action := LifecycleAction{Group: g.Key, GroupID: g.ID, Token: uuid.NewString(), HookName: hook.Key.Name, InstanceID: instanceID, Transition: transition, DefaultResult: value(hook.Data.DefaultResult), HeartbeatTimeout: heartbeat, Deadline: now.Add(heartbeat), GlobalDeadline: now.Add(time.Duration(*hook.Data.GlobalTimeout) * time.Second), OriginEventID: apievents.EventID(ctx)}
		if action.OriginEventID == "" {
			action.OriginEventID = g.OriginEventID
		}
		if err = tx.PutLifecycleAction(action); err != nil {
			return false, err
		}
		payload, err := lifecycleNotification(g, hook, action, transition, origin, destination)
		if err != nil {
			return false, err
		}
		if err = s.events.Publish(ctx, g, eventType, payload); err != nil {
			return false, err
		}
		if value(hook.Data.NotificationTargetARN) != "" {
			if err = s.events.Notify(ctx, hook, payload); err != nil {
				var rejected *awswire.Error
				if !errors.As(err, &rejected) || rejected.StatusCode < 400 || rejected.StatusCode >= 500 {
					return false, err
				}
				rejectedActions = append(rejectedActions, action)
			}
		}
		waiting = true
	}
	suffix := ":Proceed"
	if waiting {
		suffix = ":Wait"
	}
	instance.Data.LifecycleState = new(api.LifecycleState(state + suffix))
	if err = tx.PutInstance(instance); err != nil {
		return false, err
	}
	// A rejected notification applies its default immediately. Resolve through
	// the same barrier as completion/expiry, after all matching hooks exist so
	// CONTINUE retains siblings and ABANDON cancels the entire transition.
	for _, action := range rejectedActions {
		waiting, err = s.finishLifecycleAction(tx, g, action, action.DefaultResult)
		if err != nil {
			return false, err
		}
	}
	return waiting, nil
}

func lifecycleNotification(g GroupRecord, hook HookRecord, a LifecycleAction, event, origin, destination string) ([]byte, error) {
	action := ""
	if a.Transition == launchTransition {
		action = "Launch"
	} else if a.Transition == terminateTransition {
		action = "Terminate"
	}
	if event != "autoscaling:TEST_NOTIFICATION" {
		event = ""
	}
	detail := struct {
		LifecycleActionToken string `json:"LifecycleActionToken,omitempty"`
		AutoScalingGroupName string `json:"AutoScalingGroupName"`
		LifecycleHookName    string `json:"LifecycleHookName"`
		EC2InstanceID        string `json:"EC2InstanceId,omitempty"`
		LifecycleTransition  string `json:"LifecycleTransition,omitempty"`
		NotificationMetadata string `json:"NotificationMetadata,omitempty"`
		Event                string `json:"Event,omitempty"`
		Origin               string `json:"Origin,omitempty"`
		Destination          string `json:"Destination,omitempty"`
		Action               string `json:"Action,omitempty"`
	}{a.Token, g.Key.Name, hook.Key.Name, a.InstanceID, a.Transition, value(hook.Data.NotificationMetadata), event, origin, destination, action}
	return json.Marshal(detail)
}

func (s *Service) finishLifecycleAction(tx Transaction, g GroupRecord, a LifecycleAction, result string) (bool, error) {
	if a.GroupID != g.ID {
		return false, tx.DeleteLifecycleAction(g.Key, a.Token)
	}
	actions, err := tx.LifecycleActions(g.Key)
	if err != nil {
		return false, err
	}
	found := false
	for _, current := range actions {
		if current.Token == a.Token {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	if err := tx.DeleteLifecycleAction(g.Key, a.Token); err != nil {
		return false, err
	}
	instance, err := tx.Instance(g.Key.Scope, a.InstanceID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if instance.Group != g.Key || instance.GroupID != g.ID {
		return false, nil
	}
	waiting := false
	for _, other := range actions {
		if other.Token == a.Token || other.GroupID != g.ID || other.InstanceID != a.InstanceID || other.Transition != a.Transition {
			continue
		}
		// ABANDON skips every remaining hook in this transition. On launch it
		// additionally requests actual termination, never admitting the instance.
		if result == "ABANDON" {
			if err = tx.DeleteLifecycleAction(g.Key, other.Token); err != nil {
				return false, err
			}
		} else {
			waiting = true
		}
	}
	if result == "ABANDON" && a.Transition == launchTransition {
		instance.TerminationRequested = true
	}
	if !waiting {
		state := "Pending:Proceed"
		if a.Transition == terminateTransition {
			state = "Terminating:Proceed"
			if warmMember(instance) {
				if strings.HasPrefix(value(instance.Data.LifecycleState), "Warmed:Pending") {
					// Without retention, ABANDON skips remaining hooks but still
					// completes this return to the warm pool.
					state = "Warmed:Pending:Proceed"
				} else {
					state = "Warmed:Terminating:Proceed"
				}
			}
			if result == "ABANDON" && retainOnAbandon(g.Data.InstanceLifecyclePolicy) {
				state = strings.TrimSuffix(state, ":Proceed") + ":Retained"
				instance.TerminationRequested = false
				activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: instance.ActivityID})
				if err != nil {
					return false, err
				}
				if err := s.cancelActivity(tx.Context(), tx, g, activity, "Termination lifecycle action was abandoned; the instance lifecycle policy retains the instance."); err != nil {
					return false, err
				}
			}
		}
		if a.Transition == launchTransition && warmMember(instance) {
			state = "Warmed:Pending:Proceed"
		}
		instance.Data.LifecycleState = new(api.LifecycleState(state))
	}
	if err = tx.PutInstance(instance); err != nil {
		return false, err
	}
	current, err := tx.Group(g.Key)
	if err != nil {
		return false, err
	}
	origin := apievents.EventID(tx.Context())
	if origin == "" {
		origin = a.OriginEventID
	}
	if origin != "" {
		current.OriginEventID = origin
	}
	return waiting, s.requestReconcile(tx, current)
}

type lifecycleJobs struct{ s *Service }

func lifecycleJobKey(a LifecycleAction) string {
	return strings.Join([]string{a.Group.Partition, a.Group.AccountID, a.Group.Region, a.Group.Name, a.GroupID, a.Token}, "\x00")
}
func lifecycleDeadline(a LifecycleAction) time.Time {
	if a.GlobalDeadline.Before(a.Deadline) {
		return a.GlobalDeadline
	}
	return a.Deadline
}
func nextLifecycleAction(reader Reader) (LifecycleAction, bool, error) {
	rows, err := reader.PendingLifecycleActions()
	if err != nil {
		return LifecycleAction{}, false, err
	}
	var selected LifecycleAction
	found := false
	for _, a := range rows {
		if !found || lifecycleDeadline(a).Before(lifecycleDeadline(selected)) || lifecycleDeadline(a).Equal(lifecycleDeadline(selected)) && lifecycleJobKey(a) < lifecycleJobKey(selected) {
			selected = a
			found = true
		}
	}
	return selected, found, nil
}
func (j lifecycleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var selected LifecycleAction
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; selected, found, err = nextLifecycleAction(r); return err })
	if err != nil || !found {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: lifecycleJobKey(selected), Due: lifecycleDeadline(selected)}, true, nil
}
func (j lifecycleJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		a, found, err := nextLifecycleAction(tx)
		if err != nil || !found {
			return err
		}
		if lifecycleJobKey(a) != job.Key || !lifecycleDeadline(a).Equal(job.Due) || job.Due.After(j.s.clock.Now()) {
			return nil
		}
		g, err := tx.Group(a.Group)
		if errors.Is(err, ErrNotFound) {
			return tx.DeleteLifecycleAction(a.Group, a.Token)
		}
		if err != nil {
			return err
		}
		_, err = j.s.finishLifecycleAction(tx, g, a, a.DefaultResult)
		return err
	})
}
