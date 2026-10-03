package autoscaling

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/autoscaling"
)

const launchTransition = "autoscaling:EC2_INSTANCE_LAUNCHING"
const terminateTransition = "autoscaling:EC2_INSTANCE_TERMINATING"

func registerHooks(s *Service) {
	register(s, "PutLifecycleHook", s.putLifecycleHook)
	register(s, "DeleteLifecycleHook", s.deleteLifecycleHook)
	register(s, "DescribeLifecycleHooks", s.describeLifecycleHooks)
	register(s, "DescribeLifecycleHookTypes", s.describeLifecycleHookTypes)
	register(s, "RecordLifecycleActionHeartbeat", s.recordLifecycleActionHeartbeat)
	register(s, "CompleteLifecycleAction", s.completeLifecycleAction)
}

func (s *Service) putLifecycleHook(ctx context.Context, tx Transaction, in *api.PutLifecycleHookInput) (*api.PutLifecycleHookOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "PutLifecycleHook")
	if err != nil {
		return nil, err
	}
	if err = s.storeLifecycleHook(ctx, tx, g, in); err != nil {
		return nil, err
	}
	return &api.PutLifecycleHookOutput{}, nil
}

func (s *Service) installLifecycleHook(ctx context.Context, tx Transaction, g GroupRecord, spec api.LifecycleHookSpecification) error {
	return s.storeLifecycleHook(ctx, tx, g, &api.PutLifecycleHookInput{AutoScalingGroupName: new(api.XmlStringMaxLen255(g.Key.Name)), LifecycleHookName: spec.LifecycleHookName, LifecycleTransition: spec.LifecycleTransition, HeartbeatTimeout: spec.HeartbeatTimeout, DefaultResult: spec.DefaultResult, NotificationMetadata: spec.NotificationMetadata, NotificationTargetARN: spec.NotificationTargetARN, RoleARN: spec.RoleARN})
}

// storeLifecycleHook is also used for CreateAutoScalingGroup's initial hooks.
// Admission authorization is the caller's responsibility; notification admission
// goes through the same real destination command as a later PutLifecycleHook.
func (s *Service) storeLifecycleHook(ctx context.Context, tx Transaction, g GroupRecord, in *api.PutLifecycleHookInput) error {
	name := value(in.LifecycleHookName)
	if name == "" || len(name) > 255 || strings.IndexFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '/')
	}) >= 0 {
		return invalid("Lifecycle hook names may contain only letters, numbers, hyphens, underscores and slashes")
	}
	key := HookKey{GroupKey: g.Key, Name: name}
	record, err := tx.Hook(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if errors.Is(err, ErrNotFound) {
		hooks, err := tx.Hooks(g.Key)
		if err != nil {
			return err
		}
		if len(hooks) >= 50 {
			return failure("LimitExceeded", "You may not create more than 50 lifecycle hooks for an Auto Scaling group")
		}
		record = HookRecord{Key: key, GroupID: g.ID, Data: api.LifecycleHook{AutoScalingGroupName: new(api.XmlStringMaxLen255(g.Key.Name)), LifecycleHookName: in.LifecycleHookName, HeartbeatTimeout: new(api.HeartbeatTimeout(3600)), DefaultResult: new(api.LifecycleActionResult("ABANDON"))}}
	}
	data := record.Data
	if in.LifecycleTransition != nil {
		data.LifecycleTransition = in.LifecycleTransition
	}
	if value(data.LifecycleTransition) != launchTransition && value(data.LifecycleTransition) != terminateTransition {
		return invalid("LifecycleTransition must be autoscaling:EC2_INSTANCE_LAUNCHING or autoscaling:EC2_INSTANCE_TERMINATING")
	}
	if in.HeartbeatTimeout != nil {
		data.HeartbeatTimeout = in.HeartbeatTimeout
	}
	if data.HeartbeatTimeout == nil || *data.HeartbeatTimeout < 30 || *data.HeartbeatTimeout > 7200 {
		return invalid("HeartbeatTimeout must be between 30 and 7200 seconds")
	}
	if in.DefaultResult != nil {
		data.DefaultResult = in.DefaultResult
	}
	if value(data.DefaultResult) != "CONTINUE" && value(data.DefaultResult) != "ABANDON" {
		return invalid("DefaultResult must be CONTINUE or ABANDON")
	}
	data.GlobalTimeout = new(api.GlobalTimeout(min(int32(*data.HeartbeatTimeout)*100, 172800)))
	if in.NotificationMetadata != nil {
		data.NotificationMetadata = in.NotificationMetadata
	}
	if in.NotificationTargetARN != nil {
		data.NotificationTargetARN = in.NotificationTargetARN
	}
	if in.RoleARN != nil {
		data.RoleARN = in.RoleARN
	}
	if value(data.NotificationTargetARN) != "" {
		if value(data.RoleARN) == "" {
			return invalid("RoleARN is required when NotificationTargetARN is specified")
		}
		if s.events == nil {
			return unsupported("Lifecycle notification delivery is unavailable")
		}
		record.Data = api.CloneLifecycleHook(data)
		payload, err := lifecycleNotification(g, record, LifecycleAction{}, "autoscaling:TEST_NOTIFICATION", "", "")
		if err != nil {
			return err
		}
		if err = s.events.Notify(ctx, record, payload); err != nil {
			return err
		}
	}
	record.Data = api.CloneLifecycleHook(data)
	return tx.PutHook(record)
}

func (s *Service) describeLifecycleHooks(ctx context.Context, tx Transaction, in *api.DescribeLifecycleHooksInput) (*api.DescribeLifecycleHooksOutput, error) {
	if err := s.authorize(ctx, "DescribeLifecycleHooks", "*", nil); err != nil {
		return nil, err
	}
	g, err := tx.Group(GroupKey{Scope: scopeFor(ctx), Name: value(in.AutoScalingGroupName)})
	if errors.Is(err, ErrNotFound) {
		return nil, invalid("AutoScalingGroup name not found - AutoScalingGroup '" + value(in.AutoScalingGroupName) + "' not found")
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.Hooks(g.Key)
	if err != nil {
		return nil, err
	}
	names := listSelection(in.LifecycleHookNames)
	out := &api.DescribeLifecycleHooksOutput{LifecycleHooks: api.LifecycleHooks{}}
	for _, row := range rows {
		if row.GroupID == g.ID && (len(names) == 0 || slices.Contains(names, row.Key.Name)) {
			out.LifecycleHooks = append(out.LifecycleHooks, row.Data)
		}
	}
	return out, nil
}

func (s *Service) describeLifecycleHookTypes(ctx context.Context, _ Transaction, _ *api.DescribeLifecycleHookTypesInput) (*api.DescribeLifecycleHookTypesOutput, error) {
	if err := s.authorize(ctx, "DescribeLifecycleHookTypes", "*", nil); err != nil {
		return nil, err
	}
	return &api.DescribeLifecycleHookTypesOutput{LifecycleHookTypes: api.AutoScalingNotificationTypes{api.XmlStringMaxLen255(launchTransition), api.XmlStringMaxLen255(terminateTransition)}}, nil
}

func (s *Service) deleteLifecycleHook(ctx context.Context, tx Transaction, in *api.DeleteLifecycleHookInput) (*api.DeleteLifecycleHookOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DeleteLifecycleHook")
	if err != nil {
		return nil, err
	}
	key := HookKey{GroupKey: g.Key, Name: value(in.LifecycleHookName)}
	if _, err = tx.Hook(key); errors.Is(err, ErrNotFound) {
		return nil, invalid("No Lifecycle Hook found with name '" + key.Name + "' for group '" + g.Key.Name + "'")
	}
	if err != nil {
		return nil, err
	}
	actions, err := tx.LifecycleActions(g.Key)
	if err != nil {
		return nil, err
	}
	for _, a := range actions {
		if a.GroupID == g.ID && a.HookName == key.Name {
			result := "CONTINUE"
			if a.Transition == launchTransition {
				result = "ABANDON"
			}
			if _, err = s.finishLifecycleAction(tx, g, a, result); err != nil {
				return nil, err
			}
		}
	}
	if err = tx.DeleteHook(key); err != nil {
		return nil, err
	}
	return &api.DeleteLifecycleHookOutput{}, nil
}

func (s *Service) activeLifecycleAction(tx Transaction, g GroupRecord, hook, token, instance string) (LifecycleAction, error) {
	if token == "" && instance == "" {
		return LifecycleAction{}, invalid("Either LifecycleActionToken or InstanceId must be specified")
	}
	rows, err := tx.LifecycleActions(g.Key)
	if err != nil {
		return LifecycleAction{}, err
	}
	now := s.clock.Now()
	for _, a := range rows {
		if a.GroupID == g.ID && a.HookName == hook && (token == "" || a.Token == token) && (instance == "" || a.InstanceID == instance) && now.Before(a.Deadline) && now.Before(a.GlobalDeadline) {
			return a, nil
		}
	}
	if token != "" {
		return LifecycleAction{}, invalid("No active Lifecycle Action found with token " + token)
	}
	return LifecycleAction{}, invalid("No active Lifecycle Action found with instance ID " + instance)
}

func (s *Service) recordLifecycleActionHeartbeat(ctx context.Context, tx Transaction, in *api.RecordLifecycleActionHeartbeatInput) (*api.RecordLifecycleActionHeartbeatOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "RecordLifecycleActionHeartbeat")
	if err != nil {
		return nil, err
	}
	a, err := s.activeLifecycleAction(tx, g, value(in.LifecycleHookName), value(in.LifecycleActionToken), value(in.InstanceId))
	if err != nil {
		return nil, err
	}
	a.Deadline = s.clock.Now().Add(a.HeartbeatTimeout)
	if a.Deadline.After(a.GlobalDeadline) {
		a.Deadline = a.GlobalDeadline
	}
	if err = tx.PutLifecycleAction(a); err != nil {
		return nil, err
	}
	return &api.RecordLifecycleActionHeartbeatOutput{}, nil
}

func (s *Service) completeLifecycleAction(ctx context.Context, tx Transaction, in *api.CompleteLifecycleActionInput) (*api.CompleteLifecycleActionOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "CompleteLifecycleAction")
	if err != nil {
		return nil, err
	}
	result := value(in.LifecycleActionResult)
	if result != "CONTINUE" && result != "ABANDON" {
		return nil, invalid("LifecycleActionResult must be CONTINUE or ABANDON")
	}
	a, err := s.activeLifecycleAction(tx, g, value(in.LifecycleHookName), value(in.LifecycleActionToken), value(in.InstanceId))
	if err != nil {
		return nil, err
	}
	if _, err = s.finishLifecycleAction(tx, g, a, result); err != nil {
		return nil, err
	}
	return &api.CompleteLifecycleActionOutput{}, nil
}
