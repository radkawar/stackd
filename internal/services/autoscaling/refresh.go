package autoscaling

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
)

func registerRefresh(s *Service) {
	registerPrepared(s, "StartInstanceRefresh", s.prepareStartInstanceRefresh)
	register(s, "DescribeInstanceRefreshes", s.describeInstanceRefreshes)
	register(s, "CancelInstanceRefresh", s.cancelInstanceRefresh)
	register(s, "RollbackInstanceRefresh", s.rollbackInstanceRefresh)
}

func (s *Service) prepareStartInstanceRefresh(ctx context.Context, in *api.StartInstanceRefreshInput) (func(Transaction) (*api.StartInstanceRefreshOutput, error), error) {
	group, refresh, err := s.prepareRefresh(ctx, in)
	if err != nil {
		return nil, err
	}
	return func(tx Transaction) (*api.StartInstanceRefreshOutput, error) {
		current, err := s.loadGroup(tx.Context(), tx, value(in.AutoScalingGroupName), "StartInstanceRefresh")
		if err != nil {
			return nil, err
		}
		if !sameGroupConfiguration(current, group) {
			return nil, failure("ResourceContention", "You already have a pending update to an Auto Scaling resource.")
		}
		rows, err := tx.Refreshes(current.Key)
		if err != nil {
			return nil, err
		}
		if _, ok := activeRefresh(rows, current.ID); ok {
			return nil, failure("InstanceRefreshInProgress", "An Instance Refresh is already in progress and blocks the execution of this Instance Refresh.")
		}
		members, err := tx.Instances(current.Key)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			if !retainedMember(m) && !m.DetachRequested {
				refresh.Members = append(refresh.Members, RefreshMember{value(m.Data.InstanceId), warmMember(m)})
			}
		}
		if err = tx.PutRefresh(refresh); err != nil {
			return nil, err
		}
		current.OriginEventID = refresh.OriginEventID
		if err = s.requestReconcile(tx, current); err != nil {
			return nil, err
		}
		return &api.StartInstanceRefreshOutput{InstanceRefreshId: refresh.Data.InstanceRefreshId}, nil
	}, nil
}

func refreshActive(r RefreshRecord) bool {
	switch value(r.Data.Status) {
	case "Pending", "InProgress", "Baking", "Cancelling", "RollbackInProgress":
		return true
	}
	return false
}
func activeRefresh(rows []RefreshRecord, groupID string) (RefreshRecord, bool) {
	for _, r := range rows {
		if r.GroupID == groupID && refreshActive(r) {
			return r, true
		}
	}
	return RefreshRecord{}, false
}

func (s *Service) prepareRefresh(ctx context.Context, in *api.StartInstanceRefreshInput) (GroupRecord, RefreshRecord, error) {
	var group GroupRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		var e error
		group, e = s.loadGroup(tx.Context(), tx, value(in.AutoScalingGroupName), "StartInstanceRefresh")
		if e != nil {
			return e
		}
		rows, e := tx.Refreshes(group.Key)
		if e != nil {
			return e
		}
		if _, ok := activeRefresh(rows, group.ID); ok {
			return failure("InstanceRefreshInProgress", "An Instance Refresh is already in progress and blocks the execution of this Instance Refresh.")
		}
		return nil
	})
	if err != nil {
		return group, RefreshRecord{}, err
	}
	if group.Deleting {
		return group, RefreshRecord{}, failure("ResourceInUse", "The Auto Scaling group is being deleted.")
	}
	if in.Strategy != nil && value(in.Strategy) != "Rolling" {
		if value(in.Strategy) == "ReplaceRootVolume" && in.DesiredConfiguration == nil {
			return group, RefreshRecord{}, invalid("The request isn't valid. The DesiredConfiguration parameter must be specified when using ReplaceRootVolume. Add the DesiredConfiguration parameter and try again.")
		}
		// TODO: Comeback implement mixed-instance refresh and ReplaceRootVolume
		// through the mixed-capacity and EC2 owners.
		if value(in.Strategy) == "ReplaceRootVolume" {
			return group, RefreshRecord{}, unsupported("ReplaceRootVolume requires a mixed instances policy with ImageId overrides; mixed instances groups are not implemented.")
		}
		return group, RefreshRecord{}, invalid("The instance refresh strategy is not valid.")
	}
	if in.DesiredConfiguration != nil && (in.DesiredConfiguration.MixedInstancesPolicy != nil || in.DesiredConfiguration.LaunchTemplate == nil) {
		return group, RefreshRecord{}, unsupported("Instance refresh requires a launch-template desired configuration; mixed instances policies are not implemented.")
	}
	p, err := refreshPreferences(group, in.Preferences)
	if err != nil {
		return group, RefreshRecord{}, err
	}
	if p.AutoRollback != nil && bool(*p.AutoRollback) && in.DesiredConfiguration == nil {
		return group, RefreshRecord{}, invalid("The request isn’t valid. The AutoRollback parameter cannot be set to true when the DesiredConfiguration parameter is empty. Set AutoRollback to false or specify a desired configuration and try again.")
	}
	if s.instances == nil || s.identity == nil {
		return group, RefreshRecord{}, unsupported("EC2 Auto Scaling execution is not configured.")
	}
	desired := cloneGroup(group)
	if in.DesiredConfiguration != nil {
		desired.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*in.DesiredConfiguration.LaunchTemplate))
		if err = s.resolveGroupTemplate(ctx, &desired); err != nil {
			return group, RefreshRecord{}, err
		}
		if desired.Data.WarmPoolConfiguration != nil {
			if err = s.instances.ValidateWarmPool(ctx, desired); err != nil {
				return group, RefreshRecord{}, err
			}
		}
	}
	execution, err := s.identity.Context(ctx, group)
	if err != nil {
		return group, RefreshRecord{}, err
	}
	target, err := s.instances.Template(execution, *desired.Data.LaunchTemplate)
	if err != nil {
		return group, RefreshRecord{}, err
	}
	r := RefreshRecord{Group: group.Key, GroupID: group.ID, Original: api.CloneLaunchTemplateSpecification(*group.Data.LaunchTemplate), Target: target, OriginEventID: apievents.EventID(ctx), RequestedAt: s.clock.Now(), ActiveDeadline: s.clock.Now().Add(14 * 24 * time.Hour), WaitForTransitioning: true}
	r.Data = api.InstanceRefresh{AutoScalingGroupName: new(api.XmlStringMaxLen255(group.Key.Name)), InstanceRefreshId: new(api.XmlStringMaxLen255(uuid.NewString())), Status: new(api.InstanceRefreshStatus("Pending")), Strategy: new(api.RefreshStrategy("Rolling")), Preferences: &p}
	if in.DesiredConfiguration != nil {
		r.Data.DesiredConfiguration = &api.DesiredConfiguration{LaunchTemplate: new(api.CloneLaunchTemplateSpecification(*desired.Data.LaunchTemplate))}
	}
	if p.AutoRollback != nil && bool(*p.AutoRollback) {
		if err = refreshRollbackAllowed(r); err != nil {
			return group, r, err
		}
	}
	if p.AlarmSpecification != nil {
		state, e := s.refreshAlarmState(ctx, p.AlarmSpecification)
		if e != nil {
			return group, r, e
		}
		if state != "OK" {
			return group, r, invalid("The specified CloudWatch alarms must be in the OK state before starting an instance refresh.")
		}
	}
	return group, r, nil
}

func refreshPreferences(group GroupRecord, in *api.RefreshPreferences) (api.RefreshPreferences, error) {
	p := api.RefreshPreferences{}
	if in != nil {
		p = api.CloneRefreshPreferences(*in)
	}
	if p.MinHealthyPercentage == nil {
		number(&p.MinHealthyPercentage, 90)
	}
	if group.Data.InstanceMaintenancePolicy != nil {
		if in == nil || in.MinHealthyPercentage == nil {
			number(&p.MinHealthyPercentage, intValue(group.Data.InstanceMaintenancePolicy.MinHealthyPercentage))
		}
		if p.MaxHealthyPercentage == nil {
			number(&p.MaxHealthyPercentage, intValue(group.Data.InstanceMaintenancePolicy.MaxHealthyPercentage))
		}
	}
	if p.InstanceWarmup == nil {
		n := intValue(group.Data.HealthCheckGracePeriod)
		if group.Data.DefaultInstanceWarmup != nil && intValue(group.Data.DefaultInstanceWarmup) >= 0 {
			n = intValue(group.Data.DefaultInstanceWarmup)
		}
		number(&p.InstanceWarmup, n)
	}
	if p.SkipMatching == nil {
		boolean(&p.SkipMatching, false)
	}
	if p.AutoRollback == nil {
		boolean(&p.AutoRollback, false)
	}
	maximum := int64(100)
	if p.MaxHealthyPercentage != nil {
		maximum = intValue(p.MaxHealthyPercentage)
	}
	minimum := intValue(p.MinHealthyPercentage)
	if minimum < 0 || minimum > 100 || maximum < 100 || maximum > 200 || maximum-minimum > 100 {
		return p, invalid("The difference between MaxHealthyPercentage and MinHealthyPercentage must be less than or equal to 100.")
	}
	if intValue(p.InstanceWarmup) < 0 {
		return p, invalid("InstanceWarmup must be greater than or equal to 0.")
	}
	if intValue(p.BakeTime) < 0 || intValue(p.BakeTime) > 172800 {
		return p, invalid("BakeTime must be between 0 and 172800 seconds.")
	}
	if intValue(p.CheckpointDelay) < 0 || intValue(p.CheckpointDelay) > 172800 {
		return p, invalid("CheckpointDelay must be between 0 and 172800 seconds.")
	}
	if p.CheckpointDelay != nil && len(p.CheckpointPercentages) == 0 {
		return p, invalid("CheckpointPercentages must be specified when CheckpointDelay is specified.")
	}
	previous := int64(0)
	for _, n := range p.CheckpointPercentages {
		if int64(n) <= previous || n > 100 {
			return p, invalid("Checkpoint percentages must be sorted in ascending order with no duplicates.")
		}
		previous = int64(n)
	}
	if len(p.CheckpointPercentages) > 0 && p.CheckpointDelay == nil {
		number(&p.CheckpointDelay, 3600)
	}
	if p.ScaleInProtectedInstances != nil && !slices.Contains([]string{"Wait", "Ignore", "Refresh"}, value(p.ScaleInProtectedInstances)) {
		return p, invalid("ScaleInProtectedInstances must be Wait, Ignore, or Refresh.")
	}
	if p.StandbyInstances != nil && !slices.Contains([]string{"Wait", "Ignore", "Terminate"}, value(p.StandbyInstances)) {
		return p, invalid("StandbyInstances must be Wait, Ignore, or Terminate.")
	}
	if p.AlarmSpecification != nil && len(p.AlarmSpecification.Alarms) > 10 {
		return p, invalid("AlarmSpecification must contain at most 10 alarms.")
	}
	if p.AlarmSpecification == nil {
		p.AlarmSpecification = &api.AlarmSpecification{}
	}
	return p, nil
}

func refreshRollbackAllowed(r RefreshRecord) error {
	if r.Data.DesiredConfiguration == nil {
		return invalid("The instance refresh cannot be rolled back because a desired configuration was not specified.")
	}
	if _, err := strconv.ParseUint(value(r.Original.Version), 10, 64); err != nil {
		return invalid("The instance refresh cannot be rolled back because the Auto Scaling group uses $Latest or $Default for its launch template version.")
	}
	return nil
}

func (s *Service) describeInstanceRefreshes(ctx context.Context, tx Transaction, in *api.DescribeInstanceRefreshesInput) (*api.DescribeInstanceRefreshesOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DescribeInstanceRefreshes")
	if err != nil {
		return nil, err
	}
	if len(in.InstanceRefreshIds) > 50 {
		return nil, invalid("You can specify up to 50 instance refresh IDs.")
	}
	rows, err := tx.Refreshes(group.Key)
	if err != nil {
		return nil, err
	}
	ids := listSelection(in.InstanceRefreshIds)
	rows = slices.DeleteFunc(rows, func(r RefreshRecord) bool {
		return r.GroupID != group.ID || r.RequestedAt.Before(s.clock.Now().AddDate(0, -6, 0)) || len(ids) > 0 && !slices.Contains(ids, value(r.Data.InstanceRefreshId))
	})
	rows, next, err := pageRows(group.Key.Scope, "DescribeInstanceRefreshes", struct {
		Group string
		IDs   []string
	}{group.ID, ids}, in.MaxRecords, in.NextToken, rows, func(r RefreshRecord) string {
		return fmt.Sprintf("%020d/%s", ^uint64(r.RequestedAt.UnixNano()), value(r.Data.InstanceRefreshId))
	})
	if err != nil {
		return nil, err
	}
	out := &api.DescribeInstanceRefreshesOutput{InstanceRefreshes: api.InstanceRefreshes{}, NextToken: next}
	for _, r := range rows {
		out.InstanceRefreshes = append(out.InstanceRefreshes, r.Data)
	}
	return out, nil
}

func (s *Service) cancelInstanceRefresh(ctx context.Context, tx Transaction, in *api.CancelInstanceRefreshInput) (*api.CancelInstanceRefreshOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "CancelInstanceRefresh")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Refreshes(group.Key)
	if err != nil {
		return nil, err
	}
	r, ok := activeRefresh(rows, group.ID)
	if !ok {
		return nil, failure("ActiveInstanceRefreshNotFound", "No in progress, baking, pending, or cancelling Instance Refresh found for Auto Scaling group "+group.Key.Name+".")
	}
	if value(r.Data.Status) == "RollbackInProgress" {
		return nil, invalid("An instance refresh that is rolling back cannot be cancelled.")
	}
	r.WaitForTransitioning = in.WaitForTransitioningInstances == nil || bool(*in.WaitForTransitioningInstances)
	text(&r.Data.Status, "Cancelling")
	if err = tx.PutRefresh(r); err != nil {
		return nil, err
	}
	if err = s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.CancelInstanceRefreshOutput{InstanceRefreshId: r.Data.InstanceRefreshId}, nil
}

func (s *Service) rollbackInstanceRefresh(ctx context.Context, tx Transaction, in *api.RollbackInstanceRefreshInput) (*api.RollbackInstanceRefreshOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "RollbackInstanceRefresh")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Refreshes(group.Key)
	if err != nil {
		return nil, err
	}
	r, ok := activeRefresh(rows, group.ID)
	if !ok || value(r.Data.Status) == "Pending" || value(r.Data.Status) == "Cancelling" {
		return nil, failure("ActiveInstanceRefreshNotFound", "No in progress or baking Instance Refresh found for Auto Scaling group "+group.Key.Name+".")
	}
	if value(r.Data.Status) == "RollbackInProgress" {
		return nil, failure("InstanceRefreshInProgress", "The instance refresh is already rolling back.")
	}
	if err = refreshRollbackAllowed(r); err != nil {
		return nil, err
	}
	s.beginRefreshRollback(&r, "Rollback triggered due to user request.")
	if err = s.refreshEvent(tx.Context(), group, r, "Rollback Started", 0); err != nil {
		return nil, err
	}
	if err = tx.PutRefresh(r); err != nil {
		return nil, err
	}
	if err = s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.RollbackInstanceRefreshOutput{InstanceRefreshId: r.Data.InstanceRefreshId}, nil
}

func (s *Service) beginRefreshRollback(r *RefreshRecord, reason string) {
	r.Data.RollbackDetails = &api.RollbackDetails{RollbackReason: new(api.XmlStringMaxLen1023(reason)), RollbackStartTime: new(api.TimestampType(s.clock.Now().UTC())), PercentageCompleteOnRollback: r.Data.PercentageComplete, InstancesToUpdateOnRollback: r.Data.InstancesToUpdate, ProgressDetailsOnRollback: r.Data.ProgressDetails}
	text(&r.Data.Status, "RollbackInProgress")
	text(&r.Data.StatusReason, reason)
	r.BlockedSince = time.Time{}
	r.PauseUntil = time.Time{}
	r.ActiveDeadline = s.clock.Now().Add(14 * 24 * time.Hour)
}

func refreshCause(r RefreshRecord) string {
	return fmt.Sprintf("Instance refresh %s is replacing instances.", value(r.Data.InstanceRefreshId))
}

func validateRefreshGroupUpdate(tx Reader, group GroupRecord, in *api.UpdateAutoScalingGroupInput) error {
	changed := in.LaunchConfigurationName != nil || in.MixedInstancesPolicy != nil
	if in.LaunchTemplate != nil {
		current := group.Data.LaunchTemplate
		changed = current == nil || value(in.LaunchTemplate.LaunchTemplateId) != "" && value(in.LaunchTemplate.LaunchTemplateId) != value(current.LaunchTemplateId) || value(in.LaunchTemplate.LaunchTemplateName) != "" && value(in.LaunchTemplate.LaunchTemplateName) != value(current.LaunchTemplateName)
		version := value(in.LaunchTemplate.Version)
		if version == "" {
			version = "$Default"
		}
		if current != nil && version != value(current.Version) {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	rows, err := tx.Refreshes(group.Key)
	if err != nil {
		return err
	}
	if r, ok := activeRefresh(rows, group.ID); ok && r.Data.DesiredConfiguration != nil {
		return invalid("An active instance refresh with a desired configuration exists. All configuration options derived from the desired configuration are not available for update while the instance refresh is active.")
	}
	return nil
}
