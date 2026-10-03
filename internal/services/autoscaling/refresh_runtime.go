package autoscaling

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	cwapi "stackd/internal/awsapi/cloudwatch"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func (s *Service) refreshLaunchGroup(ctx context.Context, group GroupRecord) (GroupRecord, error) {
	var rows []RefreshRecord
	err := s.repository.View(ctx, func(tx Reader) error { var err error; rows, err = tx.Refreshes(group.Key); return err })
	if err != nil {
		return group, err
	}
	if r, ok := activeRefresh(rows, group.ID); ok {
		group = cloneGroup(group)
		if value(r.Data.Status) == "RollbackInProgress" {
			group.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(r.Original))
		} else if r.Data.DesiredConfiguration != nil {
			group.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*r.Data.DesiredConfiguration.LaunchTemplate))
		}
		group.PendingInstanceWarmup = new(int32(intValue(r.Data.Preferences.InstanceWarmup)))
	}
	return group, nil
}

func (s *Service) refreshAlarmState(ctx context.Context, spec *api.AlarmSpecification) (string, error) {
	if spec == nil || len(spec.Alarms) == 0 {
		return "OK", nil
	}
	if s.alarms == nil {
		return "", unsupported("CloudWatch alarm integration is not configured.")
	}
	names := make(cwapi.AlarmNames, len(spec.Alarms))
	for i, n := range spec.Alarms {
		names[i] = cwapi.AlarmName(n)
	}
	out, err := s.alarms.Describe(ctx, &cwapi.DescribeAlarmsInput{AlarmNames: names, AlarmTypes: cwapi.AlarmTypes{cwapi.AlarmType("MetricAlarm"), cwapi.AlarmType("CompositeAlarm")}})
	if err != nil {
		return "", err
	}
	found := map[string]string{}
	for _, a := range out.MetricAlarms {
		found[value(a.AlarmName)] = value(a.StateValue)
	}
	for _, a := range out.CompositeAlarms {
		found[value(a.AlarmName)] = value(a.StateValue)
	}
	state := "OK"
	for _, n := range spec.Alarms {
		current, ok := found[string(n)]
		if !ok {
			return "", invalid("The specified CloudWatch alarm does not exist: " + string(n))
		}
		if current == "ALARM" {
			return current, nil
		}
		if current != "OK" {
			state = "INSUFFICIENT_DATA"
		}
	}
	return state, nil
}

func templateMatches(member InstanceRecord, spec api.LaunchTemplateSpecification) bool {
	m := member.Data.LaunchTemplate
	return m != nil && value(m.LaunchTemplateId) == value(spec.LaunchTemplateId) && value(m.Version) == value(spec.Version)
}

func refreshOriginal(r RefreshRecord, id string) bool {
	return slices.ContainsFunc(r.Members, func(m RefreshMember) bool { return m.InstanceID == id })
}

func refreshIgnored(r RefreshRecord, m InstanceRecord) bool {
	p := r.Data.Preferences
	return retainedMember(m) || m.DetachRequested || value(m.Data.LifecycleState) == "Standby" && value(p.StandbyInstances) == "Ignore" || m.Data.ProtectedFromScaleIn != nil && bool(*m.Data.ProtectedFromScaleIn) && value(p.ScaleInProtectedInstances) == "Ignore"
}

func refreshNeedsReplacement(r RefreshRecord, m InstanceRecord) bool {
	if refreshIgnored(r, m) {
		return false
	}
	if value(r.Data.Status) == "RollbackInProgress" {
		return !refreshOriginal(r, value(m.Data.InstanceId)) && !templateMatches(m, r.Original)
	}
	if r.Data.DesiredConfiguration != nil && !templateMatches(m, r.Target) {
		return true
	}
	return refreshOriginal(r, value(m.Data.InstanceId)) && !(r.Data.Preferences.SkipMatching != nil && bool(*r.Data.Preferences.SkipMatching) && templateMatches(m, r.Target))
}

func refreshReady(m InstanceRecord, now time.Time) bool {
	return !m.TerminationRequested && !m.DetachRequested && value(m.Data.HealthStatus) == "Healthy" && !m.WarmUntil.After(now) && (value(m.Data.LifecycleState) == "InService" || warmReady(m))
}

// refreshProgress derives native progress from the original cohort and current
// membership. EC2 disappearance alone is not completion: replacement readiness is
// bounded by current desired capacity, health, warmup and the warm-pool owner.
func refreshProgress(r RefreshRecord, group GroupRecord, members []InstanceRecord, health map[string]bool, now time.Time) (remaining, liveRemaining, warmRemaining, capacity, healthy, warmed, readyWarm int64) {
	for _, m := range members {
		if m.GroupID != group.ID {
			continue
		}
		if countsCapacity(m) && !m.TerminationRequested {
			capacity++
			if refreshReady(m, now) && health[value(m.Data.InstanceId)] {
				healthy++
			}
		}
		if warmMember(m) && !retainedMember(m) && !m.TerminationRequested {
			warmed++
			if refreshReady(m, now) {
				readyWarm++
			}
		}
		if refreshNeedsReplacement(r, m) {
			remaining++
			if warmMember(m) {
				warmRemaining++
			} else {
				liveRemaining++
			}
		}
	}
	return
}

func (s *Service) updateRefresh(ctx context.Context, group GroupRecord, r RefreshRecord, members []InstanceRecord, change func(Transaction, GroupRecord, *RefreshRecord) error) (bool, error) {
	changed := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Group(group.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != group.ID || current.Version != group.Version {
			return nil
		}
		valid, err := terminationSelectionCurrent(tx, group, members)
		if err != nil || !valid {
			return err
		}
		rows, err := tx.Refreshes(group.Key)
		if err != nil {
			return err
		}
		owned, ok := activeRefresh(rows, group.ID)
		if !ok || value(owned.Data.InstanceRefreshId) != value(r.Data.InstanceRefreshId) || value(owned.Data.Status) != value(r.Data.Status) {
			return nil
		}
		if err = change(tx, current, &owned); err != nil {
			return err
		}
		if err = tx.PutRefresh(owned); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}

func (s *Service) refreshEvent(ctx context.Context, group GroupRecord, r RefreshRecord, event string, checkpoint int64) error {
	if s.events == nil {
		return nil
	}
	detail := map[string]string{"InstanceRefreshId": value(r.Data.InstanceRefreshId), "AutoScalingGroupName": group.Key.Name}
	if event == "Checkpoint Reached" {
		detail["CheckpointPercentage"] = strconv.FormatInt(checkpoint, 10)
		detail["CheckpointDelay"] = strconv.FormatInt(intValue(r.Data.Preferences.CheckpointDelay), 10)
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	metadata := awsctx.FromContext(ctx)
	metadata.ParentEventID = r.OriginEventID
	return s.events.Publish(awsctx.WithMetadata(ctx, metadata), group, "EC2 Auto Scaling Instance Refresh "+event, body)
}

func (s *Service) finishRefresh(tx Transaction, group GroupRecord, r *RefreshRecord, status, reason string) error {
	text(&r.Data.Status, status)
	if reason != "" {
		text(&r.Data.StatusReason, reason)
	} else {
		r.Data.StatusReason = nil
	}
	r.Data.EndTime = new(api.TimestampType(s.clock.Now().UTC()))
	r.BlockedSince = time.Time{}
	r.PauseUntil = time.Time{}
	event := status
	switch status {
	case "Successful":
		event = "Succeeded"
	case "RollbackSuccessful":
		event = "Rollback Succeeded"
	case "RollbackFailed":
		event = "Rollback Failed"
	}
	if status == "Successful" {
		if status == "Successful" && r.Data.DesiredConfiguration != nil {
			group.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*r.Data.DesiredConfiguration.LaunchTemplate))
			if err := s.requestReconcile(tx, group); err != nil {
				return err
			}
		}
	}
	return s.refreshEvent(tx.Context(), group, *r, event, 0)
}

func (s *Service) failRefresh(tx Transaction, group GroupRecord, r *RefreshRecord, reason string) error {
	if value(r.Data.Status) == "RollbackInProgress" {
		return s.finishRefresh(tx, group, r, "RollbackFailed", reason)
	}
	if r.Data.Preferences.AutoRollback != nil && bool(*r.Data.Preferences.AutoRollback) {
		s.beginRefreshRollback(r, reason)
		return s.refreshEvent(tx.Context(), group, *r, "Rollback Started", 0)
	}
	return s.finishRefresh(tx, group, r, "Failed", reason)
}

func (s *Service) blockRefresh(ctx context.Context, group GroupRecord, r RefreshRecord, members []InstanceRecord, reason string) (bool, error) {
	if !r.BlockedSince.IsZero() && s.clock.Now().Before(r.BlockedSince.Add(time.Hour)) && value(r.Data.StatusReason) == reason {
		return false, nil
	}
	return s.updateRefresh(ctx, group, r, members, func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
		if r.BlockedSince.IsZero() {
			r.BlockedSince = s.clock.Now()
		}
		if !s.clock.Now().Before(r.BlockedSince.Add(time.Hour)) {
			return s.failRefresh(tx, g, r, "Instance refresh failed after waiting for one hour: "+reason)
		}
		text(&r.Data.StatusReason, reason)
		return nil
	})
}

func (s *Service) reconcileRefresh(ctx context.Context, snapshot GroupRecord) (bool, bool, error) {
	var group GroupRecord
	var r RefreshRecord
	var members []InstanceRecord
	var activities []ActivityRecord
	active := false
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		group, err = tx.Group(snapshot.Key)
		if err != nil {
			return err
		}
		if group.ID != snapshot.ID || group.Version != snapshot.Version {
			return nil
		}
		rows, err := tx.Refreshes(group.Key)
		if err != nil {
			return err
		}
		r, active = activeRefresh(rows, group.ID)
		if !active {
			return nil
		}
		members, err = tx.Instances(group.Key)
		if err != nil {
			return err
		}
		activities, err = tx.Activities(group.Key.Scope, group.Key.Name, false)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return false, false, nil
	}
	if err != nil || !active {
		return false, false, err
	}
	update := func(fn func(Transaction, GroupRecord, *RefreshRecord) error) (bool, bool, error) {
		changed, err := s.updateRefresh(ctx, group, r, members, fn)
		return true, changed, err
	}
	if group.Deleting {
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			return s.finishRefresh(tx, g, r, "Cancelled", "The Auto Scaling group is being deleted.")
		})
	}
	pending := false
	for _, a := range activities {
		if a.GroupID == group.ID && a.Data.EndTime == nil && (launchActivity(a.Kind) || terminateActivity(a.Kind)) {
			pending = true
			break
		}
	}
	if value(r.Data.Status) == "Cancelling" {
		if r.WaitForTransitioning && pending {
			return false, false, nil
		}
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			reason := "Cancelled due to user request."
			if !r.WaitForTransitioning {
				reason = "Cancelled without waiting for ongoing instance launches and terminations due to user request."
			}
			return s.finishRefresh(tx, g, r, "Cancelled", reason)
		})
	}
	if value(r.Data.Status) == "Pending" {
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			text(&r.Data.Status, "InProgress")
			r.Data.StartTime = new(api.TimestampType(s.clock.Now().UTC()))
			r.ActiveDeadline = s.clock.Now().Add(14 * 24 * time.Hour)
			return s.refreshEvent(tx.Context(), g, *r, "Started", 0)
		})
	}
	if value(r.Data.Status) != "RollbackInProgress" {
		if desired := r.Data.DesiredConfiguration; desired != nil && (value(desired.LaunchTemplate.Version) == "$Default" || value(desired.LaunchTemplate.Version) == "$Latest") {
			target, e := s.instances.Template(ctx, *desired.LaunchTemplate)
			if e != nil {
				changed, err := s.blockRefresh(ctx, group, r, members, e.Error())
				return true, changed, err
			}
			if value(target.Version) != value(r.Target.Version) {
				return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
					r.Target = target
					r.PauseUntil = time.Time{}
					text(&r.Data.Status, "InProgress")
					return nil
				})
			}
		}
		state, e := s.refreshAlarmState(ctx, r.Data.Preferences.AlarmSpecification)
		if e != nil {
			changed, err := s.blockRefresh(ctx, group, r, members, e.Error())
			return true, changed, err
		}
		if state == "ALARM" {
			return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
				return s.failRefresh(tx, g, r, "A CloudWatch alarm specified for the instance refresh is in ALARM state.")
			})
		}
		if state != "OK" {
			changed, err := s.blockRefresh(ctx, group, r, members, "Waiting for CloudWatch alarms to have sufficient data.")
			return true, changed, err
		}
	}
	health, healthErr := s.refreshHealth(ctx, group, members)
	if healthErr != nil {
		changed, err := s.blockRefresh(ctx, group, r, members, healthErr.Error())
		return true, changed, err
	}
	if value(r.Data.Status) == "Baking" {
		if s.clock.Now().Before(r.PauseUntil) {
			return false, false, nil
		}
		_, _, _, _, healthy, _, readyWarm := refreshProgress(r, group, members, health, s.clock.Now())
		if pending || healthy < intValue(group.Data.DesiredCapacity) || readyWarm < warmPoolDesired(group) {
			if refreshWarmupPending(members, health, s.clock.Now()) {
				changed, err := s.waitRefreshWarmup(ctx, group, r, members)
				return true, changed, err
			}
			changed, err := s.blockRefresh(ctx, group, r, members, "Waiting for healthy replacement capacity at the end of bake time.")
			return changed || err != nil, changed, err
		}
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			return s.finishRefresh(tx, g, r, "Successful", "")
		})
	}
	if !s.clock.Now().Before(r.ActiveDeadline) {
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			return s.failRefresh(tx, g, r, "The instance refresh exceeded the maximum active replacement duration of 14 days.")
		})
	}
	if processSuspended(group, "InstanceRefresh") {
		return refreshSurge(group, r, members, activities), false, nil
	}
	if r.PauseUntil.After(s.clock.Now()) {
		return false, false, nil
	}
	remaining, liveRemaining, warmRemaining, capacity, healthy, warmed, readyWarm := refreshProgress(r, group, members, health, s.clock.Now())
	desired := intValue(group.Data.DesiredCapacity)
	pool := warmPoolDesired(group)
	totalLive, totalWarm := int64(0), int64(0)
	for _, m := range r.Members {
		if m.Warm {
			totalWarm++
		} else {
			totalLive++
		}
	}
	total := totalLive + totalWarm
	percent := int64(100)
	if total > 0 {
		percent = max(0, 100*(total-remaining)/total)
	}
	// Until replacements warm, retired originals are not complete units.
	notReady := max(0, desired-healthy) + max(0, pool-readyWarm)
	progressRemaining := remaining + notReady
	if total > 0 {
		percent = max(0, 100*(total-min(total, progressRemaining))/total)
	}
	if value(r.Data.Status) == "RollbackInProgress" {
		forwardComplete := int64(0)
		for _, m := range members {
			if !refreshOriginal(r, value(m.Data.InstanceId)) && templateMatches(m, r.Target) {
				forwardComplete++
			}
		}
		progressRemaining = max(0, total-forwardComplete)
		if total > 0 {
			percent = min(100, 100*forwardComplete/total)
		}
	}
	if intValue(r.Data.InstancesToUpdate) != progressRemaining || r.Data.InstancesToUpdate == nil || intValue(r.Data.PercentageComplete) != percent {
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			if r.Data.InstancesToUpdate != nil && (value(r.Data.Status) == "RollbackInProgress" && progressRemaining > intValue(r.Data.InstancesToUpdate) || value(r.Data.Status) != "RollbackInProgress" && progressRemaining < intValue(r.Data.InstancesToUpdate)) {
				r.BlockedSince = time.Time{}
				r.Data.StatusReason = nil
			}
			number(&r.Data.InstancesToUpdate, progressRemaining)
			number(&r.Data.PercentageComplete, percent)
			livePercent, warmPercent := int64(100), int64(100)
			if totalLive > 0 {
				livePercent = max(0, 100*(totalLive-min(totalLive, liveRemaining+max(0, desired-healthy)))/totalLive)
			}
			if totalWarm > 0 {
				warmPercent = max(0, 100*(totalWarm-min(totalWarm, warmRemaining+max(0, pool-readyWarm)))/totalWarm)
			}
			if totalWarm > 0 || g.Data.WarmPoolConfiguration != nil {
				r.Data.ProgressDetails = &api.InstanceRefreshProgressDetails{LivePoolProgress: &api.InstanceRefreshLivePoolProgress{PercentageComplete: new(api.IntPercent(livePercent)), InstancesToUpdate: new(api.InstancesToUpdate(liveRemaining + max(0, desired-healthy)))}, WarmPoolProgress: &api.InstanceRefreshWarmPoolProgress{PercentageComplete: new(api.IntPercent(warmPercent)), InstancesToUpdate: new(api.InstancesToUpdate(warmRemaining + max(0, pool-readyWarm)))}}
			}
			return nil
		})
	}
	if value(r.Data.Status) != "RollbackInProgress" && r.Checkpoint < len(r.Data.Preferences.CheckpointPercentages) && percent >= int64(r.Data.Preferences.CheckpointPercentages[r.Checkpoint]) {
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			index := r.Checkpoint
			for index+1 < len(r.Data.Preferences.CheckpointPercentages) && percent >= int64(r.Data.Preferences.CheckpointPercentages[index+1]) {
				index++
			}
			threshold := int64(r.Data.Preferences.CheckpointPercentages[index])
			r.Checkpoint = index + 1
			if r.Checkpoint < len(r.Data.Preferences.CheckpointPercentages) {
				delay := time.Duration(intValue(r.Data.Preferences.CheckpointDelay)) * time.Second
				r.PauseUntil = s.clock.Now().Add(delay)
				r.ActiveDeadline = r.ActiveDeadline.Add(delay)
			}
			if threshold == 100 {
				return nil
			}
			return s.refreshEvent(tx.Context(), g, *r, "Checkpoint Reached", threshold)
		})
	}
	finalCheckpointReached := value(r.Data.Status) != "RollbackInProgress" && len(r.Data.Preferences.CheckpointPercentages) > 0 && percent >= int64(r.Data.Preferences.CheckpointPercentages[len(r.Data.Preferences.CheckpointPercentages)-1])
	if (remaining == 0 || finalCheckpointReached) && healthy >= desired && readyWarm >= pool && !pending {
		return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
			if value(r.Data.Status) == "RollbackInProgress" {
				return s.finishRefresh(tx, g, r, "RollbackSuccessful", "")
			}
			if intValue(r.Data.Preferences.BakeTime) > 0 {
				text(&r.Data.Status, "Baking")
				r.PauseUntil = s.clock.Now().Add(time.Duration(intValue(r.Data.Preferences.BakeTime)) * time.Second)
				text(&r.Data.StatusReason, fmt.Sprintf("Waiting for bake time to finish before continuing. There are %d seconds left.", intValue(r.Data.Preferences.BakeTime)))
				return s.refreshEvent(tx.Context(), g, *r, "Started Baking", 0)
			}
			return s.finishRefresh(tx, g, r, "Successful", "")
		})
	}
	// Ordinary scaling retains its own authority. The only excess capacity owned
	// by refresh is a replacement launch with the refresh origin/cause.
	surge := refreshSurge(group, r, members, activities)
	if capacity < desired || liveRemaining == 0 && warmed < pool {
		changed, err := s.blockRefresh(ctx, group, r, members, "Waiting for replacement instances to launch and become healthy.")
		return changed || err != nil, changed, err
	}
	if capacity > desired && !surge {
		return false, false, nil
	}
	if refreshWarmupPending(members, health, s.clock.Now()) {
		changed, err := s.waitRefreshWarmup(ctx, group, r, members)
		return true, changed, err
	}
	if remaining == 0 || pending && capacity <= desired {
		changed, err := s.blockRefresh(ctx, group, r, members, "Waiting for instances to become healthy, finish warming up, or complete lifecycle actions.")
		return true, changed, err
	}
	eligible := []string{}
	reason := "Waiting for instances to become healthy or complete lifecycle actions."
	for _, m := range members {
		if !refreshNeedsReplacement(r, m) || m.TerminationRequested || m.DetachRequested || retainedMember(m) {
			continue
		}
		if warmMember(m) && (liveRemaining > 0 || healthy < desired) {
			continue
		}
		if value(m.Data.LifecycleState) == "Standby" {
			if r.Data.Preferences.StandbyInstances == nil || value(r.Data.Preferences.StandbyInstances) == "Wait" {
				reason = "Waiting for instances in Standby to return to service."
				continue
			}
		} else if !refreshReady(m, s.clock.Now()) || countsCapacity(m) && !health[value(m.Data.InstanceId)] {
			continue
		}
		if m.Data.ProtectedFromScaleIn != nil && bool(*m.Data.ProtectedFromScaleIn) && (r.Data.Preferences.ScaleInProtectedInstances == nil || value(r.Data.Preferences.ScaleInProtectedInstances) == "Wait") {
			reason = "Waiting for remaining instances to be available. For example: " + value(m.Data.InstanceId) + " is protected. Remove instance scale-in protection to continue."
			continue
		}
		eligible = append(eligible, value(m.Data.InstanceId))
	}
	if len(eligible) == 0 {
		changed, err := s.blockRefresh(ctx, group, r, members, reason)
		return true, changed, err
	}
	minimum := (desired*intValue(r.Data.Preferences.MinHealthyPercentage) + 99) / 100
	maximumPercent := int64(100)
	if r.Data.Preferences.MaxHealthyPercentage != nil {
		maximumPercent = intValue(r.Data.Preferences.MaxHealthyPercentage)
	}
	maximum := desired * maximumPercent / 100
	warmPhase := liveRemaining == 0
	simultaneous := !warmPhase && minimum == desired && maximum == desired && r.Data.Preferences.MaxHealthyPercentage == nil
	if minimum == desired && maximum == desired {
		if r.Data.Preferences.MaxHealthyPercentage != nil {
			// Explicit bounds prefer availability when rounding makes
			// replacement impossible without briefly exceeding the maximum.
			maximum++
		} else {
			// An omitted maximum instead replaces one instance concurrently.
			minimum = max(0, desired-1)
		}
	}
	canTerminate := warmPhase || healthy > minimum
	if !canTerminate {
		standby := slices.DeleteFunc(slices.Clone(eligible), func(id string) bool {
			return !slices.ContainsFunc(members, func(m InstanceRecord) bool {
				return value(m.Data.InstanceId) == id && value(m.Data.LifecycleState) == "Standby"
			})
		})
		if len(standby) > 0 {
			eligible = standby
			canTerminate = true
		}
	}
	if !canTerminate && capacity < maximum && !processSuspended(group, "Launch") {
		changed, err := s.admitRefreshLaunch(ctx, group, r, members, nil)
		return true, changed, err
	}
	if !canTerminate || processSuspended(group, "Terminate") || simultaneous && processSuspended(group, "Launch") {
		changed, err := s.blockRefresh(ctx, group, r, members, "Waiting for healthy capacity or suspended Launch/Terminate processes.")
		return true, changed, err
	}
	selected, err := s.selectTerminations(ctx, group, members, "INSTANCE_REFRESH", 1, eligible)
	if err != nil || len(selected) == 0 {
		reason := "Waiting for the custom termination policy to select an instance."
		if err != nil {
			reason += " " + err.Error()
		}
		changed, e := s.blockRefresh(ctx, group, r, members, reason)
		return true, changed, e
	}
	if simultaneous {
		changed, err := s.admitRefreshLaunch(ctx, group, r, members, &selected[0])
		return true, changed, err
	}
	return update(func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
		member := selected[0]
		g.OriginEventID = r.OriginEventID
		r.BlockedSince = time.Time{}
		r.Data.StatusReason = nil
		_, err := s.terminateMember(tx, g, &member, refreshCause(*r))
		return err
	})
}

func (s *Service) admitRefreshLaunch(ctx context.Context, group GroupRecord, r RefreshRecord, members []InstanceRecord, retirement *InstanceRecord) (bool, error) {
	launchGroup, err := s.refreshLaunchGroup(ctx, group)
	if err != nil {
		return false, err
	}
	spec, err := s.instances.Template(ctx, *launchGroup.Data.LaunchTemplate)
	if err != nil {
		return s.blockRefresh(ctx, group, r, members, err.Error())
	}
	subnets, err := s.instances.Placement(ctx, strings.Split(value(group.Data.VPCZoneIdentifier), ","), nil)
	if err != nil {
		return s.blockRefresh(ctx, group, r, members, err.Error())
	}
	if len(subnets) == 0 {
		return s.blockRefresh(ctx, group, r, members, "The Auto Scaling group has no usable subnets.")
	}
	counts := map[string]int{}
	for _, m := range members {
		if countsCapacity(m) {
			counts[value(m.Data.AvailabilityZone)]++
		}
	}
	slices.SortFunc(subnets, func(a, b ec2api.Subnet) int {
		return cmp.Or(cmp.Compare(counts[value(a.AvailabilityZone)], counts[value(b.AvailabilityZone)]), strings.Compare(value(a.SubnetId), value(b.SubnetId)))
	})
	return s.updateRefresh(ctx, group, r, members, func(tx Transaction, g GroupRecord, r *RefreshRecord) error {
		g.OriginEventID = r.OriginEventID
		if retirement != nil {
			if _, err := s.terminateMember(tx, g, retirement, refreshCause(*r)); err != nil {
				return err
			}
			r.BlockedSince = time.Time{}
			r.Data.StatusReason = nil
		}
		activity := s.newActivity(g, "launch", refreshCause(*r))
		activity.LaunchTemplate = spec
		activity.SubnetID = value(subnets[0].SubnetId)
		activity.InstanceWarmup = launchGroup.PendingInstanceWarmup
		activity.ProtectedFromScaleIn = g.Data.NewInstancesProtectedFromScaleIn != nil && bool(*g.Data.NewInstancesProtectedFromScaleIn)
		for _, tag := range g.Data.Tags {
			if tag.PropagateAtLaunch != nil && bool(*tag.PropagateAtLaunch) {
				activity.LaunchTags = append(activity.LaunchTags, tag)
			}
		}
		text(&activity.Data.Description, "Launching a new EC2 instance.")
		return tx.PutActivity(activity)
	})
}

// Grace periods postpone replacement of unhealthy members, not the refresh's
// minimum-healthy gate. Observe the actual EC2 and ALB owners before retirement.
func (s *Service) refreshHealth(ctx context.Context, g GroupRecord, members []InstanceRecord) (map[string]bool, error) {
	ids := []string{}
	for _, m := range members {
		if countsCapacity(m) && !m.TerminationRequested && value(m.Data.LifecycleState) == "InService" {
			ids = append(ids, value(m.Data.InstanceId))
		}
	}
	health := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return health, nil
	}
	if s.instances == nil {
		return nil, unsupported("EC2 Auto Scaling execution is not configured.")
	}
	observations, err := s.instances.Observe(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, observation := range observations {
		id := value(observation.Instance.InstanceId)
		healthy := observation.Healthy && observation.Instance.State != nil && value(observation.Instance.State.Name) == "running"
		if healthy && value(g.Data.HealthCheckType) == "ELB" {
			if s.targetGroups == nil {
				return nil, unsupported("Auto Scaling target group integration is not configured.")
			}
			for _, target := range g.Data.TargetGroupARNs {
				ready, err := s.targetGroups.Healthy(ctx, g.Key.ARN(g.ID), string(target), id)
				if err != nil {
					return nil, err
				}
				healthy = healthy && ready
			}
		}
		health[id] = healthy
	}
	return health, nil
}

func refreshSurge(group GroupRecord, r RefreshRecord, members []InstanceRecord, activities []ActivityRecord) bool {
	capacity := int64(0)
	for _, m := range members {
		if countsCapacity(m) && !m.TerminationRequested {
			capacity++
		}
	}
	if capacity <= intValue(group.Data.DesiredCapacity) {
		return false
	}
	cause := refreshCause(r)
	for _, a := range activities {
		if a.GroupID == group.ID && a.Kind == "launch" && value(a.Data.Cause) == cause && a.InstanceID != "" && slices.ContainsFunc(members, func(m InstanceRecord) bool {
			return value(m.Data.InstanceId) == a.InstanceID && !m.TerminationRequested
		}) {
			return true
		}
	}
	return false
}

// A healthy member's scheduled warmup is not a failure to make progress. The
// active-refresh deadline still bounds it; the one-hour deadline is reserved for
// actual blockage such as unhealthy, protected, or standby instances.
func refreshWarmupPending(members []InstanceRecord, health map[string]bool, now time.Time) bool {
	for _, member := range members {
		if !member.TerminationRequested && !member.DetachRequested && value(member.Data.LifecycleState) == "InService" &&
			value(member.Data.HealthStatus) == "Healthy" && health[value(member.Data.InstanceId)] && member.WarmUntil.After(now) {
			return true
		}
	}
	return false
}

func (s *Service) waitRefreshWarmup(ctx context.Context, group GroupRecord, r RefreshRecord, members []InstanceRecord) (bool, error) {
	const reason = "Waiting for healthy instances to finish warming up."
	if r.BlockedSince.IsZero() && value(r.Data.StatusReason) == reason {
		return false, nil
	}
	return s.updateRefresh(ctx, group, r, members, func(_ Transaction, _ GroupRecord, current *RefreshRecord) error {
		current.BlockedSince = time.Time{}
		text(&current.Data.StatusReason, reason)
		return nil
	})
}
