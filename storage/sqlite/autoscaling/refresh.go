package autoscaling

import (
	api "stackd/internal/awsapi/autoscaling"
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
)

func (r reader) Refreshes(key domain.GroupKey) ([]domain.RefreshRecord, error) {
	rows, err := r.q.ListRefreshes(r.ctx, sqlcgen.ListRefreshesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RefreshRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.refresh(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) refresh(row sqlcgen.AsgRefresh) (domain.RefreshRecord, error) {
	v := domain.RefreshRecord{Group: groupKey(row.Partition, row.AccountID, row.Region, row.GroupName), GroupID: row.GroupID, OriginEventID: row.OriginEventID, RequestedAt: row.RequestedAt, BlockedSince: row.BlockedSince.Time, PauseUntil: row.PauseUntil.Time, ActiveDeadline: row.ActiveDeadline, Checkpoint: int(row.Checkpoint), WaitForTransitioning: row.WaitForTransitioning}
	v.Data.AutoScalingGroupName = new(api.XmlStringMaxLen255(row.GroupName))
	v.Data.InstanceRefreshId = new(api.XmlStringMaxLen255(row.RefreshID))
	v.Data.Status = stringPointer[api.InstanceRefreshStatus](row.Status)
	v.Data.StatusReason = stringPointer[api.XmlStringMaxLen1023](row.StatusReason)
	v.Data.Strategy = stringPointer[api.RefreshStrategy](row.Strategy)
	v.Data.PercentageComplete = intPointer[api.IntPercent](row.PercentageComplete)
	v.Data.InstancesToUpdate = intPointer[api.InstancesToUpdate](row.InstancesToUpdate)
	v.Data.StartTime = timePointer(row.StartTime)
	v.Data.EndTime = timePointer(row.EndTime)
	v.Data.Preferences = &api.RefreshPreferences{AlarmSpecification: &api.AlarmSpecification{}}
	v.Data.Preferences.MinHealthyPercentage = intPointer[api.IntPercent](row.MinHealthy)
	v.Data.Preferences.MaxHealthyPercentage = intPointer[api.IntPercent100To200](row.MaxHealthy)
	v.Data.Preferences.InstanceWarmup = intPointer[api.RefreshInstanceWarmup](row.InstanceWarmup)
	v.Data.Preferences.CheckpointDelay = intPointer[api.CheckpointDelay](row.CheckpointDelay)
	v.Data.Preferences.BakeTime = intPointer[api.BakeTime](row.BakeTime)
	v.Data.Preferences.SkipMatching = boolPointer[api.SkipMatching](row.SkipMatching)
	v.Data.Preferences.AutoRollback = boolPointer[api.AutoRollback](row.AutoRollback)
	v.Data.Preferences.ScaleInProtectedInstances = stringPointer[api.ScaleInProtectedInstances](row.ProtectedInstances)
	v.Data.Preferences.StandbyInstances = stringPointer[api.StandbyInstances](row.StandbyInstances)
	v.Original.LaunchTemplateId = stringPointer[api.XmlStringMaxLen255](row.OriginalID)
	v.Original.LaunchTemplateName = stringPointer[api.LaunchTemplateName](row.OriginalName)
	v.Original.Version = stringPointer[api.XmlStringMaxLen255](row.OriginalVersion)
	v.Target.LaunchTemplateId = stringPointer[api.XmlStringMaxLen255](row.TargetID)
	v.Target.LaunchTemplateName = stringPointer[api.LaunchTemplateName](row.TargetName)
	v.Target.Version = stringPointer[api.XmlStringMaxLen255](row.TargetVersion)
	if row.HasDesired {
		v.Data.DesiredConfiguration = &api.DesiredConfiguration{LaunchTemplate: &api.LaunchTemplateSpecification{}}
		v.Data.DesiredConfiguration.LaunchTemplate.LaunchTemplateId = stringPointer[api.XmlStringMaxLen255](row.DesiredID)
		v.Data.DesiredConfiguration.LaunchTemplate.LaunchTemplateName = stringPointer[api.LaunchTemplateName](row.DesiredName)
		v.Data.DesiredConfiguration.LaunchTemplate.Version = stringPointer[api.XmlStringMaxLen255](row.DesiredVersion)
	}
	if row.HasProgress {
		v.Data.ProgressDetails = &api.InstanceRefreshProgressDetails{LivePoolProgress: &api.InstanceRefreshLivePoolProgress{PercentageComplete: intPointer[api.IntPercent](row.LivePercentage), InstancesToUpdate: intPointer[api.InstancesToUpdate](row.LiveRemaining)}}
		if row.HasWarmProgress {
			v.Data.ProgressDetails.WarmPoolProgress = &api.InstanceRefreshWarmPoolProgress{PercentageComplete: intPointer[api.IntPercent](row.WarmPercentage), InstancesToUpdate: intPointer[api.InstancesToUpdate](row.WarmRemaining)}
		}
	}
	if row.HasRollback {
		v.Data.RollbackDetails = &api.RollbackDetails{RollbackReason: stringPointer[api.XmlStringMaxLen1023](row.RollbackReason), RollbackStartTime: timePointer(row.RollbackStart), PercentageCompleteOnRollback: intPointer[api.IntPercent](row.RollbackPercentage), InstancesToUpdateOnRollback: intPointer[api.InstancesToUpdate](row.RollbackRemaining)}
		if row.HasRollbackProgress {
			v.Data.RollbackDetails.ProgressDetailsOnRollback = &api.InstanceRefreshProgressDetails{LivePoolProgress: &api.InstanceRefreshLivePoolProgress{PercentageComplete: intPointer[api.IntPercent](row.RollbackLivePercentage), InstancesToUpdate: intPointer[api.InstancesToUpdate](row.RollbackLiveRemaining)}}
			if row.HasRollbackWarmProgress {
				v.Data.RollbackDetails.ProgressDetailsOnRollback.WarmPoolProgress = &api.InstanceRefreshWarmPoolProgress{PercentageComplete: intPointer[api.IntPercent](row.RollbackWarmPercentage), InstancesToUpdate: intPointer[api.InstancesToUpdate](row.RollbackWarmRemaining)}
			}
		}
	}
	members, err := r.q.ListRefreshMembers(r.ctx, row.RefreshPk)
	if err != nil {
		return v, err
	}
	for _, m := range members {
		v.Members = append(v.Members, domain.RefreshMember{InstanceID: m.InstanceID, Warm: m.Warm})
	}
	checkpoints, err := r.q.ListRefreshCheckpoints(r.ctx, row.RefreshPk)
	if err != nil {
		return v, err
	}
	for _, c := range checkpoints {
		v.Data.Preferences.CheckpointPercentages = append(v.Data.Preferences.CheckpointPercentages, api.NonZeroIntPercent(c.Percentage))
	}
	alarms, err := r.q.ListRefreshAlarms(r.ctx, row.RefreshPk)
	if err != nil {
		return v, err
	}
	for _, a := range alarms {
		v.Data.Preferences.AlarmSpecification.Alarms = append(v.Data.Preferences.AlarmSpecification.Alarms, api.XmlStringMaxLen255(a.Name))
	}
	return v, nil
}

func (w writer) PutRefresh(v domain.RefreshRecord) error {
	p := sqlcgen.PutRefreshParams{
		Partition:               v.Group.Partition,
		AccountID:               v.Group.AccountID,
		Region:                  v.Group.Region,
		GroupName:               v.Group.Name,
		GroupID:                 v.GroupID,
		RefreshID:               value(v.Data.InstanceRefreshId),
		OriginEventID:           v.OriginEventID,
		RequestedAt:             v.RequestedAt,
		BlockedSince:            deadline(v.BlockedSince),
		PauseUntil:              deadline(v.PauseUntil),
		ActiveDeadline:          v.ActiveDeadline,
		Checkpoint:              int64(v.Checkpoint),
		WaitForTransitioning:    v.WaitForTransitioning,
		Status:                  nullableString(v.Data.Status),
		StatusReason:            nullableString(v.Data.StatusReason),
		Strategy:                nullableString(v.Data.Strategy),
		StartTime:               nullableTime(v.Data.StartTime),
		EndTime:                 nullableTime(v.Data.EndTime),
		PercentageComplete:      nullableInt(v.Data.PercentageComplete),
		InstancesToUpdate:       nullableInt(v.Data.InstancesToUpdate),
		HasDesired:              v.Data.DesiredConfiguration != nil,
		HasProgress:             v.Data.ProgressDetails != nil,
		HasWarmProgress:         v.Data.ProgressDetails != nil && v.Data.ProgressDetails.WarmPoolProgress != nil,
		HasRollback:             v.Data.RollbackDetails != nil,
		HasRollbackProgress:     v.Data.RollbackDetails != nil && v.Data.RollbackDetails.ProgressDetailsOnRollback != nil,
		HasRollbackWarmProgress: v.Data.RollbackDetails != nil && v.Data.RollbackDetails.ProgressDetailsOnRollback != nil && v.Data.RollbackDetails.ProgressDetailsOnRollback.WarmPoolProgress != nil,
	}
	p.MinHealthy = nullableInt(v.Data.Preferences.MinHealthyPercentage)
	p.MaxHealthy = nullableInt(v.Data.Preferences.MaxHealthyPercentage)
	p.InstanceWarmup = nullableInt(v.Data.Preferences.InstanceWarmup)
	p.CheckpointDelay = nullableInt(v.Data.Preferences.CheckpointDelay)
	p.BakeTime = nullableInt(v.Data.Preferences.BakeTime)
	p.SkipMatching = nullableBool(v.Data.Preferences.SkipMatching)
	p.AutoRollback = nullableBool(v.Data.Preferences.AutoRollback)
	p.ProtectedInstances = nullableString(v.Data.Preferences.ScaleInProtectedInstances)
	p.StandbyInstances = nullableString(v.Data.Preferences.StandbyInstances)
	p.OriginalID = nullableString(v.Original.LaunchTemplateId)
	p.OriginalName = nullableString(v.Original.LaunchTemplateName)
	p.OriginalVersion = nullableString(v.Original.Version)
	p.TargetID = nullableString(v.Target.LaunchTemplateId)
	p.TargetName = nullableString(v.Target.LaunchTemplateName)
	p.TargetVersion = nullableString(v.Target.Version)
	if v.Data.DesiredConfiguration != nil && v.Data.DesiredConfiguration.LaunchTemplate != nil {
		p.DesiredID = nullableString(v.Data.DesiredConfiguration.LaunchTemplate.LaunchTemplateId)
		p.DesiredName = nullableString(v.Data.DesiredConfiguration.LaunchTemplate.LaunchTemplateName)
		p.DesiredVersion = nullableString(v.Data.DesiredConfiguration.LaunchTemplate.Version)
	}
	if v.Data.ProgressDetails != nil {
		if v.Data.ProgressDetails.LivePoolProgress != nil {
			p.LivePercentage = nullableInt(v.Data.ProgressDetails.LivePoolProgress.PercentageComplete)
			p.LiveRemaining = nullableInt(v.Data.ProgressDetails.LivePoolProgress.InstancesToUpdate)
		}
		if v.Data.ProgressDetails.WarmPoolProgress != nil {
			p.WarmPercentage = nullableInt(v.Data.ProgressDetails.WarmPoolProgress.PercentageComplete)
			p.WarmRemaining = nullableInt(v.Data.ProgressDetails.WarmPoolProgress.InstancesToUpdate)
		}
	}
	if v.Data.RollbackDetails != nil {
		if v.Data.RollbackDetails.ProgressDetailsOnRollback != nil {
			if v.Data.RollbackDetails.ProgressDetailsOnRollback.LivePoolProgress != nil {
				p.RollbackLivePercentage = nullableInt(v.Data.RollbackDetails.ProgressDetailsOnRollback.LivePoolProgress.PercentageComplete)
				p.RollbackLiveRemaining = nullableInt(v.Data.RollbackDetails.ProgressDetailsOnRollback.LivePoolProgress.InstancesToUpdate)
			}
			if v.Data.RollbackDetails.ProgressDetailsOnRollback.WarmPoolProgress != nil {
				p.RollbackWarmPercentage = nullableInt(v.Data.RollbackDetails.ProgressDetailsOnRollback.WarmPoolProgress.PercentageComplete)
				p.RollbackWarmRemaining = nullableInt(v.Data.RollbackDetails.ProgressDetailsOnRollback.WarmPoolProgress.InstancesToUpdate)
			}
		}
	}
	if d := v.Data.RollbackDetails; d != nil {
		p.RollbackReason = nullableString(d.RollbackReason)
		p.RollbackStart = nullableTime(d.RollbackStartTime)
		p.RollbackPercentage = nullableInt(d.PercentageCompleteOnRollback)
		p.RollbackRemaining = nullableInt(d.InstancesToUpdateOnRollback)
	}
	pk, err := w.q.PutRefresh(w.ctx, p)
	if err != nil {
		return err
	}
	if err = w.q.DeleteRefreshMembers(w.ctx, pk); err != nil {
		return err
	}
	if err = w.q.DeleteRefreshCheckpoints(w.ctx, pk); err != nil {
		return err
	}
	if err = w.q.DeleteRefreshAlarms(w.ctx, pk); err != nil {
		return err
	}
	for i, m := range v.Members {
		if err = w.q.PutRefreshMember(w.ctx, sqlcgen.PutRefreshMemberParams{RefreshPk: pk, Position: int64(i), InstanceID: m.InstanceID, Warm: m.Warm}); err != nil {
			return err
		}
	}
	for i, c := range v.Data.Preferences.CheckpointPercentages {
		if err = w.q.PutRefreshCheckpoint(w.ctx, sqlcgen.PutRefreshCheckpointParams{RefreshPk: pk, Position: int64(i), Percentage: int64(c)}); err != nil {
			return err
		}
	}
	if v.Data.Preferences.AlarmSpecification != nil {
		for i, a := range v.Data.Preferences.AlarmSpecification.Alarms {
			if err = w.q.PutRefreshAlarm(w.ctx, sqlcgen.PutRefreshAlarmParams{RefreshPk: pk, Position: int64(i), Name: string(a)}); err != nil {
				return err
			}
		}
	}
	return nil
}
