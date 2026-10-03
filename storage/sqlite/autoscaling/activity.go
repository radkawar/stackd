package autoscaling

import (
	api "stackd/internal/awsapi/autoscaling"
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
)

func (r reader) activity(row sqlcgen.AsgActivity) (domain.ActivityRecord, error) {
	out := domain.ActivityRecord{
		Key:                  domain.ActivityKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ActivityID},
		Group:                groupKey(row.GroupPartition, row.GroupAccountID, row.GroupRegion, row.GroupName),
		GroupID:              row.GroupID,
		Kind:                 row.Kind,
		InstanceID:           row.InstanceID,
		SubnetID:             row.SubnetID,
		OriginEventID:        row.OriginEventID,
		RetryAt:              row.RetryAt.Time,
		InstanceWarmup:       intPointer[int32](row.InstanceWarmup),
		ProtectedFromScaleIn: row.ProtectedFromScaleIn,
		WarmPoolState:        row.WarmPoolState,
	}
	out.Data.ActivityId = stringPointer[api.XmlString](row.DataActivityID)
	out.Data.AutoScalingGroupARN = stringPointer[api.ResourceName](row.DataAutoScalingGroupArn)
	out.Data.AutoScalingGroupName = stringPointer[api.XmlStringMaxLen255](row.DataAutoScalingGroupName)
	out.Data.AutoScalingGroupState = stringPointer[api.AutoScalingGroupState](row.DataAutoScalingGroupState)
	out.Data.Cause = stringPointer[api.XmlStringMaxLen1023](row.DataCause)
	out.Data.Description = stringPointer[api.XmlString](row.DataDescription)
	out.Data.Details = stringPointer[api.XmlString](row.DataDetails)
	out.Data.EndTime = timePointer(row.DataEndTime)
	out.Data.Progress = intPointer[api.Progress](row.DataProgress)
	out.Data.StartTime = timePointer(row.DataStartTime)
	out.Data.StatusCode = stringPointer[api.ScalingActivityStatusCode](row.DataStatusCode)
	out.Data.StatusMessage = stringPointer[api.XmlStringMaxLen255](row.DataStatusMessage)
	out.LaunchTemplate.LaunchTemplateId = stringPointer[api.XmlStringMaxLen255](row.LaunchTemplateLaunchTemplateID)
	out.LaunchTemplate.LaunchTemplateName = stringPointer[api.LaunchTemplateName](row.LaunchTemplateLaunchTemplateName)
	out.LaunchTemplate.Version = stringPointer[api.XmlStringMaxLen255](row.LaunchTemplateVersion)
	if row.HasLaunchTags {
		tags, err := r.q.ListActivityLaunchTags(r.ctx, row.ActivityPk)
		if err != nil {
			return domain.ActivityRecord{}, err
		}
		out.LaunchTags = make(api.TagDescriptionList, 0, len(tags))
		for _, tag := range tags {
			out.LaunchTags = append(out.LaunchTags, api.TagDescription{
				Key:               stringPointer[api.TagKey](tag.Key),
				Value:             stringPointer[api.TagValue](tag.Value),
				ResourceId:        stringPointer[api.XmlString](tag.ResourceID),
				ResourceType:      stringPointer[api.XmlString](tag.ResourceType),
				PropagateAtLaunch: boolPointer[api.PropagateAtLaunch](tag.PropagateAtLaunch),
			})
		}
	}
	return out, nil
}

func (w writer) PutActivity(v domain.ActivityRecord) error {
	p := sqlcgen.PutActivityParams{
		Partition:            v.Key.Partition,
		AccountID:            v.Key.AccountID,
		Region:               v.Key.Region,
		ActivityID:           v.Key.ID,
		GroupPartition:       v.Group.Partition,
		GroupAccountID:       v.Group.AccountID,
		GroupRegion:          v.Group.Region,
		GroupName:            v.Group.Name,
		GroupID:              v.GroupID,
		Kind:                 v.Kind,
		InstanceID:           v.InstanceID,
		SubnetID:             v.SubnetID,
		OriginEventID:        v.OriginEventID,
		RetryAt:              deadline(v.RetryAt),
		InstanceWarmup:       nullableInt(v.InstanceWarmup),
		HasLaunchTags:        v.LaunchTags != nil,
		ProtectedFromScaleIn: v.ProtectedFromScaleIn,
		WarmPoolState:        v.WarmPoolState,
	}
	p.DataActivityID = nullableString(v.Data.ActivityId)
	p.DataAutoScalingGroupArn = nullableString(v.Data.AutoScalingGroupARN)
	p.DataAutoScalingGroupName = nullableString(v.Data.AutoScalingGroupName)
	p.DataAutoScalingGroupState = nullableString(v.Data.AutoScalingGroupState)
	p.DataCause = nullableString(v.Data.Cause)
	p.DataDescription = nullableString(v.Data.Description)
	p.DataDetails = nullableString(v.Data.Details)
	p.DataEndTime = nullableTime(v.Data.EndTime)
	p.DataProgress = nullableInt(v.Data.Progress)
	p.DataStartTime = nullableTime(v.Data.StartTime)
	p.DataStatusCode = nullableString(v.Data.StatusCode)
	p.DataStatusMessage = nullableString(v.Data.StatusMessage)
	p.LaunchTemplateLaunchTemplateID = nullableString(v.LaunchTemplate.LaunchTemplateId)
	p.LaunchTemplateLaunchTemplateName = nullableString(v.LaunchTemplate.LaunchTemplateName)
	p.LaunchTemplateVersion = nullableString(v.LaunchTemplate.Version)
	activityPK, err := w.q.PutActivity(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.q.DeleteActivityLaunchTags(w.ctx, activityPK); err != nil {
		return err
	}
	for position, tag := range v.LaunchTags {
		if err := w.q.InsertActivityLaunchTag(w.ctx, sqlcgen.InsertActivityLaunchTagParams{
			ActivityPk: activityPK, Position: int64(position),
			Key: nullableString(tag.Key), Value: nullableString(tag.Value),
			ResourceID: nullableString(tag.ResourceId), ResourceType: nullableString(tag.ResourceType),
			PropagateAtLaunch: nullableBool(tag.PropagateAtLaunch),
		}); err != nil {
			return err
		}
	}
	return nil
}
