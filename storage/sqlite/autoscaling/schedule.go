package autoscaling

import (
	api "stackd/internal/awsapi/autoscaling"
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
)

func (r reader) schedule(row sqlcgen.AsgSchedule) (domain.ScheduleRecord, error) {
	out := domain.ScheduleRecord{
		Key:           domain.ScheduleKey{GroupKey: groupKey(row.Partition, row.AccountID, row.Region, row.GroupName), Name: row.Name},
		GroupID:       row.GroupID,
		NextDue:       row.NextDue.Time,
		OriginEventID: row.OriginEventID,
	}
	out.Data.AutoScalingGroupName = stringPointer[api.XmlStringMaxLen255](row.DataAutoScalingGroupName)
	out.Data.DesiredCapacity = intPointer[api.AutoScalingGroupDesiredCapacity](row.DataDesiredCapacity)
	out.Data.EndTime = timePointer(row.DataEndTime)
	out.Data.MaxSize = intPointer[api.AutoScalingGroupMaxSize](row.DataMaxSize)
	out.Data.MinSize = intPointer[api.AutoScalingGroupMinSize](row.DataMinSize)
	out.Data.Recurrence = stringPointer[api.XmlStringMaxLen255](row.DataRecurrence)
	out.Data.ScheduledActionARN = stringPointer[api.ResourceName](row.DataScheduledActionArn)
	out.Data.ScheduledActionName = stringPointer[api.XmlStringMaxLen255](row.DataScheduledActionName)
	out.Data.StartTime = timePointer(row.DataStartTime)
	out.Data.Time = timePointer(row.DataTime)
	out.Data.TimeZone = stringPointer[api.XmlStringMaxLen255](row.DataTimeZone)
	return out, nil
}

func (w writer) PutSchedule(v domain.ScheduleRecord) error {
	p := sqlcgen.PutScheduleParams{
		Partition:     v.Key.Partition,
		AccountID:     v.Key.AccountID,
		Region:        v.Key.Region,
		GroupName:     v.Key.GroupKey.Name,
		Name:          v.Key.Name,
		GroupID:       v.GroupID,
		NextDue:       deadline(v.NextDue),
		OriginEventID: v.OriginEventID,
	}
	p.DataAutoScalingGroupName = nullableString(v.Data.AutoScalingGroupName)
	p.DataDesiredCapacity = nullableInt(v.Data.DesiredCapacity)
	p.DataEndTime = nullableTime(v.Data.EndTime)
	p.DataMaxSize = nullableInt(v.Data.MaxSize)
	p.DataMinSize = nullableInt(v.Data.MinSize)
	p.DataRecurrence = nullableString(v.Data.Recurrence)
	p.DataScheduledActionArn = nullableString(v.Data.ScheduledActionARN)
	p.DataScheduledActionName = nullableString(v.Data.ScheduledActionName)
	p.DataStartTime = nullableTime(v.Data.StartTime)
	p.DataTime = nullableTime(v.Data.Time)
	p.DataTimeZone = nullableString(v.Data.TimeZone)
	return w.q.PutSchedule(w.ctx, p)
}
