package autoscaling

import (
	api "stackd/internal/awsapi/autoscaling"
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
)

func (r reader) hook(row sqlcgen.AsgHook) (domain.HookRecord, error) {
	out := domain.HookRecord{Ownership: row.Ownership, Key: domain.HookKey{GroupKey: groupKey(row.Partition, row.AccountID, row.Region, row.GroupName), Name: row.Name},
		GroupID: row.GroupID}
	out.Data.AutoScalingGroupName = stringPointer[api.XmlStringMaxLen255](row.DataAutoScalingGroupName)
	out.Data.DefaultResult = stringPointer[api.LifecycleActionResult](row.DataDefaultResult)
	out.Data.GlobalTimeout = intPointer[api.GlobalTimeout](row.DataGlobalTimeout)
	out.Data.HeartbeatTimeout = intPointer[api.HeartbeatTimeout](row.DataHeartbeatTimeout)
	out.Data.LifecycleHookName = stringPointer[api.AsciiStringMaxLen255](row.DataLifecycleHookName)
	out.Data.LifecycleTransition = stringPointer[api.LifecycleTransition](row.DataLifecycleTransition)
	out.Data.NotificationMetadata = stringPointer[api.AnyPrintableAsciiStringMaxLen4000](row.DataNotificationMetadata)
	out.Data.NotificationTargetARN = stringPointer[api.NotificationTargetResourceName](row.DataNotificationTargetArn)
	out.Data.RoleARN = stringPointer[api.XmlStringMaxLen255](row.DataRoleArn)
	return out, nil
}

func (w writer) PutHook(v domain.HookRecord) error {
	p := sqlcgen.PutHookParams{Ownership: v.Ownership, Partition: v.Key.Partition,
		AccountID: v.Key.AccountID,
		Region:    v.Key.Region,
		GroupName: v.Key.GroupKey.Name,
		Name:      v.Key.Name,
		GroupID:   v.GroupID}
	p.DataAutoScalingGroupName = nullableString(v.Data.AutoScalingGroupName)
	p.DataDefaultResult = nullableString(v.Data.DefaultResult)
	p.DataGlobalTimeout = nullableInt(v.Data.GlobalTimeout)
	p.DataHeartbeatTimeout = nullableInt(v.Data.HeartbeatTimeout)
	p.DataLifecycleHookName = nullableString(v.Data.LifecycleHookName)
	p.DataLifecycleTransition = nullableString(v.Data.LifecycleTransition)
	p.DataNotificationMetadata = nullableString(v.Data.NotificationMetadata)
	p.DataNotificationTargetArn = nullableString(v.Data.NotificationTargetARN)
	p.DataRoleArn = nullableString(v.Data.RoleARN)
	return w.q.PutHook(w.ctx, p)
}
