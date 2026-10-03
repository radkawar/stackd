package resourcegroups

import (
	api "stackd/internal/awsapi/resourcegroups"
	domain "stackd/storage/resourcegroups"
	"stackd/storage/sqlite/resourcegroups/internal/sqlcgen"
	"time"
)

func (r reader) TagSyncTasks() ([]domain.TagSyncTask, error) {
	rows, err := r.q.ListTagSyncTasks(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.TagSyncTask, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.TagSyncTask{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, GroupARN: row.GroupArn, GroupName: row.GroupName, RoleARN: row.RoleArn, Query: api.ResourceQuery{Type: new(api.QueryType(row.QueryType)), Query: new(api.Query(row.QueryString))}, TagKey: row.TagKey, TagValue: row.TagValue, UsesTag: row.UsesTag != 0, Status: row.Status, ErrorMessage: row.ErrorMessage, Created: time.Unix(0, row.Created).UTC(), NextCheck: readTime(row.NextCheck), Version: uint64(row.Version)})
	}
	return out, nil
}
func (w writer) PutTagSyncTask(t domain.TagSyncTask) error {
	return w.q.PutTagSyncTask(w.ctx, sqlcgen.PutTagSyncTaskParams{Arn: t.ARN, GroupArn: t.GroupARN, Partition: t.Partition, AccountID: t.AccountID, Region: t.Region, GroupName: t.GroupName, RoleArn: t.RoleARN, QueryType: storeString(t.Query.Type).String, QueryString: storeString(t.Query.Query).String, TagKey: t.TagKey, TagValue: t.TagValue, UsesTag: flag(t.UsesTag), Status: t.Status, ErrorMessage: t.ErrorMessage, Created: t.Created.UnixNano(), NextCheck: storeTime(t.NextCheck), Version: int64(t.Version)})
}
func (w writer) DeleteTagSyncTask(arn string) error { return w.q.DeleteTagSyncTask(w.ctx, arn) }
func (r reader) AppliedMemberships(arn string) ([]domain.AppliedMembership, error) {
	rows, err := r.q.ListAppliedMemberships(r.ctx, arn)
	if err != nil {
		return nil, err
	}
	out := make([]domain.AppliedMembership, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.AppliedMembership{TaskARN: row.TaskArn, ResourceARN: row.ResourceArn, ResourceType: row.ResourceType, Incarnation: row.Incarnation, AppliedAt: time.Unix(0, row.AppliedAt).UTC()})
	}
	return out, nil
}
func (w writer) PutAppliedMembership(m domain.AppliedMembership) error {
	return w.q.PutAppliedMembership(w.ctx, sqlcgen.PutAppliedMembershipParams{TaskArn: m.TaskARN, ResourceArn: m.ResourceARN, ResourceType: m.ResourceType, Incarnation: m.Incarnation, AppliedAt: m.AppliedAt.UnixNano()})
}
func (w writer) DeleteAppliedMembership(task, arn string) error {
	return w.q.DeleteAppliedMembership(w.ctx, sqlcgen.DeleteAppliedMembershipParams{TaskArn: task, ResourceArn: arn})
}
func flag(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func (r reader) LifecycleAccounts() ([]domain.LifecycleAccount, error) {
	rows, err := r.q.ListLifecycleAccounts(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.LifecycleAccount, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.LifecycleAccount{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Desired: row.Desired, Status: row.Status, Message: row.Message, Initialized: row.Initialized != 0, NextCheck: readTime(row.NextCheck), Version: uint64(row.Version)})
	}
	return out, nil
}
func (w writer) PutLifecycleAccount(a domain.LifecycleAccount) error {
	return w.q.PutLifecycleAccount(w.ctx, sqlcgen.PutLifecycleAccountParams{Partition: a.Partition, AccountID: a.AccountID, Region: a.Region, Desired: a.Desired, Status: a.Status, Message: a.Message, Initialized: flag(a.Initialized), NextCheck: storeTime(a.NextCheck), Version: int64(a.Version)})
}
func (r reader) LifecycleSnapshots(scope domain.Scope) ([]domain.LifecycleSnapshot, error) {
	rows, err := r.q.ListLifecycleSnapshots(r.ctx, sqlcgen.ListLifecycleSnapshotsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.LifecycleSnapshot, 0, len(rows))
	for _, row := range rows {
		g := domain.Group{Scope: scope, ARN: row.GroupArn, Name: row.Name, Description: row.Description, Incarnation: row.Incarnation, Created: readTime(row.Created), ManagedType: row.ManagedType, ApplicationARN: row.ApplicationArn, SourceARN: row.SourceArn, SourceName: row.SourceName, ParentARN: row.ParentArn}
		if row.QueryType.Valid {
			g.Query = &api.ResourceQuery{Type: readString[api.QueryType](row.QueryType), Query: readString[api.Query](row.QueryString)}
		}
		snapshot := domain.LifecycleSnapshot{Group: g, Sequence: uint64(row.Sequence)}
		members, err := r.q.ListLifecycleMembers(r.ctx, g.ARN)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			snapshot.Members = append(snapshot.Members, domain.LifecycleMember{ARN: m.ResourceArn, Type: m.ResourceType, Incarnation: m.Incarnation})
		}
		out = append(out, snapshot)
	}
	return out, nil
}
func (w writer) PutLifecycleSnapshot(s domain.LifecycleSnapshot) error {
	g := s.Group
	row := sqlcgen.PutLifecycleSnapshotParams{GroupArn: g.ARN, Partition: g.Partition, AccountID: g.AccountID, Region: g.Region, Name: g.Name, Description: g.Description, Incarnation: g.Incarnation, Created: storeTime(g.Created), ManagedType: g.ManagedType, ApplicationArn: g.ApplicationARN, SourceArn: g.SourceARN, SourceName: g.SourceName, ParentArn: g.ParentARN, Sequence: int64(s.Sequence)}
	if g.Query != nil {
		row.QueryType = storeString(g.Query.Type)
		row.QueryString = storeString(g.Query.Query)
	}
	if err := w.q.PutLifecycleSnapshot(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteLifecycleMembers(w.ctx, g.ARN); err != nil {
		return err
	}
	for _, m := range s.Members {
		if err := w.q.PutLifecycleMember(w.ctx, sqlcgen.PutLifecycleMemberParams{GroupArn: g.ARN, ResourceArn: m.ARN, ResourceType: m.Type, Incarnation: m.Incarnation}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteLifecycleSnapshot(arn string) error {
	return w.q.DeleteLifecycleSnapshot(w.ctx, arn)
}
