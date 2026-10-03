package xray

import (
	"stackd/storage/sqlite/xray/internal/sqlcgen"
	domain "stackd/storage/xray"
)

func traceRecord(row sqlcgen.XrayTrace) domain.TraceRecord {
	return domain.TraceRecord{Key: domain.TraceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.TraceID}, Start: row.StartTime, End: row.EndTime, Updated: row.Updated, Revision: row.Revision}
}

func (r reader) Trace(k domain.TraceKey) (domain.TraceRecord, error) {
	row, err := r.q.GetTrace(r.ctx, sqlcgen.GetTraceParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TraceID: k.ID})
	return traceRecord(row), missing(err)
}

func (w writer) PutTrace(v domain.TraceRecord) error {
	k := v.Key
	return w.q.PutTrace(w.ctx, sqlcgen.PutTraceParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TraceID: k.ID, StartTime: v.Start, EndTime: v.End, Updated: v.Updated, Revision: v.Revision})
}

func (r reader) Traces(selection domain.TraceSelection) ([]domain.TraceData, error) {
	start, end := selection.TimeBounds()
	params := sqlcgen.ListSelectedTracesParams{Partition: selection.Partition, AccountID: selection.AccountID, Region: selection.Region, Kind: int64(selection.Kind), StartSeconds: float64(start.Unix()) + float64(start.Nanosecond())/1e9, EndSeconds: float64(end.Unix()) + float64(end.Nanosecond())/1e9, ReceiptStart: start, ReceiptEnd: end}
	if selection.Group != nil {
		params.GroupID = selection.Group.ID
	}
	rows, err := r.q.ListSelectedTraces(r.ctx, params)
	if err != nil {
		return nil, err
	}
	result := make([]domain.TraceData, len(rows))
	if len(rows) == 0 {
		return result, nil
	}
	positions := make(map[string]int, len(rows))
	for i, row := range rows {
		result[i] = domain.TraceData{Record: traceRecord(row.XrayTrace), Segments: []domain.SegmentRecord{}, Membership: domain.GroupMembership{Version: row.GroupVersion, Admitted: row.GroupAdmitted.Time, AdmittedRevision: row.GroupAdmittedRevision}}
		positions[row.XrayTrace.TraceID] = i
	}
	segments, err := r.q.ListSelectedSegments(r.ctx, sqlcgen.ListSelectedSegmentsParams(params))
	if err != nil {
		return nil, err
	}
	for _, row := range segments {
		i := positions[row.TraceID]
		result[i].Segments = append(result[i].Segments, segment(row))
	}
	return result, nil
}

func groupRecord(row sqlcgen.XrayGroup) domain.GroupRecord {
	return domain.GroupRecord{Key: domain.GroupKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name, ID: row.ID}, FilterExpression: row.FilterExpression, Version: row.Version, Tags: map[string]string{}}
}

func (r reader) Group(k domain.GroupKey) (domain.GroupRecord, error) {
	row, err := r.q.GetGroup(r.ctx, sqlcgen.GetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID, Name: k.Name})
	if err != nil {
		return domain.GroupRecord{}, missing(err)
	}
	result := groupRecord(row)
	tags, err := r.q.ListGroupTags(r.ctx, sqlcgen.ListGroupTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GroupID: k.ID})
	if err != nil {
		return domain.GroupRecord{}, err
	}
	for _, tag := range tags {
		result.Tags[tag.Key] = tag.Value
	}
	return result, nil
}

func (r reader) Groups(scope domain.Scope) ([]domain.GroupRecord, error) {
	rows, err := r.q.ListGroups(r.ctx, sqlcgen.ListGroupsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	result := make([]domain.GroupRecord, len(rows))
	if len(rows) == 0 {
		return result, nil
	}
	positions := make(map[string]int, len(rows))
	for i, row := range rows {
		result[i] = groupRecord(row)
		positions[row.ID] = i
	}
	tags, err := r.q.ListScopeGroupTags(r.ctx, sqlcgen.ListScopeGroupTagsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		result[positions[tag.GroupID]].Tags[tag.Key] = tag.Value
	}
	return result, nil
}

func (w writer) PutGroup(v domain.GroupRecord) error {
	k := v.Key
	if err := w.q.PutGroup(w.ctx, sqlcgen.PutGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID, Name: k.Name, FilterExpression: v.FilterExpression, Version: v.Version}); err != nil {
		return err
	}
	if err := w.q.DeleteGroupTags(w.ctx, sqlcgen.DeleteGroupTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GroupID: k.ID}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutGroupTag(w.ctx, sqlcgen.PutGroupTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GroupID: k.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) AddGroupTrace(group domain.GroupKey, trace domain.TraceKey, membership domain.GroupMembership) (bool, error) {
	inserted, err := w.q.AddGroupTrace(w.ctx, sqlcgen.AddGroupTraceParams{Partition: group.Partition, AccountID: group.AccountID, Region: group.Region, GroupID: group.ID, TraceID: trace.ID, Version: membership.Version, Admitted: membership.Admitted, AdmittedRevision: membership.AdmittedRevision})
	return inserted != 0, err
}

func (w writer) DeleteGroup(k domain.GroupKey) error {
	return w.q.DeleteGroup(w.ctx, sqlcgen.DeleteGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
}
