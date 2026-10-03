package applicationautoscaling

import (
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
	domain "stackd/storage/applicationautoscaling"
	"stackd/storage/sqlite/applicationautoscaling/internal/sqlcgen"
)

func (r reader) Activities(query domain.ActivityQuery) ([]domain.ActivityRecord, error) {
	var from domain.ActivityCursor
	if query.From != nil {
		from = *query.From
	}
	rows, err := r.q.ListActivities(r.ctx, sqlcgen.ListActivitiesParams{
		Partition: query.Partition, AccountID: query.AccountID, Region: query.Region,
		Namespace: query.Namespace, FilterResourceID: query.ResourceID, FilterDimension: query.Dimension,
		Since: query.Since.UTC(), IncludeNotScaled: flag(query.IncludeNotScaled),
		FromTime: from.StartTime.UTC(), FromSequence: from.Sequence, RowLimit: rowLimit(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	return r.activities(rows)
}

func (r reader) PendingActivities(key domain.TargetKey) ([]domain.ActivityRecord, error) {
	rows, err := r.q.ListPendingActivities(r.ctx, sqlcgen.ListPendingActivitiesParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension,
	})
	if err != nil {
		return nil, err
	}
	return r.activities(rows)
}

func (r reader) NextPendingActivity() (domain.ActivityRecord, bool, error) {
	rows, err := r.q.NextPendingActivity(r.ctx)
	if err != nil || len(rows) == 0 {
		return domain.ActivityRecord{}, false, err
	}
	records, err := r.activities(rows)
	if err != nil {
		return domain.ActivityRecord{}, false, err
	}
	return records[0], true, nil
}

func (r reader) activities(rows []sqlcgen.AasActivity) ([]domain.ActivityRecord, error) {
	out := make([]domain.ActivityRecord, 0, len(rows))
	for _, row := range rows {
		record := domain.ActivityRecord{
			Key:      domain.ActivityKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ActivityID},
			Sequence: row.ActivityPk, PolicyName: row.PolicyName, From: int32(row.CapacityFrom), To: int32(row.CapacityTo),
			OriginEventID: row.OriginEventID,
			Data: api.ScalingActivity{
				ActivityId: new(api.ResourceId(row.ActivityID)), Cause: new(api.XmlString(row.Cause)),
				Description: new(api.XmlString(row.Description)), Details: stringPointer[api.XmlString](row.Details),
				StartTime: new(row.StartTime), EndTime: timePointer(row.EndTime),
				ServiceNamespace: new(api.ServiceNamespace(row.Namespace)), ResourceId: new(api.ResourceIdMaxLen1600(row.ResourceID)),
				ScalableDimension: new(api.ScalableDimension(row.Dimension)), StatusCode: new(api.ScalingActivityStatusCode(row.StatusCode)),
				StatusMessage: stringPointer[api.XmlString](row.StatusMessage),
			},
		}
		reasons, err := r.q.ListActivityReasons(r.ctx, row.ActivityPk)
		if err != nil {
			return nil, err
		}
		for _, reason := range reasons {
			record.Data.NotScaledReasons = append(record.Data.NotScaledReasons, api.NotScaledReason{
				Code: new(api.XmlString(reason.Code)), CurrentCapacity: intPointer[api.ResourceCapacity](reason.CurrentCapacity),
				MinCapacity: intPointer[api.ResourceCapacity](reason.MinCapacity), MaxCapacity: intPointer[api.ResourceCapacity](reason.MaxCapacity),
			})
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutActivity(record domain.ActivityRecord) error {
	key, data := record.Key, record.Data
	pk, err := w.q.PutActivity(w.ctx, sqlcgen.PutActivityParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ActivityID: key.ID,
		Namespace: string(*data.ServiceNamespace), ResourceID: string(*data.ResourceId), Dimension: string(*data.ScalableDimension),
		Cause: string(*data.Cause), Description: string(*data.Description), Details: nullableString(data.Details),
		StartTime: data.StartTime.UTC(), EndTime: nullableTime(data.EndTime),
		StatusCode: string(*data.StatusCode), StatusMessage: nullableString(data.StatusMessage),
		PolicyName: record.PolicyName, CapacityFrom: int64(record.From), CapacityTo: int64(record.To),
		OriginEventID: record.OriginEventID,
	})
	if err != nil {
		return err
	}
	if err := w.q.DeleteActivityReasons(w.ctx, pk); err != nil {
		return err
	}
	for i, reason := range data.NotScaledReasons {
		if err := w.q.PutActivityReason(w.ctx, sqlcgen.PutActivityReasonParams{
			ActivityPk: pk, Position: int64(i), Code: string(*reason.Code),
			CurrentCapacity: nullableInt(reason.CurrentCapacity), MinCapacity: nullableInt(reason.MinCapacity), MaxCapacity: nullableInt(reason.MaxCapacity),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteActivitiesBefore(scope domain.Scope, before time.Time) error {
	return w.q.DeleteActivitiesBefore(w.ctx, sqlcgen.DeleteActivitiesBeforeParams{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, BeforeTime: before.UTC(),
	})
}
