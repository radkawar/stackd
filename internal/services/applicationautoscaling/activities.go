package applicationautoscaling

import (
	"context"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/applicationautoscaling"
)

const activityRetention = 6 * 7 * 24 * time.Hour

func (s *Service) describeScalingActivities(ctx context.Context, tx Transaction, in *api.DescribeScalingActivitiesInput) (*api.DescribeScalingActivitiesOutput, error) {
	key := TargetKey{Scope: scopeFor(ctx), Namespace: value(in.ServiceNamespace), ResourceID: value(in.ResourceId), Dimension: value(in.ScalableDimension)}
	if err := validateTargetFilter(key.Namespace, ""); err != nil {
		return nil, err
	}
	if key.Dimension != "" && key.ResourceID == "" {
		return nil, invalid("ResourceId must be specified when ScalableDimension is specified")
	}
	if key.ResourceID != "" && !validResource(key.Namespace, key.ResourceID, "") {
		return nil, invalid("Unsupported service namespace, resource type or scalable dimension")
	}
	include := in.IncludeNotScaledActivities != nil && bool(*in.IncludeNotScaledActivities)
	// Native continuations bind the resource, but permit dimension and
	// IncludeNotScaledActivities changes between pages.
	page, err := newListPage[ActivityCursor](listPageQuery{Operation: "DescribeScalingActivities", Key: TargetKey{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID}}, in.MaxResults, in.NextToken)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DescribeScalingActivities", "*", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeScalingActivitiesOutput{ScalingActivities: api.ScalingActivities{}}
	if page.limit == 0 {
		return out, nil
	}
	rows, err := tx.Activities(ActivityQuery{
		Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension,
		Since: s.clock.Now().Add(-activityRetention), IncludeNotScaled: include, From: page.token.Cursor, Limit: page.readLimit,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) > page.limit {
		out.NextToken = page.next(activityPosition(rows[page.limit]))
		rows = rows[:page.limit]
	}
	for _, row := range rows {
		out.ScalingActivities = append(out.ScalingActivities, row.Data)
	}
	return out, nil
}

func (s *Service) newActivity(key TargetKey, description, cause string, status api.ScalingActivityStatusCode) ActivityRecord {
	id := uuid.NewString()
	return ActivityRecord{
		Key: ActivityKey{Scope: key.Scope, ID: id},
		Data: api.ScalingActivity{
			ActivityId: new(api.ResourceId(id)), Description: new(api.XmlString(description)), Cause: new(api.XmlString(cause)),
			ServiceNamespace: new(api.ServiceNamespace(key.Namespace)), ResourceId: new(api.ResourceIdMaxLen1600(key.ResourceID)),
			ScalableDimension: new(api.ScalableDimension(key.Dimension)), StartTime: new(s.clock.Now().UTC().Truncate(time.Millisecond)),
			StatusCode: new(status),
		},
	}
}

func activityTarget(record ActivityRecord) TargetKey {
	return TargetKey{Scope: record.Key.Scope, Namespace: value(record.Data.ServiceNamespace), ResourceID: value(record.Data.ResourceId), Dimension: value(record.Data.ScalableDimension)}
}

func activityActive(data api.ScalingActivity) bool {
	return data.StatusCode != nil && (*data.StatusCode == api.ScalingActivityStatusCodePending || *data.StatusCode == api.ScalingActivityStatusCodeInProgress)
}

// Insertion reclaims expired history. Queries apply the same retention boundary
// even when the scope has had no new scaling work since the clock advanced.
func (s *Service) insertActivity(tx Transaction, record ActivityRecord) error {
	if err := tx.DeleteActivitiesBefore(record.Key.Scope, s.clock.Now().Add(-activityRetention)); err != nil {
		return err
	}
	return tx.PutActivity(record)
}

func (s *Service) recordNotScaled(tx Transaction, key TargetKey, cause string, reason api.NotScaledReason) error {
	previous, err := tx.Activities(ActivityQuery{
		Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension,
		Since: s.clock.Now().Add(-activityRetention), IncludeNotScaled: true, Limit: 1,
	})
	if err != nil {
		return err
	}
	// History, not a policy or current registration, owns native suppression.
	if len(previous) != 0 && len(previous[0].Data.NotScaledReasons) == 1 && value(previous[0].Data.NotScaledReasons[0].Code) == value(reason.Code) {
		return nil
	}
	status := api.ScalingActivityStatusCodeFailed
	if value(reason.Code) == "AlreadyAtDesiredCapacity" {
		status = api.ScalingActivityStatusCodeSuccessful
	}
	record := s.newActivity(key, "Attempting to scale due to alarm triggered", cause, status)
	record.Data.NotScaledReasons = api.NotScaledReasons{reason}
	return s.insertActivity(tx, record)
}
