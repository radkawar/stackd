package applicationautoscaling

import (
	"cmp"
	"slices"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
)

func cloneActivity(record ActivityRecord) ActivityRecord {
	record.Data = api.CloneScalingActivity(record.Data)
	return record
}

func activityPosition(record ActivityRecord) ActivityCursor {
	return ActivityCursor{StartTime: *record.Data.StartTime, Sequence: record.Sequence}
}

func compareActivityPositions(a, b ActivityCursor) int {
	return cmp.Or(b.StartTime.Compare(a.StartTime), cmp.Compare(b.Sequence, a.Sequence))
}

func (r memoryReader) Activities(query ActivityQuery) ([]ActivityRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ActivityRecord{}
	for key, record := range r.state.activities {
		data := &record.Data
		if key.Scope != query.Scope || value(data.ServiceNamespace) != query.Namespace || query.ResourceID != "" && value(data.ResourceId) != query.ResourceID || query.Dimension != "" && value(data.ScalableDimension) != query.Dimension {
			continue
		}
		if data.StartTime.Before(query.Since) || !query.IncludeNotScaled && len(data.NotScaledReasons) != 0 {
			continue
		}
		if query.From != nil && compareActivityPositions(activityPosition(record), *query.From) < 0 {
			continue
		}
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b ActivityRecord) int {
		return compareActivityPositions(activityPosition(a), activityPosition(b))
	})
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[:query.Limit:query.Limit]
	}
	for i := range out {
		out[i] = cloneActivity(out[i])
	}
	return out, nil
}

func (r memoryReader) PendingActivities(key TargetKey) ([]ActivityRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ActivityRecord{}
	for _, record := range r.state.pendingActivities {
		if activityTarget(record) == key {
			out = append(out, cloneActivity(record))
		}
	}
	slices.SortFunc(out, func(a, b ActivityRecord) int {
		return compareActivityPositions(activityPosition(a), activityPosition(b))
	})
	return out, nil
}

func (r memoryReader) NextPendingActivity() (ActivityRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ActivityRecord{}, false, err
	}
	var next ActivityRecord
	found := false
	for _, record := range r.state.pendingActivities {
		if *record.Data.StatusCode != api.ScalingActivityStatusCodePending {
			continue
		}
		if !found || compareActivityPositions(activityPosition(record), activityPosition(next)) > 0 {
			next, found = record, true
		}
	}
	return cloneActivity(next), found, nil
}

func (w memoryWriter) PutActivity(record ActivityRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if previous, exists := w.state.activities[record.Key]; exists {
		record.Sequence = previous.Sequence
	} else {
		w.state.activitySequence++
		record.Sequence = w.state.activitySequence
	}
	record = cloneActivity(record)
	w.state.activities[record.Key] = record
	if activityActive(record.Data) {
		w.state.pendingActivities[record.Key] = record
	} else {
		delete(w.state.pendingActivities, record.Key)
	}
	return nil
}

func (w memoryWriter) DeleteActivitiesBefore(scope Scope, before time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key, record := range w.state.activities {
		if key.Scope == scope && record.Data.StartTime.Before(before) {
			delete(w.state.activities, key)
			delete(w.state.pendingActivities, key)
		}
	}
	return nil
}
