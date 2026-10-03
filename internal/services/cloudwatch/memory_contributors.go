package cloudwatch

import (
	"cmp"
	"maps"
	"slices"
)

type alarmContributorKey struct {
	alarmID, contributorID string
}

func cloneAlarmContributorIdentity(v *AlarmContributorIdentity) *AlarmContributorIdentity {
	if v == nil {
		return nil
	}
	copy := *v
	copy.Attributes = maps.Clone(v.Attributes)
	return &copy
}

func cloneAlarmContributor(v AlarmContributorRecord) AlarmContributorRecord {
	v.Attributes = maps.Clone(v.Attributes)
	return v
}

func (r memoryReader) AlarmContributors(q AlarmContributorQuery) ([]AlarmContributorRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []AlarmContributorRecord{}
	if q.Limit <= 0 {
		return out, nil
	}
	for key, contributor := range r.state.alarmContributors {
		if key.alarmID == q.AlarmID && contributor.ID > q.AfterID {
			out = append(out, contributor)
		}
	}
	slices.SortFunc(out, func(a, b AlarmContributorRecord) int { return cmp.Compare(a.ID, b.ID) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	for i := range out {
		out[i] = cloneAlarmContributor(out[i])
	}
	return out, nil
}

func (w memoryWriter) PutAlarmContributor(alarmID string, contributor AlarmContributorRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := w.state.alarms[alarmID]; !exists {
		return ErrNotFound
	}
	w.state.alarmContributors[alarmContributorKey{alarmID, contributor.ID}] = cloneAlarmContributor(contributor)
	return nil
}

func (w memoryWriter) DeleteAlarmContributor(alarmID, contributorID string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.alarmContributors, alarmContributorKey{alarmID, contributorID})
	return nil
}
