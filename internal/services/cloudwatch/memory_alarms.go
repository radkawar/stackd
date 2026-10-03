package cloudwatch

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

func cloneAlarmPointer[T any](v *T) *T {
	if v == nil {
		return nil
	}
	copy := *v
	return &copy
}

func cloneAlarmMetric(v *AlarmMetricStat) *AlarmMetricStat {
	if v == nil {
		return nil
	}
	copy := *v
	copy.Dimensions = slices.Clone(v.Dimensions)
	return &copy
}

func cloneAlarm(v AlarmRecord) AlarmRecord {
	v.Description = cloneAlarmPointer(v.Description)
	v.State.Reason = cloneAlarmPointer(v.State.Reason)
	v.NextEvaluation = cloneAlarmPointer(v.NextEvaluation)
	v.SuppressionUntil = cloneAlarmPointer(v.SuppressionUntil)
	v.Actions.Alarm = slices.Clone(v.Actions.Alarm)
	v.Actions.OK = slices.Clone(v.Actions.OK)
	v.Actions.InsufficientData = slices.Clone(v.Actions.InsufficientData)
	v.Tags = maps.Clone(v.Tags)
	if v.Metric != nil {
		config := *v.Metric
		config.Metric = cloneAlarmMetric(config.Metric)
		config.DatapointsToAlarm = cloneAlarmPointer(config.DatapointsToAlarm)
		config.Queries = slices.Clone(config.Queries)
		for i := range config.Queries {
			q := &config.Queries[i]
			q.Metric = cloneAlarmMetric(q.Metric)
			q.Label = cloneAlarmPointer(q.Label)
			q.Period = cloneAlarmPointer(q.Period)
			q.ReturnData = cloneAlarmPointer(q.ReturnData)
		}
		v.Metric = &config
	}
	if v.Composite != nil {
		config := *v.Composite
		config.Children = slices.Clone(config.Children)
		v.Composite = &config
	}
	return v
}

func cloneAlarmHistory(v AlarmHistoryRecord) AlarmHistoryRecord {
	v.Contributor = cloneAlarmContributorIdentity(v.Contributor)
	return v
}

func cloneAlarmAction(v AlarmActionRecord) AlarmActionRecord {
	v.Payload = slices.Clone(v.Payload)
	v.Contributor = cloneAlarmContributorIdentity(v.Contributor)
	return v
}

func (r memoryReader) Alarm(key AlarmKey) (AlarmRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AlarmRecord{}, err
	}
	id, ok := r.state.alarmNames[key]
	if !ok {
		return AlarmRecord{}, ErrNotFound
	}
	return cloneAlarm(r.state.alarms[id]), nil
}

func (r memoryReader) AlarmByID(id string) (AlarmRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AlarmRecord{}, err
	}
	alarm, ok := r.state.alarms[id]
	if !ok {
		return AlarmRecord{}, ErrNotFound
	}
	return cloneAlarm(alarm), nil
}

func alarmHasActionPrefix(actions AlarmActions, prefix string) bool {
	for _, targets := range [][]string{actions.Alarm, actions.OK, actions.InsufficientData} {
		for _, target := range targets {
			if strings.HasPrefix(target, prefix) {
				return true
			}
		}
	}
	return false
}

func (r memoryReader) Alarms(q AlarmQuery) ([]AlarmRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []AlarmRecord{}
	if q.Limit <= 0 {
		return out, nil
	}
	for _, alarm := range r.state.alarms {
		if alarm.Key.Scope != q.Scope || alarm.Key.Name < q.FromName || !strings.HasPrefix(alarm.Key.Name, q.Prefix) {
			continue
		}
		if len(q.Names) != 0 && !slices.Contains(q.Names, alarm.Key.Name) || len(q.Types) != 0 && !slices.Contains(q.Types, alarm.Type()) {
			continue
		}
		if q.State != "" && alarm.State.Value != q.State || q.ActionPrefix != "" && !alarmHasActionPrefix(alarm.Actions, q.ActionPrefix) {
			continue
		}
		if q.ParentOf != "" && (alarm.Composite == nil || !slices.Contains(alarm.Composite.Children, q.ParentOf)) {
			continue
		}
		if q.SuppressedBy != "" && (alarm.Composite == nil || alarm.Composite.Suppressor != q.SuppressedBy && alarm.Composite.Suppressor != (AlarmKey{Scope: q.Scope, Name: q.SuppressedBy}).ARN()) {
			continue
		}
		out = append(out, alarm)
	}
	slices.SortFunc(out, func(a, b AlarmRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	for i := range out {
		out[i] = cloneAlarm(out[i])
	}
	return out, nil
}

func compareAlarmTimeID(at time.Time, id string, otherAt time.Time, otherID string) int {
	if c := at.Compare(otherAt); c != 0 {
		return c
	}
	return cmp.Compare(id, otherID)
}

func (r memoryReader) AlarmHistory(q AlarmHistoryQuery) ([]AlarmHistoryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []AlarmHistoryRecord{}
	if q.Limit <= 0 {
		return out, nil
	}
	for _, h := range r.state.alarmHistory {
		if (h.Contributor != nil) != q.Contributors {
			continue
		}
		if h.Key.Scope != q.Scope || q.Name != "" && h.Key.Name != q.Name || q.Type != "" && h.Type != q.Type {
			continue
		}
		if q.ContributorID != "" && (h.Contributor == nil || h.Contributor.ID != q.ContributorID) {
			continue
		}
		if len(q.AlarmTypes) != 0 && !slices.Contains(q.AlarmTypes, h.AlarmType) {
			continue
		}
		if !q.Start.IsZero() && h.At.Before(q.Start) || !q.End.IsZero() && h.At.After(q.End) {
			continue
		}
		if q.AfterAt != nil {
			c := compareAlarmTimeID(h.At, h.ID, *q.AfterAt, q.AfterID)
			if !q.Descending && c <= 0 || q.Descending && c >= 0 {
				continue
			}
		}
		out = append(out, h)
	}
	slices.SortFunc(out, func(a, b AlarmHistoryRecord) int {
		c := compareAlarmTimeID(a.At, a.ID, b.At, b.ID)
		if q.Descending {
			return -c
		}
		return c
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	for i := range out {
		out[i] = cloneAlarmHistory(out[i])
	}
	return out, nil
}

func (r memoryReader) NextAlarmEvaluation() (scheduler.Job, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for _, alarm := range r.state.alarms {
		due, scheduled := alarm.EvaluationDeadline()
		if !scheduled {
			continue
		}
		job := scheduler.Job{Key: alarm.ID, Version: alarm.Version, Due: due}
		if !found || scheduler.Compare(job, next) < 0 {
			next, found = job, true
		}
	}
	return next, found, nil
}

func (r memoryReader) AlarmAction(id string) (AlarmActionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AlarmActionRecord{}, err
	}
	action, ok := r.state.alarmActions[id]
	if !ok {
		return AlarmActionRecord{}, ErrNotFound
	}
	return cloneAlarmAction(action), nil
}

func (r memoryReader) NextAlarmAction() (scheduler.Job, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for _, action := range r.state.alarmActions {
		job := scheduler.Job{Key: action.ID, Version: action.Version, Due: action.Due}
		if !found || scheduler.Compare(job, next) < 0 {
			next, found = job, true
		}
	}
	return next, found, nil
}

func (w memoryWriter) PutAlarm(alarm AlarmRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if id, exists := w.state.alarmNames[alarm.Key]; exists && id != alarm.ID {
		return fmt.Errorf("CloudWatch alarm name already owned: %s", alarm.Key.Name)
	}
	if previous, exists := w.state.alarms[alarm.ID]; exists && previous.Key != alarm.Key {
		delete(w.state.alarmNames, previous.Key)
	}
	w.state.alarms[alarm.ID] = cloneAlarm(alarm)
	w.state.alarmNames[alarm.Key] = alarm.ID
	return nil
}

func (w memoryWriter) UpdateAlarmEvaluation(alarm AlarmRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	current, exists := w.state.alarms[alarm.ID]
	if !exists {
		return ErrNotFound
	}
	current.Version = alarm.Version
	current.State = alarm.State
	current.State.Reason = cloneAlarmPointer(alarm.State.Reason)
	current.NextEvaluation = cloneAlarmPointer(alarm.NextEvaluation)
	current.EvaluationOrigin = alarm.EvaluationOrigin
	current.SuppressionPhase = alarm.SuppressionPhase
	current.SuppressionReason = alarm.SuppressionReason
	current.SuppressionUntil = cloneAlarmPointer(alarm.SuppressionUntil)
	w.state.alarms[alarm.ID] = current
	return nil
}

func (w memoryWriter) DeleteAlarm(key AlarmKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if id, exists := w.state.alarmNames[key]; exists {
		delete(w.state.alarms, id)
		delete(w.state.alarmNames, key)
		for contributorKey := range w.state.alarmContributors {
			if contributorKey.alarmID == id {
				delete(w.state.alarmContributors, contributorKey)
			}
		}
	}
	return nil
}

func (w memoryWriter) AppendAlarmHistory(history AlarmHistoryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, exists := w.state.alarmHistory[history.ID]; exists {
		return fmt.Errorf("CloudWatch alarm history ID already exists: %s", history.ID)
	}
	w.state.alarmHistory[history.ID] = cloneAlarmHistory(history)
	return nil
}

func (w memoryWriter) PutAlarmAction(action AlarmActionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.alarmActions[action.ID] = cloneAlarmAction(action)
	return nil
}

func (w memoryWriter) DeleteAlarmAction(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.alarmActions, id)
	return nil
}

func (w memoryWriter) ExpireAlarmHistory(scope Scope, cutoff time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for id, history := range w.state.alarmHistory {
		if history.Key.Scope == scope && history.At.Before(cutoff) {
			delete(w.state.alarmHistory, id)
		}
	}
	return nil
}
