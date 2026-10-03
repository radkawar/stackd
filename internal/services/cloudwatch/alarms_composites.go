package cloudwatch

import (
	"github.com/google/uuid"
	"slices"
	"time"

	"stackd/internal/awswire"
)

// Composite evaluation reads its staged component, not partially committed
// resource state. A cycle stops at the repeated dependency in the active path;
// a later independent path may still reevaluate a shared downstream alarm.
type alarmEvaluationView struct {
	Reader
	alarms map[AlarmKey]AlarmRecord
}

func (r alarmEvaluationView) Alarm(key AlarmKey) (AlarmRecord, error) {
	if alarm, ok := r.alarms[key]; ok {
		return alarm, nil
	}
	return r.Reader.Alarm(key)
}

func (s *Service) evaluateCompositeAlarms(tx Transaction, root AlarmRecord, now time.Time) *awswire.Error {
	original := map[AlarmKey]AlarmRecord{}
	staged := map[AlarmKey]AlarmRecord{}
	order := []AlarmKey{}
	active := map[string]bool{}
	view := alarmEvaluationView{Reader: tx, alarms: staged}
	var visit func(AlarmRecord) *awswire.Error
	visit = func(alarm AlarmRecord) *awswire.Error {
		if current, ok := staged[alarm.Key]; ok {
			alarm = current
		} else {
			original[alarm.Key] = alarm
			order = append(order, alarm.Key)
		}
		alarm.NextEvaluation = nil
		state, reason, data, w := evaluateCompositeAlarm(view, alarm)
		if w != nil {
			return w
		}
		changed := state != alarm.State.Value
		if changed {
			alarm.State = AlarmState{Value: state, Reason: new(reason), ReasonData: data, Updated: now, Transitioned: now}
			before := original[alarm.Key]
			if state == before.State.Value {
				// Native cyclic propagation can return to the committed value within one
				// evaluation: retain its transition time and reason data, not a fictional
				// intermediate transition/history entry.
				alarm.State.Transitioned, alarm.State.ReasonData = before.State.Transitioned, before.State.ReasonData
				alarm.State.Origin = before.State.Origin
			}
		}
		staged[alarm.Key] = alarm
		if !changed {
			return nil
		}
		parents, err := tx.Alarms(AlarmQuery{Scope: alarm.Key.Scope, ParentOf: alarm.Key.Name, Limit: 151})
		if err != nil {
			return wireError(err)
		}
		for _, parent := range parents {
			if active[parent.ID] {
				continue
			}
			active[parent.ID] = true
			w := visit(parent)
			delete(active, parent.ID)
			if w != nil {
				return w
			}
		}
		return nil
	}
	// The initiating evaluation is outside its downstream dependency walk. This
	// permits feedback to settle the root once without following the cycle again.
	if w := visit(root); w != nil {
		return w
	}
	for _, key := range order {
		alarm := staged[key]
		if alarm.State.Value != original[key].State.Value {
			alarm.State.Origin = AlarmOrigin{EventID: uuid.NewString(), RequestID: root.EvaluationOrigin.RequestID}
			if w := s.beginAlarmSuppression(view, &alarm, now); w != nil {
				return w
			}
		}
		alarm.Version = original[key].Version + 1
		staged[key] = alarm
		if err := tx.UpdateAlarmEvaluation(alarm); err != nil {
			return wireError(err)
		}
	}
	// State and emitted effects share the transaction. Only final transitions
	// produce history/actions; suppressors observe the complete component.
	for _, key := range order {
		alarm := staged[key]
		if alarm.State.Value == original[key].State.Value {
			continue
		}
		if w := s.recordAlarmState(tx, original[key], alarm, root.EvaluationOrigin); w != nil {
			return w
		}
	}
	for _, key := range order {
		alarm := staged[key]
		if alarm.State.Value == original[key].State.Value {
			continue
		}
		if w := s.notifyAlarmSuppressed(tx, alarm); w != nil {
			return w
		}
	}
	s.jobs.Wake()
	return nil
}

type compositeTrigger struct {
	ARN   string `json:"arn"`
	State struct {
		Value     string `json:"value"`
		Timestamp string `json:"timestamp"`
	} `json:"state"`
}

func evaluateCompositeAlarm(r Reader, alarm AlarmRecord) (string, string, string, *awswire.Error) {
	rule, _, w := parseAlarmRule(alarm.Key.Scope, alarm.Composite.Rule)
	if w != nil {
		return "", "", "", w
	}
	states := make(map[string]string, len(alarm.Composite.Children))
	children := make(map[string]AlarmRecord, len(alarm.Composite.Children))
	reason := struct {
		TriggeringAlarms []compositeTrigger `json:"triggeringAlarms"`
	}{TriggeringAlarms: []compositeTrigger{}}
	for _, name := range alarm.Composite.Children {
		child, err := r.Alarm(AlarmKey{Scope: alarm.Key.Scope, Name: name})
		if err != nil {
			return "", "", "", wireError(err)
		}
		states[name] = child.State.Value
		children[name] = child
	}
	matched, witnesses := rule.evaluate(states, make([]string, 0, len(states)))
	slices.Sort(witnesses)
	for _, name := range slices.Compact(witnesses) {
		child := children[name]
		trigger := compositeTrigger{ARN: child.Key.ARN()}
		trigger.State.Value, trigger.State.Timestamp = child.State.Value, alarmDocumentTime(child.State.Updated)
		reason.TriggeringAlarms = append(reason.TriggeringAlarms, trigger)
	}
	state := "OK"
	if matched {
		state = "ALARM"
	}
	return state, "Composite alarm rule evaluated to " + state + ".", string(encodeAlarmDocument(reason)), nil
}
