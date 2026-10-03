package cloudwatch

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func (s *Service) registerAlarms() {
	register(s, "PutMetricAlarm", s.putMetricAlarm)
	register(s, "PutCompositeAlarm", s.putCompositeAlarm)
	register(s, "DescribeAlarms", s.describeAlarms)
	register(s, "DescribeAlarmsForMetric", s.describeAlarmsForMetric)
	register(s, "DescribeAlarmHistory", s.describeAlarmHistory)
	register(s, "DescribeAlarmContributors", s.describeAlarmContributors)
	register(s, "SetAlarmState", s.setAlarmStateCommand)
	register(s, "DeleteAlarms", s.deleteAlarms)
	register(s, "EnableAlarmActions", s.enableAlarmActions)
	register(s, "DisableAlarmActions", s.disableAlarmActions)
}

func (s *Service) putMetricAlarm(tx Transaction, in *api.PutMetricAlarmInput) (*api.PutMetricAlarmOutput, *awswire.Error) {
	key := AlarmKey{Scope: scopeFor(tx.Context()), Name: value(in.AlarmName)}
	if w := validateAlarmName(key.Name); w != nil {
		return nil, w
	}
	config, w := s.admitMetricAlarm(key.Scope, in)
	if w != nil {
		return nil, w
	}
	actions, w := admitAlarmActions(in.AlarmActions, in.OKActions, in.InsufficientDataActions)
	if w != nil {
		return nil, w
	}
	previous, w := alarmPrevious(tx, key, "MetricAlarm")
	if w != nil {
		return nil, w
	}
	next := AlarmRecord{Key: key, Metric: config, Actions: actions, ActionsEnabled: in.ActionsEnabled == nil || bool(*in.ActionsEnabled)}
	if in.AlarmDescription != nil {
		next.Description = new(value(in.AlarmDescription))
	}
	if w := s.admitAlarmWrite(tx, "PutMetricAlarm", previous, &next, in.Tags); w != nil {
		return nil, w
	}
	if w := s.saveAlarm(tx, previous, next); w != nil {
		return nil, w
	}
	return &api.PutMetricAlarmOutput{}, nil
}

func (s *Service) putCompositeAlarm(tx Transaction, in *api.PutCompositeAlarmInput) (*api.PutCompositeAlarmOutput, *awswire.Error) {
	key := AlarmKey{Scope: scopeFor(tx.Context()), Name: value(in.AlarmName)}
	if w := validateAlarmName(key.Name); w != nil {
		return nil, w
	}
	children, w := compileAlarmRule(key.Scope, value(in.AlarmRule))
	if w != nil {
		return nil, w
	}
	config := &CompositeAlarmConfig{Rule: value(in.AlarmRule), Children: children}
	if in.ActionsSuppressor != nil {
		if in.ActionsSuppressorWaitPeriod == nil || in.ActionsSuppressorExtensionPeriod == nil {
			return nil, alarmInvalid("ActionsSuppressor requires ActionsSuppressorWaitPeriod and ActionsSuppressorExtensionPeriod.")
		}
		suppressor, w := alarmReference(key.Scope, value(in.ActionsSuppressor))
		if w != nil {
			return nil, w
		}
		if _, err := tx.Alarm(suppressor); errors.Is(err, ErrNotFound) {
			return nil, alarmInvalid("ActionsSuppressor must identify an existing alarm.")
		} else if err != nil {
			return nil, wireError(err)
		}
		config.Suppressor = value(in.ActionsSuppressor)
		config.WaitPeriod, config.ExtensionPeriod = int32(*in.ActionsSuppressorWaitPeriod), int32(*in.ActionsSuppressorExtensionPeriod)
		if config.WaitPeriod < 0 || config.ExtensionPeriod < 0 {
			return nil, alarmInvalid("Suppressor periods must not be negative.")
		}
	} else if in.ActionsSuppressorWaitPeriod != nil || in.ActionsSuppressorExtensionPeriod != nil {
		return nil, alarmInvalid("ActionsSuppressor is required when suppressor periods are specified.")
	}
	actions, w := admitAlarmActions(in.AlarmActions, in.OKActions, in.InsufficientDataActions)
	if w != nil {
		return nil, w
	}
	for _, list := range [][]string{actions.Alarm, actions.OK, actions.InsufficientData} {
		for _, action := range list {
			if strings.SplitN(action, ":", 4)[2] == "autoscaling" {
				return nil, alarmInvalid("Auto Scaling actions are not supported for composite alarms.")
			}
		}
	}
	previous, w := alarmPrevious(tx, key, "CompositeAlarm")
	if w != nil {
		return nil, w
	}
	next := AlarmRecord{Key: key, Composite: config, Actions: actions, ActionsEnabled: in.ActionsEnabled == nil || bool(*in.ActionsEnabled)}
	if in.AlarmDescription != nil {
		next.Description = new(value(in.AlarmDescription))
	}
	if w := s.admitAlarmWrite(tx, "PutCompositeAlarm", previous, &next, in.Tags); w != nil {
		return nil, w
	}
	for _, child := range children {
		if child == key.Name {
			return nil, alarmInvalid("An alarm cannot reference itself in AlarmRule.")
		}
		if _, err := tx.Alarm(AlarmKey{Scope: key.Scope, Name: child}); errors.Is(err, ErrNotFound) {
			return nil, alarmInvalid("AlarmRule references an alarm that does not exist: " + child)
		} else if err != nil {
			return nil, wireError(err)
		}
		parents, err := tx.Alarms(AlarmQuery{Scope: key.Scope, ParentOf: child, Limit: 151})
		if err != nil {
			return nil, wireError(err)
		}
		count := 0
		for _, parent := range parents {
			if parent.Key != key {
				count++
			}
		}
		if count >= 150 {
			return nil, failure("LimitExceeded", "An alarm cannot be referenced by more than 150 composite alarms.")
		}
	}
	if w := s.saveAlarm(tx, previous, next); w != nil {
		return nil, w
	}
	return &api.PutCompositeAlarmOutput{}, nil
}

func alarmPrevious(r Reader, key AlarmKey, kind string) (*AlarmRecord, *awswire.Error) {
	alarm, err := r.Alarm(key)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, wireError(err)
	}
	if alarm.Type() != kind {
		return nil, alarmInvalid("AlarmName [" + key.Name + "] is already used by another alarm of a different type")
	}
	return &alarm, nil
}

func (s *Service) setAlarmStateCommand(tx Transaction, in *api.SetAlarmStateInput) (*api.SetAlarmStateOutput, *awswire.Error) {
	state := value(in.StateValue)
	if !slices.Contains([]string{"OK", "ALARM", "INSUFFICIENT_DATA"}, state) {
		return nil, alarmInvalid("StateValue must be OK, ALARM, or INSUFFICIENT_DATA.")
	}
	if in.StateReasonData != nil && !json.Valid([]byte(value(in.StateReasonData))) {
		return nil, failure("InvalidFormat", "StateReasonData must be valid JSON.")
	}
	key := AlarmKey{Scope: scopeFor(tx.Context()), Name: value(in.AlarmName)}
	alarm, err := tx.Alarm(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, wireError(err)
	}
	if errors.Is(err, ErrNotFound) {
		alarm.Key = key
	}
	if w := s.authorizeAlarm(tx, "SetAlarmState", alarm, nil, nil, false); w != nil {
		return nil, w
	}
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ResourceNotFound", "Alarm "+key.Name+" does not exist.")
	}
	if w := s.setAlarmState(tx, alarm, state, value(in.StateReason), value(in.StateReasonData)); w != nil {
		return nil, w
	}
	return &api.SetAlarmStateOutput{}, nil
}

// Resolve and authorize every batch member before effects. The surrounding
// repository transaction also rolls back effects if a later write fails.
func (s *Service) alarmBatch(tx Transaction, names api.AlarmNames, action string) ([]AlarmRecord, *awswire.Error) {
	alarms := make([]AlarmRecord, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[string(name)] {
			continue
		}
		seen[string(name)] = true
		key := AlarmKey{Scope: scopeFor(tx.Context()), Name: string(name)}
		if w := validateAlarmName(key.Name); w != nil {
			return nil, w
		}
		alarm, err := tx.Alarm(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, wireError(err)
		}
		if errors.Is(err, ErrNotFound) {
			alarm.Key = key
		}
		if w := s.authorizeAlarm(tx, action, alarm, nil, nil, false); w != nil {
			return nil, w
		}
		if err == nil {
			alarms = append(alarms, alarm)
		}
	}
	return alarms, nil
}

func (s *Service) deleteAlarms(tx Transaction, in *api.DeleteAlarmsInput) (*api.DeleteAlarmsOutput, *awswire.Error) {
	alarms, w := s.alarmBatch(tx, in.AlarmNames, "DeleteAlarms")
	if w != nil {
		return nil, w
	}
	composites := 0
	for _, alarm := range alarms {
		if alarm.Composite != nil {
			composites++
		}
	}
	if composites > 1 {
		return nil, alarmInvalid("You cannot delete more than one composite alarm in one operation.")
	}
	for _, alarm := range alarms {
		parents, err := tx.Alarms(AlarmQuery{Scope: alarm.Key.Scope, ParentOf: alarm.Key.Name, Limit: 1})
		if err != nil {
			return nil, wireError(err)
		}
		suppressions, err := tx.Alarms(AlarmQuery{Scope: alarm.Key.Scope, SuppressedBy: alarm.Key.Name, Limit: 1})
		if err != nil {
			return nil, wireError(err)
		}
		if len(parents) != 0 || len(suppressions) != 0 {
			return nil, alarmInvalid("Cannot delete " + alarm.Key.Name + " as there are composite alarm(s) depending on it.")
		}
	}
	for _, alarm := range alarms {
		if w := s.deleteAlarm(tx, alarm); w != nil {
			return nil, w
		}
	}
	// Native successful deletion audits contain only the alarms actually removed.
	// The decoded input is request-owned; project it here while that set is known.
	in.AlarmNames = in.AlarmNames[:0]
	for _, alarm := range alarms {
		in.AlarmNames = append(in.AlarmNames, api.AlarmName(alarm.Key.Name))
	}
	return &api.DeleteAlarmsOutput{}, nil
}

func (s *Service) changeAlarmActions(tx Transaction, names api.AlarmNames, enabled bool) *awswire.Error {
	action := "DisableAlarmActions"
	if enabled {
		action = "EnableAlarmActions"
	}
	alarms, w := s.alarmBatch(tx, names, action)
	if w != nil {
		return w
	}
	for _, alarm := range alarms {
		if w := s.setAlarmActionsEnabled(tx, alarm, enabled); w != nil {
			return w
		}
	}
	return nil
}

func (s *Service) enableAlarmActions(tx Transaction, in *api.EnableAlarmActionsInput) (*api.EnableAlarmActionsOutput, *awswire.Error) {
	if w := s.changeAlarmActions(tx, in.AlarmNames, true); w != nil {
		return nil, w
	}
	return &api.EnableAlarmActionsOutput{}, nil
}

func (s *Service) disableAlarmActions(tx Transaction, in *api.DisableAlarmActionsInput) (*api.DisableAlarmActionsOutput, *awswire.Error) {
	if w := s.changeAlarmActions(tx, in.AlarmNames, false); w != nil {
		return nil, w
	}
	return &api.DisableAlarmActionsOutput{}, nil
}
