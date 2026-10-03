package cloudwatch

import (
	"errors"
	"maps"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func (s *Service) authorizeAlarm(r Reader, action string, alarm AlarmRecord, requested map[string]string, keys []string, wildcard bool) *awswire.Error {
	conditions := cloudwatchTagConditions(alarm.Tags, requested, keys)
	if action == "PutMetricAlarm" || action == "PutCompositeAlarm" {
		actions := make([]string, 0, len(alarm.Actions.Alarm)+len(alarm.Actions.OK)+len(alarm.Actions.InsufficientData))
		actions = append(actions, alarm.Actions.Alarm...)
		actions = append(actions, alarm.Actions.OK...)
		actions = append(actions, alarm.Actions.InsufficientData...)
		if len(actions) != 0 {
			conditions["cloudwatch:AlarmActions"] = actions
		}
	}
	arn := alarm.Key.ARN()
	if wildcard {
		arn = "*"
	}
	return s.authorizer.Authorize(r.Context(), authorization.Request{Action: "cloudwatch:" + action, ResourceARN: arn, ResourceAccountID: alarm.Key.AccountID, Context: conditions})
}

func (s *Service) admitAlarmWrite(tx Transaction, action string, previous *AlarmRecord, next *AlarmRecord, input api.TagList) *awswire.Error {
	var requested map[string]string
	if previous != nil {
		next.Tags = maps.Clone(previous.Tags)
	} else {
		var w *awswire.Error
		requested, w = admitTags(input)
		if w != nil {
			return w
		}
		if len(requested) > 50 {
			return alarmInvalid("The resultant tag set must not have more than 50 user tags.")
		}
		next.Tags = requested
	}
	// Resource-tag conditions describe existing state, never the proposed tags.
	authAlarm := *next
	if previous == nil {
		authAlarm.Tags = nil
	}
	if w := s.authorizeAlarm(tx, action, authAlarm, requested, nil, action == "PutCompositeAlarm"); w != nil {
		return w
	}
	if previous == nil && len(requested) != 0 {
		if w := s.authorizeAlarm(tx, "TagResource", authAlarm, requested, nil, false); w != nil {
			return w
		}
	}
	return nil
}

func (s *Service) alarmTagTarget(tx Transaction, arn, action string, requested map[string]string, keys []string) (AlarmRecord, *awswire.Error) {
	scope := scopeFor(tx.Context())
	if !strings.HasPrefix(arn, "arn:") {
		return AlarmRecord{}, alarmInvalid("ResourceARN must be an alarm ARN.")
	}
	key, w := alarmReference(scope, arn)
	if w != nil {
		return AlarmRecord{}, w
	}
	alarm, err := tx.Alarm(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return AlarmRecord{}, wireError(err)
	}
	if errors.Is(err, ErrNotFound) {
		alarm.Key = key
	}
	if w := s.authorizeAlarm(tx, action, alarm, requested, keys, false); w != nil {
		return AlarmRecord{}, w
	}
	if errors.Is(err, ErrNotFound) {
		return AlarmRecord{}, failure("ResourceNotFoundException", "The specified resource does not exist.")
	}
	return alarm, nil
}
