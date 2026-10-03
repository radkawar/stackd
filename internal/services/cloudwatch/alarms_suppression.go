package cloudwatch

import (
	"strings"
	"time"

	"stackd/internal/awswire"
)

func alarmSuppressorKey(alarm AlarmRecord) AlarmKey {
	key := AlarmKey{Scope: alarm.Key.Scope}
	if alarm.Composite != nil {
		key.Name = strings.TrimPrefix(alarm.Composite.Suppressor, key.ARN())
	}
	return key
}

func (s *Service) beginAlarmSuppression(r Reader, alarm *AlarmRecord, now time.Time) *awswire.Error {
	alarm.SuppressionPhase, alarm.SuppressionReason, alarm.SuppressionUntil = "", "", nil
	if alarm.Composite.Suppressor == "" {
		return nil
	}
	suppressor, err := r.Alarm(alarmSuppressorKey(*alarm))
	if err != nil {
		return wireError(err)
	}
	if suppressor.State.Value == "ALARM" {
		alarmSuppressedByAlarm(alarm, suppressor)
	} else if alarm.Composite.WaitPeriod > 0 {
		alarm.SuppressionPhase = "WaitPeriod"
		alarm.SuppressionUntil = new(now.Add(time.Duration(alarm.Composite.WaitPeriod) * time.Second))
	}
	return nil
}

func alarmSuppressedByAlarm(alarm *AlarmRecord, suppressor AlarmRecord) {
	alarm.SuppressionPhase, alarm.SuppressionUntil = "Alarm", nil
	alarm.SuppressionReason = "Actions suppressed by " + suppressor.Key.ARN() + " that transitioned to ALARM at " + suppressor.State.Transitioned.UTC().Format("Monday 2 January, 2006 15:04:05 MST")
}

func (s *Service) advanceAlarmSuppression(tx Transaction, alarm AlarmRecord, now time.Time, cause AlarmOrigin) *awswire.Error {
	// Once actions have been released, a later suppressor change does not begin
	// a new suppression episode. Only a new alarm-value transition does that.
	if alarm.SuppressionPhase == "" {
		return nil
	}
	previous := alarm
	suppressor, err := tx.Alarm(alarmSuppressorKey(alarm))
	if err != nil {
		return wireError(err)
	}
	switch alarm.SuppressionPhase {
	case "WaitPeriod", "ExtensionPeriod":
		if suppressor.State.Value == "ALARM" {
			alarmSuppressedByAlarm(&alarm, suppressor)
		} else if !alarm.SuppressionUntil.After(now) {
			alarm.SuppressionPhase, alarm.SuppressionReason, alarm.SuppressionUntil = "", "", nil
		}
	case "Alarm":
		if suppressor.State.Value != "ALARM" {
			alarm.SuppressionPhase, alarm.SuppressionReason = "ExtensionPeriod", ""
			alarm.SuppressionUntil = new(now.Add(time.Duration(alarm.Composite.ExtensionPeriod) * time.Second))
			if alarm.Composite.ExtensionPeriod == 0 {
				alarm.SuppressionPhase, alarm.SuppressionUntil = "", nil
			}
		}
	}
	if previous.SuppressionPhase == alarm.SuppressionPhase {
		return nil
	}
	alarm.State.Updated = now.UTC().Truncate(time.Millisecond)
	return s.writeAlarmState(tx, previous, alarm, cause)
}
