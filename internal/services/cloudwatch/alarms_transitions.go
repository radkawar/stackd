package cloudwatch

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) saveAlarm(tx Transaction, previous *AlarmRecord, next AlarmRecord) *awswire.Error {
	// Exact admitted configuration repeats preserve native state, history and
	// generated query identity. Authorization still runs before this no-op.
	if previous != nil && equalAlarmConfiguration(*previous, next) {
		return nil
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	next.Updated = now
	next.EvaluationOrigin = AlarmOrigin{EventID: uuid.NewString(), RequestID: awsctx.FromContext(tx.Context()).RequestID}
	change := "create"
	if previous == nil {
		next.ID, next.Created, next.Version = uuid.NewString(), now, 1
		next.State = AlarmState{Value: "INSUFFICIENT_DATA", Reason: new("Unchecked: Initial alarm creation"), Updated: now, Transitioned: now, Origin: next.EvaluationOrigin}
	} else {
		change = "update"
		next.ID, next.Created, next.Version, next.State = previous.ID, previous.Created, previous.Version+1, previous.State
		next.SuppressionPhase, next.SuppressionReason, next.SuppressionUntil = previous.SuppressionPhase, previous.SuppressionReason, previous.SuppressionUntil
	}
	// Native configuration writes normalize an empty state reason to absence;
	// SetAlarmState itself retains the explicitly supplied empty string.
	if value(next.State.Reason) == "" {
		next.State.Reason = nil
	}
	if next.Metric != nil {
		next.Metric.QueryID = "m" + strings.ReplaceAll(uuid.NewString(), "-", "")
		next.NextEvaluation = new(now.Add(alarmEvaluationCadence(next.Metric)))
	} else {
		next.NextEvaluation = new(now)
		if previous != nil && alarmSuppressorKey(next) != alarmSuppressorKey(*previous) {
			next.SuppressionPhase, next.SuppressionReason, next.SuppressionUntil = "", "", nil
			if previous.SuppressionPhase != "" {
				next.State.Updated = now
			}
		}
	}
	if previous != nil && previous.SuppressionPhase != next.SuppressionPhase {
		next.State.Origin = AlarmOrigin{EventID: uuid.NewString(), RequestID: next.EvaluationOrigin.RequestID}
	}
	if err := tx.PutAlarm(next); err != nil {
		return wireError(err)
	}
	if previous != nil {
		before, w := alarmContributorQuery(previous.Metric)
		if w != nil {
			return w
		}
		if before != nil {
			after, w := alarmContributorQuery(next.Metric)
			if w != nil {
				return w
			}
			if after == nil {
				// Changing alarm kind retires active membership, not the
				// contributor's retained history or an invented OK transition.
				contributors, err := tx.AlarmContributors(AlarmContributorQuery{AlarmID: next.ID, Limit: 500})
				if err != nil {
					return wireError(err)
				}
				for _, contributor := range contributors {
					if err := tx.DeleteAlarmContributor(next.ID, contributor.ID); err != nil {
						return wireError(err)
					}
				}
			}
		}
	}
	if w := s.recordAlarmConfiguration(tx, next, previous, change, next.EvaluationOrigin); w != nil {
		return w
	}
	if previous != nil && previous.SuppressionPhase != next.SuppressionPhase {
		if w := s.recordAlarmState(tx, *previous, next, next.EvaluationOrigin); w != nil {
			return w
		}
	}
	s.jobs.Wake()
	return nil
}

func (s *Service) setAlarmActionsEnabled(tx Transaction, alarm AlarmRecord, enabled bool) *awswire.Error {
	previous := alarm
	alarm.ActionsEnabled, alarm.Updated, alarm.Version = enabled, s.clock.Now().UTC().Truncate(time.Millisecond), alarm.Version+1
	origin := AlarmOrigin{EventID: uuid.NewString(), RequestID: awsctx.FromContext(tx.Context()).RequestID}
	if value(alarm.State.Reason) == "" {
		alarm.State.Reason = nil
	}
	if err := tx.PutAlarm(alarm); err != nil {
		return wireError(err)
	}
	return s.recordAlarmConfiguration(tx, alarm, &previous, "update", origin)
}

func (s *Service) deleteAlarm(tx Transaction, alarm AlarmRecord) *awswire.Error {
	origin := AlarmOrigin{EventID: uuid.NewString(), RequestID: awsctx.FromContext(tx.Context()).RequestID}
	if w := s.recordAlarmConfiguration(tx, alarm, nil, "delete", origin); w != nil {
		return w
	}
	return wireError(tx.DeleteAlarm(alarm.Key))
}

func (s *Service) recordAlarmConfiguration(tx Transaction, alarm AlarmRecord, previous *AlarmRecord, change string, origin AlarmOrigin) *awswire.Error {
	names := []string{}
	for _, record := range []*AlarmRecord{&alarm, previous} {
		if record == nil || record.Composite == nil {
			continue
		}
		names = append(names, record.Composite.Children...)
		if record.Composite.Suppressor != "" {
			names = append(names, alarmSuppressorKey(*record).Name)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	children := []AlarmRecord{}
	if len(names) != 0 {
		var err error
		children, err = tx.Alarms(AlarmQuery{Scope: alarm.Key.Scope, Names: names, Limit: len(names)})
		if err != nil {
			return wireError(err)
		}
	}
	at := s.clock.Now().UTC().Truncate(time.Millisecond)
	history := AlarmHistoryRecord{ID: uuid.NewString(), Key: alarm.Key, AlarmType: alarm.Type(), Type: "ConfigurationUpdate", Summary: "Alarm " + alarm.Key.Name + " " + change, At: at, Data: alarmConfigurationHistoryData(alarm, previous, change, children)}
	if w := s.appendAlarmHistory(tx, history); w != nil {
		return w
	}
	return s.publishAlarmEvent(tx.Context(), AlarmEvent{ID: origin.EventID, Alarm: alarm.Key, At: at, DetailType: "CloudWatch Alarm Configuration Change", Detail: alarmConfigurationEventDetail(alarm, previous, change)}, alarmRequestOrigin(tx.Context()))
}

// A manual same-state request is a complete no-op, including its supplied reason.
func (s *Service) setAlarmState(tx Transaction, alarm AlarmRecord, state, reason, data string) *awswire.Error {
	if alarm.State.Value == state {
		return nil
	}
	previous := alarm
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	alarm.State = AlarmState{Value: state, Reason: new(reason), ReasonData: data, Updated: now, Transitioned: now}
	if alarm.Composite != nil {
		if w := s.beginAlarmSuppression(tx, &alarm, now); w != nil {
			return w
		}
	}
	return s.writeAlarmState(tx, previous, alarm, alarmRequestOrigin(tx.Context()))
}

func (s *Service) writeAlarmState(tx Transaction, previous, alarm AlarmRecord, cause AlarmOrigin) *awswire.Error {
	alarm.Version = previous.Version + 1
	alarm.State.Origin = AlarmOrigin{EventID: uuid.NewString(), RequestID: cause.RequestID}
	if err := tx.UpdateAlarmEvaluation(alarm); err != nil {
		return wireError(err)
	}
	if w := s.recordAlarmState(tx, previous, alarm, cause); w != nil {
		return w
	}
	if previous.State.Value != alarm.State.Value {
		if w := s.notifyAlarmDependents(tx, alarm); w != nil {
			return w
		}
	}
	s.jobs.Wake()
	return nil
}

// Suppression updates are native state events even when the alarm value is
// unchanged. Actions are selected only when unsuppressed, from this current
// transition; there is no fictitious accepted action waiting behind suppression.
func (s *Service) recordAlarmState(tx Transaction, previous, alarm AlarmRecord, cause AlarmOrigin) *awswire.Error {
	id := alarm.State.Origin.EventID
	reasonOnly := previous.State.Value == alarm.State.Value && previous.SuppressionPhase == alarm.SuppressionPhase && previous.SuppressionReason == alarm.SuppressionReason
	summary := "Alarm updated from " + previous.State.Value + " to " + alarm.State.Value
	if previous.State.Value == alarm.State.Value {
		summary = "Alarm actions suppression updated"
		if reasonOnly {
			summary = fmt.Sprintf("State Reason changed from %q to %q", value(previous.State.Reason), value(alarm.State.Reason))
		}
	}
	history := AlarmHistoryRecord{ID: id, Key: alarm.Key, AlarmType: alarm.Type(), Type: "StateUpdate", Summary: summary, At: alarm.State.Updated, Data: alarmStateHistoryData(alarm, previous)}
	if w := s.appendAlarmHistory(tx, history); w != nil {
		return w
	}
	if reasonOnly {
		return nil
	}
	if w := s.publishAlarmEvent(tx.Context(), AlarmEvent{ID: id, Alarm: alarm.Key, At: alarm.State.Updated, DetailType: "CloudWatch Alarm State Change", Detail: alarmStateEventDetail(alarm, &previous, nil)}, cause); w != nil {
		return w
	}
	return s.enqueueAlarmActions(tx, previous, alarm, false, nil)
}

// enqueueAlarmActions is shared by transitions and the native minute-by-minute
// Auto Scaling action. Repeated scaling is not a state transition or SNS/Lambda
// notification; its evaluation snapshot supplies fresh reason data.
func (s *Service) enqueueAlarmActions(tx Transaction, previous, alarm AlarmRecord, scalingOnly bool, contributor *AlarmContributorIdentity) *awswire.Error {
	id := alarm.State.Origin.EventID
	if !alarm.ActionsEnabled {
		return nil
	}
	insights, w := alarmContributorQuery(alarm.Metric)
	if w != nil {
		return w
	}
	var targets []string
	switch alarm.State.Value {
	case "ALARM":
		targets = alarm.Actions.Alarm
	case "OK":
		targets = alarm.Actions.OK
	case "INSUFFICIENT_DATA":
		targets = alarm.Actions.InsufficientData
	}
	var lambdaPayload, snsPayload []byte
	var snsSubject string
	for _, target := range targets {
		service := strings.SplitN(target, ":", 4)[2]
		if scalingOnly && service != "autoscaling" {
			continue
		}
		if insights != nil && contributor == nil {
			continue
		}
		action := AlarmActionRecord{ID: uuid.NewString(), EventID: id, RequestID: alarm.State.Origin.RequestID, Key: alarm.Key, AlarmType: alarm.Type(), TargetARN: target, State: alarm.State.Value, Accepted: alarm.State.Updated, Due: alarm.State.Updated, Version: 1, Contributor: contributor}
		if alarm.SuppressionPhase == "" {
			switch service {
			case "sns":
				if snsPayload == nil {
					snsPayload, snsSubject = alarmSNSPublication(alarm, previous, contributor)
				}
				action.Payload, action.Subject = snsPayload, snsSubject
			case "autoscaling":
				action.Payload = encodeAlarmDocument(ScalingAlarmSignal{ReasonData: alarm.State.ReasonData, Comparison: alarm.Metric.Comparison})
			default:
				if lambdaPayload == nil {
					lambdaPayload = alarmInvocationPayload(alarm, previous, contributor)
				}
				action.Payload = lambdaPayload
			}
		}
		if alarm.SuppressionPhase != "" {
			if w := s.recordAlarmAction(tx, action, "Suppressed", alarmSuppressionReason(alarm)); w != nil {
				return w
			}
		} else if err := tx.PutAlarmAction(action); err != nil {
			return wireError(err)
		}
	}
	return nil
}

func (s *Service) publishAlarmEvent(ctx context.Context, event AlarmEvent, cause AlarmOrigin) *awswire.Error {
	if s.events == nil {
		return nil
	}
	metadata := awsctx.FromContext(ctx)
	metadata.ParentEventID, metadata.RequestID = cause.EventID, cause.RequestID
	return wireError(s.events.PublishAlarmEvent(awsctx.WithMetadata(ctx, metadata), event))
}

func (s *Service) notifyAlarmDependents(tx Transaction, source AlarmRecord) *awswire.Error {
	parents, err := tx.Alarms(AlarmQuery{Scope: source.Key.Scope, ParentOf: source.Key.Name, Limit: 151})
	if err != nil {
		return wireError(err)
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	for _, parent := range parents {
		// Evaluate dependent components on the next deterministic service-time tick.
		parent.NextEvaluation, parent.Version = new(now.Add(time.Second)), parent.Version+1
		parent.EvaluationOrigin = source.State.Origin
		if err := tx.UpdateAlarmEvaluation(parent); err != nil {
			return wireError(err)
		}
	}
	return s.notifyAlarmSuppressed(tx, source)
}

func (s *Service) notifyAlarmSuppressed(tx Transaction, source AlarmRecord) *awswire.Error {
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	query := AlarmQuery{Scope: source.Key.Scope, SuppressedBy: source.Key.Name, Limit: 100}
	for {
		suppressed, err := tx.Alarms(query)
		if err != nil {
			return wireError(err)
		}
		for _, alarm := range suppressed {
			if w := s.advanceAlarmSuppression(tx, alarm, now, source.State.Origin); w != nil {
				return w
			}
		}
		if len(suppressed) < query.Limit {
			break
		}
		query.FromName = suppressed[len(suppressed)-1].Key.Name + "\x00"
	}
	return nil
}

func (s *Service) recordAlarmAction(tx Transaction, action AlarmActionRecord, status, reason string) *awswire.Error {
	at := s.clock.Now().UTC().Truncate(time.Millisecond)
	summary := status + " executing action " + action.TargetARN
	kind := "Action"
	if action.Contributor != nil {
		kind = "AlarmContributorAction"
	}
	return s.appendAlarmHistory(tx, AlarmHistoryRecord{ID: uuid.NewString(), Key: action.Key, AlarmType: action.AlarmType, Type: kind, Summary: summary, At: at, Data: alarmActionHistoryData(action, status, reason, at), Contributor: action.Contributor})
}

func alarmRequestOrigin(ctx context.Context) AlarmOrigin {
	metadata := awsctx.FromContext(ctx)
	id := apievents.EventID(ctx)
	if id == "" {
		id = metadata.ParentEventID
	}
	return AlarmOrigin{EventID: id, RequestID: metadata.RequestID}
}

func (s *Service) appendAlarmHistory(tx Transaction, history AlarmHistoryRecord) *awswire.Error {
	if err := tx.AppendAlarmHistory(history); err != nil {
		return wireError(err)
	}
	return s.expireAlarmHistory(tx, history.Key.Scope)
}

// Prune on history writes and reads: active scopes stay bounded without another
// maintenance job, and idle scopes cannot expose history beyond thirty days.
func (s *Service) expireAlarmHistory(tx Transaction, scope Scope) *awswire.Error {
	return wireError(tx.ExpireAlarmHistory(scope, s.clock.Now().Add(-30*24*time.Hour)))
}
