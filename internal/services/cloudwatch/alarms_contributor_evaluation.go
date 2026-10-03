package cloudwatch

import (
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"
	"stackd/internal/awswire"
)

func alarmContributorIdentity(fields []string, values []insightsGroupValue) AlarmContributorIdentity {
	attributes := make(map[string]string, len(fields))
	for i, name := range fields {
		attribute := values[i].value
		if !values[i].present {
			attribute = "Other"
		}
		attributes[name] = attribute
	}
	// IDs identify the native attribute tuple, not its label, rank, namespace,
	// or alarm incarnation. Missing values and literal Other share that tuple.
	hash := fnv.New64a()
	_, _ = hash.Write(encodeAlarmDocument(attributes))
	return AlarmContributorIdentity{ID: fmt.Sprintf("%016x", hash.Sum64()), Attributes: attributes}
}

type alarmContributorSeries struct {
	identity AlarmContributorIdentity
	series   *mathSeries
}

func (s *Service) evaluateContributorAlarm(tx Transaction, alarm AlarmRecord, now time.Time, plan *metricQueryPlan, series []*mathSeries) *awswire.Error {
	retained, err := tx.AlarmContributors(AlarmContributorQuery{AlarmID: alarm.ID, Limit: 500})
	if err != nil {
		return wireError(err)
	}
	previous := make(map[string]AlarmContributorRecord, len(retained))
	for _, contributor := range retained {
		previous[contributor.ID] = contributor
	}
	selected := make(map[string]alarmContributorSeries, len(series))
	for _, item := range series {
		identity := alarmContributorIdentity(plan.insights.group, item.group)
		selected[identity.ID] = alarmContributorSeries{identity: identity, series: item}
	}
	count, breaching := len(selected), 0
	for _, id := range slices.Sorted(maps.Keys(selected)) {
		item := selected[id]
		old, active := previous[id]
		individual := alarm
		individual.State = AlarmState{Value: "OK"}
		if active {
			individual.State = AlarmState{Value: "ALARM", Reason: new(old.Reason), Transitioned: old.Transitioned}
		}
		state, reason, _ := evaluateAlarmSeries(individual, now, plan, item.series, nil)
		if state == "ALARM" {
			breaching++
			if !active {
				contributor := AlarmContributorRecord{AlarmContributorIdentity: item.identity, Reason: reason, Transitioned: now}
				if err := tx.PutAlarmContributor(alarm.ID, contributor); err != nil {
					return wireError(err)
				}
				if w := s.recordAlarmContributorState(tx, alarm, item.identity, "ALARM", reason, now); w != nil {
					return w
				}
			}
		} else if active {
			if err := tx.DeleteAlarmContributor(alarm.ID, id); err != nil {
				return wireError(err)
			}
			if w := s.recordAlarmContributorState(tx, alarm, item.identity, "OK", reason, now); w != nil {
				return w
			}
		}
		delete(previous, id)
	}
	for _, id := range slices.Sorted(maps.Keys(previous)) {
		contributor := previous[id]
		count++
		if err := tx.DeleteAlarmContributor(alarm.ID, id); err != nil {
			return wireError(err)
		}
		if w := s.recordAlarmContributorState(tx, alarm, contributor.AlarmContributorIdentity, "OK", "No data was returned for this contributor", now); w != nil {
			return w
		}
	}
	state := "OK"
	reason := fmt.Sprintf("%d time series evaluated to OK", count)
	if breaching > 0 {
		state = "ALARM"
		reason = fmt.Sprintf("%d out of %d time series evaluated to ALARM", breaching, count)
	}
	if len(selected) == 0 {
		policy := "Missing"
		switch alarm.Metric.TreatMissingData {
		case "breaching":
			state, policy = "ALARM", "Breaching"
		case "notBreaching":
			state, policy = "OK", "NotBreaching"
		case "ignore":
			state, policy = alarm.State.Value, "Ignore"
		default:
			state = "INSUFFICIENT_DATA"
		}
		reason = "No time series were returned by the query. Treat missing data is configured as [" + policy + "]."
	}
	data := string(encodeAlarmDocument(struct {
		Version   string `json:"version"`
		QueryDate string `json:"queryDate"`
	}{Version: "1.0", QueryDate: alarmDocumentTime(now)}))
	return s.applyMetricAlarmEvaluation(tx, alarm, now, state, reason, data, true)
}

func (s *Service) recordAlarmContributorState(tx Transaction, alarm AlarmRecord, contributor AlarmContributorIdentity, state, reason string, now time.Time) *awswire.Error {
	id := uuid.NewString()
	alarm.State = AlarmState{Value: state, Reason: new(reason), Updated: now, Transitioned: now, Origin: AlarmOrigin{EventID: id, RequestID: alarm.EvaluationOrigin.RequestID}}
	data := string(encodeAlarmDocument(struct {
		Version  string                    `json:"version"`
		NewState alarmDocumentHistoryState `json:"newState"`
	}{Version: "1.0", NewState: alarmHistoryState(alarm)}))
	history := AlarmHistoryRecord{ID: id, Key: alarm.Key, AlarmType: alarm.Type(), Type: "AlarmContributorStateUpdate", Summary: "Contributor state updated to " + state, At: now, Data: data, Contributor: &contributor}
	if w := s.appendAlarmHistory(tx, history); w != nil {
		return w
	}
	event := AlarmEvent{ID: id, Alarm: alarm.Key, At: now, DetailType: "CloudWatch Alarm Contributor State Change", Detail: alarmStateEventDetail(alarm, nil, &contributor)}
	if w := s.publishAlarmEvent(tx.Context(), event, alarm.EvaluationOrigin); w != nil {
		return w
	}
	previous := alarm
	previous.State.Value = "OK"
	if state == "OK" {
		previous.State.Value = "ALARM"
	}
	return s.enqueueAlarmActions(tx, previous, alarm, false, &contributor)
}
