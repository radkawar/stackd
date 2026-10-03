package cloudwatch

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func alarmMetricQueries(config *MetricAlarmConfig) api.MetricDataQueries {
	if config.Metric != nil {
		return api.MetricDataQueries{alarmQueryInput(AlarmMetricQuery{ID: config.QueryID, Metric: config.Metric})}
	}
	queries := make(api.MetricDataQueries, len(config.Queries))
	for i, query := range config.Queries {
		queries[i] = alarmQueryInput(query)
	}
	return queries
}

func validateAlarmMetricQueries(scope Scope, config *MetricAlarmConfig) (bool, *awswire.Error) {
	queries := config.Queries
	inputs := alarmMetricQueries(config)
	plan, w := compileMetricQueryPlan(scope, inputs)
	if w != nil {
		return false, w
	}
	if len(plan.searches) > 0 {
		return false, mathValidation("SEARCH is not supported on Metric Alarms.")
	}
	if plan.insights != nil && *inputs[plan.insightsIndex].Period < 60 {
		return false, mathValidation("MetricsInsights monitors do not support less than 60 seconds period")
	}
	if plan.insights != nil && int64(*inputs[plan.insightsIndex].Period)*int64(config.EvaluationPeriods) > 3*60*60 {
		return false, mathValidation("MetricsInsights monitors cannot be checked across more than 3 hours")
	}
	// Execute expression shapes over an empty, unavailable window. This uses the
	// same function/type/dependency rules as actual queries, without storage IO.
	evaluated, _, w := evaluateMetricQueryPlan(nil, scope, inputs, plan, time.Time{}, func(int64, bool) metricQueryBounds { return metricQueryBounds{} }, nil, nil)
	if w != nil {
		return false, w
	}
	contributors := false
	for i, query := range queries {
		if query.ReturnData != nil && !*query.ReturnData {
			continue
		}
		if evaluated[i].value.array || len(evaluated[i].value.series) != 1 {
			if i == plan.insightsIndex && plan.insights.order != "" {
				contributors = true
				continue
			}
			return false, alarmInvalid("An alarm expression must return one time series.")
		}
	}
	return contributors, nil
}

func alarmMetricPeriod(config *MetricAlarmConfig) int64 {
	if config.Metric != nil {
		return int64(config.Metric.Period)
	}
	fallback := int64(0)
	for _, query := range config.Queries {
		if query.Metric != nil && (fallback == 0 || int64(query.Metric.Period) < fallback) {
			fallback = int64(query.Metric.Period)
		}
		if query.ReturnData != nil && !*query.ReturnData {
			continue
		}
		if query.Period != nil {
			return int64(*query.Period)
		}
		if query.Metric != nil {
			return int64(query.Metric.Period)
		}
	}
	if fallback == 0 {
		return 60
	}
	return fallback
}

func alarmEvaluationCadence(config *MetricAlarmConfig) time.Duration {
	period := alarmMetricPeriod(config)
	if period*int64(config.EvaluationPeriods) > 86400 {
		return time.Hour
	}
	if period < 60 {
		return 10 * time.Second
	}
	return time.Minute
}

func alarmMetricWindow(now time.Time, config *MetricAlarmConfig, period int64, insights bool) metricQueryBounds {
	rounding := int64(60)
	extra := int64(2)
	if period < 60 {
		rounding, extra = period, 60/period
	} else if alarmEvaluationCadence(config) == time.Hour {
		rounding = 3600
	}
	// Native scalar evaluation trails the metric-query path by one service tick.
	// The extra range is N+2 standard buckets or N plus one high-resolution minute;
	// it is a deterministic choice matching the native bounded matrices, not an
	// AWS guarantee of ingestion latency or a universal retrieval-window formula.
	cutoff := now
	if config.Metric != nil {
		cutoff = cutoff.Add(-10 * time.Second)
	}
	end := floorTime(cutoff.Unix(), rounding)
	if alarmEvaluationCadence(config) == time.Hour {
		end = floorTime(now.Unix(), rounding)
	}
	start := end - (int64(config.EvaluationPeriods)+extra)*period
	if insights {
		start = max(start, end-3*60*60)
	}
	return metricQueryBounds{start: start, end: end, available: true}
}

type alarmEvaluationPoint struct {
	at           int64
	value, count float64
	significant  bool
}

type alarmEvaluatedPoint struct {
	Timestamp   string   `json:"timestamp"`
	SampleCount *float64 `json:"sampleCount,omitempty"`
	Value       *float64 `json:"value,omitempty"`
}

type alarmMetricReason struct {
	Version             string                `json:"version"`
	QueryDate           string                `json:"queryDate"`
	StartDate           string                `json:"startDate,omitempty"`
	Unit                string                `json:"unit,omitempty"`
	Statistic           string                `json:"statistic,omitempty"`
	Period              int64                 `json:"period"`
	RecentDatapoints    []*float64            `json:"recentDatapoints"`
	Threshold           float64               `json:"threshold"`
	EvaluatedDatapoints []alarmEvaluatedPoint `json:"evaluatedDatapoints"`
}

// TODO: Comeback join namespace-specific evaluation and per-sample causes to actual service-owned metric producers.
func (s *Service) evaluateMetricAlarm(tx Transaction, alarm AlarmRecord, now time.Time) *awswire.Error {
	config := alarm.Metric
	queries := alarmMetricQueries(config)
	plan, w := compileMetricQueryPlan(alarm.Key.Scope, queries)
	if w != nil {
		return w
	}
	counts := map[int64]float64{}
	readBuckets := func(r Reader, metricID string, start, end, period int64, unit string, distribution bool) ([]*metricBucket, *awswire.Error) {
		buckets, w := s.readMetricPointBuckets(r, metricID, start, end, period, unit, distribution)
		if config.Metric != nil {
			for i, bucket := range buckets {
				if i == 0 || buckets[i-1].at != bucket.at {
					counts[bucket.at] = bucket.count
				}
			}
		}
		return buckets, w
	}
	evaluated, _, w := evaluateMetricQueryPlan(tx, alarm.Key.Scope, queries, plan, now, func(period int64, _ bool) metricQueryBounds {
		return alarmMetricWindow(now, config, period, plan.insights != nil)
	}, readBuckets, nil)
	if w != nil {
		return w
	}
	var result mathValue
	for i, query := range queries {
		if query.ReturnData != nil && !bool(*query.ReturnData) {
			continue
		}
		result = evaluated[i].value
	}
	if result.array {
		return s.evaluateContributorAlarm(tx, alarm, now, plan, result.series)
	}
	state, reason, data := evaluateAlarmSeries(alarm, now, plan, result.series[0], counts)
	return s.applyMetricAlarmEvaluation(tx, alarm, now, state, reason, data, false)
}

func evaluateAlarmSeries(alarm AlarmRecord, now time.Time, plan *metricQueryPlan, series *mathSeries, counts map[int64]float64) (string, string, string) {
	config := alarm.Metric
	period := series.period
	bounds := alarmMetricWindow(now, config, period, plan.insights != nil)
	points := make([]alarmEvaluationPoint, 0, len(series.values))
	percentileTail := float64(0)
	if config.Metric != nil && config.LowSampleCount == "ignore" {
		spec, _ := parseStatistic(config.Metric.Statistic)
		if spec.kind == "p" && spec.high > 0 && spec.high < 100 {
			percentileTail = math.Min(spec.high, 100-spec.high)
		}
	}
	for at, value := range series.values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		points = append(points, alarmEvaluationPoint{at: at, value: value, count: counts[at], significant: percentileTail == 0 || counts[at]*percentileTail >= 1000})
	}
	slices.SortFunc(points, func(a, b alarmEvaluationPoint) int {
		if a.at > b.at {
			return -1
		}
		if a.at < b.at {
			return 1
		}
		return 0
	})
	n := int(config.EvaluationPeriods)
	if len(points) > n {
		points = points[:n]
	}
	m := n
	if config.DatapointsToAlarm != nil {
		m = int(*config.DatapointsToAlarm)
	}
	bad, good, lowSample := 0, 0, false
	for _, point := range points {
		if !point.significant {
			lowSample = true
			continue
		}
		if alarmBreaches(config, point.value) {
			bad++
		} else {
			good++
		}
	}
	missing := n - len(points)
	policy := config.TreatMissingData
	if policy == "" {
		policy = "missing"
		// Native defaults consider every MetricStat, including unused hidden
		// queries. An ordinary namespace disables the DynamoDB-only default.
		for _, metric := range plan.compiled {
			if metric.key.Namespace == "" {
				continue
			}
			if metric.key.Namespace != "AWS/DynamoDB" {
				policy = "missing"
				break
			}
			policy = "ignore"
		}
	}
	state := "OK"
	switch {
	case bad >= m:
		state = "ALARM"
	case good >= n-m+1:
		state = "OK"
	case lowSample || policy == "ignore":
		return alarm.State.Value, value(alarm.State.Reason), alarm.State.ReasonData
	case policy == "breaching":
		if bad+missing >= m {
			state = "ALARM"
		}
	case policy == "notBreaching":
		state = "OK"
	case len(points) == 0:
		state = "INSUFFICIENT_DATA"
	default:
		if good == 0 {
			state = "INSUFFICIENT_DATA"
			// A lone aging breach eventually alarms, but a retained good sample
			// prevents that missing-data override in the native sparse window.
			for _, point := range points {
				if (bounds.end-point.at)/period >= int64(m) {
					state = "ALARM"
					break
				}
			}
		}
	}
	if len(series.group) > 0 {
		if state == "INSUFFICIENT_DATA" {
			return state, fmt.Sprintf("Insufficient Data: %d datapoints were unknown.", missing), ""
		}
		required := m
		if state == "OK" {
			required = n - m + 1
		}
		return state, contributorThresholdReason(config, state, points, bad, good, required), ""
	}
	reason := alarmMetricReason{Version: "1.0", QueryDate: alarmDocumentTime(now), Period: period, RecentDatapoints: []*float64{}, Threshold: config.Threshold, EvaluatedDatapoints: []alarmEvaluatedPoint{}}
	if config.Metric != nil {
		reason.Unit, reason.Statistic = config.Metric.Unit, config.Metric.Statistic
	}
	if len(points) != 0 {
		start := points[len(points)-1].at
		reason.StartDate = alarmDocumentTime(time.Unix(start, 0))
		for at := start; at <= points[0].at; at += period {
			if value, ok := series.values[at]; ok && !math.IsNaN(value) && !math.IsInf(value, 0) {
				reason.RecentDatapoints = append(reason.RecentDatapoints, new(value))
			} else {
				reason.RecentDatapoints = append(reason.RecentDatapoints, nil)
			}
		}
	}
	needed := m
	if state == "OK" {
		needed = n - m + 1
	}
	for _, point := range points {
		if !point.significant || alarmBreaches(config, point.value) != (state == "ALARM") || state == "INSUFFICIENT_DATA" {
			continue
		}
		item := alarmEvaluatedPoint{Timestamp: alarmDocumentTime(time.Unix(point.at, 0)), Value: new(point.value)}
		if config.Metric != nil {
			item.SampleCount = new(point.count)
		}
		reason.EvaluatedDatapoints = append(reason.EvaluatedDatapoints, item)
		if len(reason.EvaluatedDatapoints) == needed {
			break
		}
	}
	for at := bounds.end - period; len(reason.EvaluatedDatapoints) < needed && at >= bounds.start; at -= period {
		if _, real := series.values[at]; real {
			continue
		}
		reason.EvaluatedDatapoints = append(reason.EvaluatedDatapoints, alarmEvaluatedPoint{Timestamp: alarmDocumentTime(time.Unix(at, 0))})
	}
	slices.SortFunc(reason.EvaluatedDatapoints, func(a, b alarmEvaluatedPoint) int { return -cmp.Compare(a.Timestamp, b.Timestamp) })
	text := fmt.Sprintf("Threshold Crossed: %d out of the last %d datapoints breached the threshold (%g); %d required.", bad, n, config.Threshold, m)
	if state == "OK" {
		text = fmt.Sprintf("Threshold Crossed: %d out of the last %d datapoints did not breach the threshold (%g).", good, n, config.Threshold)
	}
	if state == "INSUFFICIENT_DATA" {
		text = fmt.Sprintf("Insufficient Data: %d datapoints were unknown.", missing)
	}
	return state, text, string(encodeAlarmDocument(reason))
}

func alarmBreaches(config *MetricAlarmConfig, value float64) bool {
	switch config.Comparison {
	case "GreaterThanThreshold":
		return value > config.Threshold
	case "GreaterThanOrEqualToThreshold":
		return value >= config.Threshold
	case "LessThanThreshold":
		return value < config.Threshold
	case "LessThanOrEqualToThreshold":
		return value <= config.Threshold
	}
	return false
}

func (s *Service) applyMetricAlarmEvaluation(tx Transaction, alarm AlarmRecord, now time.Time, state, reason, data string, contributors bool) *awswire.Error {
	previous := alarm
	cadence := alarmEvaluationCadence(alarm.Metric)
	repeatScaling := state == "ALARM" && now.Truncate(time.Minute).After(alarm.NextEvaluation.Add(-cadence).Truncate(time.Minute))
	alarm.NextEvaluation = new(now.Add(cadence))
	changed := state != previous.State.Value
	if changed || contributors && reason != value(previous.State.Reason) {
		alarm.State = AlarmState{Value: state, Reason: new(reason), ReasonData: data, Updated: now, Transitioned: previous.State.Transitioned}
		if changed {
			alarm.State.Transitioned = now
		}
		return s.writeAlarmState(tx, previous, alarm, alarm.EvaluationOrigin)
	}
	alarm.Version++
	if err := tx.UpdateAlarmEvaluation(alarm); err != nil {
		return wireError(err)
	}
	if repeatScaling {
		// Repeated scaling receives the current evaluation snapshot without
		// rewriting the last transition exposed by DescribeAlarms.
		alarm.State.Updated, alarm.State.ReasonData = now, data
		return s.enqueueAlarmActions(tx, previous, alarm, true, nil)
	}
	return nil
}
