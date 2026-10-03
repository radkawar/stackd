package cloudwatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awscatalog"
)

// Native alarm documents use millisecond precision and an offset without a colon,
// unlike the second-precision UTC time on the surrounding EventBridge envelope.
const alarmDocumentTimeLayout = "2006-01-02T15:04:05.000-0700"

func alarmDocumentTime(at time.Time) string {
	return at.UTC().Format(alarmDocumentTimeLayout)
}

// These private projections contain only strings, integers, booleans, finite
// admitted thresholds, acyclic typed structs, and admitted JSON ReasonData.
// Consequently encoding cannot fail for repository state. Panic on a violated
// invariant rather than publish an empty document or silently lose history.
func encodeAlarmDocument(document any) []byte {
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(fmt.Errorf("encode admitted CloudWatch alarm document: %w", err))
	}
	return encoded
}

type alarmDocumentState struct {
	Value                   string  `json:"value"`
	Reason                  *string `json:"reason,omitempty"`
	ReasonData              string  `json:"reasonData,omitempty"`
	Timestamp               string  `json:"timestamp"`
	ActionsSuppressedBy     string  `json:"actionsSuppressedBy,omitempty"`
	ActionsSuppressedReason string  `json:"actionsSuppressedReason,omitempty"`
}

func alarmProjectedState(alarm AlarmRecord) alarmDocumentState {
	state := alarm.State
	return alarmDocumentState{Value: state.Value, Reason: state.Reason, ReasonData: state.ReasonData, Timestamp: alarmDocumentTime(state.Updated), ActionsSuppressedBy: alarm.SuppressionPhase, ActionsSuppressedReason: alarmSuppressionReason(alarm)}
}

func alarmSuppressionReason(alarm AlarmRecord) string {
	switch alarm.SuppressionPhase {
	case "WaitPeriod":
		return "Actions suppressed by WaitPeriod"
	case "ExtensionPeriod":
		return "Actions suppressed by ExtensionPeriod"
	case "Alarm":
		return alarm.SuppressionReason
	default:
		return ""
	}
}

type alarmDocumentMetric struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	Dimensions map[string]string `json:"dimensions"`
}

type alarmDocumentMetricStat struct {
	Metric alarmDocumentMetric `json:"metric"`
	Period int32               `json:"period"`
	Stat   string              `json:"stat"`
	Unit   string              `json:"unit,omitempty"`
}

type alarmDocumentMetricQuery struct {
	ID         string                   `json:"id"`
	MetricStat *alarmDocumentMetricStat `json:"metricStat,omitempty"`
	Expression string                   `json:"expression,omitempty"`
	AccountID  string                   `json:"accountId,omitempty"`
	Label      *string                  `json:"label,omitempty"`
	Period     *int32                   `json:"period,omitempty"`
	ReturnData *bool                    `json:"returnData,omitempty"`
}

func alarmProjectedMetricStat(metric *AlarmMetricStat) *alarmDocumentMetricStat {
	if metric == nil {
		return nil
	}
	dimensions := make(map[string]string, len(metric.Dimensions))
	for _, dimension := range metric.Dimensions {
		dimensions[dimension.Name] = dimension.Value
	}
	return &alarmDocumentMetricStat{
		Metric: alarmDocumentMetric{Namespace: metric.Key.Namespace, Name: metric.Key.Name, Dimensions: dimensions},
		Period: metric.Period, Stat: metric.Statistic, Unit: metric.Unit,
	}
}

func alarmProjectedMetrics(config *MetricAlarmConfig) []alarmDocumentMetricQuery {
	if config == nil {
		return nil
	}
	if config.Metric != nil {
		return []alarmDocumentMetricQuery{{ID: config.QueryID, MetricStat: alarmProjectedMetricStat(config.Metric), ReturnData: new(true)}}
	}
	queries := make([]alarmDocumentMetricQuery, len(config.Queries))
	for i, query := range config.Queries {
		queries[i] = alarmDocumentMetricQuery{ID: query.ID, MetricStat: alarmProjectedMetricStat(query.Metric), Expression: query.Expression, AccountID: query.AccountID, Label: query.Label, Period: query.Period, ReturnData: query.ReturnData}
	}
	return queries
}

type alarmDocumentReducedConfiguration struct {
	Description                      *string                    `json:"description,omitempty"`
	Metrics                          []alarmDocumentMetricQuery `json:"metrics,omitempty"`
	AlarmRule                        string                     `json:"alarmRule,omitempty"`
	ActionsSuppressor                string                     `json:"actionsSuppressor,omitempty"`
	ActionsSuppressorWaitPeriod      *int32                     `json:"actionsSuppressorWaitPeriod,omitempty"`
	ActionsSuppressorExtensionPeriod *int32                     `json:"actionsSuppressorExtensionPeriod,omitempty"`
}

func alarmReducedConfiguration(alarm AlarmRecord) alarmDocumentReducedConfiguration {
	configuration := alarmDocumentReducedConfiguration{Description: alarm.Description, Metrics: alarmProjectedMetrics(alarm.Metric)}
	if composite := alarm.Composite; composite != nil {
		configuration.AlarmRule = composite.Rule
		configuration.ActionsSuppressor = composite.Suppressor
		if composite.Suppressor != "" {
			configuration.ActionsSuppressorWaitPeriod = &composite.WaitPeriod
			configuration.ActionsSuppressorExtensionPeriod = &composite.ExtensionPeriod
		}
	}
	return configuration
}

type alarmDocumentFullConfiguration struct {
	alarmDocumentReducedConfiguration
	AlarmName                        string   `json:"alarmName"`
	ActionsEnabled                   bool     `json:"actionsEnabled"`
	Timestamp                        string   `json:"timestamp"`
	OKActions                        []string `json:"okActions"`
	AlarmActions                     []string `json:"alarmActions"`
	InsufficientDataActions          []string `json:"insufficientDataActions"`
	EvaluationPeriods                *int32   `json:"evaluationPeriods,omitempty"`
	DatapointsToAlarm                *int32   `json:"datapointsToAlarm,omitempty"`
	Threshold                        *float64 `json:"threshold,omitempty"`
	ComparisonOperator               string   `json:"comparisonOperator,omitempty"`
	TreatMissingData                 string   `json:"treatMissingData,omitempty"`
	EvaluateLowSampleCountPercentile string   `json:"evaluateLowSampleCountPercentile,omitempty"`
}

func alarmDocumentActions(actions []string) []string {
	if actions == nil {
		return []string{}
	}
	return actions
}

func alarmFullConfiguration(alarm AlarmRecord) alarmDocumentFullConfiguration {
	configuration := alarmDocumentFullConfiguration{
		alarmDocumentReducedConfiguration: alarmReducedConfiguration(alarm),
		AlarmName:                         alarm.Key.Name, ActionsEnabled: alarm.ActionsEnabled, Timestamp: alarmDocumentTime(alarm.Updated),
		OKActions: alarmDocumentActions(alarm.Actions.OK), AlarmActions: alarmDocumentActions(alarm.Actions.Alarm), InsufficientDataActions: alarmDocumentActions(alarm.Actions.InsufficientData),
	}
	if metric := alarm.Metric; metric != nil {
		configuration.EvaluationPeriods = &metric.EvaluationPeriods
		configuration.DatapointsToAlarm = metric.DatapointsToAlarm
		configuration.Threshold = &metric.Threshold
		configuration.ComparisonOperator = metric.Comparison
		configuration.TreatMissingData = metric.TreatMissingData
		configuration.EvaluateLowSampleCountPercentile = metric.LowSampleCount
	}
	return configuration
}

type alarmDocumentContributor struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
}

type alarmDocumentStateDetail struct {
	AlarmName        string                            `json:"alarmName"`
	State            alarmDocumentState                `json:"state"`
	PreviousState    *alarmDocumentState               `json:"previousState,omitempty"`
	AlarmContributor *alarmDocumentContributor         `json:"alarmContributor,omitempty"`
	Configuration    alarmDocumentReducedConfiguration `json:"configuration"`
}

func alarmStateDetail(alarm AlarmRecord, previous *AlarmRecord, contributor *AlarmContributorIdentity) alarmDocumentStateDetail {
	detail := alarmDocumentStateDetail{AlarmName: alarm.Key.Name, State: alarmProjectedState(alarm), Configuration: alarmReducedConfiguration(alarm)}
	if contributor != nil {
		detail.AlarmContributor = &alarmDocumentContributor{ID: contributor.ID, Attributes: contributor.Attributes}
	} else if previous != nil {
		detail.PreviousState = new(alarmProjectedState(*previous))
	}
	return detail
}

func alarmStateEventDetail(alarm AlarmRecord, previous *AlarmRecord, contributor *AlarmContributorIdentity) []byte {
	return encodeAlarmDocument(alarmStateDetail(alarm, previous, contributor))
}

type alarmDocumentConfigurationDetail struct {
	AlarmName             string                          `json:"alarmName"`
	Operation             string                          `json:"operation"`
	State                 alarmDocumentState              `json:"state"`
	Configuration         alarmDocumentFullConfiguration  `json:"configuration"`
	PreviousConfiguration *alarmDocumentFullConfiguration `json:"previousConfiguration,omitempty"`
}

func alarmConfigurationEventDetail(alarm AlarmRecord, previous *AlarmRecord, change string) []byte {
	detail := alarmDocumentConfigurationDetail{
		AlarmName: alarm.Key.Name, Operation: change,
		State:         alarmDocumentState{Value: alarm.State.Value, Timestamp: alarmDocumentTime(alarm.State.Updated), ActionsSuppressedBy: alarm.SuppressionPhase},
		Configuration: alarmFullConfiguration(alarm),
	}
	// Native delete includes the state reason, but not its reasonData; create
	// and update include only the value and timestamp.
	if change == "delete" {
		detail.State.Reason = alarm.State.Reason
	}
	if change == "update" && previous != nil {
		configuration := alarmFullConfiguration(*previous)
		detail.PreviousConfiguration = &configuration
	}
	return encodeAlarmDocument(detail)
}

type alarmDocumentInvocation struct {
	Source    string                   `json:"source"`
	AlarmARN  string                   `json:"alarmArn"`
	AccountID string                   `json:"accountId"`
	Time      string                   `json:"time"`
	Region    string                   `json:"region"`
	AlarmData alarmDocumentStateDetail `json:"alarmData"`
}

func alarmInvocationPayload(alarm AlarmRecord, previous AlarmRecord, contributor *AlarmContributorIdentity) []byte {
	return encodeAlarmDocument(alarmDocumentInvocation{Source: "aws.cloudwatch", AlarmARN: alarm.Key.ARN(), AccountID: alarm.Key.AccountID, Time: alarmDocumentTime(alarm.State.Updated), Region: alarm.Key.Region, AlarmData: alarmStateDetail(alarm, &previous, contributor)})
}

// SNS has its own alarm document, not the reduced Lambda invocation. Scalar,
// query and child-driven composite projections follow sns_publications.json.
type alarmSNSDocument struct {
	AlarmName                     string            `json:"AlarmName"`
	AlarmDescription              *string           `json:"AlarmDescription"`
	AWSAccountID                  string            `json:"AWSAccountId"`
	ConfigurationUpdated          string            `json:"AlarmConfigurationUpdatedTimestamp,omitempty"`
	NewStateValue                 string            `json:"NewStateValue"`
	NewStateReason                *string           `json:"NewStateReason"`
	StateChangeTime               string            `json:"StateChangeTime"`
	Region                        string            `json:"Region"`
	AlarmARN                      string            `json:"AlarmArn"`
	OldStateValue                 string            `json:"OldStateValue"`
	ContributorID                 string            `json:"AlarmContributorId,omitempty"`
	ContributorAttributes         map[string]string `json:"AlarmContributorAttributes,omitempty"`
	ActionExecutedAfterMuteWindow *bool             `json:"ActionExecutedAfterMuteWindow,omitempty"`
	OKActions                     []string          `json:"OKActions"`
	AlarmActions                  []string          `json:"AlarmActions"`
	InsufficientDataActions       []string          `json:"InsufficientDataActions"`
	Trigger                       any               `json:"Trigger,omitempty"`
	AlarmRule                     string            `json:"AlarmRule,omitempty"`
	TriggeringChildren            *[]alarmSNSChild  `json:"TriggeringChildren,omitempty"`
}

type alarmSNSDimension struct {
	Value string `json:"value"`
	Name  string `json:"name"`
}

func alarmSNSDimensions(dimensions []Dimension) []alarmSNSDimension {
	out := make([]alarmSNSDimension, len(dimensions))
	for i, dimension := range dimensions {
		out[i] = alarmSNSDimension{Value: dimension.Value, Name: dimension.Name}
	}
	return out
}

type alarmSNSTriggerEvaluation struct {
	Period                           int32       `json:"Period"`
	EvaluationPeriods                int32       `json:"EvaluationPeriods"`
	DatapointsToAlarm                *int32      `json:"DatapointsToAlarm,omitempty"`
	ComparisonOperator               string      `json:"ComparisonOperator"`
	Threshold                        json.Number `json:"Threshold"`
	TreatMissingData                 string      `json:"TreatMissingData"`
	EvaluateLowSampleCountPercentile string      `json:"EvaluateLowSampleCountPercentile"`
}

type alarmSNSScalarTrigger struct {
	MetricName    string              `json:"MetricName"`
	Namespace     string              `json:"Namespace"`
	StatisticType string              `json:"StatisticType"`
	Statistic     string              `json:"Statistic"`
	Unit          *string             `json:"Unit"`
	Dimensions    []alarmSNSDimension `json:"Dimensions"`
	alarmSNSTriggerEvaluation
}

type alarmSNSMetric struct {
	Dimensions []alarmSNSDimension `json:"Dimensions"`
	MetricName string              `json:"MetricName"`
	Namespace  string              `json:"Namespace"`
}

type alarmSNSMetricStat struct {
	Metric alarmSNSMetric `json:"Metric"`
	Period int32          `json:"Period"`
	Stat   string         `json:"Stat"`
	Unit   string         `json:"Unit,omitempty"`
}

type alarmSNSMetricQuery struct {
	Expression string              `json:"Expression,omitempty"`
	ID         string              `json:"Id"`
	Label      *string             `json:"Label,omitempty"`
	MetricStat *alarmSNSMetricStat `json:"MetricStat,omitempty"`
	Period     *int32              `json:"Period,omitempty"`
	ReturnData *bool               `json:"ReturnData,omitempty"`
	AccountID  string              `json:"AccountId,omitempty"`
}

type alarmSNSQueryTrigger struct {
	alarmSNSTriggerEvaluation
	Metrics []alarmSNSMetricQuery `json:"Metrics"`
}

type alarmSNSChild struct {
	ARN   string `json:"Arn"`
	State struct {
		Value     string `json:"Value"`
		Timestamp string `json:"Timestamp"`
	} `json:"State"`
}

func alarmSNSPublication(alarm, previous AlarmRecord, contributor *AlarmContributorIdentity) ([]byte, string) {
	region := awscatalog.RegionDisplayName(alarm.Key.Region)
	document := alarmSNSDocument{
		AlarmName: alarm.Key.Name, AlarmDescription: alarm.Description, AWSAccountID: alarm.Key.AccountID,
		NewStateValue: alarm.State.Value, NewStateReason: alarm.State.Reason,
		StateChangeTime: alarmDocumentTime(alarm.State.Updated), Region: region, AlarmARN: alarm.Key.ARN(),
		OldStateValue: previous.State.Value, OKActions: alarmDocumentActions(alarm.Actions.OK),
		AlarmActions: alarmDocumentActions(alarm.Actions.Alarm), InsufficientDataActions: alarmDocumentActions(alarm.Actions.InsufficientData),
		ActionExecutedAfterMuteWindow: new(false),
	}
	if contributor != nil {
		document.ContributorID, document.ContributorAttributes = contributor.ID, contributor.Attributes
	}
	if metric := alarm.Metric; metric != nil {
		document.ConfigurationUpdated = alarmDocumentTime(alarm.Updated)
		document.Trigger = alarmSNSTrigger(metric)
	} else {
		document.AlarmRule = alarm.Composite.Rule
		// The evaluation-owned reason retains the actual triggering children. Do
		// not read current children: their states may already have advanced.
		var reason struct {
			TriggeringAlarms []compositeTrigger `json:"triggeringAlarms"`
		}
		children := []alarmSNSChild{}
		if json.Unmarshal([]byte(alarm.State.ReasonData), &reason) == nil {
			for _, trigger := range reason.TriggeringAlarms {
				child := alarmSNSChild{ARN: trigger.ARN}
				child.State.Value, child.State.Timestamp = trigger.State.Value, trigger.State.Timestamp
				children = append(children, child)
			}
		}
		document.TriggeringChildren = &children
	}
	publication := struct {
		Default string `json:"default"`
		SMS     string `json:"sms"`
		Email   string `json:"email"`
	}{
		Default: string(encodeAlarmDocument(document)),
		SMS:     alarmSNSHeading(alarm, region, 90),
		Email:   alarmSNSEmail(alarm, previous, document),
	}
	// Unlike SMS's observed 90-character alarm-name budget, Subject has a
	// 100-character total budget, preserving the state, quotes and region.
	nameBudget := 100 - len(alarm.State.Value) - len(region) - len(": \"\" in ")
	return encodeAlarmDocument(publication), alarmSNSHeading(alarm, region, nameBudget)
}

// Native contiguous Unicode names collapse to one underscore. Printable ASCII
// is an inference beyond that capture, not an SNS restriction: public Publish
// accepts UTF-8 subjects. Punctuation outside the captured names is unprobed.
var alarmSNSNonASCII = regexp.MustCompile(`[^\x20-\x7e]+`)

func alarmSNSHeading(alarm AlarmRecord, region string, nameBudget int) string {
	name := alarmSNSNonASCII.ReplaceAllString(alarm.Key.Name, "_")
	if len(name) > nameBudget {
		name = name[:nameBudget-3] + "..."
	}
	return alarm.State.Value + ": \"" + name + "\" in " + region
}

const alarmSNSHumanTimeLayout = "Monday 2 January, 2006 15:04:05 MST"

func alarmSNSActions(actions []string) string {
	if len(actions) == 0 {
		return ""
	}
	return "[" + strings.Join(actions, ", ") + "]"
}

func alarmSNSEmail(alarm, previous AlarmRecord, document alarmSNSDocument) string {
	var body strings.Builder
	reason, description := "", ""
	if alarm.State.Reason != nil {
		reason = *alarm.State.Reason
	}
	if alarm.Description != nil {
		description = *alarm.Description
	}
	at := alarm.State.Updated.UTC().Format(alarmSNSHumanTimeLayout)
	fmt.Fprintf(&body, "You are receiving this email because your Amazon CloudWatch Alarm \"%s\" in the %s region has ", alarm.Key.Name, document.Region)
	if alarm.Composite != nil {
		fmt.Fprintf(&body, "transitioned to %s state on %s, because \"%s\".\n", alarm.State.Value, at, reason)
	} else {
		fmt.Fprintf(&body, "entered the %s state, because \"%s\" at \"%s\".\n", alarm.State.Value, reason, at)
	}
	fmt.Fprintf(&body, "\nView this alarm in the AWS Management Console:\nhttps://%s.console.aws.amazon.com/cloudwatch/deeplink.js?region=%s#alarmsV2:alarm/%s\n", alarm.Key.Region, alarm.Key.Region, url.PathEscape(alarm.Key.Name))
	fmt.Fprintf(&body, "\nAlarm Details:\n- Name:                       %s\n- Description:                %s\n- State Change:               %s -> %s\n", alarm.Key.Name, description, previous.State.Value, alarm.State.Value)
	if alarm.Composite != nil {
		fmt.Fprintf(&body, "- Alarm Rule:                 %s\n", alarm.Composite.Rule)
	}
	fmt.Fprintf(&body, "- Reason for State Change:    %s\n- Timestamp:                  %s\n- AWS Account:                %s\n- Alarm Arn:                  %s\n", reason, at, alarm.Key.AccountID, alarm.Key.ARN())
	if metric := alarm.Metric; metric != nil {
		datapoints := metric.EvaluationPeriods
		if metric.DatapointsToAlarm != nil {
			datapoints = *metric.DatapointsToAlarm
		}
		fmt.Fprintf(&body, "\nThreshold:\n- The alarm is in the ALARM state when the metric is %s %s for at least %d of the last %d period(s) of %d seconds. \n", metric.Comparison, alarmSNSThreshold(metric.Threshold), datapoints, metric.EvaluationPeriods, alarmMetricPeriod(metric))
		if scalar := metric.Metric; scalar != nil {
			unit := scalar.Unit
			if unit == "" {
				unit = "not specified"
			}
			dimensions := make([]string, len(scalar.Dimensions))
			for i, dimension := range scalar.Dimensions {
				dimensions[i] = "[" + dimension.Name + " = " + dimension.Value + "]"
			}
			fmt.Fprintf(&body, "\nMonitored Metric:\n- MetricNamespace:                     %s\n- MetricName:                          %s\n- Dimensions:                          %s\n- Period:                              %d seconds\n- Statistic:                           %s\n- Unit:                                %s\n- TreatMissingData:                    %s\n\n", scalar.Key.Namespace, scalar.Key.Name, strings.Join(dimensions, ", "), scalar.Period, scalar.Statistic, unit, metric.TreatMissingData)
		} else {
			body.WriteString("\nMonitored Metrics:\n")
			for _, query := range metric.Queries {
				if query.ReturnData != nil && !*query.ReturnData {
					continue
				}
				if query.Expression != "" {
					fmt.Fprintf(&body, "- MetricExpression:           %s\n", query.Expression)
				}
				if query.Label != nil {
					fmt.Fprintf(&body, "- MetricLabel:                %s\n", *query.Label)
				}
			}
		}
	} else {
		body.WriteString("\nTriggering children (max. 10):\n")
		for i, child := range *document.TriggeringChildren {
			if i == 10 {
				break
			}
			timestamp := child.State.Timestamp
			if childAt, err := time.Parse(alarmDocumentTimeLayout, timestamp); err == nil {
				timestamp = childAt.UTC().Format(alarmSNSHumanTimeLayout)
			}
			fmt.Fprintf(&body, "- %s   %-20s%s\n", child.ARN, child.State.Value, timestamp)
		}
	}
	fmt.Fprintf(&body, "\nState Change Actions:\n- OK: %s\n- ALARM: %s\n- INSUFFICIENT_DATA: %s\n", alarmSNSActions(alarm.Actions.OK), alarmSNSActions(alarm.Actions.Alarm), alarmSNSActions(alarm.Actions.InsufficientData))
	return body.String()
}

func alarmSNSThreshold(value float64) string {
	threshold := strconv.FormatFloat(value, 'f', -1, 64)
	if !strings.Contains(threshold, ".") {
		threshold += ".0"
	}
	return threshold
}

func alarmSNSTrigger(config *MetricAlarmConfig) any {
	threshold := alarmSNSThreshold(config.Threshold)
	evaluation := alarmSNSTriggerEvaluation{
		EvaluationPeriods: config.EvaluationPeriods, DatapointsToAlarm: config.DatapointsToAlarm,
		ComparisonOperator: config.Comparison, Threshold: json.Number(threshold),
		TreatMissingData: config.TreatMissingData, EvaluateLowSampleCountPercentile: config.LowSampleCount,
	}
	if scalar := config.Metric; scalar != nil {
		evaluation.Period = scalar.Period
		trigger := alarmSNSScalarTrigger{
			MetricName: scalar.Key.Name, Namespace: scalar.Key.Namespace,
			StatisticType: "ExtendedStatistic", Statistic: scalar.Statistic,
			Dimensions: alarmSNSDimensions(scalar.Dimensions), alarmSNSTriggerEvaluation: evaluation,
		}
		if basicStatistic(scalar.Statistic) {
			trigger.StatisticType, trigger.Statistic = "Statistic", strings.ToUpper(scalar.Statistic)
		}
		if scalar.Unit != "" {
			trigger.Unit = &scalar.Unit
		}
		return trigger
	}
	queries := make([]alarmSNSMetricQuery, len(config.Queries))
	for i, query := range config.Queries {
		projected := alarmSNSMetricQuery{Expression: query.Expression, ID: query.ID, Label: query.Label, Period: query.Period, ReturnData: query.ReturnData, AccountID: query.AccountID}
		if metric := query.Metric; metric != nil {
			projected.MetricStat = &alarmSNSMetricStat{
				Metric: alarmSNSMetric{Dimensions: alarmSNSDimensions(metric.Dimensions), MetricName: metric.Key.Name, Namespace: metric.Key.Namespace},
				Period: metric.Period, Stat: metric.Statistic, Unit: metric.Unit,
			}
		}
		queries[i] = projected
	}
	evaluation.Period = int32(alarmMetricPeriod(config))
	return alarmSNSQueryTrigger{alarmSNSTriggerEvaluation: evaluation, Metrics: queries}
}

type alarmHistoryDimension struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func alarmHistoryDimensions(dimensions []Dimension) []alarmHistoryDimension {
	projected := make([]alarmHistoryDimension, len(dimensions))
	for i, dimension := range dimensions {
		projected[i] = alarmHistoryDimension(dimension)
	}
	return projected
}

type alarmHistoryMetric struct {
	Namespace  string                  `json:"namespace"`
	MetricName string                  `json:"metricName"`
	Dimensions []alarmHistoryDimension `json:"dimensions"`
}

type alarmHistoryMetricStat struct {
	Metric alarmHistoryMetric `json:"metric"`
	Period int32              `json:"period"`
	Stat   string             `json:"stat"`
	Unit   string             `json:"unit,omitempty"`
}

type alarmHistoryMetricQuery struct {
	ID         string                  `json:"id"`
	MetricStat *alarmHistoryMetricStat `json:"metricStat,omitempty"`
	Expression string                  `json:"expression,omitempty"`
	AccountID  string                  `json:"accountId,omitempty"`
	Label      *string                 `json:"label,omitempty"`
	Period     *int32                  `json:"period,omitempty"`
	ReturnData *bool                   `json:"returnData,omitempty"`
}

func alarmHistoryMetrics(queries []AlarmMetricQuery) []alarmHistoryMetricQuery {
	projected := make([]alarmHistoryMetricQuery, len(queries))
	for i, query := range queries {
		projected[i] = alarmHistoryMetricQuery{ID: query.ID, Expression: query.Expression, AccountID: query.AccountID, Label: query.Label, Period: query.Period, ReturnData: query.ReturnData}
		if metric := query.Metric; metric != nil {
			projected[i].MetricStat = &alarmHistoryMetricStat{
				Metric: alarmHistoryMetric{Namespace: metric.Key.Namespace, MetricName: metric.Key.Name, Dimensions: alarmHistoryDimensions(metric.Dimensions)},
				Period: metric.Period, Stat: metric.Statistic, Unit: metric.Unit,
			}
		}
	}
	return projected
}

type alarmHistoryChildState struct {
	Value               string `json:"value"`
	TransitionTimestamp string `json:"transitionTimestamp"`
	Timestamp           string `json:"timestamp"`
}

type alarmHistoryChild struct {
	ARN   string                 `json:"arn"`
	State alarmHistoryChildState `json:"state"`
}

func alarmHistoryChildren(alarm AlarmRecord, children []AlarmRecord) []alarmHistoryChild {
	projected := make([]alarmHistoryChild, 0, len(children))
	for _, child := range children {
		if !slices.Contains(alarm.Composite.Children, child.Key.Name) && alarm.Composite.Suppressor != child.Key.Name && alarm.Composite.Suppressor != child.Key.ARN() {
			continue
		}
		projected = append(projected, alarmHistoryChild{ARN: child.Key.ARN(), State: alarmHistoryChildState{
			Value: child.State.Value, TransitionTimestamp: alarmDocumentTime(child.State.Transitioned), Timestamp: alarmDocumentTime(child.State.Updated),
		}})
	}
	return projected
}

// History is not an EventBridge configuration. Scalar metrics remain scalar,
// basic statistics are upper-case extendedStatistic values, and okactions has
// native all-lowercase spelling. Optional admission fields remain absent.
type alarmHistoryConfiguration struct {
	AlarmName                          string                    `json:"alarmName"`
	AlarmDescription                   *string                   `json:"alarmDescription,omitempty"`
	AlarmARN                           string                    `json:"alarmArn"`
	AlarmConfigurationUpdatedTimestamp string                    `json:"alarmConfigurationUpdatedTimestamp"`
	Namespace                          string                    `json:"namespace,omitempty"`
	MetricName                         string                    `json:"metricName,omitempty"`
	ExtendedStatistic                  string                    `json:"extendedStatistic,omitempty"`
	Period                             *int32                    `json:"period,omitempty"`
	Dimensions                         *[]alarmHistoryDimension  `json:"dimensions,omitempty"`
	Unit                               string                    `json:"unit,omitempty"`
	Metrics                            []alarmHistoryMetricQuery `json:"metrics,omitempty"`
	Threshold                          *float64                  `json:"threshold,omitempty"`
	ComparisonOperator                 string                    `json:"comparisonOperator,omitempty"`
	EvaluationPeriods                  *int32                    `json:"evaluationPeriods,omitempty"`
	DatapointsToAlarm                  *int32                    `json:"datapointsToAlarm,omitempty"`
	TreatMissingData                   string                    `json:"treatMissingData,omitempty"`
	EvaluateLowSampleCountPercentile   string                    `json:"evaluateLowSampleCountPercentile,omitempty"`
	AlarmRule                          string                    `json:"alarmRule,omitempty"`
	ActionsSuppressor                  string                    `json:"actionsSuppressor,omitempty"`
	ActionsSuppressorWaitPeriod        *int32                    `json:"actionsSuppressorWaitPeriod,omitempty"`
	ActionsSuppressorExtensionPeriod   *int32                    `json:"actionsSuppressorExtensionPeriod,omitempty"`
	StateValue                         string                    `json:"stateValue"`
	StateUpdatedTimestamp              string                    `json:"stateUpdatedTimestamp"`
	ActionsEnabled                     bool                      `json:"actionsEnabled"`
	AlarmActions                       []string                  `json:"alarmActions"`
	InsufficientDataActions            []string                  `json:"insufficientDataActions"`
	OKActions                          []string                  `json:"okactions"`
	ChildStates                        *[]alarmHistoryChild      `json:"childStates,omitempty"`
}

func alarmHistoryConfigurationFor(alarm AlarmRecord, children []AlarmRecord) alarmHistoryConfiguration {
	configuration := alarmHistoryConfiguration{
		AlarmName: alarm.Key.Name, AlarmDescription: alarm.Description, AlarmARN: alarm.Key.ARN(), AlarmConfigurationUpdatedTimestamp: alarmDocumentTime(alarm.Updated),
		StateValue: alarm.State.Value, StateUpdatedTimestamp: alarmDocumentTime(alarm.State.Updated), ActionsEnabled: alarm.ActionsEnabled,
		AlarmActions: alarmDocumentActions(alarm.Actions.Alarm), InsufficientDataActions: alarmDocumentActions(alarm.Actions.InsufficientData), OKActions: alarmDocumentActions(alarm.Actions.OK),
	}
	if metric := alarm.Metric; metric != nil {
		configuration.Threshold = &metric.Threshold
		configuration.ComparisonOperator = metric.Comparison
		configuration.EvaluationPeriods = &metric.EvaluationPeriods
		configuration.DatapointsToAlarm = metric.DatapointsToAlarm
		configuration.TreatMissingData = metric.TreatMissingData
		configuration.EvaluateLowSampleCountPercentile = metric.LowSampleCount
		if scalar := metric.Metric; scalar != nil {
			configuration.Namespace = scalar.Key.Namespace
			configuration.MetricName = scalar.Key.Name
			configuration.ExtendedStatistic = scalar.Statistic
			switch scalar.Statistic {
			case "Average", "Minimum", "Maximum", "Sum", "SampleCount":
				configuration.ExtendedStatistic = strings.ToUpper(scalar.Statistic)
			}
			configuration.Period = &scalar.Period
			configuration.Unit = scalar.Unit
			dimensions := alarmHistoryDimensions(scalar.Dimensions)
			configuration.Dimensions = &dimensions
		} else {
			dimensions := []alarmHistoryDimension{}
			configuration.Dimensions = &dimensions
			configuration.Metrics = alarmHistoryMetrics(metric.Queries)
		}
	}
	if composite := alarm.Composite; composite != nil {
		childStates := alarmHistoryChildren(alarm, children)
		configuration.ChildStates = &childStates
		configuration.AlarmRule = composite.Rule
		configuration.ActionsSuppressor = composite.Suppressor
		if composite.Suppressor != "" {
			configuration.ActionsSuppressorWaitPeriod = &composite.WaitPeriod
			configuration.ActionsSuppressorExtensionPeriod = &composite.ExtensionPeriod
		}
	}
	return configuration
}

type alarmDocumentConfigurationHistory struct {
	Version               string                      `json:"version"`
	Type                  string                      `json:"type"`
	CreatedAlarm          *alarmHistoryConfiguration  `json:"createdAlarm,omitempty"`
	UpdatedAlarm          *alarmHistoryConfiguration  `json:"updatedAlarm,omitempty"`
	DeletedAlarm          *alarmHistoryConfiguration  `json:"deletedAlarm,omitempty"`
	OriginalUpdatedFields *map[string]json.RawMessage `json:"originalUpdatedFields,omitempty"`
}

func alarmConfigurationHistoryData(alarm AlarmRecord, previous *AlarmRecord, change string, children []AlarmRecord) string {
	configuration := alarmHistoryConfigurationFor(alarm, children)
	history := alarmDocumentConfigurationHistory{Version: "1.0"}
	switch change {
	case "create":
		history.Type, history.CreatedAlarm = "Create", &configuration
	case "delete":
		history.Type, history.DeletedAlarm = "Delete", &configuration
	case "update":
		history.Type, history.UpdatedAlarm = "Update", &configuration
		if previous != nil {
			fields := alarmOriginalUpdatedFields(alarmHistoryConfigurationFor(*previous, children), configuration)
			history.OriginalUpdatedFields = &fields
		}
	default:
		panic("invalid admitted alarm configuration change: " + change)
	}
	return string(encodeAlarmDocument(history))
}

// Native originalUpdatedFields is a sparse subset of the typed old document,
// not previousConfiguration. Newly introduced fields have no original value.
// RawMessage is used only for this dynamic subset; its values are all encoded
// from the typed projection above, not arbitrary caller-supplied objects.
func alarmOriginalUpdatedFields(previous, current alarmHistoryConfiguration) map[string]json.RawMessage {
	var oldFields, newFields map[string]json.RawMessage
	if err := json.Unmarshal(encodeAlarmDocument(previous), &oldFields); err != nil {
		panic(fmt.Errorf("decode encoded alarm history fields: %w", err))
	}
	if err := json.Unmarshal(encodeAlarmDocument(current), &newFields); err != nil {
		panic(fmt.Errorf("decode encoded alarm history fields: %w", err))
	}
	for name, oldValue := range oldFields {
		if bytes.Equal(oldValue, newFields[name]) {
			delete(oldFields, name)
		}
	}
	return oldFields
}

type alarmDocumentHistoryState struct {
	Value                   string          `json:"stateValue"`
	Reason                  *string         `json:"stateReason"`
	ReasonData              json.RawMessage `json:"stateReasonData,omitempty"`
	ActionsSuppressedBy     string          `json:"actionsSuppressedBy,omitempty"`
	ActionsSuppressedReason string          `json:"actionsSuppressedReason,omitempty"`
}

func alarmHistoryState(alarm AlarmRecord) alarmDocumentHistoryState {
	state := alarm.State
	return alarmDocumentHistoryState{Value: state.Value, Reason: state.Reason, ReasonData: json.RawMessage(state.ReasonData), ActionsSuppressedBy: alarm.SuppressionPhase, ActionsSuppressedReason: alarmSuppressionReason(alarm)}
}

func alarmStateHistoryData(alarm AlarmRecord, previous AlarmRecord) string {
	return string(encodeAlarmDocument(struct {
		Version  string                    `json:"version"`
		OldState alarmDocumentHistoryState `json:"oldState"`
		NewState alarmDocumentHistoryState `json:"newState"`
	}{Version: "1.0", OldState: alarmHistoryState(previous), NewState: alarmHistoryState(alarm)}))
}

func alarmActionHistoryData(action AlarmActionRecord, status string, reason string, at time.Time) string {
	var failure *string
	if status == "Failed" {
		failure = &reason
	}
	var published *string
	if status == "Succeeded" && strings.SplitN(action.TargetARN, ":", 4)[2] == "sns" {
		published = new(string(action.Payload))
	}
	// The native timestamp identifies the source state update (including a
	// suppression release), not asynchronous delivery completion. Accepted is
	// captured at that update; at belongs to the enclosing history timestamp.
	return string(encodeAlarmDocument(struct {
		ActionState            string  `json:"actionState"`
		StateUpdateTimestamp   int64   `json:"stateUpdateTimestamp"`
		NotificationResource   string  `json:"notificationResource"`
		PublishedMessage       *string `json:"publishedMessage"`
		Error                  *string `json:"error"`
		MuteWindowEndTimestamp *int64  `json:"muteWindowEndTimestamp"`
	}{ActionState: status, StateUpdateTimestamp: action.Accepted.UnixMilli(), NotificationResource: action.TargetARN, PublishedMessage: published, Error: failure}))
}
