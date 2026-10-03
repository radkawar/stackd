package cloudwatch

import "time"

// AlarmKey identifies the shared metric/composite alarm name within a Region.
type AlarmKey struct {
	Scope
	Name string
}

func (k AlarmKey) ARN() string {
	return "arn:" + k.Partition + ":cloudwatch:" + k.Region + ":" + k.AccountID + ":alarm:" + k.Name
}

// AlarmMetricStat retains the admitted metric identity and query statistic.
// Dimensions are detached canonical name/value pairs, as for MetricRecord.
type AlarmMetricStat struct {
	Key        MetricKey
	Dimensions []Dimension
	Period     int32
	Statistic  string
	Unit       string
}

// AlarmMetricQuery preserves optional query fields for native descriptions.
// Admission requires exactly one of Metric and Expression.
type AlarmMetricQuery struct {
	ID         string
	Metric     *AlarmMetricStat
	Expression string
	AccountID  string
	Label      *string
	Period     *int32
	ReturnData *bool
}

// MetricAlarmConfig retains scalar versus query-based configuration. Defaults
// used by evaluation do not manufacture absent fields in DescribeAlarms.
type MetricAlarmConfig struct {
	QueryID           string
	Metric            *AlarmMetricStat
	Queries           []AlarmMetricQuery
	Comparison        string
	Threshold         float64
	EvaluationPeriods int32
	DatapointsToAlarm *int32
	TreatMissingData  string
	LowSampleCount    string
}

// CompositeAlarmConfig stores the admitted rule and canonical local child names.
// Referenced rule children and suppressors cannot be deleted while in use.
type CompositeAlarmConfig struct {
	Rule            string
	Children        []string
	Suppressor      string
	WaitPeriod      int32
	ExtensionPeriod int32
}

type AlarmActions struct {
	Alarm            []string
	OK               []string
	InsufficientData []string
}

// AlarmOrigin connects retained evaluation work to its committed source event.
// RequestID is correlation metadata, not the identity used to authorize actions.
type AlarmOrigin struct {
	EventID, RequestID string
}

// AlarmState distinguishes the last evaluation update from a state transition.
// Empty ReasonData means absent; JSON null is retained as the string "null".
type AlarmState struct {
	Value, ReasonData     string
	Reason                *string
	Updated, Transitioned time.Time
	Origin                AlarmOrigin
}

// AlarmRecord owns configuration, current state and the next retained evaluation.
// Exactly one configuration is present. Version fences scheduler selections;
// a recreated name receives a new ID. Histories and accepted actions outlive it.
type AlarmRecord struct {
	Key               AlarmKey
	ID                string
	Version           uint64
	Created, Updated  time.Time
	Description       *string
	ActionsEnabled    bool
	Actions           AlarmActions
	Tags              map[string]string
	Metric            *MetricAlarmConfig
	Composite         *CompositeAlarmConfig
	State             AlarmState
	NextEvaluation    *time.Time
	SuppressionPhase  string
	SuppressionReason string
	SuppressionUntil  *time.Time
	EvaluationOrigin  AlarmOrigin
}

func (a AlarmRecord) Type() string {
	if a.Composite != nil {
		return "CompositeAlarm"
	}
	return "MetricAlarm"
}

// EvaluationDeadline selects the next rule/metric evaluation or suppression timer.
func (a AlarmRecord) EvaluationDeadline() (time.Time, bool) {
	deadline := a.NextEvaluation
	if a.SuppressionUntil != nil && (deadline == nil || a.SuppressionUntil.Before(*deadline)) {
		deadline = a.SuppressionUntil
	}
	if deadline == nil {
		return time.Time{}, false
	}
	return *deadline, true
}

// AlarmQuery selects detached records in name order, starting at FromName
// inclusively. Empty Names or Types impose no corresponding filter; API defaults
// belong to the command. ParentOf selects rule references, SuppressedBy suppressors.
type AlarmQuery struct {
	Scope
	Names                            []string
	Types                            []string
	Prefix, State, ActionPrefix      string
	ParentOf, SuppressedBy, FromName string
	Limit                            int
}

// AlarmContributorIdentity identifies a grouped query result independently of
// its rank and alarm incarnation. Attributes are the native GROUP BY values.
type AlarmContributorIdentity struct {
	ID         string
	Attributes map[string]string
}

// AlarmContributorRecord retains only contributors currently in ALARM. Recovery
// removes this record, not the contributor's history or accepted actions.
type AlarmContributorRecord struct {
	AlarmContributorIdentity
	Reason       string
	Transitioned time.Time
}

// AlarmContributorQuery selects detached active contributors in ID order,
// excluding AfterID, for one live alarm incarnation.
type AlarmContributorQuery struct {
	AlarmID string
	AfterID string
	Limit   int
}

// AlarmHistoryRecord remains addressable by name after deletion and recreation.
// Data is the native HistoryData JSON document, not serialized resource state.
type AlarmHistoryRecord struct {
	ID                       string
	Key                      AlarmKey
	AlarmType, Type, Summary string
	At                       time.Time
	Data                     string
	Contributor              *AlarmContributorIdentity
}

// AlarmHistoryQuery selects [Start, End] in timestamp/ID order. AfterAt/AfterID
// continue that order; Descending reverses it. Empty Name/Types/Type are unfiltered.
type AlarmHistoryQuery struct {
	Scope
	Name          string
	ContributorID string
	Contributors  bool
	AlarmTypes    []string
	Type          string
	Start, End    time.Time
	AfterAt       *time.Time
	AfterID       string
	Descending    bool
	Limit         int
}

// AlarmActionRecord is an accepted asynchronous action, independent of current
// configuration and source-resource lifetime. Payload and Subject are the native
// destination document. Due schedules ready actions, never suppressed actions.
type AlarmActionRecord struct {
	ID, EventID, RequestID      string
	Key                         AlarmKey
	AlarmType, TargetARN, State string
	Payload                     []byte
	Subject                     string
	Accepted                    time.Time
	Due                         time.Time
	Version                     uint64
	Attempts                    int64
	Contributor                 *AlarmContributorIdentity
}
