// Package cloudwatch owns metrics, alarms and account-global dashboards.
package cloudwatch

import (
	"context"
	"errors"
	"time"

	"stackd/internal/scheduler"
)

// ErrNotFound reports a missing CloudWatch resource or retained work record.
var ErrNotFound = errors.New("CloudWatch resource not found")

type Scope struct{ Partition, AccountID, Region string }

type Dimension struct{ Name, Value string }

// MetricKey uses the canonical dimension encoding produced by metric admission.
// Unit and storage resolution describe observations, not metric identity.
type MetricKey struct {
	Scope
	Namespace, Name, Dimensions string
}

type MetricRecord struct {
	Key                  MetricKey
	ID                   string
	Dimensions           []Dimension
	Created, PublishedAt time.Time
}

// Point retains one weighted value or one supplied statistic set. Raw marks
// whether its distribution is known; general statistic sets cannot supply it.
// Timestamp is a Unix second at the admitted storage resolution.
type Point struct {
	Timestamp                          int64
	Unit                               string
	Resolution                         int32
	SampleCount, Sum, Minimum, Maximum float64
	Raw                                bool
}

type DimensionFilter struct {
	Name  string
	Value *string
}

type MetricQuery struct {
	Scope
	Namespace, Name string
	Dimensions      []DimensionFilter
	PublishedAfter  time.Time
	After           *MetricKey
	Limit           int
}

type PointQuery struct {
	MetricID   string
	Start, End int64
}

type Reader interface {
	Context() context.Context
	Metric(MetricKey) (MetricRecord, error)
	// Metrics returns matching identities in namespace/name/dimensions order.
	Metrics(MetricQuery) ([]MetricRecord, error)
	// Points visits [Start, End) in publication order without retaining an
	// unbounded result slice. The callback runs inside this read transaction.
	Points(PointQuery, func(Point) error) error
	Alarm(AlarmKey) (AlarmRecord, error)
	AlarmByID(string) (AlarmRecord, error)
	Alarms(AlarmQuery) ([]AlarmRecord, error)
	AlarmContributors(AlarmContributorQuery) ([]AlarmContributorRecord, error)
	AlarmHistory(AlarmHistoryQuery) ([]AlarmHistoryRecord, error)
	NextAlarmEvaluation() (scheduler.Job, bool, error)
	AlarmAction(string) (AlarmActionRecord, error)
	NextAlarmAction() (scheduler.Job, bool, error)
	Dashboard(DashboardKey) (DashboardRecord, error)
	// Dashboards returns metadata in case-sensitive name order, excluding After.
	Dashboards(DashboardQuery) ([]DashboardEntry, error)
}

type Transaction interface {
	Reader
	PutMetric(MetricRecord) error
	AppendPoints(metricID string, points []Point) error
	PutAlarm(AlarmRecord) error
	// UpdateAlarmEvaluation changes only evaluation state and scheduling by ID.
	// It returns ErrNotFound if the alarm no longer exists.
	UpdateAlarmEvaluation(AlarmRecord) error
	DeleteAlarm(AlarmKey) error
	PutAlarmContributor(alarmID string, contributor AlarmContributorRecord) error
	DeleteAlarmContributor(alarmID, contributorID string) error
	AppendAlarmHistory(AlarmHistoryRecord) error
	// ExpireAlarmHistory removes rows strictly older than the scoped cutoff.
	ExpireAlarmHistory(Scope, time.Time) error
	PutAlarmAction(AlarmActionRecord) error
	DeleteAlarmAction(string) error
	PutDashboard(DashboardRecord) error
	DeleteDashboard(DashboardKey) error
}

// Repository joins the instance transaction domain. Source log ingestion,
// extracted metric publication and journal outcomes commit or roll back together.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	// Attempt isolates a public command rejection within an enclosing write.
	Attempt(context.Context, func(Transaction) error) error
}
