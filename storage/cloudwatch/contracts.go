// Package cloudwatch exposes service-owned CloudWatch storage contracts.
package cloudwatch

import (
	domain "stackd/internal/services/cloudwatch"
	"stackd/storage/memory"
)

type (
	Repository               = domain.Repository
	Reader                   = domain.Reader
	Transaction              = domain.Transaction
	Scope                    = domain.Scope
	Dimension                = domain.Dimension
	MetricKey                = domain.MetricKey
	MetricRecord             = domain.MetricRecord
	Point                    = domain.Point
	DimensionFilter          = domain.DimensionFilter
	MetricQuery              = domain.MetricQuery
	PointQuery               = domain.PointQuery
	AlarmKey                 = domain.AlarmKey
	AlarmMetricStat          = domain.AlarmMetricStat
	AlarmMetricQuery         = domain.AlarmMetricQuery
	MetricAlarmConfig        = domain.MetricAlarmConfig
	CompositeAlarmConfig     = domain.CompositeAlarmConfig
	AlarmActions             = domain.AlarmActions
	AlarmOrigin              = domain.AlarmOrigin
	AlarmState               = domain.AlarmState
	AlarmRecord              = domain.AlarmRecord
	AlarmQuery               = domain.AlarmQuery
	AlarmContributorIdentity = domain.AlarmContributorIdentity
	AlarmContributorRecord   = domain.AlarmContributorRecord
	AlarmContributorQuery    = domain.AlarmContributorQuery
	AlarmHistoryRecord       = domain.AlarmHistoryRecord
	AlarmHistoryQuery        = domain.AlarmHistoryQuery
	AlarmActionRecord        = domain.AlarmActionRecord
	DashboardKey             = domain.DashboardKey
	DashboardEntry           = domain.DashboardEntry
	DashboardRecord          = domain.DashboardRecord
	DashboardQuery           = domain.DashboardQuery
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
