package cloudwatch

import (
	"context"
	"time"

	"stackd/internal/awswire"
)

// AlarmEvent is a native CloudWatch event for one scoped alarm. Its ID also
// identifies the cause of actions selected by that transition.
type AlarmEvent struct {
	ID         string
	Alarm      AlarmKey
	At         time.Time
	DetailType string
	Detail     []byte
}

// AlarmEventPublisher joins the source transaction, admitting native events and
// their matching target work together with the alarm transition.
type AlarmEventPublisher interface {
	PublishAlarmEvent(context.Context, AlarmEvent) error
}

// ScalingAlarmSignal retains the accepted metric comparison with its reason
// data. It is an internal action payload, not an AWS API response document.
type ScalingAlarmSignal struct {
	ReasonData string `json:"reasonData"`
	Comparison string `json:"comparison"`
}

// AlarmActionSender crosses the external-effect boundary only after the action
// intent commits. The destination service owns delivery after acceptance.
type AlarmActionSender interface {
	Send(context.Context, AlarmActionRecord) *awswire.Error
}
