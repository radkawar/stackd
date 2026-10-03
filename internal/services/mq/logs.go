package mq

import (
	"context"
	"time"

	"stackd/internal/awswire"
)

// LogSettings are effective only after native broker creation or reboot.
type LogSettings struct {
	General bool
	Audit   bool
}

type LogType string

const (
	GeneralLog LogType = "general"
	AuditLog   LogType = "audit"
)

// LogCursor identifies a retained native file and the next unread byte. It is
// committed with delivery, never merely because the native file was read.
type LogCursor struct {
	FileID string
	Offset int64
}

type LogRecord struct {
	Timestamp time.Time
	Message   string
}

type LogBatch struct {
	Records []LogRecord
	Next    LogCursor
	// LostPrefix reports that rotation retired the previously retained source
	// position. Available records remain real; the caller must surface the gap.
	LostPrefix bool
}

// LogSource reads bounded native records outside resource transactions. A batch
// must fit one CloudWatch Logs PutLogEvents request, including event overhead.
type LogSource interface {
	ReadLogs(context.Context, BrokerRecord, LogType, LogCursor) (LogBatch, error)
}

// LogDelivery only mutates the shared transactional CloudWatch Logs owner.
// ActiveMQ Prepare uses the current caller and Write uses MQ resource authority.
// RabbitMQ uses its current service-linked role for both operations.
// Neither performs native/external I/O.
type LogDelivery interface {
	Prepare(context.Context, BrokerRecord, LogSettings) *awswire.Error
	Write(context.Context, BrokerRecord, LogType, []LogRecord) error
}
