package mq

import (
	"context"

	api "stackd/internal/awsapi/mq"
)

func (s *Service) logSettings(v BrokerRecord, in *api.Logs, pending bool) (LogSettings, error) {
	settings := v.Logs
	if pending && v.PendingLogs != nil {
		settings = *v.PendingLogs
	}
	if in != nil {
		if in.General != nil {
			settings.General = truth(in.General)
		}
		if in.Audit != nil {
			settings.Audit = truth(in.Audit)
		}
	}
	if v.Engine == "RABBITMQ" && settings.Audit {
		return LogSettings{}, invalid("Amazon MQ does not support audit logging for RabbitMQ brokers")
	}
	if !settings.General && !settings.Audit {
		return settings, nil
	}
	if _, ok := s.runtime.(LogSource); !ok || s.logs == nil {
		return LogSettings{}, invalid("Native broker logging and the CloudWatch Logs owner must be configured")
	}
	return settings, nil
}

func logsOutput(settings LogSettings) *api.Logs {
	out := &api.Logs{}
	boolean(&out.General, settings.General)
	boolean(&out.Audit, settings.Audit)
	return out
}

func logsSummary(v BrokerRecord) *api.LogsSummary {
	out := &api.LogsSummary{}
	boolean(&out.General, v.Logs.General)
	boolean(&out.Audit, v.Logs.Audit)
	// The modeled destination describes configuration, not delivery success.
	text(&out.GeneralLogGroup, "/aws/amazonmq/broker/"+v.ID+"/general")
	if v.Logs.Audit {
		text(&out.AuditLogGroup, "/aws/amazonmq/broker/"+v.ID+"/audit")
	}
	if v.PendingLogs != nil {
		out.Pending = &api.PendingLogs{}
		boolean(&out.Pending.General, v.PendingLogs.General)
		boolean(&out.Pending.Audit, v.PendingLogs.Audit)
	}
	return out
}

func (s *Service) prepareLogGroups(ctx context.Context, v *BrokerRecord, settings LogSettings) error {
	if !settings.General && !settings.Audit {
		return nil
	}
	if s.logs == nil {
		return invalid("CloudWatch Logs owner must be configured")
	}
	wire := s.logs.Prepare(ctx, *v, settings)
	if wire == nil {
		v.LogDeliveryError = ""
		return nil
	}
	// Keep preparation denial visible internally without blocking the broker.
	// Delivery rechecks current authority and cannot advance on denial:
	// ActiveMQ needs a resource policy; RabbitMQ needs its linked role.
	switch wire.Code {
	case "AccessDenied", "AccessDeniedException", "ForbiddenException":
		v.LogDeliveryError = wire.Error()
		return nil
	default:
		return wire
	}
}
