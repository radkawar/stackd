package mq

import (
	"context"
	"errors"
	"fmt"
)

// sameMetricObservation fences the retained reconciliation, not just API intent:
// consecutive health observations can have the same Version and native identity.
func sameMetricObservation(current, observed BrokerRecord) bool {
	return (current.Engine == "RABBITMQ" || current.Engine == "ACTIVEMQ") && current.Engine == observed.Engine &&
		current.State == "RUNNING" && current.Operation == "" &&
		current.Version == observed.Version && current.Endpoint.NativeID == observed.Endpoint.NativeID &&
		current.Endpoint.NativeID != "" && current.Endpoint.Address != "" && len(current.Endpoint.CAPEM) != 0 &&
		!current.Due.IsZero() && current.Due.Equal(observed.Due)
}

func (s *Service) deliverMetrics(ctx context.Context, observed BrokerRecord) error {
	source, ok := s.runtime.(MetricSource)
	if !ok || s.metrics == nil || (observed.Engine != "RABBITMQ" && observed.Engine != "ACTIVEMQ") {
		return nil
	}
	var current BrokerRecord
	eligible := false
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		current, err = r.Broker(observed.Scope, observed.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		eligible = sameMetricObservation(current, observed)
		return nil
	})
	if err != nil {
		return fmt.Errorf("MQ metrics source snapshot: %w", err)
	}
	if !eligible {
		return nil
	}
	// Read actual native counters only after readiness commits, and never while
	// holding a resource transaction. The source receives the current identity.
	snapshot, err := source.ReadMetrics(ctx, current)
	if err != nil {
		return fmt.Errorf("MQ metrics read: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if (current.Engine == "RABBITMQ" && (snapshot.RabbitMQ == nil || snapshot.ActiveMQ != nil)) ||
		(current.Engine == "ACTIVEMQ" && (snapshot.ActiveMQ == nil || snapshot.RabbitMQ != nil)) {
		return fmt.Errorf("MQ metrics read: snapshot does not match %s engine", current.Engine)
	}
	at := s.clock.Now()
	err = s.repository.Update(ctx, func(tx Transaction) error {
		latest, err := tx.Broker(current.Scope, current.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !sameMetricObservation(latest, current) {
			return nil
		}
		// The publisher joins this transaction; partial CloudWatch publication
		// rolls back without undoing readiness or rescheduling an old sample.
		return s.metrics.PublishMQMetrics(tx.Context(), latest, snapshot, at)
	})
	if err != nil {
		return fmt.Errorf("MQ metrics publication: %w", err)
	}
	return nil
}
