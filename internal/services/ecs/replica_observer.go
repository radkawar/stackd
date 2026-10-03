package ecs

import (
	"context"

	api "stackd/internal/awsapi/ecs"
)

// ServiceStateObserver joins dependent resource transitions to the ECS owner
// transaction. The borrowed public data contains actual running counts, not a
// claim that an accepted desired-count update has already started containers.
type ServiceStateObserver interface {
	ObserveService(context.Context, ServiceKey, *api.Service) error
}

func (s *Service) putService(tx Transaction, record ServiceRecord) error {
	if value(record.Data.Status) == "INACTIVE" {
		if err := tx.DeleteServiceRevisions(record.Key); err != nil {
			return err
		}
	}
	if err := tx.PutService(record); err != nil {
		return err
	}
	if s.serviceState != nil {
		return s.serviceState.ObserveService(tx.Context(), record.Key, &record.Data)
	}
	return nil
}
