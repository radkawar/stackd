package eventbridge

import (
	"context"
	"errors"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// ForwardToBus admits a retained event under the selected target role. It is
// internal ingress, not a customer PutEvents call: first-party sources, original
// producer identity and forwarding history survive the destination transaction.
func (s *Service) ForwardToBus(ctx context.Context, targetARN string, event EventRecord) *awswire.Error {
	key, rejected := busKey(ctx, targetARN)
	if rejected != nil {
		return rejected
	}
	crossRegion := key.Region != event.Bus.Region
	if crossRegion && event.CrossRegionHop {
		return failure("THIRD_REGION_HOP_DETECTED", "Unknown exception.")
	}
	if !crossRegion && event.SameRegionHop {
		return failure("THIRD_ACCOUNT_HOP_DETECTED", "Events received from another event bus cannot be forwarded to this event bus.")
	}
	encryption, rejected := s.prepareBusEncryption(ctx, key, event.Source, event.DetailType, true, "true")
	if rejected != nil {
		return rejected
	}
	defer clear(encryption.plain)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		bus, err := s.bus(tx, key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		conditions := map[string][]string{
			"events:source": {event.Source}, "events:detail-type": {event.DetailType},
			"events:eventBusInvocation": {"true"},
		}
		if denied := s.authorize(tx, "PutEvents", key.ARN(), bus.Tags, conditions, bus.Policy); denied != nil {
			return denied
		}
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		now := s.clock.Now()
		forwarded := event
		forwarded.ID, forwarded.Bus, forwarded.Accepted = identifier(), key, now
		metadata := awsctx.FromContext(ctx)
		forwarded.RequestID, forwarded.ActorARN = metadata.RequestID, metadata.PrincipalARN
		if crossRegion {
			forwarded.WireID, forwarded.Time = forwarded.ID, now
			forwarded.SameRegionHop, forwarded.CrossRegionHop = false, true
		} else {
			forwarded.SameRegionHop = true
		}
		return commitEvent(tx, forwarded, s.events, s.metrics, eventSelection{Encryption: encryption})
	})
	if err != nil {
		return wireError(err)
	}
	s.jobs.Wake()
	return nil
}
