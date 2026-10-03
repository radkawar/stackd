package ec2

import (
	"context"
	"time"

	native "stackd/compute/ec2"
)

// checkpointInstancePerformance retains the retiring VMM's measured contribution
// and cursor before destructive native work. The reducer publishes due windows;
// the terminal transition or replacement VMM flushes any remaining contribution
// once, even after cleanup failure. Native observations must precede this tx.
func (s *Service) checkpointInstancePerformance(tx Transaction, record *InstanceRecord, observation *instancePerformanceObservation) error {
	if err := s.recordInstancePerformance(tx.Context(), record, observation, false); err != nil {
		return err
	}
	return tx.PutInstance(*record)
}

func (s *Service) beforeInstancePerformanceStop(ctx context.Context, before InstanceRecord, handle native.Instance, cpu instanceCPUObservation) (bool, error) {
	observation, err := s.observeInstancePerformance(ctx, &before, handle, cpu, true)
	if err != nil {
		return false, err
	}
	admitted := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		record, err := tx.Instance(before.Key)
		if err != nil {
			return err
		}
		// Match the scheduler's lifecycle generation before retiring its VMM.
		// A newer API mutation is reconciled from its own current record.
		if record.Generation != before.Generation || record.Intent != before.Intent {
			return nil
		}
		if err := s.checkpointInstancePerformance(tx, &record, observation); err != nil {
			return err
		}
		admitted = true
		return nil
	})
	return admitted, err
}

func (s *Service) checkpointImageShutdown(ctx context.Context, image ImageRecord, before InstanceRecord, handle native.Instance, cpu instanceCPUObservation) (bool, error) {
	observation, err := s.observeInstancePerformance(ctx, &before, handle, cpu, true)
	if err != nil {
		return false, err
	}
	admitted := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Image(image.Key)
		if err != nil {
			return err
		}
		if current.Create == nil || (current.Create.Phase != "shutdown" && current.Create.Phase != "shutdown-wait") {
			return nil
		}
		record, err := tx.Instance(before.Key)
		if err != nil {
			return err
		}
		// Metadata generations do not cancel the image's reboot ownership, but
		// a newer lifecycle request must not capture or replace that request's VMM.
		if instanceState(record) != "running" || record.Intent != InstanceIntentObserve || !record.NextActionAt.IsZero() {
			return nil
		}
		if err := s.checkpointInstancePerformance(tx, &record, observation); err != nil {
			return err
		}
		// The phase and cursor commit together: recovery must never sample the
		// same Shutdown VMM after capture time has elapsed.
		current.Create.Phase = "capture-reboot"
		current.Create.NextActionAt = s.clock.Now().Add(time.Second)
		if err := tx.PutImage(current); err != nil {
			return err
		}
		admitted = true
		return nil
	})
	return admitted, err
}
