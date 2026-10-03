package ec2

import (
	"context"
	"errors"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

func instanceHasCPUCredits(record InstanceRecord) bool {
	typ := api.InstanceType(str(record.Data.InstanceType))
	_, found := lookupInstanceCreditRate(typ)
	return found && supportedCreditFamily(instanceCreditFamily(typ)) && record.Credits.Mode != ""
}

// beforeInstanceCreditStart must complete before handle.Start. The paused-VMM
// usage cursor and T2 launch eligibility commit first, then the kernel quota is
// applied. On reconnect, the matching VMM identity preserves cumulative usage.
// The instance worker owns instanceWorkMu around all lifecycle credit helpers.
func (s *Service) beforeInstanceCreditStart(ctx context.Context, key ResourceKey, handle native.Instance) error {
	var record InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(key); return err }); err != nil {
		return err
	}
	if record.Intent != InstanceIntentStart {
		return errors.New("ec2: instance start was superseded before credit admission")
	}
	if !instanceHasCPUCredits(record) {
		// A stopped T-family instance can be resized to fixed performance while its
		// ARN-owned cgroup survives. Clear its previous CPU-credit quota before boot.
		return handle.SetCPUQuota(ctx, native.CPUQuota{Period: instanceCreditQuotaPeriod})
	}
	status, err := handle.Inspect(ctx)
	if err != nil {
		return err
	}
	usage, err := handle.CPUUsage(ctx)
	if err != nil {
		return err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		record, err = tx.Instance(key)
		if err != nil {
			return err
		}
		if record.Intent != InstanceIntentStart {
			return errors.New("ec2: instance start was superseded before credit admission")
		}
		sameVMM := record.Credits.NativePID == status.PID && record.Credits.NativeStartTimeTicks == status.StartTimeTicks
		if sameVMM {
			at := s.clock.Now()
			// A still-paused launch has not been earning credits while the controller
			// was absent. Preserve (and debit) its native cursor rather than resetting.
			if status.State == native.Paused {
				at = record.Credits.UpdatedAt
			}
			previous := record.Credits.Usage
			charged, err := sampleInstanceCredits(&record, status, usage, at)
			if err != nil {
				return err
			}
			record.Credits.UpdatedAt = s.clock.Now()
			if err := s.recordInstanceCreditSample(tx.Context(), &record, usage-previous, charged, false); err != nil {
				return err
			}
		} else if err := s.beginInstanceCredits(tx.Context(), tx, &record, status, usage); err != nil {
			return err
		}
		return tx.PutInstance(record)
	})
	if err != nil {
		return err
	}
	return applyInstanceCreditQuota(ctx, handle, record)
}

// beforeInstanceCreditReboot attaches a paused replacement VMM used by an
// internal image-reboot operation. The public instance never stopped, so there
// is no surplus settlement, retention reset or T2 launch allocation. Its old
// VMM must have been sampled by beforeInstanceCreditStop before destruction.
func (s *Service) beforeInstanceCreditReboot(ctx context.Context, key ResourceKey, handle native.Instance) error {
	var record InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(key); return err }); err != nil {
		return err
	}
	if instanceState(record) != "running" || record.Intent != InstanceIntentObserve {
		return errors.New("ec2: internal reboot was superseded")
	}
	if !instanceHasCPUCredits(record) {
		return handle.SetCPUQuota(ctx, native.CPUQuota{Period: instanceCreditQuotaPeriod})
	}
	status, err := handle.Inspect(ctx)
	if err != nil {
		return err
	}
	if status.State != native.Paused || status.PID <= 0 || status.StartTimeTicks == 0 {
		return errors.New("ec2: internal reboot requires a paused native VMM")
	}
	usage, err := handle.CPUUsage(ctx)
	if err != nil {
		return err
	}
	if usage < 0 {
		return errors.New("ec2: invalid native CPU usage")
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		record, err = tx.Instance(key)
		if err != nil {
			return err
		}
		if instanceState(record) != "running" || record.Intent != InstanceIntentObserve {
			return errors.New("ec2: internal reboot was superseded")
		}
		credit := &record.Credits
		if credit.NativePID == 0 {
			return errors.New("ec2: internal reboot has no previous native CPU cursor")
		}
		if credit.NativePID == status.PID && credit.NativeStartTimeTicks == status.StartTimeTicks {
			previous := credit.Usage
			charged, err := sampleInstanceCredits(&record, status, usage, credit.UpdatedAt)
			if err != nil {
				return err
			}
			if err := s.recordInstanceCreditSample(tx.Context(), &record, usage-previous, charged, false); err != nil {
				return err
			}
		}
		credit.NativePID, credit.NativeStartTimeTicks = status.PID, status.StartTimeTicks
		credit.Usage, credit.UpdatedAt = usage, s.clock.Now()
		return tx.PutInstance(record)
	})
	if err != nil {
		return err
	}
	return applyInstanceCreditQuota(ctx, handle, record)
}

// pollInstanceCredits observes native CPU outside the transaction, then commits
// balance, usage cursor and metric contributions together. The fixed kernel
// quota is refreshed only after commit; there is no scheduler sleep throttle.
func (s *Service) pollInstanceCredits(ctx context.Context, key ResourceKey, handle native.Instance) (instanceCPUObservation, error) {
	var before InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; before, err = tx.Instance(key); return err }); err != nil {
		return instanceCPUObservation{}, err
	}
	if !instanceHasCPUCredits(before) {
		return instanceCPUObservation{}, nil
	}
	status, err := handle.Inspect(ctx)
	if err != nil {
		return instanceCPUObservation{}, err
	}
	usage, err := handle.CPUUsage(ctx)
	if err != nil {
		return instanceCPUObservation{}, err
	}
	observation := instanceCPUObservation{Status: status, Usage: usage, At: time.Now()}
	now := s.clock.Now()
	var record InstanceRecord
	err = s.repository.Update(ctx, func(tx Transaction) error {
		record, err = tx.Instance(key)
		if err != nil {
			return err
		}
		previous := record.Credits.Usage
		charged, err := sampleInstanceCredits(&record, status, usage, now)
		if err != nil {
			return err
		}
		if err := s.recordInstanceCreditSample(tx.Context(), &record, usage-previous, charged, false); err != nil {
			return err
		}
		return tx.PutInstance(record)
	})
	if err != nil {
		return instanceCPUObservation{}, err
	}
	return observation, applyInstanceCreditQuota(ctx, handle, record)
}

// beforeInstanceCreditStop is called only immediately before destructive Stop,
// not when merely requesting ACPI Powerdown. Pause stops vCPUs while their thread
// clocks are still readable, so the final sample does not race guest execution.
func (s *Service) beforeInstanceCreditStop(ctx context.Context, key ResourceKey, handle native.Instance) (instanceCPUObservation, error) {
	var record InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(key); return err }); err != nil {
		return instanceCPUObservation{}, err
	}
	if !instanceHasCPUCredits(record) || record.Credits.NativePID == 0 {
		return instanceCPUObservation{}, nil
	}
	status, err := handle.Inspect(ctx)
	if err != nil {
		return instanceCPUObservation{}, err
	}
	if status.State == native.Exited {
		return instanceCPUObservation{}, nil
	}
	if status.State == native.Running {
		if err := handle.Pause(ctx); err != nil {
			return instanceCPUObservation{}, err
		}
	}
	return s.pollInstanceCredits(ctx, key, handle)
}

// afterInstanceCreditStop joins the observed stopped/terminated transition's
// transaction. An already-dead VMM cannot supply a final CPU sample: only its last
// actual checkpoint is retained, never synthesized downtime utilization.
func (s *Service) afterInstanceCreditStop(ctx context.Context, record *InstanceRecord) error {
	if !instanceHasCPUCredits(*record) {
		return nil
	}
	if record.Credits.NativePID == 0 && !record.Credits.StoppedAt.IsZero() {
		return nil
	}
	charged := stopInstanceCredits(record, s.clock.Now())
	return s.recordInstanceCreditSample(ctx, record, 0, charged, true)
}

// beforeInstanceCreditDetach conservatively leaves standard VMMs at baseline
// when the controller closes gracefully. Balances/cursors remain untouched by
// the quota reduction, and the VMM continues real execution.
func (s *Service) beforeInstanceCreditDetach(ctx context.Context, key ResourceKey, handle native.Instance) error {
	var record InstanceRecord
	observed := s.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(key); return err })
	if observed == nil && instanceHasCPUCredits(record) && record.Credits.NativePID != 0 {
		_, observed = s.pollInstanceCredits(ctx, key, handle)
	}
	// Sample failure must not prevent the independent conservative quota change.
	// A prepared but never-started VMM has no usage cursor to settle.
	return errors.Join(observed, s.limitInstanceCreditReconnect(ctx, key, handle))
}

// limitInstanceCreditReconnect applies baseline before observing a surviving
// standard VMM after controller downtime. Subsequent poll accounts the original
// cumulative CPU cursor and may restore bursting. No CPU-use samples are forged
// for the controller's absence; fixed cgroups retain their last applied quota.
func (s *Service) limitInstanceCreditReconnect(ctx context.Context, key ResourceKey, handle native.Instance) error {
	var record InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(key); return err }); err != nil {
		return err
	}
	if !instanceHasCPUCredits(record) || record.Credits.Mode != "standard" {
		return nil
	}
	record.Credits.Earned, record.Credits.Launch = 0, 0
	return applyInstanceCreditQuota(ctx, handle, record)
}

// creditInstanceHandle only reopens an existing VMM; control APIs never prepare
// or start a replacement to make a credit update appear successful.
func (s *Service) creditInstanceHandle(ctx context.Context, record InstanceRecord) (native.Instance, error) {
	if handle := s.instanceHandles[record.Key]; handle != nil {
		return handle, nil
	}
	if s.instanceRuntime == nil || s.instanceVolumes == nil {
		return nil, unsupported("Native instance execution is not configured.")
	}
	spec, err := s.instanceSpecification(ctx, record)
	if err != nil {
		return nil, err
	}
	spec.Disks, err = s.instanceVolumes.ResolveInstanceVolumes(ctx, record.Data)
	if err != nil {
		return nil, err
	}
	handle, err := s.instanceRuntime.Reopen(ctx, spec)
	if err != nil {
		return nil, err
	}
	if s.instanceHandles == nil {
		s.instanceHandles = map[ResourceKey]native.Instance{}
	}
	s.instanceHandles[record.Key] = handle
	if err := s.limitInstanceCreditReconnect(ctx, record.Key, handle); err != nil {
		return nil, err
	}
	return handle, nil
}

// A paused modification is resumed only if lifecycle intent still permits it.
// Stop/Terminate committed while the native call was outside the transaction
// remains authoritative. Failed modification still resumes under the old mode.
func (s *Service) resumeCreditModification(ctx context.Context, key ResourceKey, handle native.Instance) error {
	var record InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(key); return err }); err != nil {
		return err
	}
	if err := applyInstanceCreditQuota(ctx, handle, record); err != nil {
		return err
	}
	if instanceState(record) != "running" || (record.Intent != InstanceIntentObserve && record.Intent != InstanceIntentReboot) {
		return nil
	}
	// No credits accrue for service time spent deliberately paused by this API.
	if !record.Credits.UpdatedAt.IsZero() {
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Instance(key)
			if err != nil {
				return err
			}
			current.Credits.UpdatedAt = s.clock.Now()
			return tx.PutInstance(current)
		}); err != nil {
			return err
		}
	}
	return handle.Start(ctx)
}
