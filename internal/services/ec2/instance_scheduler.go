package ec2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

// Non-lifecycle mutations wake observations without stealing CreateImage's
// graceful reboot. A running/observe instance with no deadline is claimed by
// the image worker; releaseImageSource restores its observation deadline.
func scheduleInstanceObservation(record *InstanceRecord, now time.Time) {
	if instanceState(*record) == "running" && record.Intent == InstanceIntentObserve && record.NextActionAt.IsZero() {
		return
	}
	record.NextActionAt = now
}

// NextInstanceDeadline participates in the shared scheduler. Running instances
// retain observation deadlines so guest-initiated shutdown is noticed without
// any Describe request driving the state machine.
func (s *Service) NextInstanceDeadline(ctx context.Context) (time.Time, bool, error) {
	var next time.Time
	var found bool
	err := s.repository.View(ctx, func(tx Reader) error { var err error; next, found, err = tx.NextInstanceDeadline(); return err })
	return next, found, err
}

// AdvanceInstances executes native effects only after their API intent commits.
// The worker lock serializes native work; per-record generations protect results
// against API mutations committed while an external operation was in flight.
func (s *Service) AdvanceInstances(ctx context.Context) (int, error) {
	if s.instanceRuntime == nil || s.instanceVolumes == nil {
		return 0, nil
	}
	s.instanceWorkMu.Lock()
	defer s.instanceWorkMu.Unlock()
	if s.instanceHandles == nil {
		s.instanceHandles = map[ResourceKey]native.Instance{}
	}
	var records []InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; records, err = tx.PendingInstances(s.clock.Now()); return err }); err != nil {
		return 0, err
	}
	count := 0
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		child := instanceServiceContext(ctx, record.Key)
		if err := s.repository.View(child, func(tx Reader) error { var err error; record, err = tx.Instance(record.Key); return err }); err != nil {
			return count, err
		}
		if record.NextActionAt.IsZero() || record.NextActionAt.After(s.clock.Now()) {
			continue
		}
		if err := s.advanceInstance(child, record); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// ResumeInstanceControllers restores host listeners without advancing service
// time or consuming future lifecycle deadlines. Surviving guests need IMDS even
// when a manual clock has not reached their next scheduled observation.
func (s *Service) ResumeInstanceControllers(ctx context.Context) error {
	if s.instanceRuntime == nil || s.instanceVolumes == nil {
		return nil
	}
	s.instanceWorkMu.Lock()
	defer s.instanceWorkMu.Unlock()
	var records []InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; records, err = tx.PreparedInstances(); return err }); err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	if s.instanceHandles == nil {
		s.instanceHandles = map[ResourceKey]native.Instance{}
	}
	for _, record := range records {
		if s.instanceHandles[record.Key] != nil {
			continue
		}
		child := instanceServiceContext(ctx, record.Key)
		spec, err := s.instanceSpecification(child, record)
		if err != nil {
			return err
		}
		handle, err := s.reopenInstanceController(child, record, &spec)
		if errors.Is(err, native.ErrNotFound) {
			continue // The scheduled observer owns an exited guest's state transition.
		}
		if err != nil {
			return fmt.Errorf("reopen %s: %w", spec.InstanceARN, err)
		}
		s.instanceHandles[record.Key] = handle
		if err := s.limitInstanceCreditReconnect(child, record.Key, handle); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reopenInstanceController(ctx context.Context, record InstanceRecord, spec *native.Specification) (native.Instance, error) {
	var err error
	spec.Disks, err = s.resolveExistingInstanceDisks(ctx, record)
	if err != nil {
		return nil, err
	}
	defer func() {
		for index := range spec.Disks {
			clear(spec.Disks[index].Key)
			spec.Disks[index].Key = nil
		}
	}()
	return s.instanceRuntime.Reopen(ctx, *spec)
}

// CloseInstanceControllers detaches trusted host listeners/controllers without
// stopping surviving VMMs. Reconnection uses the same instance ARN and disks.
func (s *Service) CloseInstanceControllers(ctx context.Context) error {
	s.instanceWorkMu.Lock()
	defer s.instanceWorkMu.Unlock()
	var joined error
	for key, handle := range s.instanceHandles {
		child := instanceServiceContext(ctx, key)
		status, err := handle.Inspect(child)
		if err != nil || status.State != native.Exited {
			err = errors.Join(err, s.beforeInstanceCreditDetach(child, key, handle))
		}
		joined = errors.Join(joined, err, handle.Close())
		delete(s.instanceHandles, key)
	}
	return joined
}

func (s *Service) instanceSpecification(ctx context.Context, record InstanceRecord) (native.Specification, error) {
	spec := native.Specification{InstanceARN: resourceARN(record.Key.Scope, "instance", record.Key.ID), Architecture: str(record.Data.Architecture), BootMode: str(record.Data.BootMode), Metadata: s.InstanceMetadataHandler(record.Key)}
	spec.Hibernation = record.Data.HibernationOptions != nil && boolValue(record.Data.HibernationOptions.Configured)
	// Linux HVM images with no advertised boot mode use the legacy firmware path;
	// uefi-preferred selects UEFI only when the captured instance type supports it.
	if spec.BootMode == "" {
		spec.BootMode = "legacy-bios"
	}
	typ, err := s.instanceTypes.ResolveInstanceType(ctx, api.InstanceType(str(record.Data.InstanceType)))
	if err != nil {
		return spec, err
	}
	if spec.BootMode == "uefi-preferred" {
		spec.BootMode = "legacy-bios"
		for _, mode := range typ.SupportedBootModes {
			if string(mode) == "uefi" {
				spec.BootMode = "uefi"
				break
			}
		}
	}
	if typ.MemoryInfo == nil || typ.MemoryInfo.SizeInMiB == nil || record.Data.CpuOptions == nil || record.Data.CpuOptions.CoreCount == nil || record.Data.CpuOptions.ThreadsPerCore == nil {
		return spec, unsupported("The instance has no authoritative native CPU/memory configuration.")
	}
	spec.CPU = native.CPU{Sockets: 1, Cores: int(*record.Data.CpuOptions.CoreCount), Threads: int(*record.Data.CpuOptions.ThreadsPerCore)}
	spec.MemoryBytes = int64(*typ.MemoryInfo.SizeInMiB) << 20
	err = s.repository.View(ctx, func(tx Reader) error {
		if len(record.Data.NetworkInterfaces) != 1 {
			return unsupported("The instance requires exactly one native primary interface.")
		}
		eni, err := tx.NetworkInterface(key(ctx, str(record.Data.NetworkInterfaces[0].NetworkInterfaceId)))
		if err != nil {
			return err
		}
		spec.Network, err = networkSpecification(ctx, tx, eni)
		return err
	})
	return spec, err
}

type instanceObservation struct {
	prepared, effectStarted, completed, guestShutdown bool
	hibernateFailed                                   bool
	state                                             native.State
	console                                           []byte
	consoleOffset                                     int64
	consoleAt                                         time.Time
	bootMode                                          string
	attachedVolumes                                   map[string]bool
	health                                            *InstanceHealthRecord
	performance                                       *instancePerformanceObservation
}

func (s *Service) advanceInstance(ctx context.Context, record InstanceRecord) error {
	if instanceState(record) == "stopped" {
		return s.reconcileInstanceVolumes(ctx, record, nil)
	}
	spec, err := s.instanceSpecification(ctx, record)
	if err != nil {
		return s.instanceEffectFailure(ctx, record, err)
	}
	observed := instanceObservation{prepared: record.RuntimePrepared, effectStarted: record.EffectStarted, consoleOffset: record.ConsoleOffset, bootMode: spec.BootMode}
	handle := s.instanceHandles[record.Key]
	if handle == nil && record.Intent == InstanceIntentTerminate && record.Force && record.Credits.NativePID == 0 {
		// An admitted launch can fail before disks are prepared. Native removal
		// accepts instance/network identity alone and also reaps a VMM left between
		// preparation and the observed-state commit; no disk unwrap is required.
		if err := s.instanceRuntime.Remove(ctx, spec); err != nil {
			return err
		}
		if err := s.instanceVolumes.TerminateInstanceVolumes(ctx, record.Data); err != nil {
			return err
		}
		observed.completed = true
		return s.commitInstanceObservation(ctx, record, observed)
	}
	if handle == nil {
		handle, err = s.reopenInstanceController(ctx, record, &spec)
		if errors.Is(err, native.ErrNotFound) {
			if record.Intent == InstanceIntentStart {
				spec.Disks, err = s.instanceVolumes.PrepareInstanceVolumes(ctx, record.Data)
				if err == nil {
					handle, err = s.instanceRuntime.Prepare(ctx, spec)
				}
				for i := range spec.Disks {
					clear(spec.Disks[i].Key)
					spec.Disks[i].Key = nil
				}
			} else {
				err = nil
				observed.state = native.Exited
			}
		}
		if err != nil {
			return s.instanceEffectFailure(ctx, record, err)
		}
		if handle != nil {
			s.instanceHandles[record.Key] = handle
			observed.prepared = true
			if err := s.limitInstanceCreditReconnect(ctx, record.Key, handle); err != nil {
				return err
			}
		}
	}
	if handle != nil {
		if err := handle.SetNetwork(ctx, spec.Network); err != nil {
			return err
		}
		status, err := handle.Inspect(ctx)
		if err != nil {
			return err
		}
		observed.state = status.State
		if (record.Intent == InstanceIntentStart || record.Intent == InstanceIntentObserve || record.Intent == InstanceIntentReboot) && (status.State == native.Running || status.State == native.Paused) && instanceAttachmentWork(record) {
			if err := s.reconcileInstanceVolumes(ctx, record, handle); err != nil {
				return s.instanceEffectFailure(ctx, record, err)
			}
		}
		var cpu instanceCPUObservation
		performanceCheckpointed := false
		switch record.Intent {
		case InstanceIntentStart:
			if status.State == native.Paused || status.State == native.Running {
				if err := s.beforeInstanceCreditStart(ctx, record.Key, handle); err != nil {
					return s.instanceEffectFailure(ctx, record, err)
				}
				var current InstanceRecord
				if err := s.repository.View(ctx, func(tx Reader) error { var err error; current, err = tx.Instance(record.Key); return err }); err != nil {
					return err
				}
				if current.Generation != record.Generation || current.Intent != InstanceIntentStart {
					return nil
				}
				if status.State == native.Paused {
					if err := handle.Start(ctx); err != nil {
						return s.instanceEffectFailure(ctx, record, err)
					}
				}
			}
			status, err = handle.Inspect(ctx)
			if err != nil {
				return err
			}
			observed.state = status.State
			observed.completed = status.State == native.Running
			if status.State == native.Exited {
				return s.instanceEffectFailure(ctx, record, errors.New("native process exited during launch"))
			}
			if status.State == native.Shutdown {
				observed.guestShutdown = true
			}
		case InstanceIntentReboot:
			if status.State == native.Paused {
				if err := s.resumeCreditModification(ctx, record.Key, handle); err != nil {
					return err
				}
			}
			if status.State != native.Exited {
				if cpu, err = s.pollInstanceCredits(ctx, record.Key, handle); err != nil {
					return err
				}
			}
			if !record.EffectStarted {
				if err := handle.Reset(ctx); err != nil {
					return err
				}
				observed.effectStarted = true
			}
			status, err = handle.Inspect(ctx)
			if err != nil {
				return err
			}
			observed.state = status.State
			observed.completed = status.State == native.Running
		case InstanceIntentStop, InstanceIntentHibernate, InstanceIntentTerminate:
			if record.Intent == InstanceIntentHibernate && status.State == native.Paused && !record.Force {
				if err := handle.Start(ctx); err != nil {
					return err
				}
				status, err = handle.Inspect(ctx)
				if err != nil {
					return err
				}
			}
			if status.State != native.Exited {
				timedOut := !record.ShutdownDeadline.IsZero() && !s.clock.Now().Before(record.ShutdownDeadline)
				if record.Intent == InstanceIntentHibernate && !record.Force && timedOut && status.State != native.Shutdown {
					slog.Warn("EC2 guest hibernation timed out; requesting shutdown", "instance", record.Key.ID)
					if err := handle.Powerdown(ctx); err != nil {
						return err
					}
					observed.hibernateFailed = true
					observed.effectStarted = true
				} else if record.Force || status.State == native.Shutdown || status.State == native.Paused || timedOut {
					if cpu, err = s.beforeInstanceCreditStop(ctx, record.Key, handle); err != nil {
						return err
					}
					admitted, err := s.beforeInstancePerformanceStop(ctx, record, handle, cpu)
					if err != nil {
						return err
					}
					if !admitted {
						return nil
					}
					performanceCheckpointed = true
					if err := handle.Stop(ctx); err != nil {
						return err
					}
				} else {
					if cpu, err = s.pollInstanceCredits(ctx, record.Key, handle); err != nil {
						return err
					}
					if !record.EffectStarted {
						if record.Intent == InstanceIntentHibernate {
							if err := handle.Hibernate(ctx); err != nil {
								if ctx.Err() != nil {
									return ctx.Err()
								}
								// AWS falls back to ordinary shutdown when the guest
								// cannot hibernate. The initiation reason is unchanged.
								slog.Warn("EC2 guest hibernation failed; requesting shutdown", "instance", record.Key.ID, "error", err)
								if err := handle.Powerdown(ctx); err != nil {
									return err
								}
								observed.hibernateFailed = true
							}
						} else if err := handle.Powerdown(ctx); err != nil {
							return err
						}
						observed.effectStarted = true
					}
				}
			}
			status, err = handle.Inspect(ctx)
			if err != nil {
				return err
			}
			observed.state = status.State
			observed.completed = status.State == native.Exited
		case InstanceIntentObserve:
			if status.State == native.Paused {
				if err := s.resumeCreditModification(ctx, record.Key, handle); err != nil {
					return err
				}
			}
			if status.State != native.Exited {
				if cpu, err = s.pollInstanceCredits(ctx, record.Key, handle); err != nil {
					return err
				}
			}
			observed.guestShutdown = status.State == native.Shutdown || status.State == native.Exited
		}
		if record.Intent == InstanceIntentStart && observed.state != native.Exited {
			disks, err := handle.AttachedDisks(ctx)
			if err != nil {
				return err
			}
			observed.attachedVolumes = make(map[string]bool, len(disks))
			for _, disk := range disks {
				if disk.ID != "" && disk.Device != "" {
					observed.attachedVolumes[disk.ID] = true
				}
			}
		}
		if record.Intent == InstanceIntentObserve && !observed.guestShutdown {
			observed.health, err = s.observeInstanceHealth(ctx, &record, handle, observed.state)
			if err != nil {
				return err
			}
		}
		if !performanceCheckpointed && observed.state == native.Running &&
			(record.Intent == InstanceIntentObserve || record.Intent == InstanceIntentReboot || record.Intent == InstanceIntentStop || record.Intent == InstanceIntentHibernate || record.Intent == InstanceIntentTerminate) {
			observed.performance, err = s.observeInstancePerformance(ctx, &record, handle, cpu, false)
			if err != nil {
				return err
			}
		}
		// Console is collected from actual VMM bytes, never from a simulated guest.
		bytes, err := handle.Console(ctx, record.ConsoleOffset, 64<<10)
		if err != nil {
			return err
		}
		if len(bytes) > 0 {
			observed.console = bytes
			observed.consoleOffset += int64(len(bytes))
			observed.consoleAt = s.clock.Now()
		}
	} else if record.Intent == InstanceIntentStop || record.Intent == InstanceIntentHibernate || record.Intent == InstanceIntentTerminate {
		observed.completed = true
	} else {
		observed.guestShutdown = true
	}
	if observed.completed && (record.Intent == InstanceIntentStop || record.Intent == InstanceIntentHibernate || record.Intent == InstanceIntentTerminate) {
		if handle != nil {
			if err := handle.Close(); err != nil {
				return err
			}
			delete(s.instanceHandles, record.Key)
		}
		if record.Intent == InstanceIntentTerminate {
			if err := s.instanceRuntime.Remove(ctx, spec); err != nil {
				return err
			}
			if err := s.instanceVolumes.TerminateInstanceVolumes(ctx, record.Data); err != nil {
				return err
			}
		} else if err := s.instanceVolumes.StopInstanceVolumes(ctx, record.Data); err != nil {
			return err
		}
	}
	return s.commitInstanceObservation(ctx, record, observed)
}

func (s *Service) commitInstanceObservation(ctx context.Context, before InstanceRecord, observed instanceObservation) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx = tx.Context()
		record, err := tx.Instance(before.Key)
		if err != nil {
			return err
		}
		record.RuntimePrepared = observed.prepared
		if len(observed.console) > 0 && record.ConsoleOffset == before.ConsoleOffset {
			if len(record.Console)+len(observed.console) > 64<<10 {
				keep := (64 << 10) - len(observed.console)
				record.Console = slices.Clone(record.Console[max(0, len(record.Console)-keep):])
			}
			record.Console = append(record.Console, observed.console...)
			record.ConsoleOffset = observed.consoleOffset
			record.ConsoleAt = observed.consoleAt
		}
		if record.Generation != before.Generation {
			return tx.PutInstance(record)
		}
		terminal := observed.completed && (record.Intent == InstanceIntentStop || record.Intent == InstanceIntentHibernate || record.Intent == InstanceIntentTerminate)
		if err := s.recordInstancePerformance(ctx, &record, observed.performance, terminal); err != nil {
			return err
		}
		if observed.health != nil {
			record.Health = *observed.health
			if s.instanceMetrics != nil {
				if err := s.instanceMetrics.RecordInstanceHealthMetrics(ctx, record.Key, &record.Health); err != nil {
					return err
				}
			}
		}
		if record.Intent == InstanceIntentStart && observed.prepared {
			if record.Data.MetadataOptions != nil {
				record.Data.MetadataOptions.State = new(api.InstanceMetadataOptionsState("applied"))
			}
			for i := range record.Data.BlockDeviceMappings {
				disk := record.Data.BlockDeviceMappings[i].Ebs
				if disk != nil && str(disk.Status) == "attaching" && observed.attachedVolumes[resourceARN(record.Key.Scope, "volume", str(disk.VolumeId))] {
					disk.Status = new(api.AttachmentStatus("attached"))
					if disk.AttachTime == nil {
						disk.AttachTime = new(api.DateTime(s.clock.Now()))
					}
				}
			}
		}
		if observed.hibernateFailed && record.Intent == InstanceIntentHibernate {
			record.Intent = InstanceIntentStop
			record.ShutdownDeadline = s.clock.Now().Add(2 * time.Minute)
		}
		record.EffectStarted = observed.effectStarted
		record.NextActionAt = s.clock.Now().Add(time.Second)
		if observed.guestShutdown {
			record.Intent = InstanceIntentStop
			state := "stopping"
			if record.ShutdownBehavior == "terminate" && observed.state == native.Shutdown {
				record.Intent = InstanceIntentTerminate
				state = "shutting-down"
			}
			record.Generation++
			record.EffectStarted = false
			record.NextActionAt = s.clock.Now()
			record.ShutdownDeadline = s.clock.Now()
			record.Force = true
			record.Data.StateReason = &api.StateReason{Code: new(api.String("Client.InstanceInitiatedShutdown")), Message: new(api.String("Client.InstanceInitiatedShutdown: Instance initiated shutdown"))}
			if observed.state == native.Exited {
				record.Data.StateReason = &api.StateReason{Code: new(api.String("Server.InternalError")), Message: new(api.String("The native instance process exited unexpectedly."))}
			}
			return s.changeInstanceState(ctx, tx, &record, state)
		}
		if observed.completed {
			switch record.Intent {
			case InstanceIntentStart:
				record.Intent = InstanceIntentObserve
				record.EffectStarted = false
				record.Data.CurrentInstanceBootMode = new(api.InstanceBootModeValues(observed.bootMode))
				return s.changeInstanceState(ctx, tx, &record, "running")
			case InstanceIntentReboot:
				record.Intent = InstanceIntentObserve
				record.EffectStarted = false
			case InstanceIntentStop, InstanceIntentHibernate:
				if err := s.afterInstanceCreditStop(ctx, &record); err != nil {
					return err
				}
				record.Intent = ""
				record.EffectStarted = false
				record.RuntimePrepared = false
				record.NextActionAt = time.Time{}
				if instanceAttachmentWork(record) {
					record.NextActionAt = s.clock.Now()
				}
				return s.changeInstanceState(ctx, tx, &record, "stopped")
			case InstanceIntentTerminate:
				if err := s.afterInstanceCreditStop(ctx, &record); err != nil {
					return err
				}
				if err := releaseInstanceNetworks(ctx, tx, record); err != nil {
					return err
				}
				record.Intent = ""
				record.EffectStarted = false
				record.RuntimePrepared = false
				record.NextActionAt = time.Time{}
				record.Data.NetworkInterfaces = nil
				record.Data.BlockDeviceMappings = nil
				record.Data.PrivateIpAddress = nil
				record.Data.PrivateDnsName = nil
				record.Data.PublicIpAddress = nil
				record.Data.PublicDnsName = nil
				record.Data.SecurityGroups = nil
				record.Data.SubnetId = nil
				record.Data.VpcId = nil
				clear(record.MetadataTokenKey)
				record.MetadataTokenKey = nil
				return s.changeInstanceState(ctx, tx, &record, "terminated")
			}
		}
		return tx.PutInstance(record)
	})
}

func (s *Service) instanceEffectFailure(ctx context.Context, before InstanceRecord, cause error) error {
	if before.Intent != InstanceIntentStart {
		return cause
	}
	var launch *InstanceLaunchFailure
	code, message := "Server.InternalError", "The native instance could not be started."
	if errors.As(cause, &launch) {
		code, message = launch.Code, launch.Message
	}
	var capability *native.CapabilityError
	if errors.As(cause, &capability) {
		code, message = "Client.UnsupportedOperation", capability.Error()
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	slog.Error("EC2 instance start failed", "instance", resourceARN(before.Key.Scope, "instance", before.Key.ID), "error", cause)
	return s.repository.Update(ctx, func(tx Transaction) error {
		record, err := tx.Instance(before.Key)
		if err != nil {
			return err
		}
		if record.Generation != before.Generation {
			return nil
		}
		record.Intent = InstanceIntentTerminate
		record.Generation++
		record.Force = true
		record.EffectStarted = false
		record.NextActionAt = s.clock.Now()
		record.ShutdownDeadline = s.clock.Now()
		record.Data.StateReason = &api.StateReason{Code: new(api.String(code)), Message: new(api.String(message))}
		record.Data.StateTransitionReason = new(api.String("Client.InternalError"))
		return s.changeInstanceState(tx.Context(), tx, &record, "shutting-down")
	})
}
