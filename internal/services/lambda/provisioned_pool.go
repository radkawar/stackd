package lambda

import (
	"errors"
	"log/slog"
	"math"
	"time"
)

type provisionedKernel struct{ wake chan struct{} }

func (s *Service) startProvisionedLocked() {
	if s.provisioned != nil || s.closed.Load() {
		return
	}
	p := &provisionedKernel{wake: make(chan struct{}, 1)}
	s.provisioned = p
	s.work.Add(1)
	go func() {
		defer s.work.Done()
		timer := s.clock.NewTimer(time.Minute)
		defer timer.Stop()
		for {
			if err := s.reconcileProvisioned(); err != nil && s.lifetime.Err() == nil {
				slog.Error("Lambda provisioned capacity reconciliation failed", "error", err)
			}
			timer.Reset(time.Minute)
			select {
			case <-s.lifetime.Done():
				return
			case <-p.wake:
			case <-timer.C():
			}
		}
	}()
}
func (s *Service) provisionedChangedLocked() {
	if s.provisioned != nil {
		select {
		case s.provisioned.wake <- struct{}{}:
		default:
		}
	}
}
func (s *Service) provisionedChanged() { s.mu.Lock(); s.provisionedChangedLocked(); s.mu.Unlock() }

func (s *Service) retireProvisionedLocked(ref FunctionReference) []*execution {
	var idle []*execution
	for _, pool := range s.environments {
		for _, slot := range pool {
			if slot.provisioned != ref || slot.retiring {
				continue
			}
			slot.retiring = true
			if !slot.leased {
				slot.leased = true
				idle = append(idle, slot)
			}
		}
	}
	return idle
}

type provisionedTarget struct {
	function FunctionRecord
	count    int
}

func provisionedTargets(r Reader, v ProvisionedConcurrencyRecord) ([]provisionedTarget, error) {
	f, err := loadFunction(r, v.Key)
	if err != nil {
		return nil, err
	}
	if f.Version == 0 {
		return nil, failure("InvalidParameterValueException", "Provisioned concurrency requires a published version.", 400)
	}
	targets := []provisionedTarget{{function: f, count: int(v.Requested)}}
	if _, numeric := provisionedVersion(v.Key); numeric {
		return targets, nil
	}
	alias, err := r.Alias(v.Key)
	if err != nil {
		return nil, err
	}
	if alias.AdditionalVersion != 0 && alias.AdditionalWeight > 0 {
		other, err := loadDeployment(r, FunctionVersionKey{FunctionKey: v.Key.FunctionKey, Version: alias.AdditionalVersion})
		if err != nil {
			return nil, err
		}
		targets[0].count = int(math.Ceil(float64(v.Requested) * (1 - alias.AdditionalWeight)))
		targets = append(targets, provisionedTarget{function: other, count: int(math.Ceil(float64(v.Requested) * alias.AdditionalWeight))})
	}
	return targets, nil
}

func (s *Service) reconcileProvisioned() error {
	var rows []ProvisionedConcurrencyRecord
	err := s.repository.View(s.lifetime, func(r Reader) error { var err error; rows, err = r.AllProvisionedConcurrency(); return err })
	if err != nil {
		return err
	}
	wanted := make(map[FunctionReference]string, len(rows))
	for _, row := range rows {
		wanted[row.Key] = row.Generation
	}
	s.mu.Lock()
	var idle []*execution
	for _, pool := range s.environments {
		for _, slot := range pool {
			if slot.provisionedGeneration == "" || slot.retiring {
				continue
			}
			if wanted[slot.provisioned] != slot.provisionedGeneration || !s.clock.Now().Before(slot.provisionedExpires.Add(-2*time.Minute)) {
				slot.retiring = true
				if !slot.leased {
					slot.leased = true
					idle = append(idle, slot)
				}
			}
		}
	}
	s.mu.Unlock()
	s.closeIdleExecutions(idle)
	for _, row := range rows {
		if s.lifetime.Err() != nil {
			return s.lifetime.Err()
		}
		if row.Status == "FAILED" {
			continue
		}
		if err := s.fillProvisioned(row); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}
func (s *Service) fillProvisioned(row ProvisionedConcurrencyRecord) error {
	var targets []provisionedTarget
	err := s.repository.View(s.lifetime, func(r Reader) error { var err error; targets, err = provisionedTargets(r, row); return err })
	if err != nil {
		return s.finishProvisioned(row, err)
	}
	versions := make(map[uint64]int, len(targets))
	for _, target := range targets {
		versions[target.function.Version] = target.count
	}
	s.mu.Lock()
	var idle []*execution
	for key, pool := range s.environments {
		if key.FunctionKey != row.Key.FunctionKey {
			continue
		}
		for _, slot := range pool {
			if slot.provisioned != row.Key || slot.provisionedGeneration != row.Generation || slot.retiring {
				continue
			}
			if versions[key.Version] > 0 {
				versions[key.Version]--
				continue
			}
			slot.retiring = true
			if !slot.leased {
				slot.leased = true
				idle = append(idle, slot)
			}
		}
	}
	s.mu.Unlock()
	s.closeIdleExecutions(idle)
	for _, target := range targets {
		for range versions[target.function.Version] {
			if err := s.allocateProvisioned(row, target.function); err != nil {
				return s.finishProvisioned(row, err)
			}
		}
	}
	return s.finishProvisioned(row, nil)
}
func (s *Service) allocateProvisioned(row ProvisionedConcurrencyRecord, function FunctionRecord) error {
	key := FunctionVersionKey{FunctionKey: function.Key, Version: function.Version}
	slot := &execution{key: key, leased: true, provisioned: row.Key, provisionedGeneration: row.Generation}
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return s.lifetime.Err()
	}
	s.environments[key] = append(s.environments[key], slot)
	s.mu.Unlock()
	slot.mu.Lock()
	defer slot.mu.Unlock()
	environment, expiration, err := s.prepareMode(ownerContext(s.lifetime, function.Key), function, true)
	if err != nil {
		slot.retire(environment)
		s.mu.Lock()
		slot.retiring = true
		s.mu.Unlock()
		s.releaseExecution(slot)
		return err
	}
	slot.environment, slot.revision, slot.expires, slot.lastUse = environment, function.DeploymentRevision, expiration, s.clock.Now()
	s.mu.Lock()
	check := s.repository.View(s.lifetime, func(r Reader) error {
		current, err := r.ProvisionedConcurrency(row.Key)
		if err != nil {
			return err
		}
		if current.Generation != row.Generation {
			return ErrNotFound
		}
		return nil
	})
	if check != nil || s.closed.Load() {
		slot.retiring = true
	} else {
		slot.provisionedReady = true
		slot.provisionedExpires = expiration
	}
	s.mu.Unlock()
	s.releaseExecution(slot)
	return check
}
func (s *Service) finishProvisioned(row ProvisionedConcurrencyRecord, cause error) error {
	return s.repository.Update(s.lifetime, func(tx Transaction) error {
		current, err := tx.ProvisionedConcurrency(row.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Generation != row.Generation {
			return nil
		}
		current.Status, current.StatusReason = "READY", ""
		if cause != nil {
			current.Status, current.StatusReason = "FAILED", cause.Error()
		}
		return tx.PutProvisionedConcurrency(current)
	})
}

// Invocation consumes the requested alias pool or its resolved numeric version
// pool. Unqualified calls and unrelated aliases cannot borrow alias capacity.
func (s *Service) invocationExecutionLocked(key FunctionVersionKey, ref FunctionReference) *execution {
	if slot := s.provisionedExecutionLocked(key, ref); slot != nil {
		slot.leased = true
		return slot
	}
	return s.executionLocked(key)
}

// Admission and lease selection hold Service.mu across both calls, so a slot
// credited to the qualifier cannot be consumed by another request in between.
func (s *Service) provisionedExecutionLocked(key FunctionVersionKey, ref FunctionReference) *execution {
	for _, slot := range s.environments[key] {
		if !slot.provisionedReady || slot.leased || slot.retiring {
			continue
		}
		version, numeric := provisionedVersion(slot.provisioned)
		if slot.provisioned == ref || (numeric && version == key.Version) {
			return slot
		}
	}
	return nil
}
