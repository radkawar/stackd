package kms

import (
	"context"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

// JobDriver joins KMS lifecycles to the instance scheduler before worker startup.
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

// StartWorkers discovers retained deadlines and runs them without API traffic.
func (s *Service) StartWorkers() { s.jobs.Start() }

// Close joins lifecycle work before the caller closes storage.
func (s *Service) Close() error { s.jobs.Close(); return nil }

type lifecycleJobs struct{ service *Service }

func (source lifecycleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	s := source.service
	var next scheduler.Job
	found := false
	err := s.storage.View(ctx, func(reader Reader) error {
		return s.withWorkingSet(reader, func(context.Context) error {
			scopes, err := reader.Scopes()
			if err != nil {
				return err
			}
			for _, sc := range scopes {
				s.regionalStore(scope{partition: sc.Partition, account: sc.AccountID, region: sc.Region})
			}
			if s.storageErr != nil {
				return s.storageErr
			}
			for ref, set := range s.keySets {
				if due, ok := s.nextKeySetTransition(ref.owner, set); ok {
					candidate := scheduler.Job{Key: ref.owner.Partition + "/" + ref.owner.AccountID + "/" + set.ID, Due: due}
					if !found || scheduler.Compare(candidate, next) < 0 {
						next, found = candidate, true
					}
				}
			}
			return s.storageErr
		})
	})
	return next, found, err
}

func (source lifecycleJobs) Run(ctx context.Context, selected scheduler.Job) error {
	partition, rest, _ := strings.Cut(selected.Key, "/")
	accountID, id, _ := strings.Cut(rest, "/")
	owner := KeyOwner{Partition: partition, AccountID: accountID}
	s := source.service
	return s.withTransaction(ctx, func(context.Context) (bool, error) {
		set, err := s.transaction.KeySet(owner, id)
		if err == ErrKeySetNotFound {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		s.keySets[keySetReference{owner: owner, id: id}] = &set
		due, ok := s.nextKeySetTransition(owner, &set)
		if !ok || !due.Equal(selected.Due) || due.After(s.currentTime()) {
			return false, nil
		}
		// Advance only this deadline. A large clock jump must leave subsequent
		// rotations for later jobs, preserving the drain budget and source order.
		s.advanceKeySet(owner, &set, due)
		return true, nil
	})
}

func (s *Service) nextKeySetTransition(owner KeyOwner, set *KeySetRecord) (time.Time, bool) {
	related := s.keySetKeys(owner, set)
	if len(related) == 0 {
		return time.Time{}, false
	}
	var next time.Time
	found := false
	consider := func(due time.Time) {
		if !found || due.Before(next) {
			next, found = due, true
		}
	}
	for _, k := range related {
		if k.state == "Creating" || k.state == "Updating" {
			consider(k.availableAt)
		}
		if k.deletion != nil {
			consider(*k.deletion)
		}
		for _, parameters := range k.importParameters {
			if len(parameters.PrivateKey) != 0 {
				consider(parameters.ValidTo)
			}
		}
	}
	primary := related[0]
	if primary.Origin == "EXTERNAL" {
		if due, _, _ := nextImportTransition(primary, related); !due.IsZero() {
			consider(due)
		}
	} else if due, _ := nextRotation(primary); !due.IsZero() {
		consider(due)
	}
	return next, found
}
