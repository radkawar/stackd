package lambda

import (
	"context"
)

// validateCapacityPublication counts immutable versions and the independently
// retained latest-published snapshot in the provider's transaction snapshot.
func validateCapacityPublication(tx Transaction, f FunctionRecord, replacing uint64) error {
	if f.Capacity == nil {
		return nil
	}
	key, err := capacityKey(tx.Context(), f.Capacity.ProviderARN)
	if err != nil {
		return err
	}
	versions, err := capacityVersions(tx, key)
	if err != nil {
		return err
	}
	count := 0
	for _, version := range versions {
		if replacing != 0 && version.Key == f.Key && version.Version == replacing {
			continue
		}
		count++
	}
	if count >= 100 {
		return failure("FunctionVersionsPerCapacityProviderLimitExceededException", "A capacity provider supports at most 100 function versions.", 400)
	}
	return nil
}

// Function deletion must remove its scaling intent in the same transaction so
// recreating a function name cannot inherit a previous incarnation's controls.
func deleteCapacityFunctionScaling(tx Transaction, key FunctionKey, version uint64) error {
	if version != 0 {
		return tx.DeleteCapacityScaling(FunctionReference{FunctionKey: key, Qualifier: versionName(version)})
	}
	records, err := tx.CapacityScalings(key)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err = tx.DeleteCapacityScaling(record.Key); err != nil {
			return err
		}
	}
	return nil
}

// This is called only after the EC2 boundary proves this owned guest terminated.
// Retained environment ownership is removed together, never on launch admission.
func (s *Service) forgetTerminatedCapacityGuest(ctx context.Context, g CapacityGuestRecord) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		environments, err := tx.AllCapacityEnvironments()
		if err != nil {
			return err
		}
		for _, e := range environments {
			if e.GuestID == g.ID {
				if err = tx.DeleteCapacityEnvironment(e.ID); err != nil {
					return err
				}
				s.capacity.mu.Lock()
				delete(s.capacity.credentials, e.ID)
				delete(s.capacity.samples, e.ID)
				s.capacity.mu.Unlock()
			}
		}
		return tx.DeleteCapacityGuest(g.Provider, g.ID)
	})
}
