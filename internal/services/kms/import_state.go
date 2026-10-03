package kms

import (
	"slices"
	"time"
)

func (s *Service) relatedKeys(k *key) []*key {
	sc := keyScope(k)
	regions := append([]string{k.PrimaryRegion}, k.ReplicaRegions...)
	keys := make([]*key, 0, len(regions))
	for _, region := range regions {
		sc.region = region
		keys = append(keys, s.regionalStore(sc).keys[k.ID])
	}
	return keys
}

func (s *Service) pendingImportReady(k *key) bool {
	if k.PendingMaterialID == "" {
		return false
	}
	for _, related := range s.relatedKeys(k) {
		if _, present := related.imports[k.PendingMaterialID]; !present {
			return false
		}
	}
	return true
}

// removeImportedMaterial is shared by explicit deletion and material expiry.
// Pending primary material is discarded globally; used material retains its
// identity for reimport. Bytes remain only while a related Region has them.
func (s *Service) removeImportedMaterial(k *key, id string) {
	related := s.relatedKeys(k)
	if id == k.PendingMaterialID && keyScope(k).region == k.PrimaryRegion {
		for _, regional := range related {
			delete(regional.imports, id)
		}
		for i := range k.Materials {
			if k.Materials[i].ID == id {
				clear(k.Materials[i].Material)
			}
		}
		k.Materials = slices.DeleteFunc(k.Materials, func(m KeyMaterialRecord) bool { return m.ID == id })
		k.PendingMaterialID = ""
	} else {
		delete(k.imports, id)
		if id != k.PendingMaterialID {
			markMaterialMissing(k)
		}
	}
	clearAbsentMaterial(k, related)
}

// Missing material makes an otherwise usable or disabled key await import.
// Creation and deletion retain their own lifecycle until they complete.
func markMaterialMissing(k *key) {
	switch k.state {
	case "Enabled", "Disabled", "Updating":
		k.state, k.availableAt = "PendingImport", time.Time{}
	}
}

func clearAbsentMaterial(k *key, related []*key) {
	for i := range k.Materials {
		present := slices.ContainsFunc(related, func(regional *key) bool { _, present := regional.imports[k.Materials[i].ID]; return present })
		if !present {
			clear(k.Materials[i].Material)
			k.Materials[i].Material = nil
		}
	}
}

// advanceImported applies expiry and an accepted rotation in chronological
// service time, even when a manual clock crosses both deadlines in one step.
func (s *Service) advanceImported(primary *key, now time.Time) {
	// TODO: Comeback complete token-expiry captures, remaining import/rotation concurrency, variable expiry/rotation propagation and import validation/partition conformance.
	related := s.relatedKeys(primary)
	for _, regional := range related {
		for i := range regional.importParameters {
			parameters := &regional.importParameters[i]
			if !now.Before(parameters.ValidTo) {
				clear(parameters.PrivateKey)
				parameters.PrivateKey = nil
			}
		}
	}
	for {
		due, expiredKey, expiredID := nextImportTransition(primary, related)
		if due.IsZero() || now.Before(due) {
			break
		}
		if expiredKey != nil {
			s.removeImportedMaterial(expiredKey, expiredID)
			continue
		}
		id := primary.PendingMaterialID
		// An accepted request completes against the pending slot. AWS keeps it
		// active after deletion and can rotate a replacement imported meanwhile.
		primary.Rotation.OnDemandStarted = time.Time{}
		if id == "" {
			continue
		}
		for i := range primary.Materials {
			if primary.Materials[i].ID == id {
				primary.Materials[i].RotationDate, primary.Materials[i].RotationType = due, "ON_DEMAND"
			}
		}
		primary.CurrentMaterialID, primary.PendingMaterialID = id, ""
		// Readiness in every Region is an admission check. A replica can lose
		// its copy afterward; that Region awaits import when rotation completes.
		for _, regional := range related {
			if !allImported(regional) {
				markMaterialMissing(regional)
			}
		}
	}
}

// nextImportTransition selects the same expiry/rotation edge for requests and jobs.
func nextImportTransition(primary *key, related []*key) (time.Time, *key, string) {
	var due time.Time
	if !primary.Rotation.OnDemandStarted.IsZero() {
		due = primary.Rotation.OnDemandStarted.Add(onDemandRotationDelay)
	}
	var expiredKey *key
	var expiredID string
	for _, regional := range related {
		// Material order gives equal-deadline expirations stable ordering.
		for _, material := range primary.Materials {
			// AWS retains expired pending material and permits its rotation.
			// Expiry makes the key unusable only after permanent association.
			if material.ID == primary.PendingMaterialID {
				continue
			}
			imported := regional.imports[material.ID]
			if imported.ValidTo == nil {
				continue
			}
			expires := *imported.ValidTo
			if material.RotationDate.After(expires) {
				expires = material.RotationDate
			}
			if due.IsZero() || !expires.After(due) {
				due, expiredKey, expiredID = expires, regional, material.ID
			}
		}
	}
	return due, expiredKey, expiredID
}
