package kms

import (
	"errors"
	"slices"
	"time"
)

// These delays model the observed Creating and Updating phases. AWS does not
// promise a fixed completion time; all local consumers use service time.
const replicaCreationDelay = 5 * time.Second
const primaryUpdateDelay = 5 * time.Second

// advanceKeySet owns shared transitions, including deletion ordering. Loading
// any related Region observes the same topology and cryptographic history.
func (s *Service) advanceKeySet(owner KeyOwner, set *KeySetRecord, now time.Time) {
	related := s.keySetKeys(owner, set)
	if len(related) == 0 {
		return
	}
	regional := func(region string) *keyStore {
		return s.regionalStore(scope{partition: owner.Partition, account: owner.AccountID, region: region})
	}
	primaryStore := regional(set.PrimaryRegion)
	primary := related[0]
	// Load and validate every regional record before shared import transitions.
	// Expiry/rotation must precede deletion when a clock advance crosses both.
	for _, replica := range related[1:] {
		advanceRegionalState(replica, now)
	}
	advanceRegionalState(primary, now)
	if primary.Origin == "EXTERNAL" {
		s.advanceImported(primary, now)
	}
	var lastReplicaDeletion time.Time
	for _, region := range slices.Clone(set.ReplicaRegions) {
		store := regional(region)
		replica := store.keys[set.ID]
		if replica.deletion != nil && !now.Before(*replica.deletion) {
			if replica.deletion.After(lastReplicaDeletion) {
				lastReplicaDeletion = *replica.deletion
			}
			deleteRegionalKey(store, set.ID)
			set.ReplicaRegions = slices.DeleteFunc(set.ReplicaRegions, func(value string) bool { return value == region })
		}
	}
	if primary.state == "PendingReplicaDeletion" && len(set.ReplicaRegions) == 0 {
		primary.state = "PendingDeletion"
		primary.deletion = ptr(lastReplicaDeletion.Add(time.Duration(primary.pendingDeletionWindowInDays) * 24 * time.Hour))
		primary.pendingDeletionWindowInDays = 0
	}
	if primary.deletion != nil && !now.Before(*primary.deletion) {
		deleteRegionalKey(primaryStore, set.ID)
		for _, material := range set.Materials {
			clear(material.Material)
		}
		s.keySets[keySetReference{owner: owner, id: set.ID}] = nil
		return
	}
	if primary.Origin == "EXTERNAL" {
		clearAbsentMaterial(primary, s.relatedKeys(primary))
	} else {
		advanceRotation(primary, now)
	}
}

// keySetKeys owns the invariant that each referenced Region has a key record.
// It loads the primary first, followed by replicas in their retained order.
func (s *Service) keySetKeys(owner KeyOwner, set *KeySetRecord) []*key {
	regions := append([]string{set.PrimaryRegion}, set.ReplicaRegions...)
	keys := make([]*key, 0, len(regions))
	for _, region := range regions {
		k := s.regionalStore(scope{partition: owner.Partition, account: owner.AccountID, region: region}).keys[set.ID]
		if k == nil {
			s.storageErr = errors.New("KMS key set has no referenced regional key")
			return nil
		}
		keys = append(keys, k)
	}
	return keys
}

func advanceRegionalState(k *key, now time.Time) {
	if (k.state == "Creating" || k.state == "Updating") && !now.Before(k.availableAt) {
		k.state, k.availableAt = "Enabled", time.Time{}
		if k.Origin == "EXTERNAL" && !allImported(k) {
			k.state = "PendingImport"
		}
	}
}

func deleteRegionalKey(store *keyStore, id string) {
	delete(store.keys, id)
	for name, alias := range store.aliases {
		if alias.keyID == id {
			delete(store.aliases, name)
		}
	}
}
