package organizations

import (
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type memoryPartition struct {
	record   PartitionRecord
	revision uint64
}

// MemoryStorage is the default replaceable Organizations storage backend.
type MemoryStorage struct {
	store *memory.Store[map[string]memoryPartition]
}

// NewMemoryStorage joins domain, or creates an isolated domain when it is nil.
func NewMemoryStorage(domain *memory.Domain) *MemoryStorage {
	return &MemoryStorage{store: memory.New(domain, make(map[string]memoryPartition), maps.Clone[map[string]memoryPartition])}
}

func (s *MemoryStorage) Partitions(ctx context.Context) ([]string, error) {
	var partitions []string
	err := s.store.View(ctx, func(state *map[string]memoryPartition, _ *memory.Transaction) error {
		partitions = slices.Sorted(maps.Keys(*state))
		return nil
	})
	return partitions, err
}

func (s *MemoryStorage) Load(ctx context.Context, partition string) (PartitionRecord, uint64, error) {
	var record PartitionRecord
	var revision uint64
	err := s.store.View(ctx, func(partitions *map[string]memoryPartition, _ *memory.Transaction) error {
		state, ok := (*partitions)[partition]
		if !ok {
			record = PartitionRecord{AccountSequence: 100000000000}
			return nil
		}
		record, revision = clonePartition(state.record), state.revision
		return nil
	})
	return record, revision, err
}

func (s *MemoryStorage) CompareAndSwap(ctx context.Context, partition string, expected uint64, record PartitionRecord, commit func(context.Context) error) (bool, error) {
	var swapped bool
	err := s.store.Update(ctx, func(partitions *map[string]memoryPartition, tx *memory.Transaction) error {
		if (*partitions)[partition].revision != expected {
			return nil
		}
		(*partitions)[partition] = memoryPartition{record: clonePartition(record), revision: expected + 1}
		if commit != nil {
			if err := commit(tx.Context()); err != nil {
				return err
			}
		}
		swapped = true
		return nil
	})
	return swapped && err == nil, err
}

func clonePartition(record PartitionRecord) PartitionRecord {
	record.Handshakes = slices.Clone(record.Handshakes)
	for i := range record.Handshakes {
		record.Handshakes[i].Tags = maps.Clone(record.Handshakes[i].Tags)
		record.Handshakes[i].Approvals = maps.Clone(record.Handshakes[i].Approvals)
	}
	record.Accounts = slices.Clone(record.Accounts)
	record.Organizations = slices.Clone(record.Organizations)
	for i, o := range record.Organizations {
		o.Organization.AvailablePolicyTypes = slices.Clone(o.Organization.AvailablePolicyTypes)
		o.Root.PolicyTypes = slices.Clone(o.Root.PolicyTypes)
		o.Accounts, o.Units, o.Parents, o.Creations, o.Policies = slices.Clone(o.Accounts), slices.Clone(o.Units), slices.Clone(o.Parents), slices.Clone(o.Creations), slices.Clone(o.Policies)
		for j := range o.Creations {
			o.Creations[j].Tags = maps.Clone(o.Creations[j].Tags)
		}
		o.Attachments, o.Tags, o.Services, o.Delegations = slices.Clone(o.Attachments), slices.Clone(o.Tags), slices.Clone(o.Services), slices.Clone(o.Delegations)
		o.EffectivePolicies = slices.Clone(o.EffectivePolicies)
		for j := range o.EffectivePolicies {
			o.EffectivePolicies[j].ValidationErrors = slices.Clone(o.EffectivePolicies[j].ValidationErrors)
			for k := range o.EffectivePolicies[j].ValidationErrors {
				e := &o.EffectivePolicies[j].ValidationErrors[k]
				e.ContributingPolicies = slices.Clone(e.ContributingPolicies)
			}
			if due := o.EffectivePolicies[j].Due; due != nil {
				o.EffectivePolicies[j].Due = new(*due)
			}
		}
		record.Organizations[i] = o
	}
	return record
}
