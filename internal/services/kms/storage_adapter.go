package kms

import (
	"context"
	"errors"
	"maps"
	"slices"

	"stackd/internal/awswire"
)

type keySetReference struct {
	owner KeyOwner
	id    string
}

// transact owns only an operation's working set. The replaceable Storage is
// authoritative; no committed keys are retained in Service between operations.
func (s *Service) transact(ctx context.Context, fn func(context.Context) *awswire.Error) *awswire.Error {
	err := s.storage.Attempt(ctx, func(tx Transaction) error {
		return s.withWriteSet(tx, func(ctx context.Context) (bool, error) {
			if err := fn(ctx); err != nil {
				return false, err
			}
			return true, nil
		})
	})
	return transactionError(err)
}

func transactionError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var apiErr *awswire.Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return failure("KMSInternalException", "KMS storage transaction failed.")
}

// withTransaction loads a detached working set. The callback returns false
// when no working-set writes should be saved.
func (s *Service) withTransaction(ctx context.Context, fn func(context.Context) (bool, error)) error {
	return s.storage.Transact(ctx, func(tx Transaction) error {
		return s.withWriteSet(tx, fn)
	})
}

func (s *Service) withWorkingSet(reader Reader, fn func(context.Context) error) error {
	// Join the shared transaction before taking the working-set lock: callers
	// such as Secrets Manager already own the transaction when they use KMS.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transactionTime = s.now()
	s.transaction = reader
	s.stores = make(map[scope]*keyStore)
	s.storageErr = nil
	s.keySets = make(map[keySetReference]*KeySetRecord)
	defer func() { s.transaction = nil; s.stores = nil; s.baselines = nil; s.keySets = nil; s.storageErr = nil }()
	return fn(reader.Context())
}

func (s *Service) withWriteSet(tx Transaction, fn func(context.Context) (bool, error)) error {
	return s.withWorkingSet(tx, func(ctx context.Context) error {
		s.baselines = make(map[scope]*keyStore)
		write, err := fn(ctx)
		if s.storageErr != nil {
			return s.storageErr
		}
		if err != nil || !write {
			return err
		}
		for ref, set := range s.keySets {
			if set != nil {
				if err := tx.PutKeySet(ref.owner, *set); err != nil {
					return err
				}
			}
		}
		for sc, st := range s.stores {
			if err := s.saveScope(tx, sc, st, s.baselines[sc]); err != nil {
				return err
			}
		}
		for ref, set := range s.keySets {
			if set == nil {
				if err := tx.DeleteKeySet(ref.owner, ref.id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Service) loadScope(sc scope) *keyStore {
	st := &keyStore{keys: make(map[string]*key), aliases: make(map[string]*alias)}
	keys, err := s.transaction.Keys(storageScope(sc))
	if err != nil {
		s.storageErr = err
		return st
	}
	aliases, err := s.transaction.Aliases(storageScope(sc))
	if err != nil {
		s.storageErr = err
		return st
	}
	for _, record := range keys {
		ref := keySetReference{owner: sc.owner(), id: record.ID}
		set, loaded := s.keySets[ref]
		if !loaded {
			shared, err := s.transaction.KeySet(ref.owner, ref.id)
			if err != nil {
				s.storageErr = err
				return st
			}
			set = &shared
			s.keySets[ref] = set
		}
		k := &key{KeySetRecord: set, arn: record.ARN, description: record.Description, manager: record.Manager, state: record.State, created: record.Created, deletion: record.Deletion, availableAt: record.AvailableAt, pendingDeletionWindowInDays: record.PendingDeletionWindowInDays, policy: record.Policy, importParameters: record.ImportParameters, imports: make(map[string]ImportedMaterialRecord), principalIDs: make(map[string]string), tags: make(map[string]string)}
		k.owner = record.Owner
		for _, imported := range record.Imports {
			k.imports[imported.ID] = imported
		}
		for _, p := range record.Principals {
			k.principalIDs[p.Reference] = p.ID
		}
		for _, tag := range record.Tags {
			k.tags[tag.Key] = tag.Value
		}
		k.grants = make(map[string]*grant, len(record.Grants))
		for _, g := range record.Grants {
			k.grants[g.ID] = &grant{id: g.ID, name: g.Name, grantee: g.Grantee, granteeID: g.GranteeID, retiring: g.Retiring, retiringID: g.RetiringID, issuer: g.Issuer, created: g.Created, operations: g.Operations, tokens: g.Tokens, equals: tagsMap(g.EncryptionContextEquals), subset: tagsMap(g.EncryptionContextSubset)}
		}
		st.keys[k.ID] = k
	}
	for _, a := range aliases {
		st.aliases[a.Name] = &alias{name: a.Name, keyID: a.KeyID, created: a.Created, updated: a.Updated, owner: a.Owner}
	}
	if s.baselines != nil {
		s.baselines[sc] = &keyStore{keys: maps.Clone(st.keys), aliases: maps.Clone(st.aliases)}
	}
	return st
}

func (s *Service) saveScope(tx Transaction, sc scope, st, baseline *keyStore) error {
	if baseline == nil {
		baseline = &keyStore{}
	}
	for id := range baseline.keys {
		if st.keys[id] == nil {
			if err := tx.DeleteKey(storageScope(sc), id); err != nil {
				return err
			}
		}
	}
	for name := range baseline.aliases {
		if st.aliases[name] == nil {
			if err := tx.DeleteAlias(storageScope(sc), name); err != nil {
				return err
			}
		}
	}
	for _, id := range slices.Sorted(maps.Keys(st.keys)) {
		k := st.keys[id]
		record := KeyRecord{ID: k.ID, ARN: k.arn, Description: k.description, Manager: k.manager, State: k.state, Created: k.created, Deletion: k.deletion, AvailableAt: k.availableAt, PendingDeletionWindowInDays: k.pendingDeletionWindowInDays, Policy: k.policy, ImportParameters: k.importParameters}
		record.Owner = k.owner
		for _, id := range slices.Sorted(maps.Keys(k.imports)) {
			record.Imports = append(record.Imports, k.imports[id])
		}
		for _, reference := range slices.Sorted(maps.Keys(k.principalIDs)) {
			record.Principals = append(record.Principals, PrincipalBinding{Reference: reference, ID: k.principalIDs[reference]})
		}
		for _, name := range slices.Sorted(maps.Keys(k.tags)) {
			record.Tags = append(record.Tags, TagRecord{Key: name, Value: k.tags[name]})
		}
		for _, id := range slices.Sorted(maps.Keys(k.grants)) {
			g := k.grants[id]
			record.Grants = append(record.Grants, GrantRecord{ID: g.id, Name: g.name, Grantee: g.grantee, GranteeID: g.granteeID, Retiring: g.retiring, RetiringID: g.retiringID, Issuer: g.issuer, Created: g.created, Operations: g.operations, Tokens: g.tokens, EncryptionContextEquals: mapTags(g.equals), EncryptionContextSubset: mapTags(g.subset)})
		}
		if err := tx.PutKey(storageScope(sc), record); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(st.aliases)) {
		a := st.aliases[name]
		if err := tx.PutAlias(storageScope(sc), AliasRecord{Name: name, KeyID: a.keyID, Created: a.created, Updated: a.updated, Owner: a.owner}); err != nil {
			return err
		}
	}
	return nil
}

func tagsMap(tags []TagRecord) map[string]string {
	if tags == nil {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[tag.Key] = tag.Value
	}
	return out
}

func mapTags(tags map[string]string) []TagRecord {
	if tags == nil {
		return nil
	}
	out := make([]TagRecord, 0, len(tags))
	for _, name := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, TagRecord{Key: name, Value: tags[name]})
	}
	return out
}
