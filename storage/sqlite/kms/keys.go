package kms

import (
	domain "stackd/storage/kms"
	"stackd/storage/sqlite/kms/internal/sqlcgen"
)

func (tx reader) Keys(sc domain.StorageScope) ([]domain.KeyRecord, error) {
	rows, err := tx.q.ListKeys(tx.ctx, sqlcgen.ListKeysParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region})
	if err != nil {
		return nil, err
	}
	keys := make([]domain.KeyRecord, 0, len(rows))
	for _, row := range rows {
		key := domain.KeyRecord{ID: row.KeyID, ARN: row.Arn, Description: row.Description, Manager: row.Manager, State: row.State, Created: row.Created, Deletion: row.Deletion, AvailableAt: row.AvailableAt, PendingDeletionWindowInDays: int32(row.PendingDeletionDays), Policy: row.Policy}
		principals, err := tx.q.ListPrincipals(tx.ctx, sqlcgen.ListPrincipalsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: row.KeyID})
		if err != nil {
			return nil, err
		}
		for _, p := range principals {
			key.Principals = append(key.Principals, domain.PrincipalBinding{Reference: p.Reference, ID: p.PrincipalID})
		}
		tags, err := tx.q.ListTags(tx.ctx, sqlcgen.ListTagsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: row.KeyID})
		if err != nil {
			return nil, err
		}
		for _, tag := range tags {
			key.Tags = append(key.Tags, domain.TagRecord{Key: tag.TagKey, Value: tag.TagValue})
		}
		key.Grants, err = tx.grants(sc, row.KeyID)
		if err != nil {
			return nil, err
		}
		if err := tx.imports(sc, &key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (tx transaction) PutKey(sc domain.StorageScope, key domain.KeyRecord) error {
	if err := tx.q.PutKey(tx.ctx, sqlcgen.PutKeyParams{
		Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID, Arn: key.ARN, Description: key.Description, Manager: key.Manager, State: key.State,
		Created: key.Created, Deletion: key.Deletion, AvailableAt: key.AvailableAt, PendingDeletionDays: int64(key.PendingDeletionWindowInDays), Policy: key.Policy,
	}); err != nil {
		return err
	}
	if err := tx.q.ClearPrincipals(tx.ctx, sqlcgen.ClearPrincipalsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID}); err != nil {
		return err
	}
	for _, p := range key.Principals {
		if err := tx.q.InsertPrincipal(tx.ctx, sqlcgen.InsertPrincipalParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID, Reference: p.Reference, PrincipalID: p.ID}); err != nil {
			return err
		}
	}
	if err := tx.q.ClearTags(tx.ctx, sqlcgen.ClearTagsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID}); err != nil {
		return err
	}
	for _, tag := range key.Tags {
		if err := tx.q.InsertTag(tx.ctx, sqlcgen.InsertTagParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID, TagKey: tag.Key, TagValue: tag.Value}); err != nil {
			return err
		}
	}
	if err := tx.putGrants(sc, key.ID, key.Grants); err != nil {
		return err
	}
	return tx.putImports(sc, key)
}

func (tx transaction) DeleteKey(sc domain.StorageScope, id string) error {
	return tx.q.DeleteKey(tx.ctx, sqlcgen.DeleteKeyParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: id})
}

func (tx reader) Aliases(sc domain.StorageScope) ([]domain.AliasRecord, error) {
	rows, err := tx.q.ListAliases(tx.ctx, sqlcgen.ListAliasesParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region})
	if err != nil {
		return nil, err
	}
	aliases := make([]domain.AliasRecord, 0, len(rows))
	for _, row := range rows {
		aliases = append(aliases, domain.AliasRecord{Name: row.Name, KeyID: row.KeyID, Created: row.Created, Updated: row.Updated, Owner: domain.AliasOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}})
	}
	return aliases, nil
}

func (tx transaction) PutAlias(sc domain.StorageScope, alias domain.AliasRecord) error {
	return tx.q.PutAlias(tx.ctx, sqlcgen.PutAliasParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, Name: alias.Name, KeyID: alias.KeyID, Created: alias.Created, Updated: alias.Updated, OwnerStackID: alias.Owner.StackID, OwnerLogicalID: alias.Owner.LogicalID, OwnerToken: alias.Owner.Token})
}

func (tx transaction) DeleteAlias(sc domain.StorageScope, name string) error {
	return tx.q.DeleteAlias(tx.ctx, sqlcgen.DeleteAliasParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, Name: name})
}
