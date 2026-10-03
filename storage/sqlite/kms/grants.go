package kms

import (
	domain "stackd/storage/kms"
	"stackd/storage/sqlite/kms/internal/sqlcgen"
)

func (tx reader) grants(sc domain.StorageScope, keyID string) ([]domain.GrantRecord, error) {
	rows, err := tx.q.ListGrants(tx.ctx, sqlcgen.ListGrantsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: keyID})
	if err != nil {
		return nil, err
	}
	var grants []domain.GrantRecord
	byID := make(map[string]int, len(rows))
	for _, row := range rows {
		byID[row.GrantID] = len(grants)
		grants = append(grants, domain.GrantRecord{ID: row.GrantID, Name: row.Name, Grantee: row.Grantee, GranteeID: row.GranteeID, Retiring: row.Retiring, RetiringID: row.RetiringID, Issuer: row.Issuer, Created: row.Created})
	}
	lists, err := tx.q.ListGrantLists(tx.ctx, sqlcgen.ListGrantListsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: keyID})
	if err != nil {
		return nil, err
	}
	for _, row := range lists {
		grant := &grants[byID[row.GrantID]]
		switch row.Kind {
		case "operation":
			grant.Operations = append(grant.Operations, row.Value)
		case "token":
			grant.Tokens = append(grant.Tokens, row.Value)
		}
	}
	constraints, err := tx.q.ListGrantConstraints(tx.ctx, sqlcgen.ListGrantConstraintsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: keyID})
	if err != nil {
		return nil, err
	}
	for _, row := range constraints {
		grant := &grants[byID[row.GrantID]]
		tag := domain.TagRecord{Key: row.TagKey, Value: row.TagValue}
		switch row.Kind {
		case "equals":
			grant.EncryptionContextEquals = append(grant.EncryptionContextEquals, tag)
		case "subset":
			grant.EncryptionContextSubset = append(grant.EncryptionContextSubset, tag)
		}
	}
	return grants, nil
}

func (tx transaction) putGrants(sc domain.StorageScope, keyID string, grants []domain.GrantRecord) error {
	// Deleting a grant cascades to its operation/token and constraint rows.
	if err := tx.q.ClearGrants(tx.ctx, sqlcgen.ClearGrantsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: keyID}); err != nil {
		return err
	}
	for _, grant := range grants {
		if err := tx.q.InsertGrant(tx.ctx, sqlcgen.InsertGrantParams{
			Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: keyID, GrantID: grant.ID, Name: grant.Name, Grantee: grant.Grantee,
			GranteeID: grant.GranteeID, Retiring: grant.Retiring, RetiringID: grant.RetiringID, Issuer: grant.Issuer, Created: grant.Created,
		}); err != nil {
			return err
		}
		for _, list := range []struct {
			kind   string
			values []string
		}{{"operation", grant.Operations}, {"token", grant.Tokens}} {
			for i, value := range list.values {
				if err := tx.q.InsertGrantList(tx.ctx, sqlcgen.InsertGrantListParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: keyID, GrantID: grant.ID, Kind: list.kind, Position: int64(i), Value: value}); err != nil {
					return err
				}
			}
		}
		for _, constraint := range []struct {
			kind string
			tags []domain.TagRecord
		}{{"equals", grant.EncryptionContextEquals}, {"subset", grant.EncryptionContextSubset}} {
			for _, tag := range constraint.tags {
				if err := tx.q.InsertGrantConstraint(tx.ctx, sqlcgen.InsertGrantConstraintParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: keyID, GrantID: grant.ID, Kind: constraint.kind, TagKey: tag.Key, TagValue: tag.Value}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
