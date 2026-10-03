package kms

import (
	"database/sql"
	"errors"

	domain "stackd/storage/kms"
	"stackd/storage/sqlite/kms/internal/sqlcgen"
)

func (tx reader) KeySet(owner domain.KeyOwner, id string) (domain.KeySetRecord, error) {
	row, err := tx.q.GetKeySet(tx.ctx, sqlcgen.GetKeySetParams{Partition: owner.Partition, Account: owner.AccountID, KeyID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.KeySetRecord{}, domain.ErrKeySetNotFound
	}
	if err != nil {
		return domain.KeySetRecord{}, err
	}
	set := domain.KeySetRecord{
		ID: row.KeyID, Spec: row.Spec, Usage: row.Usage, Origin: row.Origin, CurrentMaterialID: row.CurrentMaterialID, PendingMaterialID: row.PendingMaterialID,
		MultiRegion: row.MultiRegion, PrimaryRegion: row.PrimaryRegion,
		Rotation: domain.RotationState{Enabled: row.RotationEnabled, PeriodInDays: int32(row.RotationPeriodDays), Next: row.RotationNext, OnDemandStarted: row.RotationStarted},
	}
	materials, err := tx.q.ListMaterials(tx.ctx, sqlcgen.ListMaterialsParams{Partition: owner.Partition, Account: owner.AccountID, KeyID: id})
	if err != nil {
		return domain.KeySetRecord{}, err
	}
	for _, material := range materials {
		set.Materials = append(set.Materials, domain.KeyMaterialRecord{ID: material.MaterialID, Material: material.Material, RotationDate: material.RotationDate, RotationType: material.RotationType, Description: material.Description})
	}
	regions, err := tx.q.ListReplicaRegions(tx.ctx, sqlcgen.ListReplicaRegionsParams{Partition: owner.Partition, Account: owner.AccountID, KeyID: id})
	if err != nil {
		return domain.KeySetRecord{}, err
	}
	for _, region := range regions {
		set.ReplicaRegions = append(set.ReplicaRegions, region.Region)
	}
	return set, nil
}

func (tx reader) MultiRegionPrimaryRegions(owner domain.KeyOwner) ([]string, error) {
	return tx.q.MultiRegionPrimaryRegions(tx.ctx, sqlcgen.MultiRegionPrimaryRegionsParams{Partition: owner.Partition, Account: owner.AccountID})
}

func (tx transaction) PutKeySet(owner domain.KeyOwner, set domain.KeySetRecord) error {
	if err := tx.q.PutKeySet(tx.ctx, sqlcgen.PutKeySetParams{
		Partition: owner.Partition, Account: owner.AccountID, KeyID: set.ID, Spec: set.Spec, Usage: set.Usage, Origin: set.Origin,
		CurrentMaterialID: set.CurrentMaterialID, PendingMaterialID: set.PendingMaterialID, MultiRegion: set.MultiRegion, PrimaryRegion: set.PrimaryRegion,
		RotationEnabled: set.Rotation.Enabled, RotationPeriodDays: int64(set.Rotation.PeriodInDays), RotationNext: set.Rotation.Next, RotationStarted: set.Rotation.OnDemandStarted,
	}); err != nil {
		return err
	}
	if err := tx.q.ClearMaterials(tx.ctx, sqlcgen.ClearMaterialsParams{Partition: owner.Partition, Account: owner.AccountID, KeyID: set.ID}); err != nil {
		return err
	}
	for i, material := range set.Materials {
		if err := tx.q.InsertMaterial(tx.ctx, sqlcgen.InsertMaterialParams{
			Partition: owner.Partition, Account: owner.AccountID, KeyID: set.ID, Position: int64(i), MaterialID: material.ID, Material: material.Material,
			RotationDate: material.RotationDate, RotationType: material.RotationType, Description: material.Description,
		}); err != nil {
			return err
		}
	}
	if err := tx.q.ClearReplicaRegions(tx.ctx, sqlcgen.ClearReplicaRegionsParams{Partition: owner.Partition, Account: owner.AccountID, KeyID: set.ID}); err != nil {
		return err
	}
	for i, region := range set.ReplicaRegions {
		if err := tx.q.InsertReplicaRegion(tx.ctx, sqlcgen.InsertReplicaRegionParams{Partition: owner.Partition, Account: owner.AccountID, KeyID: set.ID, Position: int64(i), Region: region}); err != nil {
			return err
		}
	}
	return nil
}

func (tx transaction) DeleteKeySet(owner domain.KeyOwner, id string) error {
	return tx.q.DeleteKeySet(tx.ctx, sqlcgen.DeleteKeySetParams{Partition: owner.Partition, Account: owner.AccountID, KeyID: id})
}
