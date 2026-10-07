package cognitoidp

import (
	"database/sql"

	api "stackd/internal/awsapi/cognitoidp"
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

func (r reader) Ownership(k domain.OwnershipKey) (domain.OwnershipRecord, error) {
	row, err := r.q.GetResourceOwner(r.ctx, sqlcgen.GetResourceOwnerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, Kind: k.Kind, Name: k.Name})
	if err != nil {
		return domain.OwnershipRecord{}, missing(err)
	}
	return domain.OwnershipRecord{
		Key:        k,
		PhysicalID: row.PhysicalID, MemberUser: row.MemberUser, MemberGroup: row.MemberGroup,
		Owner: domain.ResourceOwner{StackID: row.StackID, LogicalID: row.LogicalID, Token: row.Token},
	}, nil
}

func (r reader) PoolOwnership(scope domain.Scope, owner domain.ResourceOwner) (domain.OwnershipRecord, error) {
	row, err := r.q.GetPoolResourceOwner(r.ctx, sqlcgen.GetPoolResourceOwnerParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, StackID: owner.StackID, LogicalID: owner.LogicalID, Token: owner.Token})
	if err != nil {
		return domain.OwnershipRecord{}, missing(err)
	}
	return domain.OwnershipRecord{
		Key:        domain.OwnershipKey{PoolKey: domain.PoolKey{Scope: scope, ID: row.PoolID}, Kind: row.Kind, Name: row.Name},
		PhysicalID: row.PhysicalID, MemberUser: row.MemberUser, MemberGroup: row.MemberGroup,
		Owner: domain.ResourceOwner{StackID: row.StackID, LogicalID: row.LogicalID, Token: row.Token},
	}, nil
}

func (w writer) PutOwnership(v domain.OwnershipRecord) error {
	k := v.Key
	return w.q.PutResourceOwner(w.ctx, sqlcgen.PutResourceOwnerParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, Kind: k.Kind, Name: k.Name,
		PhysicalID: v.PhysicalID, MemberUser: v.MemberUser, MemberGroup: v.MemberGroup,
		StackID: v.Owner.StackID, LogicalID: v.Owner.LogicalID, Token: v.Owner.Token,
	})
}

func (w writer) DeleteOwnership(k domain.OwnershipKey) error {
	return w.q.DeleteResourceOwner(w.ctx, sqlcgen.DeleteResourceOwnerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, Kind: k.Kind, Name: k.Name})
}

// releaseOwners removes the claims naming a deleted pool child. Pool deletion
// cascades through the owner table's foreign key.
func (w writer) releaseOwners(k domain.PoolKey, physicalID string, kinds ...string) error {
	for _, kind := range kinds {
		if err := w.q.DeleteResourceOwnersByPhysicalID(w.ctx, sqlcgen.DeleteResourceOwnersByPhysicalIDParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Kind: kind, PhysicalID: physicalID}); err != nil {
			return err
		}
	}
	return nil
}

func providerRow(row sqlcgen.CognitoidpIdentityProvider) (domain.ProviderRecord, error) {
	out := domain.ProviderRecord{
		Key: domain.ProviderKey{PoolKey: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, Name: row.ProviderName},
		Data: api.IdentityProviderType{
			UserPoolId: new(api.UserPoolIdType(row.PoolID)), ProviderName: new(api.ProviderNameType(row.ProviderName)), ProviderType: new(api.IdentityProviderTypeType(row.ProviderType)),
			CreationDate: timePointer(row.CreationDate), LastModifiedDate: timePointer(row.LastModifiedDate),
		},
	}
	err := unmarshalFields(
		jsonReadField{row.ProviderDetails, &out.Data.ProviderDetails},
		jsonReadField{row.AttributeMapping, &out.Data.AttributeMapping},
		jsonReadField{row.IdpIdentifiers, &out.Data.IdpIdentifiers},
	)
	return out, err
}

func (r reader) Provider(k domain.ProviderKey) (domain.ProviderRecord, error) {
	row, err := r.q.GetIdentityProvider(r.ctx, sqlcgen.GetIdentityProviderParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, ProviderName: k.Name})
	if err != nil {
		return domain.ProviderRecord{}, missing(err)
	}
	return providerRow(row)
}

func (r reader) Providers(k domain.PoolKey) ([]domain.ProviderRecord, error) {
	rows, err := r.q.ListIdentityProviders(r.ctx, sqlcgen.ListIdentityProvidersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ProviderRecord, len(rows))
	for i, row := range rows {
		if out[i], err = providerRow(row); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (w writer) PutProvider(v domain.ProviderRecord) error {
	k := v.Key
	row := sqlcgen.PutIdentityProviderParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, ProviderName: k.Name,
		ProviderType: string(*v.Data.ProviderType), CreationDate: nullableTime(v.Data.CreationDate), LastModifiedDate: nullableTime(v.Data.LastModifiedDate),
	}
	if err := marshalFields(
		jsonWriteField{&row.ProviderDetails, v.Data.ProviderDetails},
		jsonWriteField{&row.AttributeMapping, v.Data.AttributeMapping},
		jsonWriteField{&row.IdpIdentifiers, v.Data.IdpIdentifiers},
	); err != nil {
		return err
	}
	return w.q.PutIdentityProvider(w.ctx, row)
}

func (w writer) DeleteProvider(k domain.ProviderKey) error {
	if err := w.q.DeleteIdentityProvider(w.ctx, sqlcgen.DeleteIdentityProviderParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, ProviderName: k.Name}); err != nil {
		return err
	}
	return w.releaseOwners(k.PoolKey, k.Name, domain.OwnerKindProvider)
}

func (r reader) ClientsByID(partition, id string) ([]domain.ClientRecord, error) {
	rows, err := r.q.ListClientsByIDInPartition(r.ctx, sqlcgen.ListClientsByIDInPartitionParams{Partition: partition, ClientID: id})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ClientRecord, len(rows))
	for i, row := range rows {
		if out[i], err = clientRow(row); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) PoolByDomain(partition, region, name string) (domain.PoolRecord, error) {
	row, err := r.q.GetPoolByDomain(r.ctx, sqlcgen.GetPoolByDomainParams{Partition: partition, Region: region, Domain: sql.NullString{String: name, Valid: true}})
	if err != nil {
		return domain.PoolRecord{}, missing(err)
	}
	return poolRow(row)
}
