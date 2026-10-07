package cognitoidp

import (
	api "stackd/internal/awsapi/cognitoidp"
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

func clientRow(row sqlcgen.CognitoidpClient) (domain.ClientRecord, error) {
	out := domain.ClientRecord{
		Key: domain.ClientKey{PoolKey: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, ID: row.ClientID},

		Data: api.UserPoolClientType{
			ClientId: new(api.ClientIdType(row.ClientID)), UserPoolId: new(api.UserPoolIdType(row.PoolID)),
			AccessTokenValidity:                      integerPointer[api.AccessTokenValidityType](row.AccessTokenValidity),
			AllowedOAuthFlowsUserPoolClient:          boolPointer[api.BooleanType](row.AllowedOAuthFlowsUserPoolClient),
			AuthSessionValidity:                      integerPointer[api.AuthSessionValidityType](row.AuthSessionValidity),
			ClientName:                               stringPointer[api.ClientNameType](row.ClientName),
			ClientSecret:                             stringPointer[api.ClientSecretType](row.ClientSecret),
			CreationDate:                             timePointer(row.CreationDate),
			DefaultRedirectURI:                       stringPointer[api.RedirectUrlType](row.DefaultRedirectUri),
			EnablePropagateAdditionalUserContextData: boolPointer[api.WrappedBooleanType](row.EnablePropagateAdditionalUserContextData),
			EnableTokenRevocation:                    boolPointer[api.WrappedBooleanType](row.EnableTokenRevocation),
			IdTokenValidity:                          integerPointer[api.IdTokenValidityType](row.IDTokenValidity),
			LastModifiedDate:                         timePointer(row.LastModifiedDate),
			PreventUserExistenceErrors:               stringPointer[api.PreventUserExistenceErrorTypes](row.PreventUserExistenceErrors),
			RefreshTokenValidity:                     integerPointer[api.RefreshTokenValidityType](row.RefreshTokenValidity),
		},
	}
	err := unmarshalFields(
		jsonReadField{row.AllowedOAuthFlows, &out.Data.AllowedOAuthFlows},
		jsonReadField{row.AllowedOAuthScopes, &out.Data.AllowedOAuthScopes},
		jsonReadField{row.AnalyticsConfiguration, &out.Data.AnalyticsConfiguration},
		jsonReadField{row.CallbackUrls, &out.Data.CallbackURLs},
		jsonReadField{row.ExplicitAuthFlows, &out.Data.ExplicitAuthFlows},
		jsonReadField{row.LogoutUrls, &out.Data.LogoutURLs},
		jsonReadField{row.ReadAttributes, &out.Data.ReadAttributes},
		jsonReadField{row.RefreshTokenRotation, &out.Data.RefreshTokenRotation},
		jsonReadField{row.SupportedIdentityProviders, &out.Data.SupportedIdentityProviders},
		jsonReadField{row.TokenValidityUnits, &out.Data.TokenValidityUnits},
		jsonReadField{row.WriteAttributes, &out.Data.WriteAttributes},
	)
	return out, err
}

func (r reader) Client(k domain.ClientKey) (domain.ClientRecord, error) {
	row, err := r.q.GetClient(r.ctx, sqlcgen.GetClientParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, ClientID: k.ID})
	if err != nil {
		return domain.ClientRecord{}, missing(err)
	}
	return clientRow(row)
}

func (r reader) ClientByID(partition, region, id string) (domain.ClientRecord, error) {
	row, err := r.q.GetClientByID(r.ctx, sqlcgen.GetClientByIDParams{Partition: partition, Region: region, ClientID: id})
	if err != nil {
		return domain.ClientRecord{}, missing(err)
	}
	return clientRow(row)
}

func (r reader) Clients(k domain.PoolKey) ([]domain.ClientRecord, error) {
	rows, err := r.q.ListClients(r.ctx, sqlcgen.ListClientsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ClientRecord, len(rows))
	for i, row := range rows {
		out[i], err = clientRow(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (w writer) PutClient(v domain.ClientRecord) error {
	k := v.Key
	row := sqlcgen.PutClientParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, ClientID: k.ID,

		AccessTokenValidity:                      nullableInteger(v.Data.AccessTokenValidity),
		AllowedOAuthFlowsUserPoolClient:          nullableBool(v.Data.AllowedOAuthFlowsUserPoolClient),
		AuthSessionValidity:                      nullableInteger(v.Data.AuthSessionValidity),
		ClientName:                               nullableString(v.Data.ClientName),
		ClientSecret:                             nullableString(v.Data.ClientSecret),
		CreationDate:                             nullableTime(v.Data.CreationDate),
		DefaultRedirectUri:                       nullableString(v.Data.DefaultRedirectURI),
		EnablePropagateAdditionalUserContextData: nullableBool(v.Data.EnablePropagateAdditionalUserContextData),
		EnableTokenRevocation:                    nullableBool(v.Data.EnableTokenRevocation),
		IDTokenValidity:                          nullableInteger(v.Data.IdTokenValidity),
		LastModifiedDate:                         nullableTime(v.Data.LastModifiedDate),
		PreventUserExistenceErrors:               nullableString(v.Data.PreventUserExistenceErrors),
		RefreshTokenValidity:                     nullableInteger(v.Data.RefreshTokenValidity),
	}
	if err := marshalFields(
		jsonWriteField{&row.AllowedOAuthFlows, v.Data.AllowedOAuthFlows},
		jsonWriteField{&row.AllowedOAuthScopes, v.Data.AllowedOAuthScopes},
		jsonWriteField{&row.AnalyticsConfiguration, v.Data.AnalyticsConfiguration},
		jsonWriteField{&row.CallbackUrls, v.Data.CallbackURLs},
		jsonWriteField{&row.ExplicitAuthFlows, v.Data.ExplicitAuthFlows},
		jsonWriteField{&row.LogoutUrls, v.Data.LogoutURLs},
		jsonWriteField{&row.ReadAttributes, v.Data.ReadAttributes},
		jsonWriteField{&row.RefreshTokenRotation, v.Data.RefreshTokenRotation},
		jsonWriteField{&row.SupportedIdentityProviders, v.Data.SupportedIdentityProviders},
		jsonWriteField{&row.TokenValidityUnits, v.Data.TokenValidityUnits},
		jsonWriteField{&row.WriteAttributes, v.Data.WriteAttributes},
	); err != nil {
		return err
	}
	return w.q.PutClient(w.ctx, row)
}

func (w writer) DeleteClient(k domain.ClientKey) error {
	if err := w.q.DeleteClient(w.ctx, sqlcgen.DeleteClientParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, ClientID: k.ID}); err != nil {
		return err
	}
	return w.releaseOwners(k.PoolKey, k.ID, domain.OwnerKindClient, domain.OwnerKindClientToken)
}
