package appsync

import (
	"errors"
	api "stackd/internal/awsapi/appsync"
	domain "stackd/storage/appsync"
	"stackd/storage/sqlite/appsync/internal/sqlcgen"
)

func (r reader) decodeAPI(v sqlcgen.AppsyncApi) (domain.APIRecord, error) {
	p := domain.APIRecord{Key: domain.Key{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ApiID}, Schema: v.SchemaDefinition, SchemaStatus: v.SchemaStatus, SchemaDetails: v.SchemaDetails}
	a := &p.API
	text(&a.ApiId, v.ApiID)
	text(&a.Arn, p.Key.ARN())
	text(&a.Name, v.Name)
	text(&a.AuthenticationType, v.AuthType)
	text(&a.ApiType, v.ApiType)
	text(&a.Visibility, v.Visibility)
	text(&a.IntrospectionConfig, v.Introspection)
	text(&a.Owner, v.Owner)
	readString(&a.OwnerContact, v.OwnerContact)
	readNumber(&a.QueryDepthLimit, v.QueryDepthLimit)
	readNumber(&a.ResolverCountLimit, v.ResolverCountLimit)
	readBoolean(&a.XrayEnabled, v.XrayEnabled)
	a.Uris = api.MapOfStringToString{"GRAPHQL": api.String(v.GraphqlUri), "REALTIME": api.String(v.RealtimeUri)}
	tags, e := r.q.ListTag(r.ctx, v.ApiID)
	if e != nil {
		return p, e
	}
	if len(tags) > 0 {
		a.Tags = api.TagMap{}
	}
	for _, tag := range tags {
		a.Tags[api.TagKey(tag.TagKey)] = api.TagValue(tag.TagValue)
	}
	auth, e := r.q.ListAuth(r.ctx, v.ApiID)
	if e != nil {
		return p, e
	}
	for _, v := range auth {
		var pool *api.UserPoolConfig
		var oidc *api.OpenIDConnectConfig
		if v.PoolID.Valid {
			pool = &api.UserPoolConfig{}
			readString(&pool.UserPoolId, v.PoolID)
			readString(&pool.AwsRegion, v.PoolRegion)
			readString(&pool.AppIdClientRegex, v.ClientRegex)
			readString(&pool.DefaultAction, v.DefaultAction)
		}
		if v.Issuer.Valid {
			oidc = &api.OpenIDConnectConfig{}
			readString(&oidc.Issuer, v.Issuer)
			readString(&oidc.ClientId, v.OidcClient)
			readNumber(&oidc.AuthTTL, v.AuthTtl)
			readNumber(&oidc.IatTTL, v.IatTtl)
		}
		if v.Ordinal < 0 {
			a.UserPoolConfig = pool
			a.OpenIDConnectConfig = oidc
		} else {
			provider := api.AdditionalAuthenticationProvider{OpenIDConnectConfig: oidc}
			text(&provider.AuthenticationType, v.AuthType)
			if pool != nil {
				provider.UserPoolConfig = &api.CognitoUserPoolConfig{UserPoolId: pool.UserPoolId, AwsRegion: pool.AwsRegion, AppIdClientRegex: pool.AppIdClientRegex}
			}
			a.AdditionalAuthenticationProviders = append(a.AdditionalAuthenticationProviders, provider)
		}
	}
	return p, nil
}
func (r writer) PutAPI(p domain.APIRecord) error {
	if current, e := r.APIByID(p.Key.ID); e == nil && current.Key != p.Key {
		return domain.ErrConflict
	} else if e != nil && !errors.Is(e, domain.ErrNotFound) {
		return e
	}
	a := p.API
	details := p.SchemaDetails
	if details == nil {
		details = []byte{}
	}
	v := sqlcgen.AppsyncApi{Partition: p.Key.Partition, AccountID: p.Key.AccountID, Region: p.Key.Region, ApiID: p.Key.ID, Name: val(a.Name), AuthType: val(a.AuthenticationType), ApiType: val(a.ApiType), Visibility: val(a.Visibility), Introspection: val(a.IntrospectionConfig), Owner: val(a.Owner), OwnerContact: str(a.OwnerContact), QueryDepthLimit: number(a.QueryDepthLimit), ResolverCountLimit: number(a.ResolverCountLimit), XrayEnabled: boolean(a.XrayEnabled), GraphqlUri: string(a.Uris["GRAPHQL"]), RealtimeUri: string(a.Uris["REALTIME"]), SchemaDefinition: p.Schema, SchemaStatus: p.SchemaStatus, SchemaDetails: details}
	if e := r.q.PutAPI(r.ctx, sqlcgen.PutAPIParams(v)); e != nil {
		return e
	}
	if e := r.q.ClearTag(r.ctx, p.Key.ID); e != nil {
		return e
	}
	for k, v := range a.Tags {
		if e := r.q.PutTag(r.ctx, sqlcgen.PutTagParams{ApiID: p.Key.ID, TagKey: string(k), TagValue: string(v)}); e != nil {
			return e
		}
	}
	if e := r.q.ClearAuth(r.ctx, p.Key.ID); e != nil {
		return e
	}
	if e := r.putAuth(p.Key.ID, -1, val(a.AuthenticationType), a.UserPoolConfig, a.OpenIDConnectConfig); e != nil {
		return e
	}
	for i, v := range a.AdditionalAuthenticationProviders {
		var pool *api.UserPoolConfig
		if v.UserPoolConfig != nil {
			pool = &api.UserPoolConfig{AwsRegion: v.UserPoolConfig.AwsRegion, UserPoolId: v.UserPoolConfig.UserPoolId, AppIdClientRegex: v.UserPoolConfig.AppIdClientRegex}
		}
		if e := r.putAuth(p.Key.ID, int64(i), val(v.AuthenticationType), pool, v.OpenIDConnectConfig); e != nil {
			return e
		}
	}
	return nil
}
func (r writer) putAuth(id string, ordinal int64, mode string, pool *api.UserPoolConfig, oidc *api.OpenIDConnectConfig) error {
	v := sqlcgen.PutAuthParams{ApiID: id, Ordinal: ordinal, AuthType: mode}
	if pool != nil {
		v.PoolID = str(pool.UserPoolId)
		v.PoolRegion = str(pool.AwsRegion)
		v.ClientRegex = str(pool.AppIdClientRegex)
		v.DefaultAction = str(pool.DefaultAction)
	}
	if oidc != nil {
		v.Issuer = str(oidc.Issuer)
		v.OidcClient = str(oidc.ClientId)
		v.AuthTtl = number(oidc.AuthTTL)
		v.IatTtl = number(oidc.IatTTL)
	}
	return r.q.PutAuth(r.ctx, v)
}
