package apigatewayv2

import (
	"database/sql"
	"time"

	"stackd/internal/services/apigatewayexec"
	domain "stackd/internal/services/apigatewayv2"
	"stackd/storage/sqlite/apigatewayv2/internal/sqlcgen"
)

func (r reader) AuthorizerCache(key domain.AuthorizerCacheKey) (domain.AuthorizerCacheRecord, error) {
	stage := key.Stage
	row, err := r.q.GetAuthorizerCache(r.ctx, sqlcgen.GetAuthorizerCacheParams{Partition: stage.Partition, AccountID: stage.AccountID, Region: stage.Region, GatewayID: stage.APIKey.ID, StageID: stage.ID, AuthorizerID: key.AuthorizerID, IdentityKey: key.IdentityKey})
	if err != nil {
		return domain.AuthorizerCacheRecord{}, missing(err)
	}
	out := domain.AuthorizerCacheRecord{Key: key, AuthorizerResult: apigatewayexec.AuthorizerResult{PrincipalID: new(row.PrincipalID), PolicyDocument: row.PolicyDocument}, ExpiresAt: row.ExpiresAt.UTC()}
	if err := decode(row.Context, &out.Context); err != nil {
		return out, err
	}
	if row.IsAuthorized.Valid {
		out.IsAuthorized = new(row.IsAuthorized.Int64 != 0)
	}
	return out, nil
}

func (w writer) PutAuthorizerCache(v domain.AuthorizerCacheRecord) error {
	stage := v.Key.Stage
	context, err := encode(v.Context)
	if err != nil {
		return err
	}
	authorized := sql.NullInt64{}
	if v.IsAuthorized != nil {
		authorized = sql.NullInt64{Int64: integer(*v.IsAuthorized), Valid: true}
	}
	principal := ""
	if v.PrincipalID != nil {
		principal = *v.PrincipalID
	}
	return w.q.PutAuthorizerCache(w.ctx, sqlcgen.PutAuthorizerCacheParams{Partition: stage.Partition, AccountID: stage.AccountID, Region: stage.Region, GatewayID: stage.APIKey.ID, StageID: stage.ID, AuthorizerID: v.Key.AuthorizerID, IdentityKey: v.Key.IdentityKey, PrincipalID: principal, PolicyDocument: v.PolicyDocument, Context: context, IsAuthorized: authorized, ExpiresAt: v.ExpiresAt.UTC()})
}

func (w writer) DeleteStageAuthorizerCache(stage domain.ResourceKey) error {
	return w.q.DeleteStageAuthorizerCache(w.ctx, sqlcgen.DeleteStageAuthorizerCacheParams{Partition: stage.Partition, AccountID: stage.AccountID, Region: stage.Region, GatewayID: stage.APIKey.ID, StageID: stage.ID})
}

func (w writer) PruneAuthorizerCache(key domain.APIKey, now time.Time) error {
	return w.q.PruneAuthorizerCache(w.ctx, sqlcgen.PruneAuthorizerCacheParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GatewayID: key.ID, ExpiresAt: now.UTC()})
}
