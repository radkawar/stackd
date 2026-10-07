package cognitoidp

import (
	"time"

	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

func (r reader) OAuth(k domain.OAuthKey) (domain.OAuthRecord, error) {
	row, err := r.q.GetOAuth(r.ctx, sqlcgen.GetOAuthParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Token: k.Token})
	if err != nil {
		return domain.OAuthRecord{}, missing(err)
	}
	return domain.OAuthRecord{
		Key:      domain.OAuthKey{PoolKey: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, Token: row.Token},
		ClientID: row.ClientID, ProviderName: row.ProviderName, RedirectURI: row.RedirectUri, ClientState: row.ClientState,
		Nonce: row.Nonce, PKCEChallenge: row.PkceChallenge, UpstreamNonce: row.UpstreamNonce, UpstreamVerifier: row.UpstreamVerifier,
		Scope: row.Scope, Username: row.Username, Phase: row.Phase, Expires: row.Expires.UTC(),
	}, nil
}

func (w writer) PutOAuth(v domain.OAuthRecord) error {
	k := v.Key
	return w.q.PutOAuth(w.ctx, sqlcgen.PutOAuthParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Token: k.Token,
		ClientID: v.ClientID, ProviderName: v.ProviderName, RedirectUri: v.RedirectURI, ClientState: v.ClientState,
		Nonce: v.Nonce, PkceChallenge: v.PKCEChallenge, UpstreamNonce: v.UpstreamNonce, UpstreamVerifier: v.UpstreamVerifier,
		Scope: v.Scope, Username: v.Username, Phase: v.Phase, Expires: v.Expires.UTC(),
	})
}

func (w writer) DeleteOAuth(k domain.OAuthKey) error {
	return w.q.DeleteOAuth(w.ctx, sqlcgen.DeleteOAuthParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Token: k.Token})
}

func (w writer) DeleteExpiredOAuth(k domain.PoolKey, now time.Time) error {
	return w.q.DeleteExpiredOAuth(w.ctx, sqlcgen.DeleteExpiredOAuthParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Expires: now.UTC()})
}
