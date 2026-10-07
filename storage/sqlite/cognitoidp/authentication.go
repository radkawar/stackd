package cognitoidp

import (
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

func (r reader) SigningKeys(k domain.PoolKey) (domain.PoolSigningKeys, error) {
	row, err := r.q.GetSigningKeys(r.ctx, sqlcgen.GetSigningKeysParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
	if err != nil {
		return domain.PoolSigningKeys{}, missing(err)
	}
	return domain.PoolSigningKeys{
		Access: domain.SigningKey{ID: row.AccessKeyID, PKCS8DER: row.AccessKeyDer},
		ID:     domain.SigningKey{ID: row.IDKeyID, PKCS8DER: row.IDKeyDer},
	}, nil
}

func (w writer) PutSigningKeys(k domain.PoolKey, v domain.PoolSigningKeys) error {
	return w.q.PutSigningKeys(w.ctx, sqlcgen.PutSigningKeysParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID,
		AccessKeyID: v.Access.ID, AccessKeyDer: v.Access.PKCS8DER, IDKeyID: v.ID.ID, IDKeyDer: v.ID.PKCS8DER,
	})
}

func (r reader) Challenge(k domain.ChallengeKey) (domain.ChallengeRecord, error) {
	row, err := r.q.GetChallenge(r.ctx, sqlcgen.GetChallengeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Token: k.Token})
	if err != nil {
		return domain.ChallengeRecord{}, missing(err)
	}
	return domain.ChallengeRecord{
		Key:      domain.ChallengeKey{PoolKey: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, Token: row.Token},
		ClientID: row.ClientID, Username: row.Username, Kind: row.Kind, Expires: row.Expires.UTC(), SRPPrivate: row.SrpPrivate,
		SoftwareTokenSecret: row.SoftwareTokenSecret, SoftwareTokenVerified: row.SoftwareTokenVerified,
	}, nil
}

func (w writer) PutChallenge(v domain.ChallengeRecord) error {
	k := v.Key
	return w.q.PutChallenge(w.ctx, sqlcgen.PutChallengeParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Token: k.Token,
		ClientID: v.ClientID, Username: v.Username, Kind: v.Kind, Expires: v.Expires.UTC(), SrpPrivate: v.SRPPrivate,
		SoftwareTokenSecret: v.SoftwareTokenSecret, SoftwareTokenVerified: v.SoftwareTokenVerified,
	})
}

func (w writer) DeleteChallenge(k domain.ChallengeKey) error {
	return w.q.DeleteChallenge(w.ctx, sqlcgen.DeleteChallengeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Token: k.Token})
}

func sessionRow(row sqlcgen.CognitoidpSession) domain.SessionRecord {
	return domain.SessionRecord{
		Key:      domain.SessionKey{PoolKey: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, ID: row.SessionID},
		ClientID: row.ClientID, Username: row.Username, OriginID: row.OriginID,
		AuthTime: row.AuthTime.UTC(), RefreshExpires: row.RefreshExpires.UTC(), RefreshDigest: row.RefreshDigest,
		Revoked: row.Revoked, PreviousRefreshDigest: row.PreviousRefreshDigest,
		RefreshGraceExpires: row.RefreshGraceExpires.UTC(),
		RefreshOriginID:     row.RefreshOriginID, GloballyRevoked: row.GloballyRevoked,
		OAuthScope: row.OauthScope, OAuthNonce: row.OauthNonce,
	}
}

func (r reader) Session(k domain.SessionKey) (domain.SessionRecord, error) {
	row, err := r.q.GetSession(r.ctx, sqlcgen.GetSessionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, SessionID: k.ID})
	if err != nil {
		return domain.SessionRecord{}, missing(err)
	}
	return sessionRow(row), nil
}

func (r reader) SessionByRefresh(k domain.PoolKey, clientID string, digest []byte) (domain.SessionRecord, error) {
	row, err := r.q.GetSessionByRefresh(r.ctx, sqlcgen.GetSessionByRefreshParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, ClientID: clientID, RefreshDigest: digest})
	if err != nil {
		return domain.SessionRecord{}, missing(err)
	}
	return sessionRow(row), nil
}

func (w writer) PutSession(v domain.SessionRecord) error {
	k := v.Key
	if err := w.q.PutSession(w.ctx, sqlcgen.PutSessionParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID, SessionID: k.ID,
		ClientID: v.ClientID, Username: v.Username, OriginID: v.OriginID,
		AuthTime: v.AuthTime.UTC(), RefreshExpires: v.RefreshExpires.UTC(), RefreshDigest: v.RefreshDigest,
		Revoked: v.Revoked, PreviousRefreshDigest: v.PreviousRefreshDigest,
		RefreshGraceExpires: v.RefreshGraceExpires.UTC(),
		RefreshOriginID:     v.RefreshOriginID, GloballyRevoked: v.GloballyRevoked,
		OauthScope: v.OAuthScope, OauthNonce: v.OAuthNonce,
	}); err != nil {
		return err
	}
	if v.RefreshDigest == nil {
		return nil
	}
	return w.q.PutRefreshToken(w.ctx, sqlcgen.PutRefreshTokenParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.PoolKey.ID,
		ClientID: v.ClientID, RefreshDigest: v.RefreshDigest, SessionID: k.ID,
	})
}
