package cognitoidp

import (
	"context"
	"encoding/json"
	"errors"

	"stackd/internal/awsctx"
	"stackd/internal/jwt"
)

// VerifyIdentityToken checks a user-pool ID token against current local issuer
// material and its configured app client. Server-side checking additionally fences
// deleted/disabled users and revoked authentication families. Ordinary offline
// verification deliberately retains JWT validity after sign-out, as AWS documents.
func (s *Service) VerifyIdentityToken(ctx context.Context, poolID, clientID, raw string, serverSideCheck bool) (map[string]any, error) {
	invalid := func() error { return failure("NotAuthorizedException", "Invalid login token.") }
	token, err := jwt.Parse(raw, func(a string) bool { return a == "RS256" })
	if err != nil {
		return nil, invalid()
	}
	str := func(k string) string { v, _ := jwt.String(token.Claims, k); return v }
	if str("token_use") != "id" || str("aud") != clientID || str("sub") == "" {
		return nil, invalid()
	}
	var expires, issued, authTime int64
	if json.Unmarshal(token.Claims["exp"], &expires) != nil || json.Unmarshal(token.Claims["iat"], &issued) != nil || json.Unmarshal(token.Claims["auth_time"], &authTime) != nil {
		return nil, invalid()
	}
	var claims map[string]any
	err = s.repository.View(ctx, func(r Reader) error {
		m := awsctx.FromContext(r.Context())
		pool, e := r.PoolByID(m.Partition, m.Region, poolID)
		if errors.Is(e, ErrNotFound) {
			return invalid()
		}
		if e != nil {
			return e
		}
		if str("iss") != pool.IssuerURL {
			return invalid()
		}
		keys, e := r.SigningKeys(pool.Key)
		if e != nil {
			return e
		}
		if token.KeyID != keys.ID.ID {
			return invalid()
		}
		key, e := signingPrivate(keys.ID)
		if e != nil {
			return e
		}
		if jwt.VerifyRSA(token, &key.PublicKey) != nil {
			return invalid()
		}
		now := s.clock.Now().Unix()
		if expires <= now || issued > now || authTime > now {
			return invalid()
		}
		if _, e = r.Client(ClientKey{PoolKey: pool.Key, ID: clientID}); e != nil {
			if errors.Is(e, ErrNotFound) {
				return invalid()
			}
			return e
		}
		if serverSideCheck {
			user, e := r.User(UserKey{PoolKey: pool.Key, Username: str("cognito:username")})
			if errors.Is(e, ErrNotFound) {
				return invalid()
			}
			if e != nil {
				return e
			}
			if userAttribute(user, "sub") != str("sub") || userEnabled(user) != nil {
				return invalid()
			}
			session, e := r.Session(SessionKey{PoolKey: pool.Key, ID: str("event_id")})
			if errors.Is(e, ErrNotFound) {
				return invalid()
			}
			if e != nil {
				return e
			}
			if session.GloballyRevoked || (session.Revoked && str("origin_jti") == session.OriginID) || session.ClientID != clientID || session.Username != user.Key.Username || session.AuthTime.Unix() != authTime {
				return invalid()
			}
		}
		claims = make(map[string]any, len(token.Claims))
		for k, v := range token.Claims {
			var value any
			if e := json.Unmarshal(v, &value); e != nil {
				return invalid()
			}
			claims[k] = value
		}
		return nil
	})
	return claims, err
}
