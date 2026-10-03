package cognitoidp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
)

func refreshRotationEnabled(client ClientRecord) bool {
	return client.Data.RefreshTokenRotation != nil && value(client.Data.RefreshTokenRotation.Feature) == "ENABLED"
}

func newRefreshToken() (string, []byte, error) {
	var random [256]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	digest := sha256.Sum256([]byte(token))
	return token, digest[:], nil
}

func (s *Service) getTokensFromRefreshToken(tx Transaction, input *api.GetTokensFromRefreshTokenInput) (*api.GetTokensFromRefreshTokenOutput, error) {
	pool, client, err := s.authClient(tx, "GetTokensFromRefreshToken", "", value(input.ClientId))
	if err != nil {
		return nil, err
	}
	// A private client's secret is checked before token lookup and attribution.
	// A public client's supplied secret has no effect.
	if secret := value(client.Data.ClientSecret); secret != "" {
		if value(input.ClientSecret) == "" {
			return nil, failure("NotAuthorizedException", "Client "+client.Key.ID+" is configured for secret but secret was not received")
		}
		if !hmac.Equal([]byte(secret), []byte(value(input.ClientSecret))) {
			return nil, failure("NotAuthorizedException", "Unable to verify secret hash for client "+client.Key.ID)
		}
	}
	// DeviceKey and ClientMetadata are inert without their corresponding active
	// pool features, which configuration admission does not yet permit.
	if err := loginFeatures(pool, client); err != nil {
		return nil, err
	}
	result, err := s.refreshTokens(tx, pool, client, value(input.RefreshToken), nil)
	if err != nil {
		return nil, err
	}
	return &api.GetTokensFromRefreshTokenOutput{AuthenticationResult: result}, nil
}

func (s *Service) refreshAuth(tx Transaction, pool PoolRecord, client ClientRecord, params api.AuthParametersType) (*api.InitiateAuthOutput, error) {
	if value(client.Data.ClientSecret) != "" && params["SECRET_HASH"] == "" {
		return nil, checkSecretHash(client, "", "")
	}
	secretHash := string(params["SECRET_HASH"])
	result, err := s.refreshTokens(tx, pool, client, string(params["REFRESH_TOKEN"]), &secretHash)
	if err != nil {
		return nil, err
	}
	return &api.InitiateAuthOutput{AuthenticationResult: result, ChallengeParameters: api.ChallengeParametersType{}}, nil
}

// Both refresh APIs share family validation and token issuance. Legacy auth
// supplies a user-bound secret hash; GetTokensFromRefreshToken has already
// checked its client secret before reaching this token-owned path.
func (s *Service) refreshTokens(tx Transaction, pool PoolRecord, client ClientRecord, token string, secretHash *string) (*api.AuthenticationResultType, error) {
	if token == "" {
		return nil, failure("InvalidParameterException", "Missing required parameter REFRESH_TOKEN")
	}
	digest := sha256.Sum256([]byte(token))
	session, err := tx.SessionByRefresh(pool.Key, client.Key.ID, digest[:])
	if errors.Is(err, ErrNotFound) {
		return nil, failure("NotAuthorizedException", "Invalid Refresh Token")
	}
	if err != nil {
		return nil, err
	}
	user, err := tx.User(UserKey{PoolKey: pool.Key, Username: session.Username})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("NotAuthorizedException", "The user has been deleted for the associated refresh token")
	}
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	if secretHash != nil {
		username := user.Key.Username
		if len(pool.Data.UsernameAttributes) > 0 {
			username = userAttribute(user, "sub")
		}
		if err := checkSecretHash(client, username, *secretHash); err != nil {
			return nil, err
		}
	}
	if err := userEnabled(user); err != nil {
		return nil, err
	}
	if session.Revoked {
		message := ""
		if secretHash != nil {
			message = "Refresh Token has been revoked"
		}
		return nil, failure("NotAuthorizedException", message)
	}
	now := s.clock.Now()
	if !now.Before(session.RefreshExpires) {
		return nil, failure("NotAuthorizedException", "Refresh Token has expired")
	}
	rotating := refreshRotationEnabled(client)
	current := hmac.Equal(digest[:], session.RefreshDigest)
	if !current {
		if !rotating {
			return nil, failure("NotAuthorizedException", "Refresh Token has been revoked")
		}
		if !hmac.Equal(digest[:], session.PreviousRefreshDigest) || !now.Before(session.RefreshGraceExpires) {
			return nil, failure("RefreshTokenReuseException", "Refresh token reuse detected")
		}
	}
	var refresh string
	if rotating {
		var replacement []byte
		refresh, replacement, err = newRefreshToken()
		if err != nil {
			return nil, err
		}
		session.RefreshOriginID, err = tokenUUID()
		if err != nil {
			return nil, err
		}
		if current {
			session.PreviousRefreshDigest = session.RefreshDigest
			var grace time.Duration
			if seconds := client.Data.RefreshTokenRotation.RetryGracePeriodSeconds; seconds != nil {
				grace = time.Duration(*seconds) * time.Second
			}
			session.RefreshGraceExpires = now.Add(grace)
		}
		// Retrying the previous token replaces only the current child. The
		// previous token and its original deadline never move on a retry.
		session.RefreshDigest = replacement
		if err := tx.PutSession(session); err != nil {
			return nil, err
		}
	}
	result, err := s.sessionTokens(tx, pool, client, user, session)
	if err != nil {
		return nil, err
	}
	if rotating {
		result.RefreshToken = str[api.TokenModelType](refresh)
		if !current {
			noteRefreshRetry(tx.Context())
		}
	}
	return result, nil
}

func (s *Service) revokeToken(tx Transaction, input *api.RevokeTokenInput) (*api.RevokeTokenOutput, error) {
	pool, client, err := s.authClient(tx, "RevokeToken", "", value(input.ClientId))
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(value(client.Data.ClientSecret)), []byte(value(input.ClientSecret))) {
		return nil, failure("UnauthorizedException", "Invalid client or secret")
	}
	if client.Data.EnableTokenRevocation != nil && !bool(*client.Data.EnableTokenRevocation) {
		return nil, failure("UnsupportedOperationException", "This feature is not enabled for this client")
	}
	if value(input.Token) == "" {
		return nil, failure("InvalidParameterException", "Token is required")
	}
	digest := sha256.Sum256([]byte(value(input.Token)))
	session, err := tx.SessionByRefresh(pool.Key, client.Key.ID, digest[:])
	if errors.Is(err, ErrNotFound) {
		return &api.RevokeTokenOutput{}, nil
	}
	if err != nil {
		return nil, err
	}
	if session.Revoked {
		return &api.RevokeTokenOutput{}, nil
	}
	// Historical tokens still revoke their family, but a retired-token revoke
	// does not add user attribution to the native audit projection.
	if hmac.Equal(digest[:], session.RefreshDigest) {
		user, err := tx.User(UserKey{PoolKey: pool.Key, Username: session.Username})
		if err != nil {
			return nil, err
		}
		noteUser(tx.Context(), user)
	}
	session.Revoked = true
	if err := tx.PutSession(session); err != nil {
		return nil, err
	}
	return &api.RevokeTokenOutput{}, nil
}
