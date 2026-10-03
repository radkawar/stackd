package apigatewayexec

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/jwt"
)

// KeySource resolves public material from configured issuers, not token headers.
type KeySource interface {
	Issuer(context.Context, string) (jwt.KeySet, error)
	UserPool(context.Context, string) (jwt.KeySet, error)
}

type requestIdentity struct {
	Claims        map[string]json.RawMessage
	Scopes        []string
	Lambda        *AuthorizerResult
	LambdaLatency int64
	APIKey        APIKeyIdentity
}

type rejection struct {
	Status  int
	Message string
}

func (s *Handler) authorizeIAM(w http.ResponseWriter, r *http.Request, route *Route, path string, rest bool) (*http.Request, bool) {
	if s.authentication == nil || s.authorization == nil {
		writeRejection(w, &rejection{http.StatusInternalServerError, "Internal Server Error"})
		return nil, false
	}
	verified, rejected := s.authentication.Authenticate(r, "execute-api", route.Region)
	if rejected != nil {
		if observation := requestObservationFrom(r); observation != nil {
			observation.authorizerError = rejected.Message
			if !rest && r.Header.Get("Authorization") == "" && r.URL.Query().Get("X-Amz-Credential") == "" {
				observation.authorizerError = "The request for the IAM Authorizer doesn't match the format that API Gateway expects."
			}
		}
		message := "Forbidden"
		if rest && r.Header.Get("Authorization") == "" && r.URL.Query().Get("X-Amz-Credential") == "" {
			w.Header().Set("X-Amzn-ErrorType", "MissingAuthenticationTokenException")
			message = "Missing Authentication Token"
		}
		writeRejection(w, &rejection{http.StatusForbidden, message})
		return nil, false
	}
	resource := executionARN(route, r.Method, executionPath(route, path))
	if rejected := s.authorization.Authorize(verified.Context(), authorization.Request{Action: "execute-api:Invoke", ResourceARN: resource, ResourceAccountID: route.AccountID}); rejected != nil {
		writeRejection(w, &rejection{http.StatusForbidden, "Forbidden"})
		return verified, false
	}
	return verified, true
}

func (s *Handler) authorizeToken(r *http.Request, route *Route, rest bool) (requestIdentity, *rejection) {
	denied := &rejection{http.StatusUnauthorized, "Unauthorized"}
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, err := jwt.Parse(raw, func(algorithm string) bool {
		return algorithm == "RS256" || algorithm == "RS384" || algorithm == "RS512"
	})
	if err != nil || s.keys == nil {
		return requestIdentity{}, denied
	}
	issuer, ok := jwt.String(token.Claims, "iss")
	if !ok {
		return requestIdentity{}, denied
	}
	var keys jwt.KeySet
	if rest {
		for _, pool := range route.UserPoolARNs {
			candidate, err := s.keys.UserPool(r.Context(), pool)
			if err == nil && candidate.Issuer == issuer {
				keys = candidate
				break
			}
		}
	} else {
		if issuer != route.Issuer {
			return requestIdentity{}, denied
		}
		keys, err = s.keys.Issuer(r.Context(), route.Issuer)
		if err != nil {
			return requestIdentity{}, denied
		}
	}
	key := keys.Keys[token.KeyID]
	if keys.Issuer != issuer || key == nil || jwt.VerifyRSA(token, key) != nil {
		return requestIdentity{}, denied
	}
	now := s.clock.Now()
	if !validTokenTimes(token.Claims, now) {
		return requestIdentity{}, denied
	}
	if !rest {
		audiences := claimStrings(token.Claims["aud"])
		if _, present := token.Claims["aud"]; !present {
			if client, ok := jwt.String(token.Claims, "client_id"); ok {
				audiences = []string{client}
			}
		}
		if !intersects(route.Audiences, audiences) {
			return requestIdentity{}, denied
		}
	} else {
		use, _ := jwt.String(token.Claims, "token_use")
		if len(route.Scopes) == 0 && use != "id" || len(route.Scopes) != 0 && use != "access" {
			return requestIdentity{}, denied
		}
	}
	var scopes []string
	if scope, ok := jwt.String(token.Claims, "scope"); ok {
		scopes = strings.Fields(scope)
	}
	if len(scopes) == 0 {
		if scope, ok := jwt.String(token.Claims, "scp"); ok {
			scopes = strings.Fields(scope)
		} else {
			scopes = claimStrings(token.Claims["scp"])
		}
	}
	if len(route.Scopes) != 0 && !intersects(route.Scopes, scopes) {
		if !rest {
			denied = &rejection{http.StatusForbidden, "Forbidden"}
		}
		return requestIdentity{}, denied
	}
	if len(route.Scopes) == 0 {
		scopes = nil
	}
	return requestIdentity{Claims: token.Claims, Scopes: scopes}, nil
}

func validTokenTimes(claims map[string]json.RawMessage, now time.Time) bool {
	for _, name := range []string{"exp", "nbf", "iat"} {
		raw, present := claims[name]
		if !present {
			if name == "exp" {
				return false
			}
			continue
		}
		var number json.Number
		if json.Unmarshal(raw, &number) != nil {
			return false
		}
		seconds, err := strconv.ParseFloat(string(number), 64)
		if err != nil {
			return false
		}
		current := float64(now.Unix()) + float64(now.Nanosecond())/1e9
		if name == "exp" && seconds <= current || name != "exp" && seconds > current {
			return false
		}
	}
	return true
}

func claimStrings(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func intersects(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}
