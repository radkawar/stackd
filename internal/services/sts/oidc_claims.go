package sts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

type oidcIdentity struct {
	issuer, subject, audience, sourceIdentity string
	audiences                                 []string
	tags                                      map[string]string
	transitive                                []string
	trustContext, sessionContext              map[string][]string
	authorizedRoles                           []string
	hasRolesClaim                             bool
	authenticationNotAfter                    *time.Time
}

func validateOIDCClaims(claims map[string]json.RawMessage, now time.Time) (oidcIdentity, *awswire.Error) {
	var result oidcIdentity
	for _, name := range []string{"iss", "sub", "aud", "iat", "exp"} {
		if _, ok := claims[name]; !ok {
			return result, invalidOIDCToken("Missing a required claim: " + name)
		}
	}
	var ok bool
	result.issuer, ok = jwt.String(claims, "iss")
	if !ok {
		return result, invalidOIDCToken("The issuer claim must be a string.")
	}
	result.subject, ok = jwt.String(claims, "sub")
	if !ok {
		if bytes.Equal(claims["sub"], []byte("null")) {
			return result, &awswire.Error{Code: "InternalFailure", StatusCode: 500, Message: "Unknown error validating third-party token"}
		}
		var number json.Number
		if json.Unmarshal(claims["sub"], &number) != nil {
			return result, invalidOIDCToken("The subject claim must be a string or number.")
		}
		result.subject = string(number)
	}
	audiences, err := oidcStringValues(claims["aud"])
	if err != nil || len(audiences) == 0 {
		return result, invalidOIDCToken("The audience claim is invalid.")
	}
	result.audiences = audiences
	party, present := claims["azp"]
	if present {
		if json.Unmarshal(party, &result.audience) != nil || bytes.Equal(party, []byte("null")) {
			return result, invalidOIDCToken("The authorized party claim is invalid.")
		}
	} else {
		if len(audiences) != 1 {
			return result, invalidOIDCToken("Token audience contains more than one audience while authorized party is not present")
		}
		result.audience = audiences[0]
	}
	issued, err := oidcTimestamp(claims["iat"])
	if err != nil {
		return result, invalidOIDCToken("Invalid timestamp in token claims.")
	}
	expires, err := oidcTimestamp(claims["exp"])
	if err != nil {
		return result, invalidOIDCToken("Invalid timestamp in token claims.")
	}
	const tolerance = 5 * time.Minute
	if issued.After(now.Add(tolerance)) {
		return result, invalidOIDCToken("Token issued in the future.")
	}
	if !now.Add(-tolerance).Before(expires) {
		return result, &awswire.Error{Code: "ExpiredTokenException", StatusCode: 400, Message: "The web identity token has expired."}
	}
	deadline := expires.Add(tolerance)
	result.authenticationNotAfter = &deadline
	if raw, exists := claims["nbf"]; exists {
		notBefore, err := oidcTimestamp(raw)
		if err != nil {
			return result, invalidOIDCToken("Invalid timestamp in token claims.")
		}
		if notBefore.After(now.Add(tolerance)) {
			return result, invalidOIDCToken("The web identity token is not yet valid.")
		}
	}
	if raw, exists := claims["https://aws.amazon.com/source_identity"]; exists {
		if json.Unmarshal(raw, &result.sourceIdentity) != nil || bytes.Equal(raw, []byte("null")) {
			return result, invalidOIDCToken("The source identity claim must be a string.")
		}
		if !oidcSourceIdentity.MatchString(result.sourceIdentity) || strings.HasPrefix(strings.ToLower(result.sourceIdentity), "aws:") {
			return result, invalidOIDCToken("The source identity claim is invalid.")
		}
	}
	tags, transitive, apiErr := oidcSessionTags(claims)
	if apiErr != nil {
		return result, apiErr
	}
	result.tags, result.transitive = tags, transitive
	result.authorizedRoles, result.hasRolesClaim, apiErr = oidcAuthorizedRoles(claims)
	if apiErr != nil {
		return result, apiErr
	}
	result.trustContext, result.sessionContext = oidcConditionValues(result, claims)
	return result, nil
}

var oidcSourceIdentity = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{2,64}$`)
var oidcTagCharacters = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+@-]*$`)

func oidcTimestamp(raw json.RawMessage) (time.Time, error) {
	text := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return time.Time{}, err
		}
	}
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0), nil
}
func oidcStringValues(raw json.RawMessage) ([]string, error) {
	if len(raw) > 0 && raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, err
		}
		return []string{text}, nil
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil || bytes.Equal(raw, []byte("null")) {
		return nil, fmt.Errorf("claim must be a string or string array")
	}
	return values, nil
}
func oidcSessionTags(claims map[string]json.RawMessage) (map[string]string, []string, *awswire.Error) {
	tags := map[string]string{}
	var transitive []string
	seen := map[string]bool{}
	add := func(key, value string) *awswire.Error {
		canonical := strings.ToLower(key)
		if seen[canonical] || strings.HasPrefix(canonical, "aws:") || utf8.RuneCountInString(key) < 1 || utf8.RuneCountInString(key) > 128 || utf8.RuneCountInString(value) > 256 || !oidcTagCharacters.MatchString(key) || !oidcTagCharacters.MatchString(value) {
			return invalidOIDCToken("The session tag claim is invalid.")
		}
		seen[canonical] = true
		tags[key] = value
		return nil
	}
	const namespace = "https://aws.amazon.com/tags"
	if raw, exists := claims[namespace]; exists {
		nested, err := jwt.Object(raw)
		if err != nil {
			return nil, nil, invalidOIDCToken("Session tags passed in claim are not in correct format.")
		}
		if raw, exists := nested["principal_tags"]; exists {
			principal, err := jwt.Object(raw)
			if err != nil {
				return nil, nil, invalidOIDCToken("principal_tags passed in claim is not in correct format.")
			}
			for key, raw := range principal {
				var values []string
				if json.Unmarshal(raw, &values) != nil || len(values) != 1 {
					return nil, nil, invalidOIDCToken("principal_tags passed in claim is not in correct format.")
				}
				if err := add(key, values[0]); err != nil {
					return nil, nil, err
				}
			}
		}
		if raw, exists := nested["transitive_tag_keys"]; exists {
			if json.Unmarshal(raw, &transitive) != nil || bytes.Equal(raw, []byte("null")) {
				return nil, nil, invalidOIDCToken("The transitive tag claim is invalid.")
			}
		}
	}
	for name, raw := range claims {
		if !strings.HasPrefix(name, namespace+"/principal_tags/") {
			continue
		}
		key := strings.TrimPrefix(name, namespace+"/principal_tags/")
		var value string
		if json.Unmarshal(raw, &value) != nil || bytes.Equal(raw, []byte("null")) {
			return nil, nil, invalidOIDCToken("The session tag claim is invalid.")
		}
		if err := add(key, value); err != nil {
			return nil, nil, err
		}
	}
	if raw, exists := claims[namespace+"/transitive_tag_keys"]; exists {
		if transitive != nil {
			return nil, nil, invalidOIDCToken("Conflicting transitive tag formats.")
		}
		if json.Unmarshal(raw, &transitive) != nil || bytes.Equal(raw, []byte("null")) {
			return nil, nil, invalidOIDCToken("The transitive tag claim is invalid.")
		}
	}
	if len(tags) > 50 || len(transitive) > 50 {
		return nil, nil, invalidOIDCToken("Session tags exceed the 50-tag limit.")
	}
	inherited := map[string]bool{}
	for _, key := range transitive {
		canonical := strings.ToLower(key)
		if inherited[canonical] || !seen[canonical] {
			return nil, nil, invalidOIDCToken("Transitive tag keys must uniquely name supplied tags.")
		}
		inherited[canonical] = true
	}
	slices.Sort(transitive)
	return tags, transitive, nil
}

func oidcConditionValues(identity oidcIdentity, claims map[string]json.RawMessage) (map[string][]string, map[string][]string) {
	issuer := strings.TrimPrefix(identity.issuer, "https://")
	trust := map[string][]string{issuer + ":aud": {identity.audience}, issuer + ":oaud": slices.Clone(identity.audiences), issuer + ":sub": {identity.subject}}
	session := map[string][]string{issuer + ":aud": {identity.audience}, issuer + ":sub": {identity.subject}}
	if raw, ok := claims["amr"]; ok {
		if values, err := oidcStringValues(raw); err == nil {
			if len(values) == 0 {
				values = nil
			}
			trust[issuer+":amr"] = slices.Clone(values)
			session[issuer+":amr"] = slices.Clone(values)
		}
	}
	if email, ok := jwt.String(claims, "email"); ok {
		trust[issuer+":email"] = []string{email}
	}
	// AWS exposes only its documented extra claims for these shared issuers;
	// arbitrary custom claims do not become IAM condition keys or session data.
	keys := []string{}
	switch issuer {
	case "token.actions.githubusercontent.com":
		keys = []string{"actor", "actor_id", "job_workflow_ref", "repository", "repository_id", "repository_owner_id", "workflow", "ref", "environment", "enterprise_id"}
	case "gitlab.com":
		keys = []string{"namespace_id", "project_id", "user_id", "user_login", "user_email", "user_access_level", "ref_protected", "pipeline_source", "runner_environment"}
	case "agent.buildkite.com":
		keys = []string{"organization_slug", "organization_id", "pipeline_slug", "pipeline_id", "cluster_name", "cluster_id", "build_branch"}
	case "accounts.google.com":
		if raw, ok := claims["google:organization_number"]; ok {
			var value json.Number
			if json.Unmarshal(raw, &value) == nil {
				trust[issuer+":google/organization_number"] = []string{string(value)}
			}
		}
	default:
		parsed, _ := url.Parse("https://" + issuer)
		if parsed != nil && parsed.Hostname() == "oidc.circleci.com" && strings.HasPrefix(parsed.Path, "/org/") {
			keys = []string{"oidc.circleci.com/project-id"}
		}
		if parsed != nil && strings.HasSuffix(parsed.Hostname(), ".identity.oraclecloud.com") {
			keys = []string{"rpst_id"}
		}
	}
	for _, key := range keys {
		if value, ok := jwt.String(claims, key); ok {
			trust[issuer+":"+key] = []string{value}
		}
	}
	return trust, session
}
