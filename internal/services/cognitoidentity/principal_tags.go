package cognitoidentity

import (
	"encoding/json"
	"maps"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/cognitoidentity"
)

var principalTagCharacters = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+@-]*$`)

func registerPrincipalTags(s *Service) {
	register(s, "SetPrincipalTagAttributeMap", s.setPrincipalTags)
	register(s, "GetPrincipalTagAttributeMap", s.getPrincipalTags)
}

func hasTagProvider(p PoolRecord, name string) bool {
	for _, provider := range p.Providers {
		if value(provider.ProviderName) == name {
			return true
		}
	}
	return false
}

func (s *Service) setPrincipalTags(tx Transaction, in *api.SetPrincipalTagAttributeMapInput) (*api.SetPrincipalTagAttributeMapOutput, error) {
	p, err := s.adminPool(tx, "SetPrincipalTagAttributeMap", value(in.IdentityPoolId))
	if err != nil {
		return nil, err
	}
	provider := value(in.IdentityProviderName)
	if !hasTagProvider(p, provider) {
		return nil, failure("InvalidParameterException", "Provider is not configured for this identity pool.")
	}
	mapping := PrincipalTagMap{UseDefaults: in.UseDefaults != nil && bool(*in.UseDefaults), Tags: maps.Clone(in.PrincipalTags)}
	if mapping.UseDefaults {
		mapping.Tags = api.PrincipalTags{"client": "aud", "username": "sub"}
	}
	if len(mapping.Tags) > 50 {
		return nil, failure("InvalidParameterException", "At most 50 principal tags can be mapped.")
	}
	keys := map[string]bool{}
	for key, claim := range mapping.Tags {
		folded := strings.ToLower(string(key))
		if !validPrincipalTag(string(key), 128) || key == "" || strings.HasPrefix(folded, "aws:") || keys[folded] || claim == "" || utf8.RuneCountInString(string(claim)) > 256 {
			return nil, failure("InvalidParameterException", "Invalid principal tag mapping.")
		}
		keys[folded] = true
	}
	if len(mapping.Tags) == 0 {
		delete(p.PrincipalTagMaps, provider)
	} else {
		if p.PrincipalTagMaps == nil {
			p.PrincipalTagMaps = map[string]PrincipalTagMap{}
		}
		p.PrincipalTagMaps[provider] = mapping
	}
	if err := tx.PutPool(p); err != nil {
		return nil, err
	}
	return &api.SetPrincipalTagAttributeMapOutput{IdentityPoolId: in.IdentityPoolId, IdentityProviderName: in.IdentityProviderName, UseDefaults: new(api.UseDefaults(mapping.UseDefaults)), PrincipalTags: mapping.Tags}, nil
}

func (s *Service) getPrincipalTags(tx Transaction, in *api.GetPrincipalTagAttributeMapInput) (*api.GetPrincipalTagAttributeMapOutput, error) {
	p, err := s.adminPool(tx, "GetPrincipalTagAttributeMap", value(in.IdentityPoolId))
	if err != nil {
		return nil, err
	}
	mapping, ok := p.PrincipalTagMaps[value(in.IdentityProviderName)]
	if !ok {
		return nil, ErrNotFound
	}
	return &api.GetPrincipalTagAttributeMapOutput{IdentityPoolId: in.IdentityPoolId, IdentityProviderName: in.IdentityProviderName, UseDefaults: new(api.UseDefaults(mapping.UseDefaults)), PrincipalTags: maps.Clone(mapping.Tags)}, nil
}

func validPrincipalTag(v string, limit int) bool {
	return utf8.ValidString(v) && utf8.RuneCountInString(v) <= limit && principalTagCharacters.MatchString(v)
}

// Claims are taken exclusively from the verified ID token. Missing or invalid
// mapped claims fail closed rather than silently weakening a session's tags.
func principalSessionTags(p PoolRecord, logins []verifiedLogin) (map[string]string, error) {
	var tags map[string]string
	canonical := map[string]string{}
	for _, login := range logins {
		mapping, ok := p.PrincipalTagMaps[login.Provider]
		if !ok {
			continue
		}
		for key, claim := range mapping.Tags {
			raw, exists := login.Claims[string(claim)]
			v, ok := scalarTagValue(raw)
			if !exists || !ok || !validPrincipalTag(v, 256) {
				return nil, failure("NotAuthorizedException", "A mapped principal tag claim is missing or invalid.")
			}
			folded := strings.ToLower(string(key))
			if prior, ok := canonical[folded]; ok {
				if prior != string(key) || tags[prior] != v {
					return nil, failure("NotAuthorizedException", "Logins select conflicting principal tags.")
				}
				continue
			}
			if tags == nil {
				tags = map[string]string{}
			}
			tags[string(key)] = v
			canonical[folded] = string(key)
			if len(tags) > 50 {
				return nil, failure("NotAuthorizedException", "Too many principal session tags.")
			}
		}
	}
	return tags, nil
}

func scalarTagValue(raw any) (string, bool) {
	switch v := raw.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "", false
		}
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case json.Number:
		n, err := v.Float64()
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return "", false
		}
		return string(v), true
	default:
		return "", false
	}
}
