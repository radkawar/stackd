package cognitoidentity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cognitoidentity"
)

func registerPools(s *Service) {
	register(s, "CreateIdentityPool", s.createPool)
	register(s, "UpdateIdentityPool", s.updatePool)
	register(s, "DescribeIdentityPool", s.describePool)
	register(s, "DeleteIdentityPool", s.deletePool)
	register(s, "ListIdentityPools", s.listPools)
	register(s, "TagResource", s.tag)
	register(s, "UntagResource", s.untag)
	register(s, "ListTagsForResource", s.tags)
}
func (s *Service) authorize(tx Transaction, action, arn string, conditions map[string][]string) error {
	now := s.clock.Now()
	account := scopeFor(tx.Context()).AccountID
	if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 {
		account = parts[4]
	}
	if e := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: action, ResourceARN: arn, ResourceAccountID: account, Context: conditions, EvaluationTime: &now}); e != nil {
		return failure("NotAuthorizedException", e.Message)
	}
	return nil
}
func (s *Service) adminPool(tx Transaction, action, id string) (PoolRecord, error) {
	return s.adminPoolConditions(tx, action, id, nil)
}
func (s *Service) adminPoolConditions(tx Transaction, action, id string, conditions map[string][]string) (PoolRecord, error) {
	k := PoolKey{Scope: scopeFor(tx.Context()), ID: id}
	pool, err := tx.Pool(k)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return pool, err
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range pool.Tags {
		conditions["aws:ResourceTag/"+string(k)] = []string{string(v)}
	}
	if e := s.authorize(tx, "cognito-identity:"+action, k.ARN(), conditions); e != nil {
		return pool, e
	}
	if err == nil {
		notePool(tx.Context(), k)
	}
	return pool, err
}
func poolOutput(p PoolRecord) *api.IdentityPool {
	return &api.IdentityPool{IdentityPoolId: new(api.IdentityPoolId(p.Key.ID)), IdentityPoolName: new(api.IdentityPoolName(p.Name)), AllowUnauthenticatedIdentities: new(api.IdentityPoolUnauthenticated(p.AllowUnauthenticated)), AllowClassicFlow: new(api.ClassicFlow(p.AllowClassic)), CognitoIdentityProviders: p.Providers, IdentityPoolTags: p.Tags}
}

// TODO: Comeback — classic/developer tokens and external OIDC/SAML/social login
// owners must execute real verification before their pool configuration is admitted.
func validatePool(p *api.IdentityPool) error {
	if p.AllowClassicFlow != nil && bool(*p.AllowClassicFlow) || len(p.SupportedLoginProviders) > 0 || value(p.DeveloperProviderName) != "" || len(p.OpenIdConnectProviderARNs) > 0 || len(p.SamlProviderARNs) > 0 {
		return failure("InvalidParameterException", "Only enhanced Cognito user-pool and unauthenticated flows are supported.")
	}
	seen := map[string]bool{}
	for _, provider := range p.CognitoIdentityProviders {
		key := value(provider.ProviderName) + ":" + value(provider.ClientId)
		if seen[key] || value(provider.ProviderName) == "" || value(provider.ClientId) == "" {
			return failure("InvalidParameterException", "Invalid or duplicate Cognito provider.")
		}
		seen[key] = true
		name := value(provider.ProviderName)
		if !strings.HasPrefix(name, "cognito-idp.") || !strings.Contains(name, ".amazonaws.com/") {
			return failure("InvalidParameterException", "Invalid Cognito provider name.")
		}
	}
	for k, v := range p.IdentityPoolTags {
		if len(k) == 0 || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return failure("InvalidParameterException", "Invalid pool tag.")
		}
	}
	return nil
}
func (s *Service) createPool(tx Transaction, in *api.CreateIdentityPoolInput) (*api.CreateIdentityPoolOutput, error) {
	conditions := map[string][]string{}
	for k, v := range in.IdentityPoolTags {
		conditions["aws:RequestTag/"+string(k)] = []string{string(v)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	if e := s.authorize(tx, "cognito-identity:CreateIdentityPool", "*", conditions); e != nil {
		return nil, e
	}
	data := api.IdentityPool{IdentityPoolName: in.IdentityPoolName, AllowUnauthenticatedIdentities: in.AllowUnauthenticatedIdentities, AllowClassicFlow: in.AllowClassicFlow, SupportedLoginProviders: in.SupportedLoginProviders, DeveloperProviderName: in.DeveloperProviderName, OpenIdConnectProviderARNs: in.OpenIdConnectProviderARNs, CognitoIdentityProviders: in.CognitoIdentityProviders, SamlProviderARNs: in.SamlProviderARNs, IdentityPoolTags: in.IdentityPoolTags}
	if e := validatePool(&data); e != nil {
		return nil, e
	}
	id, e := uuid.NewRandom()
	if e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	p := PoolRecord{Key: PoolKey{Scope: scope, ID: scope.Region + ":" + id.String()}, Name: value(in.IdentityPoolName), AllowUnauthenticated: in.AllowUnauthenticatedIdentities != nil && bool(*in.AllowUnauthenticatedIdentities), Providers: in.CognitoIdentityProviders, Tags: in.IdentityPoolTags}
	if e := tx.PutPool(p); e != nil {
		return nil, e
	}
	notePool(tx.Context(), p.Key)
	return poolOutput(p), nil
}
func (s *Service) updatePool(tx Transaction, in *api.UpdateIdentityPoolInput) (*api.UpdateIdentityPoolOutput, error) {
	p, e := s.adminPool(tx, "UpdateIdentityPool", value(in.IdentityPoolId))
	if e != nil {
		return nil, e
	}
	if e := validatePool(in); e != nil {
		return nil, e
	}
	p.Name = value(in.IdentityPoolName)
	p.AllowUnauthenticated = in.AllowUnauthenticatedIdentities != nil && bool(*in.AllowUnauthenticatedIdentities)
	p.Providers = in.CognitoIdentityProviders
	for provider := range p.PrincipalTagMaps {
		if !hasTagProvider(p, provider) {
			delete(p.PrincipalTagMaps, provider)
		}
	}
	p.Tags = in.IdentityPoolTags
	if e := tx.PutPool(p); e != nil {
		return nil, e
	}
	return poolOutput(p), nil
}
func (s *Service) describePool(tx Transaction, in *api.DescribeIdentityPoolInput) (*api.DescribeIdentityPoolOutput, error) {
	p, e := s.adminPool(tx, "DescribeIdentityPool", value(in.IdentityPoolId))
	if e != nil {
		return nil, e
	}
	return poolOutput(p), nil
}
func (s *Service) deletePool(tx Transaction, in *api.DeleteIdentityPoolInput) (*api.DeleteIdentityPoolOutput, error) {
	p, e := s.adminPool(tx, "DeleteIdentityPool", value(in.IdentityPoolId))
	if e != nil {
		return nil, e
	}
	return &api.DeleteIdentityPoolOutput{}, tx.DeletePool(p.Key)
}
func pageCursor(token, scope string) (string, error) {
	if token == "" {
		return "", nil
	}
	data, e := base64.RawURLEncoding.DecodeString(token)
	var parts []string
	if e != nil || json.Unmarshal(data, &parts) != nil || len(parts) != 2 || parts[0] != scope {
		return "", failure("InvalidParameterException", "Invalid pagination token.")
	}
	return parts[1], nil
}
func pageToken(scope, last string) *api.PaginationKey {
	data, _ := json.Marshal([]string{scope, last})
	return new(api.PaginationKey(base64.RawURLEncoding.EncodeToString(data)))
}
func (s *Service) listPools(tx Transaction, in *api.ListIdentityPoolsInput) (*api.ListIdentityPoolsOutput, error) {
	if e := s.authorize(tx, "cognito-identity:ListIdentityPools", "*", nil); e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	binding := "pools:" + scope.Partition + ":" + scope.AccountID + ":" + scope.Region
	cursor, e := pageCursor(value(in.NextToken), binding)
	if e != nil {
		return nil, e
	}
	rows, e := tx.Pools(scope)
	if e != nil {
		return nil, e
	}
	limit := 60
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	out := &api.ListIdentityPoolsOutput{IdentityPools: api.IdentityPoolsList{}}
	last := ""
	for _, p := range rows {
		if p.Key.ID <= cursor {
			continue
		}
		if len(out.IdentityPools) == limit {
			out.NextToken = pageToken(binding, last)
			break
		}
		out.IdentityPools = append(out.IdentityPools, api.IdentityPoolShortDescription{IdentityPoolId: new(api.IdentityPoolId(p.Key.ID)), IdentityPoolName: new(api.IdentityPoolName(p.Name))})
		last = p.Key.ID
	}
	return out, nil
}
func (s *Service) poolARN(tx Transaction, action, arn string, conditions map[string][]string) (PoolRecord, error) {
	scope := scopeFor(tx.Context())
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "cognito-identity" || parts[3] != scope.Region || parts[4] != scope.AccountID || !strings.HasPrefix(parts[5], "identitypool/") {
		return PoolRecord{}, ErrNotFound
	}
	return s.adminPoolConditions(tx, action, strings.TrimPrefix(parts[5], "identitypool/"), conditions)
}
func (s *Service) tags(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	p, e := s.poolARN(tx, "ListTagsForResource", value(in.ResourceArn), nil)
	if e != nil {
		return nil, e
	}
	return &api.ListTagsForResourceOutput{Tags: p.Tags}, nil
}
func (s *Service) tag(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	conditions := map[string][]string{}
	for key, value := range in.Tags {
		conditions["aws:RequestTag/"+string(key)] = []string{string(value)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(key))
	}
	p, e := s.poolARN(tx, "TagResource", value(in.ResourceArn), conditions)
	if e != nil {
		return nil, e
	}
	if e := validatePool(&api.IdentityPool{IdentityPoolTags: in.Tags}); e != nil {
		return nil, e
	}
	if p.Tags == nil {
		p.Tags = api.IdentityPoolTagsType{}
	}
	maps.Copy(p.Tags, in.Tags)
	return &api.TagResourceOutput{}, tx.PutPool(p)
}
func (s *Service) untag(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	keys := make([]string, 0, len(in.TagKeys))
	for _, key := range in.TagKeys {
		keys = append(keys, string(key))
	}
	p, e := s.poolARN(tx, "UntagResource", value(in.ResourceArn), map[string][]string{"aws:TagKeys": keys})
	if e != nil {
		return nil, e
	}
	for _, k := range in.TagKeys {
		delete(p.Tags, api.TagKeysType(k))
	}
	return &api.UntagResourceOutput{}, tx.PutPool(p)
}
