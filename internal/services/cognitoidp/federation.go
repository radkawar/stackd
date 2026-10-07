package cognitoidp

import (
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/cognitoidp"
)

// ProviderKey names a user pool identity provider configuration.
type ProviderKey struct {
	PoolKey
	Name string
}

type ProviderRecord struct {
	Key  ProviderKey
	Data api.IdentityProviderType
}

func registerFederation(s *Service) {
	register(s, "CreateUserPoolDomain", s.createUserPoolDomain)
	register(s, "DescribeUserPoolDomain", s.describeUserPoolDomain)
	register(s, "UpdateUserPoolDomain", s.updateUserPoolDomain)
	register(s, "DeleteUserPoolDomain", s.deleteUserPoolDomain)
	register(s, "CreateIdentityProvider", s.createIdentityProvider)
	register(s, "DescribeIdentityProvider", s.describeIdentityProvider)
	register(s, "UpdateIdentityProvider", s.updateIdentityProvider)
	register(s, "DeleteIdentityProvider", s.deleteIdentityProvider)
	register(s, "ListIdentityProviders", s.listIdentityProviders)
	register(s, "GetIdentityProviderByIdentifier", s.getIdentityProviderByIdentifier)
}

var prefixDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Prefix domains are the only implemented domain form. Custom domains need an
// ACM certificate and a CloudFront distribution, and managed login version 2
// needs branding styles; neither exists here.
// TODO: Comeback — serve hosted UI/OAuth endpoints on the domain. Native
// configuration does not imply that external authorization is implemented.
func domainOptions(custom *api.CustomDomainConfigType, version *api.WrappedIntegerType) error {
	if custom != nil {
		return failure("InvalidParameterException", "Custom domains are not supported; use a prefix domain.")
	}
	if version != nil && *version != 1 {
		return failure("InvalidParameterException", "Managed login version 2 is not supported.")
	}
	return nil
}

func (s *Service) createUserPoolDomain(tx Transaction, in *api.CreateUserPoolDomainInput) (*api.CreateUserPoolDomainOutput, error) {
	pool, err := s.adminPool(tx, "CreateUserPoolDomain", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	if err = domainOptions(in.CustomDomainConfig, in.ManagedLoginVersion); err != nil {
		return nil, err
	}
	name := value(in.Domain)
	if !prefixDomainPattern.MatchString(name) {
		return nil, failure("InvalidParameterException", "Invalid domain prefix.")
	}
	for _, reserved := range []string{"aws", "amazon", "cognito"} {
		if strings.Contains(name, reserved) {
			return nil, failure("InvalidParameterException", "Domain cannot contain reserved word: "+reserved)
		}
	}
	if value(pool.Data.Domain) != "" {
		return nil, failure("InvalidParameterException", "User pool already has a domain configured.")
	}
	if _, err = tx.PoolByDomain(pool.Key.Partition, pool.Key.Region, name); err == nil {
		return nil, failure("InvalidParameterException", "Domain already associated with another user pool.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	pool.Data.Domain = str[api.DomainType](name)
	if err = tx.PutPool(pool); err != nil {
		return nil, err
	}
	return &api.CreateUserPoolDomainOutput{ManagedLoginVersion: ptr(api.WrappedIntegerType(1))}, nil
}

// A domain not owned by the caller's account is indistinguishable from an
// absent one: native Cognito returns an empty description for both.
func (s *Service) describeUserPoolDomain(tx Transaction, in *api.DescribeUserPoolDomainInput) (*api.DescribeUserPoolDomainOutput, error) {
	if err := s.authorize(tx, "cognito-idp:DescribeUserPoolDomain", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	pool, err := tx.PoolByDomain(scope.Partition, scope.Region, value(in.Domain))
	if errors.Is(err, ErrNotFound) || err == nil && pool.Key.AccountID != scope.AccountID {
		return &api.DescribeUserPoolDomainOutput{DomainDescription: &api.DomainDescriptionType{}}, nil
	}
	if err != nil {
		return nil, err
	}
	notePool(tx.Context(), pool.Key)
	return &api.DescribeUserPoolDomainOutput{DomainDescription: &api.DomainDescriptionType{
		UserPoolId: pool.Data.Id, AWSAccountId: str[api.AWSAccountIdType](pool.Key.AccountID), Domain: pool.Data.Domain,
		Status: str[api.DomainStatusType]("ACTIVE"), ManagedLoginVersion: ptr(api.WrappedIntegerType(1)),
	}}, nil
}

func ownedDomain(pool PoolRecord, name string) error {
	if name == "" || value(pool.Data.Domain) != name {
		return failure("InvalidParameterException", "No such domain or user pool exists.")
	}
	return nil
}

func (s *Service) updateUserPoolDomain(tx Transaction, in *api.UpdateUserPoolDomainInput) (*api.UpdateUserPoolDomainOutput, error) {
	pool, err := s.adminPool(tx, "UpdateUserPoolDomain", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	if err = ownedDomain(pool, value(in.Domain)); err != nil {
		return nil, err
	}
	if err = domainOptions(in.CustomDomainConfig, in.ManagedLoginVersion); err != nil {
		return nil, err
	}
	return &api.UpdateUserPoolDomainOutput{ManagedLoginVersion: ptr(api.WrappedIntegerType(1))}, nil
}

func (s *Service) deleteUserPoolDomain(tx Transaction, in *api.DeleteUserPoolDomainInput) (*api.DeleteUserPoolDomainOutput, error) {
	pool, err := s.adminPool(tx, "DeleteUserPoolDomain", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	name := value(in.Domain)
	if err = ownedDomain(pool, name); err != nil {
		return nil, err
	}
	pool.Data.Domain = nil
	if err = tx.PutPool(pool); err != nil {
		return nil, err
	}
	if err = tx.DeleteOwnership(OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindDomain, Name: name}); err != nil {
		return nil, err
	}
	return &api.DeleteUserPoolDomainOutput{}, nil
}

// Social providers have fixed names and documented ProviderDetails keys.
// OIDC discovery and SAML metadata retrieval are not implemented, so those
// providers are not admitted rather than stored without verification.
var socialProviderDetails = map[string]struct{ required, optional []string }{
	"Google":          {required: []string{"client_id", "client_secret", "authorize_scopes"}},
	"Facebook":        {required: []string{"client_id", "client_secret", "authorize_scopes"}, optional: []string{"api_version"}},
	"LoginWithAmazon": {required: []string{"client_id", "client_secret", "authorize_scopes"}},
	"SignInWithApple": {required: []string{"client_id", "team_id", "key_id", "private_key", "authorize_scopes"}},
}

// Service-populated endpoint details are returned by Describe; templates that
// copy them back remain valid input.
var providerEndpointDetails = []string{"attributes_url", "attributes_url_add_attributes", "authorize_url", "oidc_issuer", "token_request_method", "token_url"}

var idpIdentifierPattern = regexp.MustCompile(`^[\w\s+=.@-]+$`)

func validateProvider(tx Transaction, pool PoolRecord, kind, name string, details api.ProviderDetailsType, mapping api.AttributeMappingType, identifiers api.IdpIdentifiersListType) error {
	invalid := func(message string) error { return failure("InvalidParameterException", message) }
	rule, social := socialProviderDetails[kind]
	if !social {
		return invalid("Identity provider type " + kind + " is not supported.")
	}
	if name != kind {
		return invalid("The provider name of a " + kind + " identity provider must be " + kind + ".")
	}
	for _, key := range rule.required {
		if strings.TrimSpace(string(details[api.StringType(key)])) == "" {
			return invalid("ProviderDetails is missing " + key + ".")
		}
	}
	for key := range details {
		k := string(key)
		if !slices.Contains(rule.required, k) && !slices.Contains(rule.optional, k) && !slices.Contains(providerEndpointDetails, k) {
			return invalid("Unsupported ProviderDetails key " + k + ".")
		}
	}
	for attribute, claim := range mapping {
		a := string(attribute)
		if a != "username" && schemaAttribute(pool, a) == nil || a == "sub" || claim == "" {
			return invalid("Invalid attribute mapping for " + a + ".")
		}
	}
	if len(identifiers) > 50 {
		return invalid("At most 50 identifiers are allowed.")
	}
	providers, err := tx.Providers(pool.Key)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, id := range identifiers {
		text := string(id)
		if utf8.RuneCountInString(text) < 1 || utf8.RuneCountInString(text) > 40 || !idpIdentifierPattern.MatchString(text) || seen[text] {
			return invalid("Invalid or duplicate identity provider identifier.")
		}
		seen[text] = true
		for _, other := range providers {
			if other.Key.Name != name && slices.Contains(other.Data.IdpIdentifiers, id) {
				return failure("DuplicateProviderException", "Identity provider identifier "+text+" is already in use.")
			}
		}
	}
	return nil
}

func copyProvider(v ProviderRecord) ProviderRecord {
	v.Data.AttributeMapping = maps.Clone(v.Data.AttributeMapping)
	v.Data.ProviderDetails = maps.Clone(v.Data.ProviderDetails)
	v.Data.IdpIdentifiers = slices.Clone(v.Data.IdpIdentifiers)
	if v.Data.CreationDate != nil {
		v.Data.CreationDate = new(*v.Data.CreationDate)
	}
	if v.Data.LastModifiedDate != nil {
		v.Data.LastModifiedDate = new(*v.Data.LastModifiedDate)
	}
	return v
}

func providerOutput(v ProviderRecord) api.IdentityProviderType {
	out := copyProvider(v).Data
	if out.AttributeMapping == nil {
		out.AttributeMapping = api.AttributeMappingType{}
	}
	if out.IdpIdentifiers == nil {
		out.IdpIdentifiers = api.IdpIdentifiersListType{}
	}
	return out
}

func adminProvider(r Reader, pool PoolRecord, name string) (ProviderRecord, error) {
	v, err := r.Provider(ProviderKey{PoolKey: pool.Key, Name: name})
	if errors.Is(err, ErrNotFound) {
		return v, failure("ResourceNotFoundException", "Identity provider "+name+" does not exist.")
	}
	return v, err
}

func (s *Service) createIdentityProvider(tx Transaction, in *api.CreateIdentityProviderInput) (*api.CreateIdentityProviderOutput, error) {
	pool, err := s.adminPool(tx, "CreateIdentityProvider", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	name := value(in.ProviderName)
	if err = validateProvider(tx, pool, value(in.ProviderType), name, in.ProviderDetails, in.AttributeMapping, in.IdpIdentifiers); err != nil {
		return nil, err
	}
	key := ProviderKey{PoolKey: pool.Key, Name: name}
	if _, err = tx.Provider(key); err == nil {
		return nil, failure("DuplicateProviderException", "A provider with the name "+name+" already exists in this user pool.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := s.clock.Now()
	v := ProviderRecord{Key: key, Data: api.IdentityProviderType{
		UserPoolId: pool.Data.Id, ProviderName: (*api.ProviderNameType)(in.ProviderName), ProviderType: in.ProviderType,
		ProviderDetails: maps.Clone(in.ProviderDetails), AttributeMapping: maps.Clone(in.AttributeMapping), IdpIdentifiers: slices.Clone(in.IdpIdentifiers),
		CreationDate: &now, LastModifiedDate: &now,
	}}
	if err = tx.PutProvider(v); err != nil {
		return nil, err
	}
	out := providerOutput(v)
	return &api.CreateIdentityProviderOutput{IdentityProvider: &out}, nil
}

func (s *Service) describeIdentityProvider(tx Transaction, in *api.DescribeIdentityProviderInput) (*api.DescribeIdentityProviderOutput, error) {
	pool, err := s.adminPool(tx, "DescribeIdentityProvider", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	v, err := adminProvider(tx, pool, value(in.ProviderName))
	if err != nil {
		return nil, err
	}
	out := providerOutput(v)
	return &api.DescribeIdentityProviderOutput{IdentityProvider: &out}, nil
}

// Omitted update members retain the stored configuration, as natively.
func (s *Service) updateIdentityProvider(tx Transaction, in *api.UpdateIdentityProviderInput) (*api.UpdateIdentityProviderOutput, error) {
	pool, err := s.adminPool(tx, "UpdateIdentityProvider", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	v, err := adminProvider(tx, pool, value(in.ProviderName))
	if err != nil {
		return nil, err
	}
	if in.ProviderDetails != nil {
		v.Data.ProviderDetails = maps.Clone(in.ProviderDetails)
	}
	if in.AttributeMapping != nil {
		v.Data.AttributeMapping = maps.Clone(in.AttributeMapping)
	}
	if in.IdpIdentifiers != nil {
		v.Data.IdpIdentifiers = slices.Clone(in.IdpIdentifiers)
	}
	if err = validateProvider(tx, pool, value(v.Data.ProviderType), v.Key.Name, v.Data.ProviderDetails, v.Data.AttributeMapping, v.Data.IdpIdentifiers); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	v.Data.LastModifiedDate = &now
	if err = tx.PutProvider(v); err != nil {
		return nil, err
	}
	out := providerOutput(v)
	return &api.UpdateIdentityProviderOutput{IdentityProvider: &out}, nil
}

func (s *Service) deleteIdentityProvider(tx Transaction, in *api.DeleteIdentityProviderInput) (*api.DeleteIdentityProviderOutput, error) {
	pool, err := s.adminPool(tx, "DeleteIdentityProvider", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	v, err := adminProvider(tx, pool, value(in.ProviderName))
	if err != nil {
		return nil, err
	}
	if err = tx.DeleteProvider(v.Key); err != nil {
		return nil, err
	}
	return &api.DeleteIdentityProviderOutput{}, nil
}

func (s *Service) listIdentityProviders(tx Transaction, in *api.ListIdentityProvidersInput) (*api.ListIdentityProvidersOutput, error) {
	pool, err := s.adminPool(tx, "ListIdentityProviders", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	limit := 60
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 60 {
		return nil, failure("InvalidParameterException", "MaxResults must be between 1 and 60.")
	}
	binding := "providers:" + pool.Key.ARN()
	cursor, err := pageCursor(value(in.NextToken), binding)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Providers(pool.Key)
	if err != nil {
		return nil, err
	}
	out := &api.ListIdentityProvidersOutput{Providers: api.ProvidersListType{}}
	for _, v := range rows {
		if v.Key.Name <= cursor {
			continue
		}
		if len(out.Providers) == limit {
			out.NextToken = str[api.PaginationKeyType](nextPage(binding, value(out.Providers[len(out.Providers)-1].ProviderName)))
			break
		}
		out.Providers = append(out.Providers, api.ProviderDescription{ProviderName: v.Data.ProviderName, ProviderType: v.Data.ProviderType, CreationDate: v.Data.CreationDate, LastModifiedDate: v.Data.LastModifiedDate})
	}
	return out, nil
}

func (s *Service) getIdentityProviderByIdentifier(tx Transaction, in *api.GetIdentityProviderByIdentifierInput) (*api.GetIdentityProviderByIdentifierOutput, error) {
	pool, err := s.adminPool(tx, "GetIdentityProviderByIdentifier", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	rows, err := tx.Providers(pool.Key)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if slices.Contains(v.Data.IdpIdentifiers, api.IdpIdentifierType(value(in.IdpIdentifier))) {
			out := providerOutput(v)
			return &api.GetIdentityProviderByIdentifierOutput{IdentityProvider: &out}, nil
		}
	}
	return nil, failure("ResourceNotFoundException", "Identity provider identifier does not exist.")
}
