package cognitoidentity

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/cognitoidentity"
)

func registerIdentities(s *Service) {
	register(s, "GetId", s.getID)
	register(s, "GetCredentialsForIdentity", s.getCredentials)
	register(s, "DescribeIdentity", s.describeIdentity)
	register(s, "ListIdentities", s.listIdentities)
	register(s, "DeleteIdentities", s.deleteIdentities)
	register(s, "UnlinkIdentity", s.unlinkIdentity)
}

type verifiedLogin struct {
	Login
	ClientID string
	Claims   map[string]any
	Expires  time.Time
}

func (s *Service) verifyLogins(tx Transaction, p PoolRecord, logins api.LoginsMap) ([]verifiedLogin, error) {
	if len(logins) == 0 {
		if !p.AllowUnauthenticated {
			return nil, failure("NotAuthorizedException", "Unauthenticated access is not supported for this identity pool.")
		}
		return nil, nil
	}
	if s.tokens == nil {
		return nil, failure("NotAuthorizedException", "Cognito token verification is not configured.")
	}
	out := make([]verifiedLogin, 0, len(logins))
	for name, raw := range logins {
		var claims map[string]any
		client := ""
		var last error
		for _, provider := range p.Providers {
			if value(provider.ProviderName) != string(name) {
				continue
			}
			_, poolID, ok := strings.Cut(string(name), "/")
			if !ok {
				continue
			}
			var e error
			claims, e = s.tokens.VerifyIdentityToken(tx.Context(), poolID, value(provider.ClientId), string(raw), provider.ServerSideTokenCheck != nil && bool(*provider.ServerSideTokenCheck))
			if e == nil {
				client = value(provider.ClientId)
				break
			}
			last = e
		}
		if client == "" {
			if last != nil {
				return nil, last
			}
			return nil, failure("NotAuthorizedException", "Token is not from a supported provider of this identity pool.")
		}
		subject := claimString(claims, "sub")
		expiry, ok := claims["exp"].(float64)
		if subject == "" || !ok {
			return nil, failure("NotAuthorizedException", "Invalid login token claims.")
		}
		out = append(out, verifiedLogin{Login: Login{string(name), subject}, ClientID: client, Claims: claims, Expires: time.Unix(int64(expiry), 0)})
	}
	slices.SortFunc(out, func(a, b verifiedLogin) int { return strings.Compare(a.Provider, b.Provider) })
	return out, nil
}
func (s *Service) publicPool(tx Transaction, id string) (PoolRecord, error) {
	scope := scopeFor(tx.Context())
	p, e := tx.PoolByID(scope.Partition, scope.Region, id)
	if e == nil {
		notePool(tx.Context(), p.Key)
	}
	return p, e
}
func (s *Service) getID(tx Transaction, in *api.GetIdInput) (*api.GetIdOutput, error) {
	p, e := s.publicPool(tx, value(in.IdentityPoolId))
	if e != nil {
		return nil, e
	}
	if value(in.AccountId) != "" && value(in.AccountId) != p.Key.AccountID {
		return nil, ErrNotFound
	}
	logins, e := s.verifyLogins(tx, p, in.Logins)
	if e != nil {
		return nil, e
	}
	var found IdentityRecord
	for _, login := range logins {
		row, e := tx.IdentityByLogin(p.Key, login.Login)
		if errors.Is(e, ErrNotFound) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if found.ID != "" && found.ID != row.ID {
			return nil, failure("ResourceConflictException", "Logins belong to different identities.")
		}
		found = row
	}
	if found.ID == "" {
		id, e := uuid.NewRandom()
		if e != nil {
			return nil, e
		}
		found = IdentityRecord{Pool: p.Key, ID: p.Key.Region + ":" + id.String(), Created: s.clock.Now()}
	}
	for _, login := range logins {
		if !slices.Contains(found.Logins, login.Login) {
			found.Logins = append(found.Logins, login.Login)
		}
	}
	found.Modified = s.clock.Now()
	if e := tx.PutIdentity(found); e != nil {
		return nil, e
	}
	return &api.GetIdOutput{IdentityId: new(api.IdentityId(found.ID))}, nil
}
func (s *Service) identityPool(tx Transaction, id string) (IdentityRecord, PoolRecord, error) {
	scope := scopeFor(tx.Context())
	identity, e := tx.Identity(scope.Partition, scope.Region, id)
	if e != nil {
		return identity, PoolRecord{}, e
	}
	p, e := tx.Pool(identity.Pool)
	if e == nil {
		notePool(tx.Context(), p.Key)
	}
	return identity, p, e
}
func (s *Service) bindIdentity(tx Transaction, id IdentityRecord, logins []verifiedLogin) (IdentityRecord, error) {
	if len(logins) == 0 && len(id.Logins) > 0 {
		return id, failure("NotAuthorizedException", "Access to this identity is forbidden.")
	}
	authorized := len(id.Logins) == 0
	for _, login := range logins {
		if slices.Contains(id.Logins, login.Login) {
			authorized = true
		}
	}
	if !authorized {
		return id, failure("NotAuthorizedException", "Access to this identity is forbidden.")
	}
	for _, login := range logins {
		owner, e := tx.IdentityByLogin(id.Pool, login.Login)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return id, e
		}
		if e == nil && owner.ID != id.ID {
			if len(id.Logins) != 0 {
				return id, failure("ResourceConflictException", "Login belongs to another identity.")
			}
			if e := tx.DeleteIdentity(id.Pool.Partition, id.Pool.Region, id.ID); e != nil {
				return id, e
			}
			id = owner
		}
		if !slices.Contains(id.Logins, login.Login) {
			id.Logins = append(id.Logins, login.Login)
		}
	}
	id.Modified = s.clock.Now()
	return id, tx.PutIdentity(id)
}
func (s *Service) getCredentials(tx Transaction, in *api.GetCredentialsForIdentityInput) (*api.GetCredentialsForIdentityOutput, error) {
	id, p, e := s.identityPool(tx, value(in.IdentityId))
	if e != nil {
		return nil, e
	}
	logins, e := s.verifyLogins(tx, p, in.Logins)
	if e != nil {
		return nil, e
	}
	id, e = s.bindIdentity(tx, id, logins)
	if e != nil {
		return nil, e
	}
	role := string(p.Roles["unauthenticated"])
	var expires time.Time
	if len(logins) > 0 {
		role = ""
		for _, login := range logins {
			selected, e := mappedRole(p, login, value(in.CustomRoleArn))
			if e != nil {
				return nil, e
			}
			if role != "" && role != selected {
				return nil, failure("NotAuthorizedException", "Logins select conflicting roles.")
			}
			role = selected
			if expires.IsZero() || login.Expires.Before(expires) {
				expires = login.Expires
			}
		}
	} else if value(in.CustomRoleArn) != "" {
		return nil, failure("NotAuthorizedException", "Unauthenticated identities cannot select a custom role.")
	}
	if role == "" || s.credentials == nil {
		return nil, failure("InvalidIdentityPoolConfigurationException", "Identity pool has no valid role configuration.")
	}
	parts := strings.SplitN(role, ":", 6)
	if len(parts) != 6 || parts[1] != p.Key.Partition || parts[4] != p.Key.AccountID {
		return nil, failure("InvalidIdentityPoolConfigurationException", "Role must belong to the identity pool account.")
	}
	tags, e := principalSessionTags(p, logins)
	if e != nil {
		return nil, e
	}
	c, e := s.credentials.IssueIdentityCredentials(tx.Context(), CredentialRequest{PoolID: p.Key.ID, IdentityID: id.ID, RoleARN: role, Authenticated: len(logins) > 0, Expires: expires, Tags: tags})
	if e != nil {
		return nil, failure("InvalidIdentityPoolConfigurationException", "The identity pool role could not be assumed.")
	}
	return &api.GetCredentialsForIdentityOutput{IdentityId: new(api.IdentityId(id.ID)), Credentials: &api.Credentials{AccessKeyId: new(api.AccessKeyString(c.AccessKeyID)), SecretKey: new(api.SecretKeyString(c.SecretAccessKey)), SessionToken: new(api.SessionTokenString(c.SessionToken)), Expiration: new(c.Expiration)}}, nil
}
func identityOutput(id IdentityRecord) api.IdentityDescription {
	logins := make(api.LoginsList, 0, len(id.Logins))
	for _, l := range id.Logins {
		logins = append(logins, api.IdentityProviderName(l.Provider))
	}
	slices.Sort(logins)
	return api.IdentityDescription{IdentityId: new(api.IdentityId(id.ID)), CreationDate: new(id.Created), LastModifiedDate: new(id.Modified), Logins: logins}
}
func (s *Service) describeIdentity(tx Transaction, in *api.DescribeIdentityInput) (*api.DescribeIdentityOutput, error) {
	id, p, e := s.identityPool(tx, value(in.IdentityId))
	if e != nil {
		return nil, e
	}
	if _, e = s.adminPool(tx, "DescribeIdentity", p.Key.ID); e != nil {
		return nil, e
	}
	out := identityOutput(id)
	return &out, nil
}
func (s *Service) listIdentities(tx Transaction, in *api.ListIdentitiesInput) (*api.ListIdentitiesOutput, error) {
	p, e := s.adminPool(tx, "ListIdentities", value(in.IdentityPoolId))
	if e != nil {
		return nil, e
	}
	binding := "identities:" + p.Key.ARN()
	cursor, e := pageCursor(value(in.NextToken), binding)
	if e != nil {
		return nil, e
	}
	rows, e := tx.Identities(p.Key)
	if e != nil {
		return nil, e
	}
	limit := 60
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	out := &api.ListIdentitiesOutput{IdentityPoolId: in.IdentityPoolId, Identities: api.IdentitiesList{}}
	last := ""
	for _, id := range rows {
		if id.ID <= cursor {
			continue
		}
		if len(out.Identities) == limit {
			out.NextToken = pageToken(binding, last)
			break
		}
		out.Identities = append(out.Identities, identityOutput(id))
		last = id.ID
	}
	return out, nil
}
func (s *Service) deleteIdentities(tx Transaction, in *api.DeleteIdentitiesInput) (*api.DeleteIdentitiesOutput, error) {
	if e := s.authorize(tx, "cognito-identity:DeleteIdentities", "*", nil); e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	out := &api.DeleteIdentitiesOutput{UnprocessedIdentityIds: api.UnprocessedIdentityIdList{}}
	for _, id := range in.IdentityIdsToDelete {
		row, e := tx.Identity(scope.Partition, scope.Region, string(id))
		if errors.Is(e, ErrNotFound) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if row.Pool.AccountID != scope.AccountID {
			out.UnprocessedIdentityIds = append(out.UnprocessedIdentityIds, api.UnprocessedIdentityId{IdentityId: new(id), ErrorCode: new(api.ErrorCode("AccessDenied"))})
			continue
		}
		if e := tx.DeleteIdentity(scope.Partition, scope.Region, string(id)); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (s *Service) unlinkIdentity(tx Transaction, in *api.UnlinkIdentityInput) (*api.UnlinkIdentityOutput, error) {
	id, p, e := s.identityPool(tx, value(in.IdentityId))
	if e != nil {
		return nil, e
	}
	logins, e := s.verifyLogins(tx, p, in.Logins)
	if e != nil {
		return nil, e
	}
	if len(logins) == 0 {
		return nil, failure("NotAuthorizedException", "Login required.")
	}
	for _, name := range in.LoginsToRemove {
		verified := false
		for _, login := range logins {
			if login.Provider == string(name) && slices.Contains(id.Logins, login.Login) {
				verified = true
			}
		}
		if !verified {
			return nil, failure("NotAuthorizedException", "Login does not match the identity.")
		}
	}
	id.Logins = slices.DeleteFunc(id.Logins, func(l Login) bool { return slices.Contains(in.LoginsToRemove, api.IdentityProviderName(l.Provider)) })
	id.Modified = s.clock.Now()
	return &api.UnlinkIdentityOutput{}, tx.PutIdentity(id)
}
