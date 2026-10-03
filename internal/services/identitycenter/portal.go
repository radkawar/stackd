package identitycenter

import (
	"slices"
	api "stackd/internal/awsapi/sso"
	"strings"
)

type portalRole struct {
	permission PermissionSet
	provision  Provisioning
}

func (s *Service) registerPortal() {
	register(s, "sso", "ListAccounts", func(tx Transaction, in *api.ListAccountsInput) (*api.ListAccountsOutput, error) {
		session, instance, rejected := s.session(tx, value(in.AccessToken))
		if rejected != nil {
			return nil, rejected
		}
		roles, e := s.availableRoles(tx, instance, session.UserID)
		if e != nil {
			return nil, e
		}
		accounts := []string{}
		for _, v := range roles {
			accounts = append(accounts, v.provision.AccountID)
		}
		slices.Sort(accounts)
		accounts = slices.Compact(accounts)
		accounts, next, e := pageSlice(accounts, value(in.NextToken), "ListAccounts/"+session.ID, intValue(in.MaxResults), func(v string) string { return v })
		if e != nil {
			return nil, failure("InvalidRequestException", e.Error(), 400)
		}
		out := &api.ListAccountsOutput{AccountList: api.AccountListType{}}
		for _, id := range accounts {
			out.AccountList = append(out.AccountList, api.AccountInfo{AccountId: new(api.AccountIdType(id))})
		}
		if next != "" {
			out.NextToken = new(api.NextTokenType(next))
		}
		return out, nil
	})
	register(s, "sso", "ListAccountRoles", func(tx Transaction, in *api.ListAccountRolesInput) (*api.ListAccountRolesOutput, error) {
		session, instance, rejected := s.session(tx, value(in.AccessToken))
		if rejected != nil {
			return nil, rejected
		}
		roles, e := s.availableRoles(tx, instance, session.UserID)
		if e != nil {
			return nil, e
		}
		roles = slices.DeleteFunc(roles, func(v portalRole) bool { return v.provision.AccountID != value(in.AccountId) })
		roles, next, e := pageSlice(roles, value(in.NextToken), "ListAccountRoles/"+session.ID+"/"+value(in.AccountId), intValue(in.MaxResults), func(v portalRole) string { return v.provision.AccountID + "/" + v.permission.Name })
		if e != nil {
			return nil, failure("InvalidRequestException", e.Error(), 400)
		}
		out := &api.ListAccountRolesOutput{RoleList: api.RoleListType{}}
		for _, v := range roles {
			out.RoleList = append(out.RoleList, api.RoleInfo{AccountId: new(api.AccountIdType(v.provision.AccountID)), RoleName: new(api.RoleNameType(v.permission.Name))})
		}
		if next != "" {
			out.NextToken = new(api.NextTokenType(next))
		}
		return out, nil
	})
	register(s, "sso", "GetRoleCredentials", s.getRoleCredentials)
	register(s, "sso", "Logout", func(tx Transaction, in *api.LogoutInput) (*api.LogoutOutput, error) {
		session, _, rejected := s.session(tx, value(in.AccessToken))
		if rejected != nil {
			return nil, rejected
		}
		family, e := tx.Sessions(session.FamilyID)
		if e != nil {
			return nil, e
		}
		for _, v := range family {
			v.Revoked = true
			if e = tx.PutSession(v); e != nil {
				return nil, e
			}
		}
		return &api.LogoutOutput{}, nil
	})
}
func (s *Service) availableRoles(r Reader, i Instance, userID string) ([]portalRole, error) {
	assignments, e := r.Assignments(i.ARN)
	if e != nil {
		return nil, e
	}
	provisions, e := r.Provisionings(i.ARN)
	if e != nil {
		return nil, e
	}
	allowed := map[string]bool{}
	groups := map[string]bool{}
	for _, a := range assignments {
		granted := a.PrincipalType == "USER" && a.PrincipalID == userID
		if a.PrincipalType == "GROUP" {
			member, ok := groups[a.PrincipalID]
			if !ok {
				member, e = s.directory.IsMember(r.Context(), directoryScope(i), i.StoreID, userID, a.PrincipalID)
				if e != nil {
					return nil, e
				}
				groups[a.PrincipalID] = member
			}
			granted = member
		}
		if granted {
			allowed[a.PermissionSetARN+"/"+a.AccountID] = true
		}
	}
	out := []portalRole{}
	for _, v := range provisions {
		if !allowed[provisioningKey(v)] {
			continue
		}
		accountAllowed := v.AccountID == i.AccountID
		if s.accounts != nil {
			accountAllowed, e = s.accounts.Allowed(r.Context(), i.Scope, v.AccountID)
			if e != nil {
				return nil, e
			}
		}
		if !accountAllowed {
			continue
		}
		p, e := r.PermissionSet(v.PermissionSetARN)
		if e != nil {
			return nil, e
		}
		out = append(out, portalRole{p, v})
	}
	slices.SortFunc(out, func(a, b portalRole) int {
		return strings.Compare(a.provision.AccountID+"/"+a.permission.Name, b.provision.AccountID+"/"+b.permission.Name)
	})
	return out, nil
}
func (s *Service) getRoleCredentials(tx Transaction, in *api.GetRoleCredentialsInput) (*api.GetRoleCredentialsOutput, error) {
	session, instance, rejected := s.session(tx, value(in.AccessToken))
	if rejected != nil {
		return nil, rejected
	}
	roles, e := s.availableRoles(tx, instance, session.UserID)
	if e != nil {
		return nil, e
	}
	for _, v := range roles {
		if v.provision.AccountID != value(in.AccountId) || v.permission.Name != value(in.RoleName) {
			continue
		}
		if s.roles == nil {
			return nil, failure("ResourceNotFoundException", "IAM role credential issuance is not configured.", 404)
		}
		user, e := s.directory.FindUser(tx.Context(), directoryScope(instance), instance.StoreID, session.UserID)
		if e != nil {
			return nil, failure("UnauthorizedException", "The directory user is no longer available.", 401)
		}
		credential, e := s.roles.Credentials(tx.Context(), instance, v.permission, v.provision, user.UserName)
		if e != nil {
			return nil, failure("UnauthorizedException", "The assigned role cannot currently be assumed.", 401)
		}
		return &api.GetRoleCredentialsOutput{RoleCredentials: &api.RoleCredentials{AccessKeyId: new(api.AccessKeyType(credential.AccessKeyID)), SecretAccessKey: new(api.SecretAccessKeyType(credential.SecretAccessKey)), SessionToken: new(api.SessionTokenType(credential.SessionToken)), Expiration: new(api.ExpirationTimestampType(credential.Expiration.UnixMilli()))}}, nil
	}
	return nil, failure("UnauthorizedException", "No access to this account and role.", 401)
}
