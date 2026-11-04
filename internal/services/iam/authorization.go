package iam

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

// IdentityPolicies snapshots current IAM user or role policies for a verified
// principal. User groups, default managed-policy versions and boundaries are
// resolved atomically, so concurrent attachment/version changes cannot produce
// a mixture of old and new authorization state. GetSessionToken sessions use
// the original IAM user identity and therefore inherit its current policies.
func (s *Service) IdentityPolicies(ctx context.Context) (authorization.PolicySet, error) {
	if err := ctx.Err(); err != nil {
		return authorization.PolicySet{}, err
	}
	if IsEC2InfrastructureContext(ctx) {
		// Identity-only roles have no identity policies or permissions boundary.
		// This is not an allow: the evaluator still requires a KMS grant/key
		// policy and applies the account's SCPs as for any assumed-role actor.
		return authorization.PolicySet{}, nil
	}
	m := awsctx.FromContext(ctx)
	var result authorization.PolicySet
	err := s.view(ctx, func(tx ReadTx) error {
		var err error
		result, err = identityPolicySnapshot(tx, m)
		return err
	})
	return result, err
}

func identityPolicySnapshot(tx ReadTx, m awsctx.Metadata) (authorization.PolicySet, error) {
	principalARN, principalID := m.PrincipalARN, m.PrincipalID
	if strings.HasPrefix(m.PrincipalARN, "arn:"+m.Partition+":sts:") {
		principalARN, principalID = m.IssuerARN, m.IssuerID
	}
	scope := Scope{Partition: m.Partition, AccountID: m.AccountID}
	type identitySource struct {
		owner    string
		policies identityPolicies
	}
	var identities []identitySource
	var permissionsBoundary *boundary
	var tags []tag
	serviceLinkedRole := false
	prefix := "arn:" + m.Partition + ":iam::" + m.AccountID + ":"
	resource := strings.TrimPrefix(principalARN, prefix)
	name := resource[strings.LastIndexByte(resource, '/')+1:]
	switch {
	case principalARN == prefix+"root" && principalID == m.AccountID:
		identities = append(identities, identitySource{principalARN, identityPolicies{Inline: map[string]string{"root": `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}}})
	case strings.HasPrefix(principalARN, prefix+"user/"):
		u, err := tx.User(scope, name)
		if err != nil && !errors.Is(err, ErrRecordNotFound) {
			return authorization.PolicySet{}, err
		}
		if err != nil || u.Arn != principalARN || u.UserId != principalID {
			return authorization.PolicySet{}, fmt.Errorf("IAM principal does not exist or its identity has changed")
		}
		identities = append(identities, identitySource{u.Arn, u.IdentityPolicies})
		settings, err := tx.AccountSettings(scope)
		if err != nil {
			return authorization.PolicySet{}, err
		}
		if settings.PasswordPolicy != nil && settings.PasswordPolicy.AllowUsersToChangePassword {
			identities = append(identities, identitySource{u.Arn, passwordSelfManagementPolicies(u.Arn)})
		}
		permissionsBoundary, tags = u.PermissionsBoundary, u.Tags
		groups, err := tx.UserGroups(scope, u.UserName)
		if err != nil {
			return authorization.PolicySet{}, err
		}
		for _, g := range groups {
			identities = append(identities, identitySource{g.Arn, g.IdentityPolicies})
		}
	case strings.HasPrefix(principalARN, prefix+"role/"):
		role, err := tx.Role(scope, name)
		if err != nil && !errors.Is(err, ErrRecordNotFound) {
			return authorization.PolicySet{}, err
		}
		if err != nil || role.Arn != principalARN || role.RoleId != principalID {
			return authorization.PolicySet{}, fmt.Errorf("IAM principal does not exist or its identity has changed")
		}
		identities = append(identities, identitySource{role.Arn, role.IdentityPolicies})
		permissionsBoundary, tags = role.PermissionsBoundary, role.Tags
		serviceLinkedRole = role.ServiceLinkedService != ""
	default:
		return authorization.PolicySet{}, fmt.Errorf("IAM principal does not exist or its identity has changed")
	}
	set := authorization.PolicySet{HasBoundary: permissionsBoundary != nil, PrincipalTags: make(map[string]string, len(tags)), ServiceLinkedRole: serviceLinkedRole}
	for _, tag := range tags {
		set.PrincipalTags[tag.Key] = tag.Value
	}
	for _, identity := range identities {
		for name, document := range identity.policies.Inline {
			set.Identity = append(set.Identity, iampolicy.Policy{Source: identity.owner + "#" + name, Document: document})
		}
		for arn := range identity.policies.Attached {
			document, err := currentIdentityPolicySnapshot(tx, scope, arn)
			if err != nil {
				return authorization.PolicySet{}, err
			}
			set.Identity = append(set.Identity, document)
		}
	}
	if permissionsBoundary != nil {
		document, err := currentIdentityPolicySnapshot(tx, scope, permissionsBoundary.PermissionsBoundaryArn)
		if err != nil {
			return authorization.PolicySet{}, err
		}
		set.Boundary = []iampolicy.Policy{document}
	}
	for _, arn := range m.SessionPolicyARNs {
		doc, err := currentIdentityPolicySnapshot(tx, scope, arn)
		if err != nil {
			return authorization.PolicySet{}, err
		}
		set.ManagedSession = append(set.ManagedSession, doc)
	}
	slices.SortFunc(set.Identity, func(a, b iampolicy.Policy) int { return strings.Compare(a.Source, b.Source) })
	return set, nil
}

func currentIdentityPolicySnapshot(tx ReadTx, scope Scope, arn string) (iampolicy.Policy, error) {
	p, err := tx.ManagedPolicy(scope, arn)
	if errors.Is(err, ErrRecordNotFound) {
		var ok bool
		p, ok = lookupAWSManagedPolicy(scope.Partition, arn)
		if !ok {
			return iampolicy.Policy{}, fmt.Errorf("attached managed policy does not exist")
		}
	} else if err != nil {
		return iampolicy.Policy{}, err
	}
	version := p.Versions[p.DefaultVersionId]
	if version == nil {
		return iampolicy.Policy{}, fmt.Errorf("managed policy default version does not exist")
	}
	return iampolicy.Policy{Source: arn, Version: p.DefaultVersionId, Document: version.Document}, nil
}

func currentPolicySnapshot(a *account, arn string) (iampolicy.Policy, error) {
	p := a.policies[arn]
	if p == nil {
		if managed, ok := lookupAWSManagedPolicy(a.partition, arn); ok {
			p = &managed
		}
	}
	if p == nil {
		return iampolicy.Policy{}, fmt.Errorf("attached managed policy does not exist")
	}
	version := p.Versions[p.DefaultVersionId]
	if version == nil {
		return iampolicy.Policy{}, fmt.Errorf("managed policy default version does not exist")
	}
	return iampolicy.Policy{Source: arn, Version: p.DefaultVersionId, Document: version.Document}, nil
}

// ResolvePrincipal resolves IAM user and role ARNs or immutable IDs within the
// caller's partition. It does not require the principal to belong to the caller
// account because queue and key policies support cross-account principals.
func (s *Service) ResolvePrincipal(ctx context.Context, reference string) (authorization.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Principal{}, err
	}
	m := awsctx.FromContext(ctx)
	accountID := ""
	if strings.HasPrefix(reference, "arn:") {
		parts := strings.SplitN(reference, ":", 6)
		if len(parts) != 6 || parts[1] != m.Partition || parts[2] != "iam" || parts[3] != "" {
			return authorization.Principal{}, authorization.ErrInvalidPrincipal
		}
		accountID = parts[4]
	}
	var result authorization.Principal
	err := s.view(ctx, func(tx ReadTx) error {
		scopes := []Scope{{Partition: m.Partition, AccountID: accountID}}
		if accountID == "" {
			var err error
			scopes, err = tx.Scopes(m.Partition)
			if err != nil {
				return err
			}
		}
		for _, scope := range scopes {
			users, err := tx.Users(scope)
			if err != nil {
				return err
			}
			for _, u := range users {
				if u.Arn == reference || u.UserId == reference {
					result = authorization.Principal{ARN: u.Arn, ID: u.UserId}
					return nil
				}
			}
			roles, err := tx.Roles(scope)
			if err != nil {
				return err
			}
			for _, r := range roles {
				if r.Arn == reference || r.RoleId == reference {
					result = authorization.Principal{ARN: r.Arn, ID: r.RoleId}
					return nil
				}
			}
		}
		return authorization.ErrInvalidPrincipal
	})
	return result, err
}
