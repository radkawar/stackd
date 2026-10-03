package iam

import (
	"context"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func findUser(a *account, name string) (*user, *awswire.Error) {
	u := a.users[strings.ToLower(name)]
	if u == nil {
		return nil, missing("user", name)
	}
	return u, nil
}

func createUser(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.CreateUserInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	name := inputString(in.UserName)
	path := defaultPath(inputString(in.Path))
	tags, err := inputTags(in.Tags, "User")
	if err != nil {
		return nil, err
	}
	b, err := resolveBoundary(a, inputString(in.PermissionsBoundary), "User")
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(name)
	if a.users[key] != nil {
		return nil, duplicate("User", name)
	}
	if len(a.users) >= maxUsers {
		return nil, limit("IAM user quota exceeded.")
	}
	u := &user{Path: path, UserName: name, UserId: newID("AIDA"), Arn: resourceARN(m, "user", path, name), CreateDate: a.currentTime, Tags: tags, PermissionsBoundary: b, IdentityPolicies: newIdentityPolicies()}
	a.users[key] = u
	if b != nil {
		a.policies[b.PermissionsBoundaryArn].PermissionsBoundaryUsageCount++
	}
	return &iamapi.CreateUserOutput{User: wireUser(u, true)}, nil
}

func getUser(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.GetUserInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	name := inputString(in.UserName)
	if in.UserName == nil {
		if m.PrincipalARN == resourceARN(m, "root", "", "") {
			return &iamapi.GetUserOutput{User: &iamapi.User{
				UserId: wirePointer(iamapi.IdType(m.AccountID)), Arn: wirePointer(iamapi.ArnType(m.PrincipalARN)),
				CreateDate: wirePointer(a.metadata.CreatedAt),
			}}, nil
		}
		if m.UserName == "" {
			return nil, missing("user", "root")
		}
		name = m.UserName
	}
	u, err := findUser(a, name)
	if err != nil {
		return nil, err
	}
	return &iamapi.GetUserOutput{User: wireUser(u, true)}, nil
}

func listUsers(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListUsersInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	items := make([]*user, 0, len(a.users))
	for _, u := range a.users {
		if strings.HasPrefix(u.Path, inputString(in.PathPrefix)) {
			items = append(items, u)
		}
	}
	items, p, err := page(ctx, items, func(u *user) string { return u.UserName }, m, in)
	return &iamapi.ListUsersOutput{Users: wireUsers(items), IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, err
}

func (s *Service) updateUser(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.UpdateUserInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, err := findUser(a, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	newName, newPath := u.UserName, u.Path
	if in.NewUserName != nil {
		newName = inputString(in.NewUserName)
		if existing := a.users[strings.ToLower(newName)]; existing != nil && existing != u {
			return nil, duplicate("User", newName)
		}
	}
	if in.NewPath != nil {
		newPath = inputString(in.NewPath)
	}
	oldKey, newKey := strings.ToLower(u.UserName), strings.ToLower(newName)
	delete(a.users, oldKey)
	a.users[newKey] = u
	for _, g := range a.groups {
		if _, ok := g.Members[oldKey]; ok {
			delete(g.Members, oldKey)
			g.Members[newKey] = struct{}{}
		}
	}
	u.UserName, u.Path, u.Arn = newName, newPath, resourceARN(m, "user", newPath, newName)
	if err := s.credentialStore(ctx).RenamePrincipal(identity.Principal{AccountID: m.AccountID, ARN: u.Arn, ID: u.UserId, UserName: u.UserName}); err != nil {
		return nil, credentialError(err)
	}
	return &iamapi.UpdateUserOutput{}, nil
}

func (s *Service) deleteUser(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeleteUserInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, err := findUser(a, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	if a.loginProfiles[u.UserId] != nil {
		return nil, conflict("Cannot delete user with a login profile.")
	}
	for _, cert := range a.signingCertificates {
		if cert.UserID == u.UserId {
			return nil, conflict("Cannot delete user with signing certificates.")
		}
	}
	for _, key := range a.sshKeys {
		if key.UserID == u.UserId {
			return nil, conflict("Cannot delete user with SSH public keys.")
		}
	}
	for _, credential := range a.serviceCredentials {
		if credential.UserID == u.UserId {
			return nil, conflict("Cannot delete user with service-specific credentials.")
		}
	}
	for _, device := range a.mfaDevices {
		if device.Binding.Value.UserID == u.UserId {
			return nil, conflict("Deactivate the user's MFA devices before deleting the user.")
		}
	}
	if len(u.Inline) > 0 || len(u.Attached) > 0 {
		return nil, conflict("Cannot delete user with attached policies.")
	}
	keys, keyErr := s.credentialStore(ctx).ListAccessKeys(m.AccountID, u.UserId)
	if keyErr != nil {
		return nil, credentialError(keyErr)
	}
	if len(keys) != 0 {
		return nil, conflict("Cannot delete user with access keys.")
	}
	for _, g := range a.groups {
		if _, ok := g.Members[strings.ToLower(u.UserName)]; ok {
			return nil, conflict("Cannot delete user with group memberships.")
		}
	}
	if u.PermissionsBoundary != nil {
		a.policies[u.PermissionsBoundary.PermissionsBoundaryArn].PermissionsBoundaryUsageCount--
	}
	delete(a.users, strings.ToLower(u.UserName))
	if err := s.credentialStore(ctx).DeletePrincipal(m.AccountID, u.UserId); err != nil {
		return nil, credentialError(err)
	}
	return &iamapi.DeleteUserOutput{}, nil
}
