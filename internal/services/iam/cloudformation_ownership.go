package iam

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// CloudFormationContext carries trusted owner metadata outside customer wire input.
// The ordinary IAM dispatcher still authorizes every operation before these hooks.
type CloudFormationContext struct {
	Owner                              string
	Direct                             bool
	Creating                           bool
	RequireExisting                    bool
	SecretResult                       *string
	MemberOwners                       *map[string]string
	MembershipClaims                   *[]string
	ClaimMembership, ReleaseMembership bool
	InlineOwners                       *map[string]string
	DeletionTask                       *string
	MFASerial                          string
	MFAReady                           *bool
}
type cloudFormationContextKey struct{}

func WithCloudFormationContext(ctx context.Context, owner CloudFormationContext) context.Context {
	return context.WithValue(ctx, cloudFormationContextKey{}, owner)
}
func cloudFormationOwner(ctx context.Context) (CloudFormationContext, bool) {
	o, ok := ctx.Value(cloudFormationContextKey{}).(CloudFormationContext)
	return o, ok
}
func checkCloudFormationOwner(o CloudFormationContext, existing string) *awswire.Error {
	if !o.Direct && (o.Owner == "" || existing != o.Owner) {
		return &awswire.Error{Code: "CloudFormationOwnershipConflict", Message: "Resource is not owned by this CloudFormation incarnation.", StatusCode: 409}
	}
	return nil
}

func (s *Service) cloudFormationCommand(ctx context.Context, a *account, m awsctx.Metadata, action string, h handler) (any, *awswire.Error) {
	o, enabled := cloudFormationOwner(ctx)
	if !enabled {
		return h(ctx, a, m)
	}
	request, _ := awsapi.FromContext(ctx)
	if err := cloudFormationNativeMutation(a, o, request.Input); err != nil {
		return nil, err
	}
	switch in := request.Input.(type) {
	case *api.CreateUserInput:
		out, err := h(ctx, a, m)
		if err == nil {
			a.users[strings.ToLower(inputString(in.UserName))].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.CreateRoleInput:
		out, err := h(ctx, a, m)
		if err == nil {
			a.roles[strings.ToLower(inputString(in.RoleName))].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.CreatePolicyInput:
		out, err := h(ctx, a, m)
		if err == nil {
			p := out.(*api.CreatePolicyOutput).Policy
			a.policies[inputString(p.Arn)].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.CreateInstanceProfileInput:
		out, err := h(ctx, a, m)
		if err == nil {
			a.instanceProfiles[strings.ToLower(inputString(in.InstanceProfileName))].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.CreateOpenIDConnectProviderInput:
		out, err := h(ctx, a, m)
		if err == nil {
			p := out.(*api.CreateOpenIDConnectProviderOutput)
			a.oidcProviders[inputString(p.OpenIDConnectProviderArn)].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.CreateSAMLProviderInput:
		out, err := h(ctx, a, m)
		if err == nil {
			p := out.(*api.CreateSAMLProviderOutput)
			a.samlProviders[inputString(p.SAMLProviderArn)].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.CreateVirtualMFADeviceInput:
		out, err := h(ctx, a, m)
		if err == nil {
			p := out.(*api.CreateVirtualMFADeviceOutput).VirtualMFADevice
			a.mfaDevices[inputString(p.SerialNumber)].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.UploadServerCertificateInput:
		out, err := h(ctx, a, m)
		if err == nil {
			p, _ := findServerCertificate(a, inputString(in.ServerCertificateName))
			p.CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.CreateGroupInput:
		if g := a.groups[strings.ToLower(inputString(in.GroupName))]; g != nil {
			if err := checkCloudFormationOwner(o, g.CloudFormationOwner); err != nil {
				return nil, err
			}
			if o.Direct {
				return nil, duplicate("Group", g.GroupName)
			}
			return &api.CreateGroupOutput{Group: wireGroup(g)}, nil
		}
		out, err := h(ctx, a, m)
		if err == nil {
			a.groups[strings.ToLower(inputString(in.GroupName))].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.GetGroupInput:
		g, err := findGroup(a, inputString(in.GroupName))
		if err != nil {
			return nil, err
		}
		if o.MembershipClaims != nil || o.MemberOwners != nil {
			if o.ClaimMembership {
				if o.Owner == "" {
					return nil, invalid("Missing membership incarnation.")
				}
				if g.MembershipClaims == nil {
					g.MembershipClaims = map[string]struct{}{}
				}
				g.MembershipClaims[o.Owner] = struct{}{}
			}
			if o.ReleaseMembership {
				delete(g.MembershipClaims, o.Owner)
			}
			if o.MemberOwners != nil {
				copy := map[string]string{}
				for name, owner := range g.MemberOwners {
					copy[name] = owner
				}
				*o.MemberOwners = copy
			}
			if o.MembershipClaims != nil {
				*o.MembershipClaims = nil
				for owner := range g.MembershipClaims {
					*o.MembershipClaims = append(*o.MembershipClaims, owner)
				}
			}
		} else if err := checkCloudFormationOwner(o, g.CloudFormationOwner); err != nil {
			return nil, err
		}
	case *api.UpdateGroupInput:
		g, err := findGroup(a, inputString(in.GroupName))
		if err != nil {
			return nil, err
		}
		if err := checkCloudFormationOwner(o, g.CloudFormationOwner); err != nil {
			return nil, err
		}
	case *api.DeleteGroupInput:
		g, err := findGroup(a, inputString(in.GroupName))
		if err != nil {
			return nil, err
		}
		if err := checkCloudFormationOwner(o, g.CloudFormationOwner); err != nil {
			return nil, err
		}
	case *api.AddUserToGroupInput:
		return cloudFormationMembership(ctx, a, m, h, o, inputString(in.GroupName), inputString(in.UserName), false)
	case *api.RemoveUserFromGroupInput:
		return cloudFormationMembership(ctx, a, m, h, o, inputString(in.GroupName), inputString(in.UserName), true)
	case *api.AttachUserPolicyInput:
		return cloudFormationAttached(ctx, a, m, h, o, "User", inputString(in.UserName), inputString(in.PolicyArn), false)
	case *api.AttachGroupPolicyInput:
		return cloudFormationAttached(ctx, a, m, h, o, "Group", inputString(in.GroupName), inputString(in.PolicyArn), false)
	case *api.AttachRolePolicyInput:
		return cloudFormationAttached(ctx, a, m, h, o, "Role", inputString(in.RoleName), inputString(in.PolicyArn), false)
	case *api.DetachUserPolicyInput:
		return cloudFormationAttached(ctx, a, m, h, o, "User", inputString(in.UserName), inputString(in.PolicyArn), true)
	case *api.DetachGroupPolicyInput:
		return cloudFormationAttached(ctx, a, m, h, o, "Group", inputString(in.GroupName), inputString(in.PolicyArn), true)
	case *api.DetachRolePolicyInput:
		return cloudFormationAttached(ctx, a, m, h, o, "Role", inputString(in.RoleName), inputString(in.PolicyArn), true)
	case *api.PutUserPolicyInput:
		return cloudFormationInline(ctx, a, m, h, o, "User", inputString(in.UserName), inputString(in.PolicyName), false)
	case *api.PutGroupPolicyInput:
		return cloudFormationInline(ctx, a, m, h, o, "Group", inputString(in.GroupName), inputString(in.PolicyName), false)
	case *api.PutRolePolicyInput:
		return cloudFormationInline(ctx, a, m, h, o, "Role", inputString(in.RoleName), inputString(in.PolicyName), false)
	case *api.DeleteUserPolicyInput:
		return cloudFormationInline(ctx, a, m, h, o, "User", inputString(in.UserName), inputString(in.PolicyName), true)
	case *api.DeleteGroupPolicyInput:
		return cloudFormationInline(ctx, a, m, h, o, "Group", inputString(in.GroupName), inputString(in.PolicyName), true)
	case *api.DeleteRolePolicyInput:
		return cloudFormationInline(ctx, a, m, h, o, "Role", inputString(in.RoleName), inputString(in.PolicyName), true)
	case *api.GetUserPolicyInput:
		return cloudFormationInlineRead(ctx, a, m, h, o, "User", inputString(in.UserName), inputString(in.PolicyName))
	case *api.GetGroupPolicyInput:
		return cloudFormationInlineRead(ctx, a, m, h, o, "Group", inputString(in.GroupName), inputString(in.PolicyName))
	case *api.GetRolePolicyInput:
		return cloudFormationInlineRead(ctx, a, m, h, o, "Role", inputString(in.RoleName), inputString(in.PolicyName))
	case *api.GetRoleInput:
		r, err := findRole(a, inputString(in.RoleName))
		if err != nil {
			return nil, err
		}
		if err := checkCloudFormationOwner(o, r.CloudFormationOwner); err != nil {
			return nil, err
		}
		if o.DeletionTask != nil {
			var newest *ServiceLinkedRoleDeletion
			for _, job := range a.serviceLinkedDeletions {
				if job.RoleID == r.RoleId && (newest == nil || job.CreatedAt.After(newest.CreatedAt) || (job.CreatedAt.Equal(newest.CreatedAt) && job.Status == "IN_PROGRESS" && newest.Status != "IN_PROGRESS")) {
					newest = job
				}
			}
			if newest != nil {
				*o.DeletionTask = newest.ID
			}
		}
	case *api.CreateServiceLinkedRoleInput:
		for _, r := range a.roles {
			if !o.Direct && r.CloudFormationOwner == o.Owner && o.Owner != "" {
				return serviceLinkedRoleOutput(r), nil
			}
		}
		out, err := h(ctx, a, m)
		if err == nil {
			r := out.(*api.CreateServiceLinkedRoleOutput).Role
			a.roles[strings.ToLower(string(*r.RoleName))].CloudFormationOwner = o.Owner
		}
		return out, err
	case *api.DeleteServiceLinkedRoleInput:
		r, err := findRole(a, inputString(in.RoleName))
		if err != nil {
			return nil, err
		}
		if err := checkCloudFormationOwner(o, r.CloudFormationOwner); err != nil {
			return nil, err
		}
	case *api.UpdateRoleDescriptionInput:
		r, err := findRole(a, inputString(in.RoleName))
		if err != nil {
			return nil, err
		}
		if err := checkCloudFormationOwner(o, r.CloudFormationOwner); err != nil {
			return nil, err
		}
	case *api.CreateAccessKeyInput:
		principal, err := credentialPrincipal(a, m, inputString(in.UserName))
		if err != nil {
			return nil, err
		}
		tx := ctx.Value(transactionKey{}).(serviceTransaction).tx.(WriteTx)
		records, readErr := tx.PrincipalCredentials(principal.AccountID, principal.ID)
		if readErr != nil {
			return nil, credentialError(readErr)
		}
		for _, record := range records {
			if !o.Direct && o.Owner != "" && record.CloudFormationOwner == o.Owner {
				c := record.Credential
				return &api.CreateAccessKeyOutput{AccessKey: &api.AccessKey{UserName: wirePointer(api.UserNameType(c.UserName)), AccessKeyId: wirePointer(api.AccessKeyIdType(c.AccessKeyID)), SecretAccessKey: wirePointer(api.AccessKeySecretType(c.SecretAccessKey)), Status: wirePointer(api.StatusType(record.Status)), CreateDate: wirePointer(c.CreateDate)}}, nil
			}
		}
		out, err := h(ctx, a, m)
		if err != nil {
			return nil, err
		}
		key := out.(*api.CreateAccessKeyOutput).AccessKey
		record, readErr := tx.Credential(string(*key.AccessKeyId))
		if readErr != nil {
			return nil, credentialError(readErr)
		}
		record.CloudFormationOwner = o.Owner
		if err := tx.PutCredential(record); err != nil {
			return nil, credentialError(err)
		}
		return out, nil
	case *api.UpdateAccessKeyInput:
		record, err := ctx.Value(transactionKey{}).(serviceTransaction).tx.Credential(inputString(in.AccessKeyId))
		if err != nil {
			return nil, credentialError(err)
		}
		if err := checkCloudFormationOwner(o, record.CloudFormationOwner); err != nil {
			return nil, err
		}
		out, apiErr := h(ctx, a, m)
		if apiErr == nil && !o.Direct && o.SecretResult != nil {
			*o.SecretResult = record.Credential.SecretAccessKey
		}
		return out, apiErr
	case *api.DeleteAccessKeyInput:
		record, err := ctx.Value(transactionKey{}).(serviceTransaction).tx.Credential(inputString(in.AccessKeyId))
		if err != nil {
			return nil, credentialError(err)
		}
		if err := checkCloudFormationOwner(o, record.CloudFormationOwner); err != nil {
			return nil, err
		}
	case *api.ListAccessKeysInput:
		out, err := h(ctx, a, m)
		if err != nil || o.Direct {
			return out, err
		}
		result := out.(*api.ListAccessKeysOutput)
		filtered := result.AccessKeyMetadata[:0]
		for _, key := range result.AccessKeyMetadata {
			record, readErr := ctx.Value(transactionKey{}).(serviceTransaction).tx.Credential(inputString(key.AccessKeyId))
			if readErr != nil {
				return nil, credentialError(readErr)
			}
			if record.CloudFormationOwner == o.Owner && o.Owner != "" {
				filtered = append(filtered, key)
				if o.SecretResult != nil {
					*o.SecretResult = record.Credential.SecretAccessKey
				}
			}
		}
		result.AccessKeyMetadata = filtered
		return result, nil
	case *api.ListUserPoliciesInput:
		return cloudFormationInlineList(ctx, a, m, h, o, "User", inputString(in.UserName))
	case *api.ListGroupPoliciesInput:
		return cloudFormationInlineList(ctx, a, m, h, o, "Group", inputString(in.GroupName))
	case *api.ListRolePoliciesInput:
		return cloudFormationInlineList(ctx, a, m, h, o, "Role", inputString(in.RoleName))
	case *api.ListVirtualMFADevicesInput:
		if o.MFAReady != nil {
			d, err := findMFADevice(a, o.MFASerial)
			if err != nil {
				return nil, err
			}
			if err := checkCloudFormationOwner(o, d.CloudFormationOwner); err != nil {
				return nil, err
			}
			d.Binding.advance(a.currentTime)
			*o.MFAReady = d.Binding.Value.UserID == d.Binding.VisibleValue.UserID && d.Binding.Value.SkewSteps == d.Binding.VisibleValue.SkewSteps
		}
	case *api.EnableMFADeviceInput:
		d, err := findMFADevice(a, inputString(in.SerialNumber))
		if err != nil {
			return nil, err
		}
		u, err := findUser(a, inputString(in.UserName))
		if err != nil {
			return nil, err
		}
		if d.Binding.Value.UserID == u.UserId {
			return &api.EnableMFADeviceOutput{}, nil
		}
		copied := *in
		step := a.currentTime.Unix()/30 + d.Binding.Value.SkewSteps
		if d.LastPairStep != nil && step <= *d.LastPairStep {
			step = *d.LastPairStep + 1
		}
		copied.AuthenticationCode1 = wirePointer(api.AuthenticationCodeType(totp([]byte(d.Binding.Value.Seed), step)))
		copied.AuthenticationCode2 = wirePointer(api.AuthenticationCodeType(totp([]byte(d.Binding.Value.Seed), step+1)))
		request.Input = &copied
		ctx = awsapi.WithDecodedRequest(ctx, request)
	}
	return h(ctx, a, m)
}
func cloudFormationMembership(ctx context.Context, a *account, m awsctx.Metadata, h handler, o CloudFormationContext, groupName, userName string, remove bool) (any, *awswire.Error) {
	g, err := findGroup(a, groupName)
	if err != nil {
		return nil, err
	}
	u, err := findUser(a, userName)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(u.UserName)
	if strings.HasPrefix(o.Owner, "AWS::IAM::User#") {
		if err := checkCloudFormationOwner(o, u.CloudFormationOwner); err != nil {
			return nil, err
		}
	}
	if _, exists := g.Members[key]; exists && !o.Direct {
		if err := checkCloudFormationOwner(o, g.MemberOwners[key]); err != nil {
			return nil, err
		}
	} else if remove && !o.Direct {
		return &api.RemoveUserFromGroupOutput{}, nil
	}
	out, err := h(ctx, a, m)
	if err == nil {
		if g.MemberOwners == nil {
			g.MemberOwners = map[string]string{}
		}
		if remove {
			delete(g.MemberOwners, key)
		} else {
			g.MemberOwners[key] = o.Owner
		}
	}
	return out, err
}
func cloudFormationInline(ctx context.Context, a *account, m awsctx.Metadata, h handler, o CloudFormationContext, kind, target, name string, remove bool) (any, *awswire.Error) {
	p, _, err := findIdentity(a, kind, target)
	if err != nil {
		return nil, err
	}
	stored, exists := inlinePolicyName(p, name)
	if err := cloudFormationIdentityMutation(o, p, kind); err != nil {
		return nil, err
	}
	if o.Direct && o.Creating && exists {
		return nil, duplicate("Inline policy", name)
	}
	if o.RequireExisting && !exists {
		return nil, missing("policy", name)
	}
	if exists && !o.Direct {
		if err := checkCloudFormationOwner(o, p.InlineOwners[stored]); err != nil {
			return nil, err
		}
	} else if remove && !o.Direct {
		return &api.Unit{}, nil
	}
	out, err := h(ctx, a, m)
	if err == nil {
		if p.InlineOwners == nil {
			p.InlineOwners = map[string]string{}
		}
		if remove {
			delete(p.InlineOwners, stored)
		} else if !o.Direct || p.InlineOwners[stored] == "" {
			p.InlineOwners[stored] = o.Owner
		}
	}
	return out, err
}
func cloudFormationInlineRead(ctx context.Context, a *account, m awsctx.Metadata, h handler, o CloudFormationContext, kind, target, name string) (any, *awswire.Error) {
	p, _, err := findIdentity(a, kind, target)
	if err != nil {
		return nil, err
	}
	stored, exists := inlinePolicyName(p, name)
	if !exists {
		return nil, missing("policy", name)
	}
	if err := checkCloudFormationOwner(o, p.InlineOwners[stored]); err != nil {
		return nil, err
	}
	return h(ctx, a, m)
}
func cloudFormationInlineList(ctx context.Context, a *account, m awsctx.Metadata, h handler, o CloudFormationContext, kind, target string) (any, *awswire.Error) {
	p, _, err := findIdentity(a, kind, target)
	if err != nil {
		return nil, err
	}
	if o.InlineOwners != nil {
		copy := map[string]string{}
		for name, owner := range p.InlineOwners {
			copy[name] = owner
		}
		*o.InlineOwners = copy
	}
	return h(ctx, a, m)
}
func cloudFormationAttached(ctx context.Context, a *account, m awsctx.Metadata, h handler, o CloudFormationContext, kind, target, arn string, remove bool) (any, *awswire.Error) {
	p, _, err := findIdentity(a, kind, target)
	if err != nil {
		return nil, err
	}
	policy, err := findPolicyARN(a, arn)
	if err != nil {
		return nil, err
	}
	arn = policy.Arn
	if err := cloudFormationIdentityMutation(o, p, kind); err != nil {
		return nil, err
	}
	if strings.HasPrefix(o.Owner, "AWS::IAM::ManagedPolicy#") {
		if err := checkCloudFormationOwner(o, policy.CloudFormationOwner); err != nil {
			return nil, err
		}
	}
	if _, exists := p.Attached[arn]; exists && !o.Direct {
		if err := checkCloudFormationOwner(o, p.AttachedOwners[arn]); err != nil {
			return nil, err
		}
	}
	out, err := h(ctx, a, m)
	if err == nil {
		if p.AttachedOwners == nil {
			p.AttachedOwners = map[string]string{}
		}
		if remove {
			delete(p.AttachedOwners, arn)
		} else if !o.Direct || p.AttachedOwners[arn] == "" {
			p.AttachedOwners[arn] = o.Owner
		}
	}
	return out, err
}

func cloudFormationIdentityMutation(o CloudFormationContext, p *identityPolicies, kind string) *awswire.Error {
	if strings.HasPrefix(o.Owner, "AWS::IAM::"+kind+"#") {
		return checkCloudFormationOwner(o, p.CloudFormationOwner)
	}
	return nil
}
