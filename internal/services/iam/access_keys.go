package iam

import (
	"context"
	"errors"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/journal"
)

func credentialPrincipal(a *account, m awsctx.Metadata, name string) (identity.Principal, *awswire.Error) {
	if name == "" && m.UserName == "" {
		rootARN := resourceARN(m, "root", "", "")
		if m.PrincipalARN != rootARN {
			return identity.Principal{}, &awswire.Error{Code: "ValidationError", Message: "Must specify userName when calling with non-User credentials.", StatusCode: 400}
		}
		return identity.Principal{AccountID: m.AccountID, ARN: rootARN, ID: m.AccountID}, nil
	}
	if name == "" {
		name = m.UserName
	}
	u, err := findUser(a, name)
	if err != nil {
		return identity.Principal{}, err
	}
	return identity.Principal{AccountID: m.AccountID, ARN: u.Arn, ID: u.UserId, UserName: u.UserName}, nil
}

func credentialError(err error) *awswire.Error {
	switch {
	case errors.Is(err, identity.ErrNotFound):
		return missing("access key", "specified key")
	case errors.Is(err, identity.ErrLimitExceeded):
		return limit("A principal may have at most two access keys, including inactive keys.")
	case errors.Is(err, identity.ErrInvalidPrincipal):
		return invalidInput("Invalid credential principal or status.")
	default:
		return &awswire.Error{Code: "ServiceFailure", Message: "Unable to update credential state.", StatusCode: 500}
	}
}

func (s *Service) createAccessKey(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.CreateAccessKeyInput](ctx)
	if err != nil {
		return nil, err
	}
	principal, err := credentialPrincipal(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	credential, createErr := s.credentialStore(ctx).CreateAccessKey(principal)
	if createErr != nil {
		return nil, credentialError(createErr)
	}
	if err := s.appendAccessKeyChange(ctx, a, m, journal.AccessKeyChanged{Action: journal.AccessKeyCreated, AccessKeyID: credential.AccessKeyID, PrincipalARN: principal.ARN, Status: string(identity.Active)}); err != nil {
		return nil, err
	}
	return &iamapi.CreateAccessKeyOutput{AccessKey: &iamapi.AccessKey{
		UserName: wirePointer(iamapi.UserNameType(credential.UserName)), AccessKeyId: wirePointer(iamapi.AccessKeyIdType(credential.AccessKeyID)),
		Status: wirePointer(iamapi.StatusType(identity.Active)), CreateDate: wirePointer(credential.CreateDate), SecretAccessKey: wirePointer(iamapi.AccessKeySecretType(credential.SecretAccessKey)),
	}}, nil
}

func (s *Service) listAccessKeys(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.ListAccessKeysInput](ctx)
	if err != nil {
		return nil, err
	}
	principal, err := credentialPrincipal(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	keys, listErr := s.credentialStore(ctx).ListAccessKeys(principal.AccountID, principal.ID)
	if listErr != nil {
		return nil, credentialError(listErr)
	}
	items := make(iamapi.AccessKeyMetadataListType, 0, len(keys))
	for _, key := range keys {
		items = append(items, iamapi.AccessKeyMetadata{
			UserName: wirePointer(iamapi.UserNameType(key.Principal.UserName)), AccessKeyId: wirePointer(iamapi.AccessKeyIdType(key.AccessKeyID)),
			Status: wirePointer(iamapi.StatusType(key.Status)), CreateDate: wirePointer(key.CreateDate),
		})
	}
	// An omitted UserName still binds the marker to the effective credential owner.
	selection := *in
	if in.UserName == nil && principal.UserName != "" {
		selection.UserName = wirePointer(iamapi.ExistingUserNameType(principal.UserName))
	}
	items, p, err := page(ctx, items, func(key iamapi.AccessKeyMetadata) string { return string(*key.AccessKeyId) }, m, &selection)
	return &iamapi.ListAccessKeysOutput{AccessKeyMetadata: items, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, err
}

func (s *Service) updateAccessKey(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateAccessKeyInput](ctx)
	if err != nil {
		return nil, err
	}
	principal, err := credentialPrincipal(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	id := inputString(in.AccessKeyId)
	status := identity.Status(inputString(in.Status))
	if err := s.credentialStore(ctx).UpdateAccessKey(principal.AccountID, principal.ID, id, status); err != nil {
		return nil, credentialError(err)
	}
	if err := s.appendAccessKeyChange(ctx, a, m, journal.AccessKeyChanged{Action: journal.AccessKeyStatusUpdated, AccessKeyID: id, PrincipalARN: principal.ARN, Status: string(status)}); err != nil {
		return nil, err
	}
	return &iamapi.UpdateAccessKeyOutput{}, nil
}

func (s *Service) deleteAccessKey(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.DeleteAccessKeyInput](ctx)
	if err != nil {
		return nil, err
	}
	principal, err := credentialPrincipal(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	id := inputString(in.AccessKeyId)
	if err := s.credentialStore(ctx).DeleteAccessKey(principal.AccountID, principal.ID, id); err != nil {
		return nil, credentialError(err)
	}
	if err := s.appendAccessKeyChange(ctx, a, m, journal.AccessKeyChanged{Action: journal.AccessKeyDeleted, AccessKeyID: id, PrincipalARN: principal.ARN}); err != nil {
		return nil, err
	}
	return &iamapi.DeleteAccessKeyOutput{}, nil
}

func (s *Service) getAccessKeyLastUsed(ctx context.Context, _ *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.GetAccessKeyLastUsedInput](ctx)
	if err != nil {
		return nil, err
	}
	id := inputString(in.AccessKeyId)
	key, usage, usageErr := s.credentialStore(ctx).AccessKeyLastUsed(m.AccountID, id)
	if usageErr != nil {
		return nil, credentialError(usageErr)
	}
	result := &iamapi.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: &iamapi.AccessKeyLastUsed{ServiceName: wirePointer(iamapi.StringType(usage.Service)), Region: wirePointer(iamapi.StringType(usage.Region))}}
	if key.Principal.UserName != "" {
		result.UserName = wirePointer(iamapi.ExistingUserNameType(key.Principal.UserName))
	}
	if usage.Recorded() {
		result.AccessKeyLastUsed.LastUsedDate = &usage.Date
	}
	return result, nil
}
