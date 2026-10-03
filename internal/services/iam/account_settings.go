package iam

import (
	"context"
	"errors"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) createAccountAlias(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.CreateAccountAliasInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	alias := inputString(in.AccountAlias)
	if len(alias) == 12 && strings.Trim(alias, "0123456789") == "" {
		return nil, invalid("An account alias cannot be a twelve-digit account ID.")
	}
	var owner string
	err := s.view(ctx, func(tx ReadTx) error {
		var err error
		owner, err = tx.AccountAliasOwner(m.Partition, alias)
		return err
	})
	if err != nil && !errors.Is(err, ErrRecordNotFound) {
		return nil, passwordServiceFailure()
	}
	if owner != "" {
		return nil, duplicate("account alias", alias)
	}
	// IAM permits one alias; creating a different available alias replaces it.
	a.settings.Alias = alias
	return &iamapi.CreateAccountAliasOutput{}, nil
}

func listAccountAliases(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListAccountAliasesInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	aliases := make([]string, 0, 1)
	if a.settings.Alias != "" {
		aliases = append(aliases, a.settings.Alias)
	}
	aliases, paging, apiErr := page(ctx, aliases, func(v string) string { return v }, m, in)
	if apiErr != nil {
		return nil, apiErr
	}
	output := &iamapi.ListAccountAliasesOutput{AccountAliases: make(iamapi.AccountAliasListType, 0, len(aliases)), IsTruncated: wirePointer(iamapi.BooleanType(paging.IsTruncated))}
	for _, alias := range aliases {
		output.AccountAliases = append(output.AccountAliases, iamapi.AccountAliasType(alias))
	}
	if paging.Marker != "" {
		output.Marker = wirePointer(iamapi.ResponseMarkerType(paging.Marker))
	}
	return output, nil
}

func deleteAccountAlias(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeleteAccountAliasInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if alias := inputString(in.AccountAlias); a.settings.Alias == "" || a.settings.Alias != alias {
		return nil, missing("account alias", alias)
	}
	a.settings.Alias = ""
	return &iamapi.DeleteAccountAliasOutput{}, nil
}

// ResolveAccountAlias resolves the public sign-in name within one partition.
// It returns ErrRecordNotFound for an unknown alias, never another partition's
// account even when the alias strings are identical.
func (s *Service) ResolveAccountAlias(ctx context.Context, partition, alias string) (string, error) {
	if partition == "" || alias == "" {
		return "", ErrRecordNotFound
	}
	var accountID string
	err := s.view(ctx, func(tx ReadTx) error {
		var err error
		accountID, err = tx.AccountAliasOwner(partition, alias)
		return err
	})
	return accountID, err
}
