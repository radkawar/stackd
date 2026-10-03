package iam

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func passwordViolation() *awswire.Error {
	return &awswire.Error{Code: "PasswordPolicyViolation", Message: "The password does not meet the account password policy.", StatusCode: 400}
}

func validatePassword(policy *AccountPasswordPolicy, password string) *awswire.Error {
	length := utf8.RuneCountInString(password)
	if !utf8.ValidString(password) || length < 1 || length > 128 {
		return invalid("Password must contain 1-128 permitted characters.")
	}
	var upper, lower, number, symbol bool
	for _, r := range password {
		if r != '\t' && r != '\n' && r != '\r' && (r < 0x20 || r > 0xff) {
			return invalid("Password contains an unsupported character.")
		}
		upper = upper || r >= 'A' && r <= 'Z'
		lower = lower || r >= 'a' && r <= 'z'
		number = number || r >= '0' && r <= '9'
		symbol = symbol || strings.ContainsRune("!@#$%^&*()_+-=[]{}|'", r)
	}
	if policy == nil {
		classes := 0
		for _, present := range []bool{upper, lower, number, symbol} {
			if present {
				classes++
			}
		}
		if length < 8 || classes < 3 {
			return passwordViolation()
		}
		return nil
	}
	if length < policy.MinimumPasswordLength || policy.RequireUppercaseCharacters && !upper || policy.RequireLowercaseCharacters && !lower || policy.RequireNumbers && !number || policy.RequireSymbols && !symbol {
		return passwordViolation()
	}
	return nil
}

func replacePassword(policy *AccountPasswordPolicy, p *LoginProfileRecord, password string, now time.Time) *awswire.Error {
	if err := validatePassword(policy, password); err != nil {
		return err
	}
	if policy != nil && policy.PasswordReusePrevention > 0 {
		history := append([]PasswordDigest{p.Password}, p.PreviousPasswords...)
		for _, digest := range history[:min(len(history), policy.PasswordReusePrevention)] {
			match, err := matchesPassword(password, digest)
			if err != nil {
				return passwordServiceFailure()
			}
			if match {
				return passwordViolation()
			}
		}
	}
	digest, err := hashPassword(password)
	if err != nil {
		return passwordServiceFailure()
	}
	previous := append([]PasswordDigest{clonePasswordDigest(p.Password)}, p.PreviousPasswords...)
	p.PreviousPasswords = slices.Clone(previous[:min(len(previous), 24)])
	p.Password = digest
	p.PasswordChangedAt = now
	return nil
}

func getAccountPasswordPolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	p := a.settings.PasswordPolicy
	if p == nil {
		return nil, missing("account password policy", "default")
	}
	wire := &iamapi.PasswordPolicy{MinimumPasswordLength: wirePointer(iamapi.MinimumPasswordLengthType(p.MinimumPasswordLength)), RequireSymbols: wirePointer(iamapi.BooleanType(p.RequireSymbols)), RequireNumbers: wirePointer(iamapi.BooleanType(p.RequireNumbers)), RequireUppercaseCharacters: wirePointer(iamapi.BooleanType(p.RequireUppercaseCharacters)), RequireLowercaseCharacters: wirePointer(iamapi.BooleanType(p.RequireLowercaseCharacters)), AllowUsersToChangePassword: wirePointer(iamapi.BooleanType(p.AllowUsersToChangePassword)), ExpirePasswords: wirePointer(iamapi.BooleanType(p.MaxPasswordAge > 0)), HardExpiry: wirePointer(iamapi.BooleanObjectType(p.HardExpiry))}
	if p.MaxPasswordAge > 0 {
		wire.MaxPasswordAge = wirePointer(iamapi.MaxPasswordAgeType(p.MaxPasswordAge))
	}
	if p.PasswordReusePrevention > 0 {
		wire.PasswordReusePrevention = wirePointer(iamapi.PasswordReusePreventionType(p.PasswordReusePrevention))
	}
	return &iamapi.GetAccountPasswordPolicyOutput{PasswordPolicy: wire}, nil
}

func updateAccountPasswordPolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.UpdateAccountPasswordPolicyInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	// AWS replaces all settings; omitted fields return to their API defaults.
	p := &AccountPasswordPolicy{MinimumPasswordLength: 6, RequireSymbols: loginBool(in.RequireSymbols), RequireNumbers: loginBool(in.RequireNumbers), RequireUppercaseCharacters: loginBool(in.RequireUppercaseCharacters), RequireLowercaseCharacters: loginBool(in.RequireLowercaseCharacters), AllowUsersToChangePassword: loginBool(in.AllowUsersToChangePassword), HardExpiry: loginBool(in.HardExpiry)}
	if in.MinimumPasswordLength != nil {
		p.MinimumPasswordLength = int(*in.MinimumPasswordLength)
	}
	if in.MaxPasswordAge != nil {
		p.MaxPasswordAge = int(*in.MaxPasswordAge)
	}
	if in.PasswordReusePrevention != nil {
		p.PasswordReusePrevention = int(*in.PasswordReusePrevention)
	}
	a.settings.PasswordPolicy = p
	return &iamapi.UpdateAccountPasswordPolicyOutput{}, nil
}

func deleteAccountPasswordPolicy(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	if a.settings.PasswordPolicy == nil {
		return nil, missing("account password policy", "default")
	}
	a.settings.PasswordPolicy = nil
	return &iamapi.DeleteAccountPasswordPolicyOutput{}, nil
}
