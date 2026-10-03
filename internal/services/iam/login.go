package iam

import (
	"context"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func loginUser(a *account, m awsctx.Metadata, name string) (*user, *awswire.Error) {
	if name == "" {
		return currentPasswordUser(a, m)
	}
	u := a.users[strings.ToLower(name)]
	if u == nil {
		return nil, missing("user", name)
	}
	return u, nil
}

func currentPasswordUser(a *account, m awsctx.Metadata) (*user, *awswire.Error) {
	for _, u := range a.users {
		if u.UserId == m.PrincipalID && u.Arn == m.PrincipalARN {
			return u, nil
		}
	}
	return nil, &awswire.Error{Code: "InvalidUserType", Message: "This operation requires an IAM user principal.", StatusCode: 400}
}

func createLoginProfile(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.CreateLoginProfileInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if m.SessionType == string(identity.SessionTypeAssumeRoot) {
		if in.UserName != nil || in.Password != nil {
			return nil, invalid("UserName and Password must be omitted with an AssumeRoot session.")
		}
		if a.settings.RootLoginProfile != nil {
			return nil, duplicate("login profile", m.AccountID)
		}
		a.settings.RootLoginProfile = &RootLoginProfileRecord{CreateDate: a.currentTime}
		return &iamapi.CreateLoginProfileOutput{LoginProfile: wireRootLoginProfile(a.settings.RootLoginProfile)}, nil
	}
	u, apiErr := loginUser(a, m, inputString(in.UserName))
	if apiErr != nil {
		return nil, apiErr
	}
	if a.loginProfiles[u.UserId] != nil {
		return nil, duplicate("login profile", u.UserName)
	}
	if in.Password == nil {
		return nil, invalid("Password is required for an IAM user login profile.")
	}
	if apiErr := validatePassword(a.settings.PasswordPolicy, inputString(in.Password)); apiErr != nil {
		return nil, apiErr
	}
	digest, err := hashPassword(inputString(in.Password))
	if err != nil {
		return nil, passwordServiceFailure()
	}
	now := a.currentTime
	p := &LoginProfileRecord{UserID: u.UserId, CreateDate: now, PasswordChangedAt: now, Password: digest, PasswordResetRequired: loginBool(in.PasswordResetRequired)}
	a.loginProfiles[u.UserId] = p
	return &iamapi.CreateLoginProfileOutput{LoginProfile: wireLoginProfile(u, p)}, nil
}

func getLoginProfile(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.GetLoginProfileInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if m.SessionType == string(identity.SessionTypeAssumeRoot) && in.UserName == nil {
		if a.settings.RootLoginProfile == nil {
			return nil, missing("login profile", m.AccountID)
		}
		return &iamapi.GetLoginProfileOutput{LoginProfile: wireRootLoginProfile(a.settings.RootLoginProfile)}, nil
	}
	u, apiErr := loginUser(a, m, inputString(in.UserName))
	if apiErr != nil {
		return nil, apiErr
	}
	p := a.loginProfiles[u.UserId]
	if p == nil {
		return nil, missing("login profile", u.UserName)
	}
	return &iamapi.GetLoginProfileOutput{LoginProfile: wireLoginProfile(u, p)}, nil
}

func updateLoginProfile(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.UpdateLoginProfileInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, apiErr := loginUser(a, m, inputString(in.UserName))
	if apiErr != nil {
		return nil, apiErr
	}
	p := a.loginProfiles[u.UserId]
	if p == nil {
		return nil, missing("login profile", u.UserName)
	}
	if in.Password != nil {
		if apiErr := replacePassword(a.settings.PasswordPolicy, p, inputString(in.Password), a.currentTime); apiErr != nil {
			return nil, apiErr
		}
	}
	if in.PasswordResetRequired != nil {
		p.PasswordResetRequired = bool(*in.PasswordResetRequired)
	}
	return &iamapi.UpdateLoginProfileOutput{}, nil
}

func deleteLoginProfile(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeleteLoginProfileInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if m.SessionType == string(identity.SessionTypeAssumeRoot) && in.UserName == nil {
		if a.settings.RootLoginProfile == nil {
			return nil, missing("login profile", m.AccountID)
		}
		a.settings.RootLoginProfile = nil
		return &iamapi.DeleteLoginProfileOutput{}, nil
	}
	u, apiErr := loginUser(a, m, inputString(in.UserName))
	if apiErr != nil {
		return nil, apiErr
	}
	if a.loginProfiles[u.UserId] == nil {
		return nil, missing("login profile", u.UserName)
	}
	delete(a.loginProfiles, u.UserId)
	return &iamapi.DeleteLoginProfileOutput{}, nil
}

func changePassword(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ChangePasswordInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, apiErr := currentPasswordUser(a, m)
	if apiErr != nil {
		return nil, apiErr
	}
	p := a.loginProfiles[u.UserId]
	if p == nil {
		return nil, missing("login profile", u.UserName)
	}
	matched, err := matchesPassword(inputString(in.OldPassword), p.Password)
	if err != nil {
		return nil, passwordServiceFailure()
	}
	if !matched {
		return nil, &awswire.Error{Code: "AccessDenied", Message: "The old password is incorrect.", StatusCode: 403}
	}
	if inputString(in.NewPassword) == inputString(in.OldPassword) {
		return nil, &awswire.Error{Code: "AccessDenied", Message: "The new password must differ from the old password.", StatusCode: 403}
	}
	// HardExpiry applies to console password recovery. Signed API requests with
	// iam:ChangePassword permission can change an expired password.
	if apiErr := replacePassword(a.settings.PasswordPolicy, p, inputString(in.NewPassword), a.currentTime); apiErr != nil {
		return nil, apiErr
	}
	p.PasswordResetRequired = false
	return &iamapi.ChangePasswordOutput{}, nil
}

func wireLoginProfile(u *user, p *LoginProfileRecord) *iamapi.LoginProfile {
	return &iamapi.LoginProfile{UserName: wirePointer(iamapi.UserNameType(u.UserName)), CreateDate: wirePointer(p.CreateDate), PasswordResetRequired: wirePointer(iamapi.BooleanType(p.PasswordResetRequired))}
}

func wireRootLoginProfile(p *RootLoginProfileRecord) *iamapi.LoginProfile {
	return &iamapi.LoginProfile{CreateDate: wirePointer(p.CreateDate), PasswordResetRequired: wirePointer(iamapi.BooleanType(false))}
}

func loginBool[T ~bool](v *T) bool { return v != nil && bool(*v) }

func passwordServiceFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceFailure", Message: "Unable to process the IAM password record.", StatusCode: 500}
}
