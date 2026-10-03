package cognitoidp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awswire"
	"strings"
	"time"
)

// EmailSender accepts durable mail in the caller's shared transaction. It must
// not perform external delivery before commit. Failure rolls back the user/code.
type EmailSender interface {
	QueueEmail(context.Context, EmailMessage) error
}
type EmailMessage struct {
	Pool              PoolKey
	Configuration     EmailConfiguration
	To, Subject, Text string
}
type EmailConfiguration struct{ SendingAccount, SourceARN, From, ReplyTo, ConfigurationSet string }
type EmailSetup interface {
	PrepareEmail(context.Context, PoolKey, EmailConfiguration) error
}

func poolEmailConfiguration(p PoolRecord) EmailConfiguration {
	c := p.Data.EmailConfiguration
	if c == nil {
		return EmailConfiguration{SendingAccount: "COGNITO_DEFAULT"}
	}
	return EmailConfiguration{SendingAccount: value(c.EmailSendingAccount), SourceARN: value(c.SourceArn), From: value(c.From), ReplyTo: value(c.ReplyToEmailAddress), ConfigurationSet: value(c.ConfigurationSet)}
}
func (s *Service) prepareEmail(tx Transaction, p PoolRecord) error {
	c := poolEmailConfiguration(p)
	if c.SendingAccount != "DEVELOPER" {
		return nil
	}
	if s.emailSetup == nil {
		return failure("InvalidEmailRoleAccessPolicyException", "Developer email authority is not configured.")
	}
	return s.emailSetup.PrepareEmail(tx.Context(), p.Key, c)
}
func registerEmail(s *Service) {
	register(s, "ConfirmSignUp", s.confirmSignUp)
	register(s, "ResendConfirmationCode", s.resendConfirmationCode)
	register(s, "ForgotPassword", s.forgotPassword)
	register(s, "ConfirmForgotPassword", s.confirmForgotPassword)
	register(s, "GetUserAttributeVerificationCode", s.getAttributeCode)
	register(s, "VerifyUserAttribute", s.verifyAttribute)
	register(s, "AdminResetUserPassword", s.adminResetPassword)
}
func emailCodeKey(user UserRecord, kind string) EmailCodeKey {
	return EmailCodeKey{UserKey: user.Key, Kind: kind}
}
func (s *Service) issueEmailCode(tx Transaction, pool PoolRecord, user UserRecord, kind string) (*api.CodeDeliveryDetailsType, error) {
	destination := userAttribute(user, "email")
	if destination == "" {
		return nil, failure("InvalidParameterException", "User has no email address.")
	}
	if s.emailSender == nil {
		return nil, failure("CodeDeliveryFailureException", "Email delivery is not configured.")
	}
	number, e := rand.Int(rand.Reader, big.NewInt(1000000))
	if e != nil {
		return nil, e
	}
	code := fmt.Sprintf("%06d", number.Int64())
	digest := sha256.Sum256([]byte(destination + "\x00" + code))
	duration := 24 * time.Hour
	if kind == "RESET_PASSWORD" {
		duration = time.Hour
	}
	challenge := EmailCodeRecord{Key: emailCodeKey(user, kind), Expires: s.clock.Now().Add(duration), Digest: digest[:]}
	if e = tx.PutEmailCode(challenge); e != nil {
		return nil, e
	}
	subject := "Your verification code"
	if kind == "RESET_PASSWORD" {
		subject = "Your password reset code"
	}
	if e = s.emailSender.QueueEmail(tx.Context(), EmailMessage{Pool: pool.Key, Configuration: poolEmailConfiguration(pool), To: destination, Subject: subject, Text: "Your confirmation code is " + code + ".\n"}); e != nil {
		return nil, failure("CodeDeliveryFailureException", "Unable to accept verification email.")
	}
	local, domain, _ := strings.Cut(destination, "@")
	masked := "***@" + domain
	if local != "" {
		masked = local[:1] + masked
	}
	return &api.CodeDeliveryDetailsType{AttributeName: new(api.AttributeNameType("email")), DeliveryMedium: new(api.DeliveryMediumType("EMAIL")), Destination: new(api.StringType(masked))}, nil
}

var errPrivateEmailUser = errors.New("cognito private email response")

func (s *Service) emailUser(tx Transaction, action, clientID, username, secret string) (PoolRecord, ClientRecord, UserRecord, error) {
	p, c, e := s.authClient(tx, action, "", clientID)
	if e != nil {
		return p, c, UserRecord{}, e
	}
	if e = checkSecretHash(c, username, secret); e != nil {
		return p, c, UserRecord{}, e
	}
	u, e := resolveUser(tx, p, username)
	var wire *awswire.Error
	missing := errors.As(e, &wire) && wire.Code == "UserNotFoundException"
	disabled := e == nil && u.Data.Enabled != nil && !bool(*u.Data.Enabled)
	if value(c.Data.PreventUserExistenceErrors) == "ENABLED" && (missing || disabled) {
		switch action {
		case "ForgotPassword", "ResendConfirmationCode":
			return p, c, u, errPrivateEmailUser
		case "ConfirmForgotPassword":
			return p, c, u, failure("CodeMismatchException", "Invalid verification code provided, please try again.")
		case "ConfirmSignUp":
			return p, c, u, failure("NotAuthorizedException", "User cannot be confirmed.")
		}
	}
	if e == nil {
		noteUser(tx.Context(), u)
		if disabled {
			e = failure("NotAuthorizedException", "User is disabled.")
		}
	}
	return p, c, u, e
}

// AWS deliberately returns simulated delivery details for suppressed nonexistent
// users. No code, user or mail is accepted on this privacy-only response.
func privateEmailDetails(username string) *api.CodeDeliveryDetailsType {
	destination := "***"
	if local, domain, ok := strings.Cut(username, "@"); ok && local != "" && domain != "" {
		destination = local[:1] + "***@" + domain[:1] + "***"
	}
	return &api.CodeDeliveryDetailsType{AttributeName: new(api.AttributeNameType("email")), DeliveryMedium: new(api.DeliveryMediumType("EMAIL")), Destination: new(api.StringType(destination))}
}
func (s *Service) checkEmailCode(tx Transaction, pool PoolRecord, user UserRecord, kind, code string) error {
	challenge, e := tx.EmailCode(emailCodeKey(user, kind))
	if errors.Is(e, ErrNotFound) {
		return failure("ExpiredCodeException", "Invalid code provided, please request a code again.")
	}
	if e != nil {
		return e
	}
	if !s.clock.Now().Before(challenge.Expires) {
		return failure("ExpiredCodeException", "Invalid code provided, please request a code again.")
	}
	digest := sha256.Sum256([]byte(userAttribute(user, "email") + "\x00" + code))
	if subtle.ConstantTimeCompare(digest[:], challenge.Digest) != 1 {
		return failure("CodeMismatchException", "Invalid verification code provided, please try again.")
	}
	return tx.DeleteEmailCode(challenge.Key)
}
func (s *Service) confirmSignUp(tx Transaction, in *api.ConfirmSignUpInput) (*api.ConfirmSignUpOutput, error) {
	p, _, u, e := s.emailUser(tx, "ConfirmSignUp", value(in.ClientId), value(in.Username), value(in.SecretHash))
	if e != nil {
		return nil, e
	}
	if value(u.Data.UserStatus) != "UNCONFIRMED" {
		return nil, failure("NotAuthorizedException", "User cannot be confirmed. Current status is "+value(u.Data.UserStatus))
	}
	if e = s.checkEmailCode(tx, p, u, "SIGN_UP", value(in.ConfirmationCode)); e != nil {
		return nil, e
	}
	putUserAttribute(&u, "email_verified", "true")
	if e = ensureUserAliases(tx, p, &u, in.ForceAliasCreation != nil && bool(*in.ForceAliasCreation)); e != nil {
		return nil, e
	}
	u.Data.UserStatus = new(api.UserStatusType("CONFIRMED"))
	u.Data.UserLastModifiedDate = new(s.clock.Now())
	return &api.ConfirmSignUpOutput{}, tx.PutUser(u)
}
func (s *Service) resendConfirmationCode(tx Transaction, in *api.ResendConfirmationCodeInput) (*api.ResendConfirmationCodeOutput, error) {
	p, _, u, e := s.emailUser(tx, "ResendConfirmationCode", value(in.ClientId), value(in.Username), value(in.SecretHash))
	if errors.Is(e, errPrivateEmailUser) {
		return &api.ResendConfirmationCodeOutput{CodeDeliveryDetails: privateEmailDetails(value(in.Username))}, nil
	}
	if e != nil {
		return nil, e
	}
	if value(u.Data.UserStatus) != "UNCONFIRMED" {
		return nil, failure("InvalidParameterException", "User is already confirmed.")
	}
	details, e := s.issueEmailCode(tx, p, u, "SIGN_UP")
	return &api.ResendConfirmationCodeOutput{CodeDeliveryDetails: details}, e
}
func recoveryMethod(p PoolRecord, u UserRecord) string {
	email := userAttribute(u, "email_verified") == "true" && userAttribute(u, "email") != ""
	phone := userAttribute(u, "phone_number_verified") == "true" && userAttribute(u, "phone_number") != ""
	if p.Data.AccountRecoverySetting == nil {
		if phone {
			return "verified_phone_number"
		}
		if email {
			return "verified_email"
		}
		return ""
	}
	selected := ""
	priority := 3
	for _, r := range p.Data.AccountRecoverySetting.RecoveryMechanisms {
		name := value(r.Name)
		if (name == "verified_email" && email || name == "verified_phone_number" && phone) && r.Priority != nil && int(*r.Priority) < priority {
			selected = name
			priority = int(*r.Priority)
		}
	}
	// TODO: Comeback — implement SMS delivery before using a selected phone
	// recovery channel. Never silently substitute lower-priority email.
	return selected
}
func (s *Service) forgotPassword(tx Transaction, in *api.ForgotPasswordInput) (*api.ForgotPasswordOutput, error) {
	p, c, u, e := s.emailUser(tx, "ForgotPassword", value(in.ClientId), value(in.Username), value(in.SecretHash))
	if errors.Is(e, errPrivateEmailUser) {
		return &api.ForgotPasswordOutput{CodeDeliveryDetails: privateEmailDetails(value(in.Username))}, nil
	}
	if e != nil {
		return nil, e
	}
	method := recoveryMethod(p, u)
	if method == "verified_phone_number" {
		return nil, failure("InvalidParameterException", "SMS password recovery is not supported.")
	}
	if method != "verified_email" {
		if value(c.Data.PreventUserExistenceErrors) == "ENABLED" {
			return &api.ForgotPasswordOutput{CodeDeliveryDetails: privateEmailDetails(value(in.Username))}, nil
		}
		return nil, failure("InvalidParameterException", "No supported verified email recovery channel is available.")
	}
	if value(u.Data.UserStatus) == "UNCONFIRMED" {
		return nil, failure("UserNotConfirmedException", "User is not confirmed.")
	}
	details, e := s.issueEmailCode(tx, p, u, "RESET_PASSWORD")
	return &api.ForgotPasswordOutput{CodeDeliveryDetails: details}, e
}
func (s *Service) confirmForgotPassword(tx Transaction, in *api.ConfirmForgotPasswordInput) (*api.ConfirmForgotPasswordOutput, error) {
	p, _, u, e := s.emailUser(tx, "ConfirmForgotPassword", value(in.ClientId), value(in.Username), value(in.SecretHash))
	if e != nil {
		return nil, e
	}
	if e = s.checkEmailCode(tx, p, u, "RESET_PASSWORD", value(in.ConfirmationCode)); e != nil {
		return nil, e
	}
	password := value(in.Password)
	if e = validatePassword(p, password); e != nil {
		return nil, e
	}
	u.Password, e = makePasswordVerifier(p.Key, u.Key.Username, password)
	if e != nil {
		return nil, e
	}
	u.PasswordExpires = nil
	u.Data.UserStatus = new(api.UserStatusType("CONFIRMED"))
	u.Data.UserLastModifiedDate = new(s.clock.Now())
	if e = tx.RevokeUserSessions(u.Key); e != nil {
		return nil, e
	}
	return &api.ConfirmForgotPasswordOutput{}, tx.PutUser(u)
}
func (s *Service) getAttributeCode(tx Transaction, in *api.GetUserAttributeVerificationCodeInput) (*api.GetUserAttributeVerificationCodeOutput, error) {
	p, _, u, _, e := s.accessUser(tx, value(in.AccessToken))
	if e != nil {
		return nil, e
	}
	if value(in.AttributeName) != "email" {
		return nil, failure("InvalidParameterException", "Only email verification delivery is implemented.")
	}
	details, e := s.issueEmailCode(tx, p, u, "VERIFY_EMAIL")
	return &api.GetUserAttributeVerificationCodeOutput{CodeDeliveryDetails: details}, e
}
func (s *Service) verifyAttribute(tx Transaction, in *api.VerifyUserAttributeInput) (*api.VerifyUserAttributeOutput, error) {
	p, _, u, _, e := s.accessUser(tx, value(in.AccessToken))
	if e != nil {
		return nil, e
	}
	if value(in.AttributeName) != "email" {
		return nil, failure("InvalidParameterException", "Only email verification delivery is implemented.")
	}
	if e = s.checkEmailCode(tx, p, u, "VERIFY_EMAIL", value(in.Code)); e != nil {
		return nil, e
	}
	putUserAttribute(&u, "email_verified", "true")
	if e = ensureUserAliases(tx, p, &u, false); e != nil {
		return nil, e
	}
	u.Data.UserLastModifiedDate = new(s.clock.Now())
	return &api.VerifyUserAttributeOutput{}, tx.PutUser(u)
}
func (s *Service) adminResetPassword(tx Transaction, in *api.AdminResetUserPasswordInput) (*api.AdminResetUserPasswordOutput, error) {
	p, e := s.adminPool(tx, "AdminResetUserPassword", value(in.UserPoolId))
	if e != nil {
		return nil, e
	}
	u, e := resolveUser(tx, p, value(in.Username))
	if e != nil {
		return nil, e
	}
	method := recoveryMethod(p, u)
	if method == "verified_phone_number" {
		return nil, failure("InvalidParameterException", "SMS password recovery is not supported.")
	}
	if method != "verified_email" {
		return nil, failure("InvalidParameterException", "User has no verified email for recovery.")
	}
	if _, e = s.issueEmailCode(tx, p, u, "RESET_PASSWORD"); e != nil {
		return nil, e
	}
	u.Data.UserStatus = new(api.UserStatusType("RESET_REQUIRED"))
	u.Data.UserLastModifiedDate = new(s.clock.Now())
	if e = tx.RevokeUserSessions(u.Key); e != nil {
		return nil, e
	}
	return &api.AdminResetUserPasswordOutput{}, tx.PutUser(u)
}

// WithEmailRoleUsage keeps all-region pool dependencies and IAM deletion atomic.
func (s *Service) WithEmailRoleUsage(ctx context.Context, partition, accountID string, fn func(context.Context, []PoolKey) error) error {
	return s.repository.Update(ctx, func(r Transaction) error {
		pools, e := r.PoolsForAccount(partition, accountID)
		if e != nil {
			return e
		}
		keys := []PoolKey{}
		for _, p := range pools {
			if poolEmailConfiguration(p).SendingAccount == "DEVELOPER" {
				keys = append(keys, p.Key)
			}
		}
		return fn(r.Context(), keys)
	})
}
