package cognitoidp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awsctx"
)

// Cognito software tokens use RFC 6238 SHA-1, six digits and a 30-second step.
func softwareTokenCode(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", err
	}
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(step[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	number := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", number%1000000), nil
}

func validateSoftwareCode(secret, code string, now time.Time, last int64) (int64, error) {
	if len(code) != 6 {
		return 0, failure("CodeMismatchException", "Invalid software token code.")
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return 0, failure("CodeMismatchException", "Invalid software token code.")
		}
	}
	current := now.Unix() / 30
	for _, counter := range []int64{current, current - 1, current + 1} {
		expected, err := softwareTokenCode(secret, counter)
		if err != nil {
			return 0, err
		}
		if hmac.Equal([]byte(code), []byte(expected)) && counter > last {
			return counter, nil
		}
	}
	return 0, failure("CodeMismatchException", "Invalid software token code or code already used.")
}

func newSoftwareSecret() (string, error) {
	var secret [20]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret[:]), nil
}

func mfaPreferences(user UserRecord) (*api.StringType, api.UserMFASettingListType) {
	settings := api.UserMFASettingListType{}
	var preferred *api.StringType
	if user.SoftwareTokenEnabled {
		settings = append(settings, api.StringType("SOFTWARE_TOKEN_MFA"))
		if user.SoftwareTokenPreferred {
			preferred = str[api.StringType]("SOFTWARE_TOKEN_MFA")
		}
	}
	return preferred, settings
}

func (s *Service) getUserPoolMfaConfig(tx Transaction, in *api.GetUserPoolMfaConfigInput) (*api.GetUserPoolMfaConfigOutput, error) {
	pool, err := s.adminPool(tx, "GetUserPoolMfaConfig", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	return &api.GetUserPoolMfaConfigOutput{MfaConfiguration: pool.Data.MfaConfiguration, SoftwareTokenMfaConfiguration: &api.SoftwareTokenMfaConfigType{Enabled: ptr(api.BooleanType(pool.SoftwareTokenMFAEnabled))}}, nil
}

func (s *Service) setUserPoolMfaConfig(tx Transaction, in *api.SetUserPoolMfaConfigInput) (*api.SetUserPoolMfaConfigOutput, error) {
	pool, err := s.adminPool(tx, "SetUserPoolMfaConfig", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	if in.EmailMfaConfiguration != nil || in.SmsMfaConfiguration != nil || in.WebAuthnConfiguration != nil {
		return nil, failure("InvalidParameterException", "Only software token MFA is supported.")
	}
	mode := value(in.MfaConfiguration)
	if mode != "" && mode != "OFF" && mode != "OPTIONAL" && mode != "ON" {
		return nil, failure("InvalidParameterException", "Invalid MFA configuration.")
	}
	enabled := pool.SoftwareTokenMFAEnabled
	if in.SoftwareTokenMfaConfiguration != nil && in.SoftwareTokenMfaConfiguration.Enabled != nil {
		enabled = bool(*in.SoftwareTokenMfaConfiguration.Enabled)
	}
	if mode == "" {
		mode = value(pool.Data.MfaConfiguration)
	}
	if mode == "ON" && !enabled {
		return nil, failure("InvalidParameterException", "MFA ON requires an enabled MFA factor.")
	}
	pool.SoftwareTokenMFAEnabled = enabled
	pool.Data.MfaConfiguration = str[api.UserPoolMfaType](mode)
	pool.Data.LastModifiedDate = ptr(s.clock.Now().UTC())
	if err := tx.PutPool(pool); err != nil {
		return nil, err
	}
	return &api.SetUserPoolMfaConfigOutput{MfaConfiguration: pool.Data.MfaConfiguration, SoftwareTokenMfaConfiguration: &api.SoftwareTokenMfaConfigType{Enabled: ptr(api.BooleanType(enabled))}}, nil
}

func (s *Service) mfaAfterPassword(tx Transaction, pool PoolRecord, client ClientRecord, user UserRecord) (*api.InitiateAuthOutput, error) {
	mode := value(pool.Data.MfaConfiguration)
	if mode == "OFF" || mode == "" {
		return nil, nil
	}
	if !pool.SoftwareTokenMFAEnabled {
		if mode == "ON" {
			return nil, failure("InvalidParameterException", "No supported MFA factor is enabled for this pool.")
		}
		return nil, nil
	}
	kind := "SOFTWARE_TOKEN_MFA"
	if !user.SoftwareTokenEnabled || user.SoftwareTokenSecret == "" {
		if mode != "ON" {
			return nil, nil
		}
		kind = "MFA_SETUP"
	}
	token, err := randomToken(64)
	if err != nil {
		return nil, err
	}
	token = pool.Key.ID + "." + token
	credential := sha256.Sum256(user.Password.Verifier)
	challenge := ChallengeRecord{Key: ChallengeKey{PoolKey: pool.Key, Token: token}, ClientID: client.Key.ID, Username: user.Key.Username, Kind: kind, Expires: s.clock.Now().Add(challengeDuration(client)), SRPPrivate: credential[:]}
	if err := tx.PutChallenge(challenge); err != nil {
		return nil, err
	}
	params := api.ChallengeParametersType{"USER_ID_FOR_SRP": api.StringType(user.Key.Username)}
	if kind == "MFA_SETUP" {
		params["MFAS_CAN_SETUP"] = api.StringType(`["SOFTWARE_TOKEN_MFA"]`)
	}
	return &api.InitiateAuthOutput{ChallengeName: str[api.ChallengeNameType](kind), Session: str[api.SessionType](token), ChallengeParameters: params}, nil
}

func (s *Service) softwareTokenAuthority(tx Transaction, access, token string) (PoolRecord, UserRecord, *ChallengeRecord, error) {
	if (access == "") == (token == "") {
		return PoolRecord{}, UserRecord{}, nil, failure("InvalidParameterException", "Specify exactly one of AccessToken or Session.")
	}
	if access != "" {
		pool, _, user, _, err := s.accessUser(tx, access)
		return pool, user, nil, err
	}
	id, _, ok := strings.Cut(token, ".")
	if !ok {
		return PoolRecord{}, UserRecord{}, nil, failure("NotAuthorizedException", "Invalid session for the user.")
	}
	metadata := awsctx.FromContext(tx.Context())
	pool, err := tx.PoolByID(metadata.Partition, publicPoolRegion(tx.Context(), id), id)
	if errors.Is(err, ErrNotFound) {
		return PoolRecord{}, UserRecord{}, nil, failure("NotAuthorizedException", "Invalid session for the user.")
	}
	if err != nil {
		return PoolRecord{}, UserRecord{}, nil, err
	}
	notePool(tx.Context(), pool.Key)
	challenge, err := tx.Challenge(ChallengeKey{PoolKey: pool.Key, Token: token})
	if errors.Is(err, ErrNotFound) {
		return PoolRecord{}, UserRecord{}, nil, failure("NotAuthorizedException", "Invalid or expired session for the user.")
	}
	if err != nil {
		return PoolRecord{}, UserRecord{}, nil, err
	}
	if challenge.Kind != "MFA_SETUP" || !s.clock.Now().Before(challenge.Expires) {
		return PoolRecord{}, UserRecord{}, nil, failure("NotAuthorizedException", "Invalid or expired session for the user.")
	}
	user, err := tx.User(UserKey{PoolKey: pool.Key, Username: challenge.Username})
	if err != nil {
		return PoolRecord{}, UserRecord{}, nil, err
	}
	noteUser(tx.Context(), user)
	if err := s.authUserStatus(user); err != nil {
		return PoolRecord{}, UserRecord{}, nil, err
	}
	credential := sha256.Sum256(user.Password.Verifier)
	if !hmac.Equal(credential[:], challenge.SRPPrivate) {
		return PoolRecord{}, UserRecord{}, nil, failure("NotAuthorizedException", "Invalid session for the user.")
	}
	return pool, user, &challenge, nil
}

func softwareTokenAvailable(pool PoolRecord) error {
	if !pool.SoftwareTokenMFAEnabled {
		return failure("SoftwareTokenMFANotFoundException", "Software token MFA is not enabled for this user pool.")
	}
	return nil
}

func (s *Service) rotateSetupSession(tx Transaction, challenge *ChallengeRecord) error {
	token, err := randomToken(64)
	if err != nil {
		return err
	}
	if err := tx.DeleteChallenge(challenge.Key); err != nil {
		return err
	}
	challenge.Key.Token = challenge.Key.PoolKey.ID + "." + token
	return tx.PutChallenge(*challenge)
}

func (s *Service) associateSoftwareToken(tx Transaction, in *api.AssociateSoftwareTokenInput) (*api.AssociateSoftwareTokenOutput, error) {
	pool, user, challenge, err := s.softwareTokenAuthority(tx, value(in.AccessToken), value(in.Session))
	if err != nil {
		return nil, err
	}
	if err := softwareTokenAvailable(pool); err != nil {
		return nil, err
	}
	secret, err := newSoftwareSecret()
	if err != nil {
		return nil, err
	}
	out := &api.AssociateSoftwareTokenOutput{SecretCode: str[api.SecretCodeType](secret)}
	if challenge != nil {
		challenge.SoftwareTokenSecret, challenge.SoftwareTokenVerified = secret, false
		if err := s.rotateSetupSession(tx, challenge); err != nil {
			return nil, err
		}
		out.Session = str[api.SessionType](challenge.Key.Token)
	} else {
		user.SoftwareTokenPendingSecret = secret
		user.SoftwareTokenPendingExpires = s.clock.Now().Add(15 * time.Minute)
		if err := tx.PutUser(user); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) verifySoftwareToken(tx Transaction, in *api.VerifySoftwareTokenInput) (*api.VerifySoftwareTokenOutput, error) {
	pool, user, challenge, err := s.softwareTokenAuthority(tx, value(in.AccessToken), value(in.Session))
	if err != nil {
		return nil, err
	}
	if err := softwareTokenAvailable(pool); err != nil {
		return nil, err
	}
	secret := user.SoftwareTokenPendingSecret
	if challenge != nil {
		if challenge.SoftwareTokenVerified {
			return nil, failure("NotAuthorizedException", "Session has already verified a software token.")
		}
		secret = challenge.SoftwareTokenSecret
	} else if !s.clock.Now().Before(user.SoftwareTokenPendingExpires) {
		return nil, failure("NotAuthorizedException", "Software token association has expired.")
	}
	if secret == "" {
		return nil, failure("InvalidParameterException", "Associate a software token before verification.")
	}
	counter, err := validateSoftwareCode(secret, value(in.UserCode), s.clock.Now(), -1)
	if err != nil {
		return nil, err
	}
	user.SoftwareTokenSecret, user.SoftwareTokenLastCounter = secret, counter
	user.SoftwareTokenPendingSecret = ""
	user.SoftwareTokenPendingExpires = time.Time{}
	user.SoftwareTokenEnabled = true
	user.SoftwareTokenDeviceName = value(in.FriendlyDeviceName)
	user.Data.UserLastModifiedDate = ptr(s.clock.Now().UTC())
	if err := tx.PutUser(user); err != nil {
		return nil, err
	}
	out := &api.VerifySoftwareTokenOutput{Status: str[api.VerifySoftwareTokenResponseType]("SUCCESS")}
	if challenge != nil {
		challenge.SoftwareTokenVerified = true
		if err := s.rotateSetupSession(tx, challenge); err != nil {
			return nil, err
		}
		out.Session = str[api.SessionType](challenge.Key.Token)
	}
	return out, nil
}

func setSoftwarePreference(pool PoolRecord, user *UserRecord, settings *api.SoftwareTokenMfaSettingsType) error {
	if settings == nil {
		return nil
	}
	if err := softwareTokenAvailable(pool); err != nil {
		return err
	}
	enabled, preferred := user.SoftwareTokenEnabled, user.SoftwareTokenPreferred
	if settings.Enabled != nil {
		enabled = bool(*settings.Enabled)
	}
	if settings.PreferredMfa != nil {
		preferred = bool(*settings.PreferredMfa)
	}
	if !enabled && settings.PreferredMfa == nil {
		preferred = false
	}
	if preferred && !enabled {
		return failure("InvalidParameterException", "Preferred MFA must be enabled.")
	}
	if enabled && user.SoftwareTokenSecret == "" {
		return failure("InvalidParameterException", "User does not have a verified software token.")
	}
	user.SoftwareTokenEnabled, user.SoftwareTokenPreferred = enabled, preferred
	return nil
}

func (s *Service) setUserMFAPreference(tx Transaction, in *api.SetUserMFAPreferenceInput) (*api.SetUserMFAPreferenceOutput, error) {
	pool, _, user, _, err := s.accessUser(tx, value(in.AccessToken))
	if err != nil {
		return nil, err
	}
	if in.EmailMfaSettings != nil || in.SMSMfaSettings != nil || in.WebAuthnMfaSettings != nil {
		return nil, failure("InvalidParameterException", "Only software token MFA is supported.")
	}
	if err := setSoftwarePreference(pool, &user, in.SoftwareTokenMfaSettings); err != nil {
		return nil, err
	}
	if err := tx.PutUser(user); err != nil {
		return nil, err
	}
	return &api.SetUserMFAPreferenceOutput{}, nil
}

func (s *Service) adminSetUserMFAPreference(tx Transaction, in *api.AdminSetUserMFAPreferenceInput) (*api.AdminSetUserMFAPreferenceOutput, error) {
	pool, err := s.adminPool(tx, "AdminSetUserMFAPreference", value(in.UserPoolId))
	if err != nil {
		return nil, err
	}
	user, err := resolveUser(tx, pool, value(in.Username))
	if err != nil {
		return nil, err
	}
	noteUser(tx.Context(), user)
	if in.EmailMfaSettings != nil || in.SMSMfaSettings != nil || in.WebAuthnMfaSettings != nil {
		return nil, failure("InvalidParameterException", "Only software token MFA is supported.")
	}
	if err := setSoftwarePreference(pool, &user, in.SoftwareTokenMfaSettings); err != nil {
		return nil, err
	}
	if err := tx.PutUser(user); err != nil {
		return nil, err
	}
	return &api.AdminSetUserMFAPreferenceOutput{}, nil
}

func (s *Service) completeMFA(tx Transaction, pool PoolRecord, client ClientRecord, user UserRecord, challenge ChallengeRecord, responses api.ChallengeResponsesType) (*api.InitiateAuthOutput, error) {
	credential := sha256.Sum256(user.Password.Verifier)
	if !hmac.Equal(credential[:], challenge.SRPPrivate) {
		return nil, failure("NotAuthorizedException", "Invalid session for the user.")
	}
	if err := softwareTokenAvailable(pool); err != nil {
		return nil, err
	}
	if challenge.Kind == "MFA_SETUP" {
		if !challenge.SoftwareTokenVerified || challenge.SoftwareTokenSecret != user.SoftwareTokenSecret {
			return nil, failure("NotAuthorizedException", "Software token setup is not verified.")
		}
	} else {
		if !user.SoftwareTokenEnabled || user.SoftwareTokenSecret == "" {
			return nil, failure("NotAuthorizedException", "Software token MFA is not enabled for this user.")
		}
		counter, err := validateSoftwareCode(user.SoftwareTokenSecret, string(responses["SOFTWARE_TOKEN_MFA_CODE"]), s.clock.Now(), user.SoftwareTokenLastCounter)
		if err != nil {
			return nil, err
		}
		user.SoftwareTokenLastCounter = counter
		if err := tx.PutUser(user); err != nil {
			return nil, err
		}
	}
	if err := tx.DeleteChallenge(challenge.Key); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	result, err := s.newSession(tx, pool, client, user)
	if err != nil {
		return nil, err
	}
	return &api.InitiateAuthOutput{AuthenticationResult: result, ChallengeParameters: api.ChallengeParametersType{}}, nil
}

type softwareTokenPoolIntentKey struct{}

// WithSoftwareTokenMFAConfiguration supplies the CloudFormation-owned factor
// setting, which the pool owner commits atomically with creation or update.
func WithSoftwareTokenMFAConfiguration(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, softwareTokenPoolIntentKey{}, enabled)
}

func applySoftwareTokenPoolIntent(ctx context.Context, pool *PoolRecord) error {
	if enabled, ok := ctx.Value(softwareTokenPoolIntentKey{}).(bool); ok {
		if value(pool.Data.MfaConfiguration) == "ON" && !enabled {
			return failure("InvalidParameterException", "MFA ON requires an enabled MFA factor.")
		}
		pool.SoftwareTokenMFAEnabled = enabled
	}
	return nil
}
