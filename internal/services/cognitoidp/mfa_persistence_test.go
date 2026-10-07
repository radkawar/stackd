package cognitoidp_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/cognitoidp"
	"stackd/storage/sqlite"
	sqlcognito "stackd/storage/sqlite/cognitoidp"
)

func fixtureTOTP(secret string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(step[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func TestSoftwareTokenMemoryAndSQLiteRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repository service.Repository = service.NewMemoryRepository(nil)
			restart := func() {}
			if backend == "sqlite" {
				path := filepath.Join(t.TempDir(), "cognito.sqlite")
				db, err := sqlite.Open(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				repository = sqlcognito.New(db)
				restart = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repository = sqlcognito.New(db)
				}
			}
			c := clock.NewManual(time.Unix(1800000000, 0))
			s := service.New(service.Config{Repository: repository, Clock: c})
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
			model, _ := awscatalog.LookupService("cognitoidp")
			call := func(action string, input any) (any, *awswire.Error) {
				op, _ := model.Operation(action)
				return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
			}
			must := func(action string, input any) any {
				out, err := call(action, input)
				if err != nil {
					t.Fatalf("%s: %v", action, err)
				}
				return out
			}
			pool := must("CreateUserPool", &api.CreateUserPoolInput{PoolName: new(api.UserPoolNameType("totp")), MfaConfiguration: new(api.UserPoolMfaType("OPTIONAL"))}).(*api.CreateUserPoolOutput).UserPool
			must("SetUserPoolMfaConfig", &api.SetUserPoolMfaConfigInput{UserPoolId: pool.Id, SoftwareTokenMfaConfiguration: &api.SoftwareTokenMfaConfigType{Enabled: new(api.BooleanType(true))}})
			client := must("CreateUserPoolClient", &api.CreateUserPoolClientInput{UserPoolId: pool.Id, ClientName: new(api.ClientNameType("client")), ExplicitAuthFlows: api.ExplicitAuthFlowsListType{"ALLOW_USER_PASSWORD_AUTH"}}).(*api.CreateUserPoolClientOutput).UserPoolClient
			client2 := must("CreateUserPoolClient", &api.CreateUserPoolClientInput{UserPoolId: pool.Id, ClientName: new(api.ClientNameType("other")), ExplicitAuthFlows: api.ExplicitAuthFlowsListType{"ALLOW_USER_PASSWORD_AUTH"}}).(*api.CreateUserPoolClientOutput).UserPoolClient
			create := func(name string) {
				must("AdminCreateUser", &api.AdminCreateUserInput{UserPoolId: pool.Id, Username: new(api.UsernameType(name)), TemporaryPassword: new(api.PasswordType("Password123!")), MessageAction: new(api.MessageActionType("SUPPRESS"))})
				must("AdminSetUserPassword", &api.AdminSetUserPasswordInput{UserPoolId: pool.Id, Username: new(api.UsernameType(name)), Password: new(api.PasswordType("Password123!")), Permanent: new(api.BooleanType(true))})
			}
			create("alice")
			login := func(name string) *api.InitiateAuthOutput {
				return must("InitiateAuth", &api.InitiateAuthInput{ClientId: client.ClientId, AuthFlow: new(api.AuthFlowType("USER_PASSWORD_AUTH")), AuthParameters: api.AuthParametersType{"USERNAME": api.StringType(name), "PASSWORD": "Password123!"}}).(*api.InitiateAuthOutput)
			}
			initial := login("alice")
			if initial.AuthenticationResult == nil {
				t.Fatal("OPTIONAL unenrolled user challenged")
			}
			access := initial.AuthenticationResult.AccessToken
			association := must("AssociateSoftwareToken", &api.AssociateSoftwareTokenInput{AccessToken: access}).(*api.AssociateSoftwareTokenOutput)
			secret := string(*association.SecretCode)
			if _, err := call("SetUserMFAPreference", &api.SetUserMFAPreferenceInput{AccessToken: access, SoftwareTokenMfaSettings: &api.SoftwareTokenMfaSettingsType{Enabled: new(api.BooleanType(true))}}); err == nil {
				t.Fatal("unverified factor activated")
			}
			if _, err := call("VerifySoftwareToken", &api.VerifySoftwareTokenInput{AccessToken: access, UserCode: new(api.SoftwareTokenMFAUserCodeType("abcdef"))}); err == nil {
				t.Fatal("invalid code accepted")
			}
			must("VerifySoftwareToken", &api.VerifySoftwareTokenInput{AccessToken: access, UserCode: new(api.SoftwareTokenMFAUserCodeType(fixtureTOTP(secret, c.Now())))})
			must("SetUserMFAPreference", &api.SetUserMFAPreferenceInput{AccessToken: access, SoftwareTokenMfaSettings: &api.SoftwareTokenMfaSettingsType{Enabled: new(api.BooleanType(true)), PreferredMfa: new(api.BooleanType(true))}})
			restart()
			s = service.New(service.Config{Repository: repository, Clock: c})
			user := must("GetUser", &api.GetUserInput{AccessToken: access}).(*api.GetUserOutput)
			if user.PreferredMfaSetting == nil || string(*user.PreferredMfaSetting) != "SOFTWARE_TOKEN_MFA" {
				t.Fatal("preference lost on restart")
			}
			challenge := login("alice")
			if challenge.ChallengeName == nil || string(*challenge.ChallengeName) != "SOFTWARE_TOKEN_MFA" {
				t.Fatal("enrolled user bypassed MFA")
			}
			respond := func(session *api.SessionType, clientID *api.ClientIdType, code string) (any, *awswire.Error) {
				return call("RespondToAuthChallenge", &api.RespondToAuthChallengeInput{ClientId: clientID, Session: session, ChallengeName: new(api.ChallengeNameType("SOFTWARE_TOKEN_MFA")), ChallengeResponses: api.ChallengeResponsesType{"USERNAME": "alice", "SOFTWARE_TOKEN_MFA_CODE": api.StringType(code)}})
			}
			if _, err := respond(challenge.Session, client.ClientId, fixtureTOTP(secret, c.Now())); err == nil {
				t.Fatal("enrollment code replayed for authentication")
			}
			if err := c.Advance(30 * time.Second); err != nil {
				t.Fatal(err)
			}
			code := fixtureTOTP(secret, c.Now())
			if _, err := respond(challenge.Session, client2.ClientId, code); err == nil {
				t.Fatal("cross-client session accepted")
			}
			if _, err := respond(challenge.Session, client.ClientId, "abcdef"); err == nil {
				t.Fatal("wrong code accepted")
			}
			out, err := respond(challenge.Session, client.ClientId, code)
			if err != nil || out.(*api.RespondToAuthChallengeOutput).AuthenticationResult == nil {
				t.Fatalf("MFA completion: %v", err)
			}
			if _, err := respond(challenge.Session, client.ClientId, code); err == nil {
				t.Fatal("consumed session reused")
			}
			expired := login("alice")
			if err := c.Advance(4 * time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := respond(expired.Session, client.ClientId, fixtureTOTP(secret, c.Now())); err == nil {
				t.Fatal("expired session accepted")
			}
			must("AdminSetUserMFAPreference", &api.AdminSetUserMFAPreferenceInput{UserPoolId: pool.Id, Username: new(api.UsernameType("alice")), SoftwareTokenMfaSettings: &api.SoftwareTokenMfaSettingsType{Enabled: new(api.BooleanType(false))}})
			if login("alice").AuthenticationResult == nil {
				t.Fatal("OPTIONAL disabled factor still required")
			}
			must("SetUserPoolMfaConfig", &api.SetUserPoolMfaConfigInput{UserPoolId: pool.Id, MfaConfiguration: new(api.UserPoolMfaType("ON"))})
			create("bob")
			setup := login("bob")
			if setup.ChallengeName == nil || string(*setup.ChallengeName) != "MFA_SETUP" {
				t.Fatal("ON unenrolled user bypassed setup")
			}
			associated := must("AssociateSoftwareToken", &api.AssociateSoftwareTokenInput{Session: setup.Session}).(*api.AssociateSoftwareTokenOutput)
			if _, err := call("AssociateSoftwareToken", &api.AssociateSoftwareTokenInput{Session: setup.Session}); err == nil {
				t.Fatal("old setup session reused")
			}
			verified := must("VerifySoftwareToken", &api.VerifySoftwareTokenInput{Session: associated.Session, UserCode: new(api.SoftwareTokenMFAUserCodeType(fixtureTOTP(string(*associated.SecretCode), c.Now())))}).(*api.VerifySoftwareTokenOutput)
			completed := must("RespondToAuthChallenge", &api.RespondToAuthChallengeInput{ClientId: client.ClientId, Session: verified.Session, ChallengeName: new(api.ChallengeNameType("MFA_SETUP")), ChallengeResponses: api.ChallengeResponsesType{"USERNAME": "bob"}}).(*api.RespondToAuthChallengeOutput)
			if completed.AuthenticationResult == nil {
				t.Fatal("verified setup did not issue tokens")
			}
		})
	}
}
