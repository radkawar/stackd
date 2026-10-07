package cognitoidp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/cognitoidp"
)

func clientSRPProof(pool PoolKey, username, password string, private *big.Int, params api.ChallengeParametersType, now time.Time) api.ChallengeResponsesType {
	a := new(big.Int).Exp(srpG, private, srpN)
	b, _ := new(big.Int).SetString(string(params["SRP_B"]), 16)
	salt, _ := new(big.Int).SetString(string(params["SALT"]), 16)
	identity := sha256.Sum256([]byte(poolSuffix(pool.ID) + username + ":" + password))
	x := srpHash(srpPad(salt), identity[:])
	u := srpHash(srpPad(a), srpPad(b))
	base := new(big.Int).Sub(b, new(big.Int).Mul(srpK, new(big.Int).Exp(srpG, x, srpN)))
	exponent := new(big.Int).Add(private, new(big.Int).Mul(u, x))
	shared := new(big.Int).Exp(base, exponent, srpN)
	extract := hmac.New(sha256.New, srpPad(u))
	extract.Write(srpPad(shared))
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("Caldera Derived Key\x01"))
	block, _ := base64.StdEncoding.DecodeString(string(params["SECRET_BLOCK"]))
	timestamp := now.UTC().Format("Mon Jan 2 15:04:05 UTC 2006")
	proof := hmac.New(sha256.New, expand.Sum(nil)[:16])
	proof.Write([]byte(poolSuffix(pool.ID)))
	proof.Write([]byte(username))
	proof.Write(block)
	proof.Write([]byte(timestamp))
	return api.ChallengeResponsesType{"USERNAME": api.StringType(username), "PASSWORD_CLAIM_SECRET_BLOCK": params["SECRET_BLOCK"], "TIMESTAMP": api.StringType(timestamp), "PASSWORD_CLAIM_SIGNATURE": api.StringType(base64.StdEncoding.EncodeToString(proof.Sum(nil)))}
}

func TestSoftwareMFAAfterSRPAndNewPassword(t *testing.T) {
	for _, flow := range []string{"USER_SRP_AUTH", "NEW_PASSWORD_REQUIRED"} {
		t.Run(flow, func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			c := clock.NewManual(time.Unix(1800000000, 0))
			s := New(Config{Repository: repository, Clock: c})
			pool := PoolRecord{Key: PoolKey{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: "us-east-1_abc123"}, SoftwareTokenMFAEnabled: true, Data: api.UserPoolType{MfaConfiguration: str[api.UserPoolMfaType]("ON")}}
			client := ClientRecord{Key: ClientKey{PoolKey: pool.Key, ID: "client"}, Data: api.UserPoolClientType{ExplicitAuthFlows: api.ExplicitAuthFlowsListType{"ALLOW_USER_SRP_AUTH", "ALLOW_USER_PASSWORD_AUTH"}}}
			password := "Password123!"
			verifier, err := makePasswordVerifier(pool.Key, "alice", password)
			if err != nil {
				t.Fatal(err)
			}
			user := UserRecord{Key: UserKey{PoolKey: pool.Key, Username: "alice"}, Password: verifier, Data: api.UserType{Username: str[api.UsernameType]("alice"), Enabled: ptr(api.BooleanType(true)), UserStatus: str[api.UserStatusType]("CONFIRMED")}, SoftwareTokenEnabled: true, SoftwareTokenSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", SoftwareTokenLastCounter: -1}
			if flow == "NEW_PASSWORD_REQUIRED" {
				user.Data.UserStatus = str[api.UserStatusType]("FORCE_CHANGE_PASSWORD")
				user.SoftwareTokenEnabled = false
				user.SoftwareTokenSecret = ""
			}
			if err := repository.Update(t.Context(), func(tx Transaction) error {
				if err := tx.PutPool(pool); err != nil {
					return err
				}
				if err := tx.PutClient(client); err != nil {
					return err
				}
				return tx.PutUser(user)
			}); err != nil {
				t.Fatal(err)
			}
			private := big.NewInt(123456789)
			params := api.AuthParametersType{"USERNAME": "alice", "PASSWORD": api.StringType(password)}
			authFlow := "USER_PASSWORD_AUTH"
			if flow == "USER_SRP_AUTH" {
				authFlow = flow
				params["SRP_A"] = api.StringType(new(big.Int).Exp(srpG, private, srpN).Text(16))
			}
			var challenge *api.InitiateAuthOutput
			if err := repository.Update(t.Context(), func(tx Transaction) error {
				var err error
				challenge, err = s.beginAuth(tx, pool, client, authFlow, params, false)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			kind, session := value(challenge.ChallengeName), value(challenge.Session)
			responses := api.ChallengeResponsesType{"USERNAME": "alice", "NEW_PASSWORD": "Changed123!"}
			expected := "MFA_SETUP"
			if flow == "USER_SRP_AUTH" {
				responses = clientSRPProof(pool.Key, "alice", password, private, challenge.ChallengeParameters, c.Now())
				expected = "SOFTWARE_TOKEN_MFA"
			}
			var out *api.InitiateAuthOutput
			if err := repository.Update(t.Context(), func(tx Transaction) error {
				var err error
				out, err = s.completeChallenge(tx, pool, client, kind, session, responses)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if out.AuthenticationResult != nil || value(out.ChallengeName) != expected || value(out.Session) == "" {
				t.Fatalf("password proof bypassed MFA: %+v", out)
			}
		})
	}
}
