package cognitoidp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
)

// Cognito uses the RFC 3526 3072-bit group, generator 2, SHA-256 and
// sign-preserving integer padding (not fixed-width SRP integer padding).
const srpModulus = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

var (
	srpN, _ = new(big.Int).SetString(srpModulus, 16)
	srpG    = big.NewInt(2)
	srpK    = srpHash(srpPad(srpN), srpPad(srpG))
)

type srpChallengeState struct {
	A, Private, Credential []byte
}

func srpPad(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	if b[0]&0x80 != 0 {
		return append([]byte{0}, b...)
	}
	return b
}

func srpHash(parts ...[]byte) *big.Int {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

func srpPublic(private *big.Int, verifier []byte) *big.Int {
	b := new(big.Int).Exp(srpG, private, srpN)
	b.Add(b, new(big.Int).Mul(srpK, new(big.Int).SetBytes(verifier)))
	return b.Mod(b, srpN)
}

func (s *Service) startSRP(tx Transaction, pool PoolRecord, client ClientRecord, user UserRecord, aHex string) (*api.InitiateAuthOutput, error) {
	out, state, err := newSRPChallenge(user.Key.Username, user.Password, aHex)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(user.Password.Verifier)
	state.Credential = fingerprint[:]
	private, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	challenge := ChallengeRecord{
		Key:      ChallengeKey{PoolKey: pool.Key, Token: string(out.ChallengeParameters["SECRET_BLOCK"])},
		ClientID: client.Key.ID, Username: user.Key.Username, Kind: "PASSWORD_VERIFIER",
		Expires: s.clock.Now().Add(challengeDuration(client)), SRPPrivate: private,
	}
	if err := tx.PutChallenge(challenge); err != nil {
		return nil, err
	}
	return out, nil
}

// Native existence protection returns a stable salt per pool/username, even
// across clients. The retained private pool key supplies the secret derivation;
// no synthetic user or authenticatable challenge is written to resource state.
func (s *Service) missingUserSRP(r Reader, pool PoolRecord, username, aHex string) (*api.InitiateAuthOutput, error) {
	keys, err := r.SigningKeys(pool.Key)
	if err != nil {
		return nil, err
	}
	derive := hmac.New(sha256.New, keys.Access.PKCS8DER)
	derive.Write([]byte("Cognito missing user\x00" + username))
	seed := derive.Sum(nil)
	password := PasswordVerifier{Salt: seed[:16], Verifier: srpHash(seed, []byte("verifier")).Bytes()}
	out, _, err := newSRPChallenge(username, password, aHex)
	return out, err
}

func newSRPChallenge(username string, password PasswordVerifier, aHex string) (*api.InitiateAuthOutput, srpChallengeState, error) {
	var state srpChallengeState
	if aHex == "" {
		return nil, state, failure("InvalidParameterException", "Missing required parameter SRP_A")
	}
	if len(aHex) > len(srpModulus)+2 || strings.IndexFunc(aHex, func(r rune) bool { return !strings.ContainsRune("0123456789abcdefABCDEF", r) }) >= 0 {
		return nil, state, failure("InvalidParameterException", "Invalid SRP_A")
	}
	a, ok := new(big.Int).SetString(aHex, 16)
	if !ok {
		return nil, state, failure("InvalidParameterException", "Invalid SRP_A")
	}
	// Native Cognito issues a challenge even for zero A. Never accept its proof.
	random := make([]byte, 128)
	if _, err := rand.Read(random); err != nil {
		return nil, state, err
	}
	private := new(big.Int).SetBytes(random)
	if private.Sign() == 0 {
		private.SetInt64(1)
	}
	block, err := randomToken(128)
	if err != nil {
		return nil, state, err
	}
	state.A, state.Private = a.Bytes(), private.Bytes()
	return &api.InitiateAuthOutput{ChallengeName: str[api.ChallengeNameType]("PASSWORD_VERIFIER"), ChallengeParameters: api.ChallengeParametersType{
		"SALT":            api.StringType(new(big.Int).SetBytes(password.Salt).Text(16)),
		"SRP_B":           api.StringType(srpPublic(private, password.Verifier).Text(16)),
		"SECRET_BLOCK":    api.StringType(block),
		"USERNAME":        api.StringType(username),
		"USER_ID_FOR_SRP": api.StringType(username),
	}}, state, nil
}

func (s *Service) verifySRP(pool PoolRecord, user UserRecord, challenge ChallengeRecord, response api.ChallengeResponsesType) error {
	timestamp := string(response["TIMESTAMP"])
	const layout = "Mon Jan 2 15:04:05 UTC 2006"
	t, err := time.Parse(layout, timestamp)
	now := s.clock.Now()
	if err != nil || t.Format(layout) != timestamp || t.Before(now.Add(-5*time.Minute)) || t.After(now.Add(5*time.Minute)) {
		return failure("NotAuthorizedException", "Incorrect username or password.")
	}
	var state srpChallengeState
	if err := json.Unmarshal(challenge.SRPPrivate, &state); err != nil {
		return err
	}
	fingerprint := sha256.Sum256(user.Password.Verifier)
	if !hmac.Equal(state.Credential, fingerprint[:]) {
		return failure("NotAuthorizedException", "Incorrect username or password.")
	}
	a := new(big.Int).SetBytes(state.A)
	if new(big.Int).Mod(a, srpN).Sign() == 0 {
		return failure("NotAuthorizedException", "Incorrect username or password.")
	}
	b := new(big.Int).SetBytes(state.Private)
	public := srpPublic(b, user.Password.Verifier)
	u := srpHash(srpPad(a), srpPad(public))
	if u.Sign() == 0 {
		return failure("NotAuthorizedException", "Incorrect username or password.")
	}
	// S = (A * v^u)^b mod N. The matching client knows a and x; neither
	// password nor x is retained by the server.
	shared := new(big.Int).Exp(new(big.Int).SetBytes(user.Password.Verifier), u, srpN)
	shared.Mul(shared, a).Mod(shared, srpN)
	shared.Exp(shared, b, srpN)
	extract := hmac.New(sha256.New, srpPad(u))
	extract.Write(srpPad(shared))
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("Caldera Derived Key\x01"))
	key := expand.Sum(nil)[:16]
	block, err := base64.StdEncoding.DecodeString(challenge.Key.Token)
	if err != nil {
		return err
	}
	proof := hmac.New(sha256.New, key)
	proof.Write([]byte(poolSuffix(pool.Key.ID)))
	proof.Write([]byte(user.Key.Username))
	proof.Write(block)
	proof.Write([]byte(timestamp))
	signature, err := base64.StdEncoding.DecodeString(string(response["PASSWORD_CLAIM_SIGNATURE"]))
	if err != nil || !hmac.Equal(signature, proof.Sum(nil)) {
		return failure("NotAuthorizedException", "Incorrect username or password.")
	}
	return nil
}

func challengeDuration(client ClientRecord) time.Duration {
	if client.Data.AuthSessionValidity != nil {
		return time.Duration(*client.Data.AuthSessionValidity) * time.Minute
	}
	return 3 * time.Minute
}

func randomToken(length int) (string, error) {
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(random), nil
}
