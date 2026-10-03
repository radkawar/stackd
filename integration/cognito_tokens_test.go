package stackd_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func cognitoCheckTokens(t *testing.T, clients cloudClients, now time.Time, result map[string]any) map[string]map[string]any {
	t.Helper()
	claims := make(map[string]map[string]any, 2)
	kids := make(map[string]string, 2)
	for member, kind := range map[string]string{"AccessToken": "access", "IdToken": "id"} {
		token, ok := result[member].(string)
		if !ok {
			t.Fatalf("missing %s", member)
		}
		payload, kid := cognitoVerifiedJWT(t, clients, token)
		if payload["token_use"] != kind {
			t.Fatalf("%s token_use=%v", member, payload["token_use"])
		}
		issued, ok := payload["iat"].(float64)
		if !ok || int64(issued) != now.Unix() {
			t.Fatalf("%s iat does not match service time", member)
		}
		expires, ok := payload["exp"].(float64)
		if !ok || expires-issued != result["ExpiresIn"] {
			t.Fatalf("%s lifetime does not match ExpiresIn", member)
		}
		claims[member], kids[member] = payload, kid
	}
	access, id := claims["AccessToken"], claims["IdToken"]
	for _, field := range []string{"sub", "iss", "event_id", "auth_time"} {
		if access[field] != id[field] {
			t.Fatalf("access/ID authentication lineage differs at %s", field)
		}
	}
	if access["client_id"] != id["aud"] {
		t.Fatal("access and ID tokens identify different clients")
	}
	if kids["AccessToken"] == kids["IdToken"] {
		t.Fatal("access and ID tokens use the same signing key")
	}
	return claims
}

func cognitoVerifiedJWT(t *testing.T, clients cloudClients, token string) (map[string]any, string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT envelope")
	}
	decode := func(value string) []byte {
		data, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	var claims map[string]any
	awsDecodeJSON(t, decode(parts[0]), &header)
	awsDecodeJSON(t, decode(parts[1]), &claims)
	if header.Algorithm != "RS256" {
		t.Fatalf("JWT algorithm=%s", header.Algorithm)
	}
	issuer, ok := claims["iss"].(string)
	if !ok {
		t.Fatal("missing JWT issuer")
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, clients.server.URL+parsed.Path+"/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := clients.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JWKS HTTP %d", response.StatusCode)
	}
	var keys struct {
		Keys []struct {
			ID        string `json:"kid"`
			Algorithm string `json:"alg"`
			Type      string `json:"kty"`
			Modulus   string `json:"n"`
			Exponent  string `json:"e"`
		}
	}
	if err := json.NewDecoder(response.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys.Keys {
		if key.ID != header.KeyID {
			continue
		}
		if key.Algorithm != "RS256" || key.Type != "RSA" {
			t.Fatal("JWKS does not describe an RSA signing key")
		}
		modulus := new(big.Int).SetBytes(decode(key.Modulus))
		exponent := new(big.Int).SetBytes(decode(key.Exponent))
		if modulus.BitLen() != 2048 {
			t.Fatalf("RSA modulus bits=%d", modulus.BitLen())
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, crypto.SHA256, digest[:], decode(parts[2])); err != nil {
			t.Fatalf("independent JWT verification: %v", err)
		}
		return claims, header.KeyID
	}
	t.Fatal("JWT signing key absent from public JWKS")
	return nil, ""
}

func (r *cognitoReplay) compareTokenClaims(t *testing.T, native, local map[string]any) {
	t.Helper()
	for _, field := range []string{"iat", "exp", "auth_time"} {
		if _, ok := native[field].(float64); !ok {
			t.Fatalf("native JWT missing numeric %s", field)
		}
		if _, ok := local[field].(float64); !ok {
			t.Fatalf("local JWT missing numeric %s", field)
		}
	}
	authTime := local["auth_time"].(float64)
	if authTime > local["iat"].(float64) {
		t.Fatal("JWT authentication follows token issuance")
	}
	family := native["event_id"].(string)
	if previous, ok := r.authTimes[family]; ok {
		if previous != authTime {
			t.Fatal("JWT refresh changed authentication time")
		}
	} else {
		if native["auth_time"] == native["iat"] && local["auth_time"] != local["iat"] {
			t.Fatal("new authentication has an unrelated token issue time")
		}
		if r.authTimes == nil {
			r.authTimes = map[string]float64{}
		}
		r.authTimes[family] = authTime
	}
	// cognitoCheckTokens verifies local issuance and lifetime against service
	// time and the native-compatible ExpiresIn response. A captured native
	// exp-iat is one second below ExpiresIn; those wall times are not a bijection.
	// Preserve authentication-family continuity, not a global time substitution.
	want, got := maps.Clone(native), maps.Clone(local)
	for _, field := range []string{"iat", "exp", "auth_time"} {
		delete(want, field)
		delete(got, field)
	}
	r.compare(t, "JWT", want, got)
}
