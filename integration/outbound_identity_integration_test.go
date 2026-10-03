package stackd_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
	"stackd/clock"
)

func outboundCloud(t *testing.T, config stackd.Config) (cloudClients, *clock.Manual) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 1, 12, 0, 0, 225000000, time.UTC))
	server := httptest.NewUnstartedServer(nil)
	config.Clock = source
	config.PublicEndpoint = "http://" + server.Listener.Addr().String()
	cloud, err := stackd.New(config)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = cloud
	server.Start()
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
	})
	return cloudClients{server}, source
}

func outboundInput() *sts.GetWebIdentityTokenInput {
	return &sts.GetWebIdentityTokenInput{Audience: []string{"https://external.example.test"}, SigningAlgorithm: aws.String("RS256")}
}

func fetchOutboundJSON(t *testing.T, endpoint string, result any) {
	t.Helper()
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("discovery status %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		t.Fatal(err)
	}
}

// Validate the returned JWT using only HTTP discovery and standard public-key
// verification, as an external recipient would. No private backend state is read.
func verifyOutboundJWT(t *testing.T, issuer, token string, now time.Time) map[string]any {
	t.Helper()
	var discovery struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	fetchOutboundJSON(t, issuer+"/.well-known/openid-configuration", &discovery)
	if discovery.Issuer != issuer {
		t.Fatalf("issuer changed: %+v", discovery)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	fetchOutboundJSON(t, discovery.JWKS, &jwks)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var header map[string]string
	var claims map[string]any
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(decode(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if header["typ"] != "JWT" || claims["iss"] != issuer || claims["exp"].(float64) <= float64(now.Unix()) {
		t.Fatalf("invalid token claims/header: %+v %+v", claims, header)
	}
	input, signature := []byte(parts[0]+"."+parts[1]), decode(parts[2])
	verified := false
	for _, key := range jwks.Keys {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if key[private] != "" {
				t.Fatal("private material in public JWKS")
			}
		}
		if key["kid"] != header["kid"] {
			continue
		}
		if key["alg"] != header["alg"] {
			t.Fatal("algorithm/key mismatch")
		}
		switch header["alg"] {
		case "RS256":
			public := &rsa.PublicKey{N: new(big.Int).SetBytes(decode(key["n"])), E: int(new(big.Int).SetBytes(decode(key["e"])).Int64())}
			digest := sha256.Sum256(input)
			if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
				t.Fatal(err)
			}
		case "ES384":
			if key["crv"] != "P-384" || len(signature) != 96 {
				t.Fatal("invalid ES384 key/signature")
			}
			point := append([]byte{4}, decode(key["x"])...)
			point = append(point, decode(key["y"])...)
			public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha512.Sum384(input)
			if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:48]), new(big.Int).SetBytes(signature[48:])) {
				t.Fatal("invalid ECDSA signature")
			}
		default:
			t.Fatalf("unexpected algorithm %q", header["alg"])
		}
		verified = true
	}
	if !verified {
		t.Fatal("no matching public key")
	}
	return claims
}

func TestOutboundIdentitySDKLifecycleAndExternalVerification(t *testing.T) {
	c, source := outboundCloud(t, stackd.Config{})
	ctx := t.Context()
	root := c.iam("test", "test", "")
	_, err := root.GetOutboundWebIdentityFederationInfo(ctx, &iam.GetOutboundWebIdentityFederationInfoInput{})
	assertAPIError(t, err, "FeatureDisabled")
	enabled, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil {
		t.Fatal(err)
	}
	issuer := aws.ToString(enabled.IssuerIdentifier)
	_, err = root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	assertAPIError(t, err, "FeatureEnabled")
	arn, key, secret := c.user(t, "test", "outbound")
	caller := c.sts(key, secret, "")
	_, err = caller.GetWebIdentityToken(ctx, outboundInput())
	assertAPIError(t, err, "AccessDenied")
	putUserPolicy(t, root, "outbound", allow(`"sts:GetWebIdentityToken"`, "arn:aws:sts::000000000000:self"))
	_, err = root.TagUser(ctx, &iam.TagUserInput{UserName: aws.String("outbound"), Tags: []iamtypes.Tag{{Key: aws.String("Team"), Value: aws.String("platform")}}})
	if err != nil {
		t.Fatal(err)
	}
	var original string
	_, err = caller.GetWebIdentityToken(ctx, outboundInput())
	assertAPIError(t, err, "OutboundWebIdentityFederationDisabledException")
	advanceClock(t, source, 10*time.Second)
	for _, algorithm := range []*string{aws.String("RS256"), aws.String("ES384")} {
		input := outboundInput()
		input.SigningAlgorithm = algorithm
		out, err := caller.GetWebIdentityToken(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if out.Expiration == nil || !out.Expiration.Equal(source.Now().Add(5*time.Minute)) {
			t.Fatalf("expiration %+v", out.Expiration)
		}
		claims := verifyOutboundJWT(t, issuer, aws.ToString(out.WebIdentityToken), source.Now())
		custom := claims["https://sts.amazonaws.com/"].(map[string]any)
		if claims["sub"] != arn || claims["aud"] != input.Audience[0] || custom["principal_id"] != arn || !reflect.DeepEqual(custom["principal_tags"], map[string]any{"Team": "platform"}) {
			t.Fatalf("incorrect identity claims %+v", claims)
		}
		if _, exists := custom["original_session_exp"]; exists {
			t.Fatal("long-term user received session expiry")
		}
		original = aws.ToString(out.WebIdentityToken)
	}
	input := outboundInput()
	input.Tags = []ststypes.Tag{{Key: aws.String("aws:team"), Value: aws.String("request")}}
	_, err = caller.GetWebIdentityToken(ctx, input)
	assertAPIError(t, err, "AccessDenied")
	putUserPolicy(t, root, "outbound", allow(`["sts:GetWebIdentityToken","sts:TagGetWebIdentityToken"]`, "arn:aws:sts::000000000000:self"))
	session, err := caller.GetSessionToken(ctx, &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	sessionToken, err := c.sessionSTS(session.Credentials).GetWebIdentityToken(ctx, outboundInput())
	if err != nil {
		t.Fatal(err)
	}
	sessionClaims := verifyOutboundJWT(t, issuer, aws.ToString(sessionToken.WebIdentityToken), source.Now())
	if sessionClaims["https://sts.amazonaws.com/"].(map[string]any)["original_session_exp"] != session.Credentials.Expiration.UTC().Format(time.RFC3339) {
		t.Fatal("IAM user session expiration was lost")
	}
	input.Audience = []string{"one", "one"}
	out, err := caller.GetWebIdentityToken(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyOutboundJWT(t, issuer, aws.ToString(out.WebIdentityToken), source.Now())
	if !reflect.DeepEqual(claims["aud"], []any{"one", "one"}) {
		t.Fatalf("audiences %+v", claims["aud"])
	}
	if !reflect.DeepEqual(claims["https://sts.amazonaws.com/"].(map[string]any)["request_tags"], map[string]any{"aws:team": "request"}) {
		t.Fatal("request tags lost")
	}
	_, err = root.DisableOutboundWebIdentityFederation(ctx, &iam.DisableOutboundWebIdentityFederationInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.GetOutboundWebIdentityFederationInfo(ctx, &iam.GetOutboundWebIdentityFederationInfoInput{})
	assertAPIError(t, err, "FeatureDisabled")
	if _, err := caller.GetWebIdentityToken(ctx, outboundInput()); err != nil {
		t.Fatalf("disable propagated before its service-time deadline: %v", err)
	}
	advanceClock(t, source, 10*time.Second)
	_, err = caller.GetWebIdentityToken(ctx, outboundInput())
	assertAPIError(t, err, "OutboundWebIdentityFederationDisabledException")
	verifyOutboundJWT(t, issuer, original, source.Now())
	again, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil || aws.ToString(again.IssuerIdentifier) != issuer {
		t.Fatalf("issuer changed: %+v %v", again, err)
	}
	other, err := c.iam("111111111111", "test", "").EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil || aws.ToString(other.IssuerIdentifier) == issuer {
		t.Fatalf("account issuer isolation: %+v %v", other, err)
	}
	_, err = federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String("arn:aws:iam::111111111111:role/target"), RoleSessionName: aws.String("recycle"), WebIdentityToken: &original})
	assertAPIError(t, err, "InvalidIdentityToken")
}

func TestOutboundIdentityCurrentRoleSessionAndOrganization(t *testing.T) {
	c, source := outboundCloud(t, stackd.Config{})
	ctx := t.Context()
	root := c.iam("test", "test", "")
	enabled, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 10*time.Second)
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	created, err := org.CreateOrganization(ctx, &organizations.CreateOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := org.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		t.Fatal(err)
	}
	role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("outbound-role"), Path: aws.String("/work/"), Tags: []iamtypes.Tag{{Key: aws.String("Team"), Value: aws.String("role")}, {Key: aws.String("untouched"), Value: aws.String("kept")}}, AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}}`)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "outbound-role", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:GetWebIdentityToken","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":%q}}}}`, aws.ToString(created.Organization.Id)))
	assumed, err := c.sts("test", "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("external"), SourceIdentity: aws.String("origin"), DurationSeconds: aws.Int32(900), Tags: []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("session")}}})
	if err != nil {
		t.Fatal(err)
	}
	caller := c.sessionSTS(assumed.Credentials)
	out, err := caller.GetWebIdentityToken(ctx, outboundInput())
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyOutboundJWT(t, aws.ToString(enabled.IssuerIdentifier), aws.ToString(out.WebIdentityToken), source.Now())
	custom := claims["https://sts.amazonaws.com/"].(map[string]any)
	path := aws.ToString(created.Organization.Id) + "/" + aws.ToString(roots.Roots[0].Id) + "/"
	if claims["sub"] != aws.ToString(role.Role.Arn) || custom["source_identity"] != "origin" || custom["original_session_exp"] != assumed.Credentials.Expiration.UTC().Format(time.RFC3339) || !reflect.DeepEqual(custom["ou_path"], []any{path}) || !reflect.DeepEqual(custom["principal_tags"], map[string]any{"team": "session", "untouched": "kept"}) {
		t.Fatalf("role claims %+v", claims)
	}
	input := outboundInput()
	input.DurationSeconds = aws.Int32(901)
	_, err = caller.GetWebIdentityToken(ctx, input)
	assertAPIError(t, err, "SessionDurationEscalationException")
	advanceClock(t, source, 11*time.Minute)
	_, err = caller.GetWebIdentityToken(ctx, outboundInput())
	assertAPIError(t, err, "SessionDurationEscalationException")
	input.DurationSeconds = aws.Int32(60)
	putRolePolicy(t, root, "outbound-role", `{"Statement":{"Effect":"Deny","Action":"sts:GetWebIdentityToken","Resource":"*"}}`)
	_, err = caller.GetWebIdentityToken(ctx, input)
	assertAPIError(t, err, "AccessDenied")
}
