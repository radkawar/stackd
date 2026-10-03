package stackd_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type cognitoObservation struct {
	awsNativeObservation
	Transport, Principal string
	StartedAt            time.Time `json:"started_at"`
}
type cognitoLoginFixture struct {
	Account, Region  string
	Observations     []cognitoObservation
	Authorities      map[string]cognitoAuthority
	TokenProjections map[string]struct {
		Digest   string `json:"token_sha256"`
		Claims   map[string]any
		Verified bool `json:"signature_verified"`
	} `json:"token_projections"`
}
type cognitoReplay struct {
	bindings      map[string]string
	dates         map[float64]float64
	clientSecrets map[string]string
	lastAccess    string
	pages         map[string]*cognitoReplayPage
	authTimes     map[string]float64
}

// The native transcript exercises stateful application behavior, including
// single-use challenges and independent refresh families, through real SDK DTOs.
// SRP's ephemeral proof cannot be replayed from redacted native credentials; the
// independent pycognito runtime smoke exercises that cryptographic exchange.
func TestCognitoNativeLoginWorkflows(t *testing.T) {
	cognitoNativeRun(t, "login_workflows", "")
}

func TestCognitoNativeAdmissionWorkflows(t *testing.T) {
	cognitoNativeRun(t, "admission_workflows", "")
}

func TestCognitoNativeCredentialTransitions(t *testing.T) {
	// The later immediate post-delete success was not repeatable in the paired
	// retirement capture; do not turn unknown propagation timing into a contract.
	cognitoNativeRun(t, "credential_workflows", "credentials-after-challenge-completion-refresh")
}

func TestCognitoNativeClientRetirement(t *testing.T) {
	cognitoNativeRun(t, "client_retirement_workflows", "")
}

func TestCognitoNativeProfileWorkflows(t *testing.T) {
	cognitoNativeRun(t, "profile_workflows", "")
}

func TestCognitoNativeRefreshRotation(t *testing.T) {
	cognitoNativeRun(t, "refresh_rotation_workflows", "")
}

func cognitoNativeRun(t *testing.T, name, through string) {
	t.Helper()
	var fixture cognitoLoginFixture
	awsReadFixture(t, "cognito/"+name+".json", &fixture)
	var audits map[string]map[string]any
	switch name {
	case "login_workflows":
		audits = cognitoNativeAudits(t, "cloudtrail_login")
	case "group_workflows":
		audits = cognitoNativeAudits(t, "cloudtrail_groups")
	case "group_authority_workflows":
		audits = cognitoNativeAudits(t, "cloudtrail_group_authority")
	case "profile_workflows":
		audits = cognitoNativeAudits(t, "cloudtrail_profiles")
	case "refresh_rotation_workflows":
		audits = cognitoNativeAudits(t, "cloudtrail_refresh_rotation")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Observations[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			replay := cognitoReplay{bindings: map[string]string{}, dates: map[float64]float64{}, clientSecrets: map[string]string{}}
			issuer := credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")
			if len(fixture.Authorities) != 0 {
				_, key, secret := clients.user(t, fixture.Account, "cognito-authority")
				putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "cognito-authority", allow(`"*"`, "*"))
				issuer = credentials.NewStaticCredentialsProvider(key, secret, "")
			}
			identities := map[string]aws.Credentials{"": {AccessKeyID: fixture.Account, SecretAccessKey: "test"}}
			for _, row := range fixture.Observations {
				if row.Label == "default-client-srp-proof" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					if row.StartedAt.After(source.Now()) {
						advanceClock(t, source, row.StartedAt.Sub(source.Now()))
					}
					input := replay.input(t, row)
					identity, ok := identities[row.Principal]
					if !ok {
						identity = replay.federationCredentials(t, clients, fixture, row.Principal, issuer)
						identities[row.Principal] = identity
					}
					transport := &cognitoReplayTransport{client: clients.server.Client(), mode: row.Transport, identity: identity, region: fixture.Region}
					wire := &awstest.WireClient{Client: transport}
					client := cognitoidentityprovider.New(cognitoidentityprovider.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken), HTTPClient: wire, RetryMaxAttempts: 1})
					decoded, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
					awsNativeResult(t, row.awsNativeObservation, err)
					if wire.Status != row.Result.HTTPStatus {
						t.Fatalf("HTTP status=%d, native=%d", wire.Status, row.Result.HTTPStatus)
					}
					if native := audits[row.Label]; native != nil {
						id := nativeAuditRequestID(t, decoded, err)
						defer replay.audit(t, clients, fixture, row, native, id, source.Now())
					}
					if err != nil {
						if row.Label == "get-user-original-after-revoke" {
							var request map[string]string
							awsDecodeJSON(t, input, &request)
							cognitoVerifiedJWT(t, clients, request["AccessToken"])
						}
						return
					}
					var expected, actual any
					awsDecodeJSON(t, row.Result.Output, &expected)
					awsDecodeJSON(t, wire.Body, &actual)
					replay.compareResponse(t, row, expected, actual)
					output := actual.(map[string]any)
					if result, ok := output["UserPoolClient"].(map[string]any); ok {
						if secret, ok := result["ClientSecret"].(string); ok {
							replay.clientSecrets[result["ClientId"].(string)] = secret
						}
					}
					if result, ok := output["AuthenticationResult"].(map[string]any); ok {
						replay.lastAccess = result["AccessToken"].(string)
						claims := cognitoCheckTokens(t, clients, source.Now(), result)
						native := expected.(map[string]any)["AuthenticationResult"].(map[string]any)
						for member, payload := range claims {
							digest := cognitoBinding(native[member].(string))
							for _, projection := range fixture.TokenProjections {
								if projection.Verified && digest == "digest:"+projection.Digest {
									replay.compareTokenClaims(t, projection.Claims, payload)
								}
							}
						}
					}
				}) {
					return
				}
				if row.Label == through {
					break
				}
				switch row.Label {
				case "new-password-policy-failure", "public-password-signed", "revoke-refresh-token", "hidden-absent-first", "alias-cross-attribute-collision",
					"credentials-admin-temporary-reset", "client-access-update-given-name", "client-access-delete-default-client",
					"groups-add-writer", "groups-null-same-role", "groups-delete-writer", "groups-delete-alice",
					"profile-update-custom-default", "profile-delete-self", "profile-recreate-user",
					"authority-assign-role", "passed-absent-update", "unconditional-update",
					"rotation-zero-first", "rotation-grace-retry", "rotation-revoke-old-parent",
					"rotation-chain-second", "rotation-enable-existing-client", "rotation-disable-existing-client",
					"rotation-session-after-disable", "rotation-revoke-ancestor-while-disabled",
					"rotation-global-signout-mixed-origins":
					clients = reopen()
				}
			}
		})
	}
}

// Native redaction names differ by input/output member; the digest still binds
// the same opaque value. No real credential material is required for replay.
func cognitoBinding(value string) string {
	if strings.HasPrefix(value, "<redacted-") {
		if _, digest, ok := strings.Cut(value, "-sha256:"); ok {
			return "digest:" + strings.TrimSuffix(digest, ">")
		}
	}
	return value
}
func (r *cognitoReplay) bindInput(v any, errorCode string) any {
	switch v := v.(type) {
	case string:
		key := cognitoBinding(v)
		if bound, ok := r.bindings[key]; ok {
			return bound
		}
		if strings.HasPrefix(v, "<redacted-") {
			if strings.Contains(v, "password-sha256:") {
				password := "Aa1!" + strings.TrimPrefix(key, "digest:")[:24]
				if errorCode == "InvalidPasswordException" {
					password = "short"
				}
				r.bindings[key] = password
				return password
			}
			if strings.Contains(v, "clientsecret-sha256:") {
				// Preserve an admitted secret shape without turning a wrong
				// client proof into an unrelated schema rejection.
				return strings.TrimPrefix(key, "digest:")
			}
			return "invalid-unbound-token"
		}
		return v
	case map[string]any:
		for k, child := range v {
			v[k] = r.bindInput(child, errorCode)
		}
	case []any:
		for i, child := range v {
			v[i] = r.bindInput(child, errorCode)
		}
	}
	return v
}

func (r *cognitoReplay) input(t *testing.T, row cognitoObservation) json.RawMessage {
	t.Helper()
	var input map[string]any
	awsDecodeJSON(t, row.Input, &input)
	r.bindInput(input, row.Result.Code)
	parameters, _ := input["AuthParameters"].(map[string]any)
	if parameters["SECRET_HASH"] != nil && (strings.Contains(row.Label, "hash-valid") || row.Result.Code == "Success") {
		username, _ := parameters["USERNAME"].(string)
		if username == "" {
			username = "owned-user"
		}
		client := input["ClientId"].(string)
		mac := hmac.New(sha256.New, []byte(r.clientSecrets[client]))
		_, _ = io.WriteString(mac, username+client)
		parameters["SECRET_HASH"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	if row.Label == "get-user-tampered-signature" {
		parts := strings.Split(r.lastAccess, ".")
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		signature[0] ^= 1
		parts[2] = base64.RawURLEncoding.EncodeToString(signature)
		input["AccessToken"] = strings.Join(parts, ".")
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (r *cognitoReplay) compare(t *testing.T, path string, want, got any) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("%s: expected object, got %T", path, got)
		}
		if len(expected) != len(actual) {
			t.Fatalf("%s: response fields differ: native=%v local=%v", path, cognitoMapKeys(expected), cognitoMapKeys(actual))
		}
		for key, child := range expected {
			value, present := actual[key]
			if !present {
				t.Fatalf("%s.%s missing", path, key)
			}
			childPath := path + "." + key
			if key == "Value" && expected["Name"] == "sub" {
				childPath = ".Sub"
			}
			r.compare(t, childPath, child, value)
		}
	case []any:
		actual, ok := got.([]any)
		if !ok || len(expected) != len(actual) {
			t.Fatalf("%s: native collection length=%d, local=%v", path, len(expected), got)
		}
		// These records have native stable identities, not native order guarantees.
		for _, key := range []string{"ClientName", "Username", "Name", "GroupName"} {
			if len(expected) > 0 {
				first, ok := expected[0].(map[string]any)
				if ok && first[key] != nil {
					sort.Slice(expected, func(i, j int) bool {
						return fmt.Sprint(expected[i].(map[string]any)[key]) < fmt.Sprint(expected[j].(map[string]any)[key])
					})
					sort.Slice(actual, func(i, j int) bool {
						return fmt.Sprint(actual[i].(map[string]any)[key]) < fmt.Sprint(actual[j].(map[string]any)[key])
					})
					break
				}
			}
		}
		if strings.HasSuffix(path, ".ExplicitAuthFlows") || strings.HasSuffix(path, ".explicitAuthFlows") ||
			strings.HasSuffix(path, ".cognito:groups") || strings.HasSuffix(path, ".cognito:roles") {
			sort.Slice(expected, func(i, j int) bool { return expected[i].(string) < expected[j].(string) })
			sort.Slice(actual, func(i, j int) bool { return actual[i].(string) < actual[j].(string) })
		}
		for i, child := range expected {
			r.compare(t, fmt.Sprintf("%s[%d]", path, i), child, actual[i])
		}
	case string:
		actual, ok := got.(string)
		if !ok {
			t.Fatalf("%s: expected string, got %T", path, got)
		}
		if strings.HasSuffix(path, "Date") {
			for _, layout := range []string{time.RFC3339, "Jan 2, 2006, 3:04:05 PM"} {
				nativeTime, err := time.Parse(layout, expected)
				if err != nil {
					continue
				}
				localTime, err := time.Parse(layout, actual)
				if err != nil {
					t.Fatalf("%s: native timestamp layout changed", path)
				}
				for native, local := range r.dates {
					if int64(native) == nativeTime.Unix() && int64(local) == localTime.Unix() {
						return
					}
				}
				t.Fatalf("%s: audit timestamp differs from API resource time", path)
			}
		}
		if strings.HasSuffix(path, ".AuthenticationResult.IdToken") {
			// Verify decoded native claims and RSA signatures below, not byte
			// identity: tokens without jti can repeat within an AWS clock second.
			return
		}
		key := cognitoBinding(expected)
		if bound, ok := r.bindings[key]; ok {
			if actual != bound {
				t.Fatalf("%s: retained identity/value changed", path)
			}
			return
		}
		dynamic := strings.HasPrefix(expected, "<redacted-")
		for _, suffix := range []string{".Id", ".Arn", ".ClientId", ".Sub", ".UserSub", ".SALT", ".SRP_B", ".sub", ".iss", ".event_id", ".origin_jti", ".jti", ".NextToken", ".nextToken"} {
			dynamic = dynamic || strings.HasSuffix(path, suffix)
		}
		if dynamic {
			for native, local := range r.bindings {
				if native != key && local == actual {
					t.Fatalf("%s: distinct native identities collapsed to one local value", path)
				}
			}
			r.bindings[key] = actual
			return
		}
		if expected != actual {
			t.Fatalf("%s: native=%q local=%q", path, expected, actual)
		}
	case float64:
		if strings.HasSuffix(path, "Date") {
			actual, ok := got.(float64)
			if !ok {
				t.Fatalf("%s: expected epoch timestamp, got %T", path, got)
			}
			if bound, ok := r.dates[expected]; ok && bound != actual {
				t.Fatalf("%s: retained timestamp changed", path)
			}
			r.dates[expected] = actual
			return
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: native=%v local=%v", path, want, got)
		}
	default:
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: native=%v local=%v", path, want, got)
		}
	}
}
func cognitoMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type cognitoReplayTransport struct {
	client       aws.HTTPClient
	mode, region string
	identity     aws.Credentials
}

func (c *cognitoReplayTransport) Do(request *http.Request) (*http.Response, error) {
	for _, name := range []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token"} {
		request.Header.Del(name)
	}
	switch c.mode {
	case "signed", "invalid-signature":
		data, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(data))
		sum := sha256.Sum256(data)
		identity := c.identity
		if c.mode == "invalid-signature" {
			identity.AccessKeyID = "AKIAFAKECOGNITOPROBE0"
		}
		if err := v4.NewSigner().SignHTTP(request.Context(), identity, request, hex.EncodeToString(sum[:]), "cognito-idp", c.region, time.Now()); err != nil {
			return nil, err
		}
	case "malformed-authorization":
		request.Header.Set("Authorization", "broken authorization")
	}
	return c.client.Do(request)
}
