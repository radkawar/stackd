package stackd_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
	"stackd/storage"
	iamstore "stackd/storage/iam"
)

// Discovery is an injected trusted issuer, never a network or credential-chain
// fallback. A one-shot hook exercises provider changes during verification.
type federationIntegrationDiscovery struct {
	mu   sync.Mutex
	key  *rsa.PrivateKey
	kid  string
	hook func()
}

func (d *federationIntegrationDiscovery) Discover(ctx context.Context, request stackd.OIDCDiscoveryRequest) (stackd.OIDCDiscoveryResult, error) {
	if err := ctx.Err(); err != nil {
		return stackd.OIDCDiscoveryResult{}, err
	}
	if request.IssuerURL != "https://federation.example.test" {
		return stackd.OIDCDiscoveryResult{}, fmt.Errorf("unexpected issuer")
	}
	d.mu.Lock()
	key, kid, hook := d.key, d.kid, d.hook
	d.hook = nil
	d.mu.Unlock()
	if hook != nil {
		hook()
	}
	return stackd.OIDCDiscoveryResult{
		IssuerURL:         request.IssuerURL,
		JWKSURL:           request.IssuerURL + "/keys",
		SigningAlgorithms: []string{"RS256"},
		Thumbprints:       request.Thumbprints,
		SigningKeys: []stackd.OIDCSigningKey{{
			ID: kid, Type: "RSA", Use: "sig", Algorithm: "RS256",
			N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
		CacheUntil: time.Now().Add(time.Hour),
	}, nil
}

func (d *federationIntegrationDiscovery) token(t *testing.T, changes map[string]any) string {
	t.Helper()
	claims := map[string]any{"iss": "https://federation.example.test", "sub": "verified-subject", "aud": "audience", "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(), "amr": []string{"pwd"}, "email": "test@example.test"}
	for key, value := range changes {
		if value == nil {
			delete(claims, key)
		} else {
			claims[key] = value
		}
	}
	d.mu.Lock()
	key, kid := d.key, d.kid
	d.mu.Unlock()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func newFederationIntegrationCloud(t *testing.T) (cloudClients, *federationIntegrationDiscovery, iamstore.Repository) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	source := &federationIntegrationDiscovery{key: key, kid: "initial"}
	backends := storage.NewMemory()
	cloud, err := stackd.New(stackd.Config{Storage: backends, OIDCDiscovery: source})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cloud)
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
	})
	return cloudClients{server}, source, backends.IAM
}

func federationIntegrationRole(t *testing.T, c cloudClients, account, name, actions string) (*iamtypes.Role, string) {
	t.Helper()
	root := c.iam(account, "test", "")
	created, err := root.CreateOpenIDConnectProvider(t.Context(), &iam.CreateOpenIDConnectProviderInput{Url: aws.String("https://federation.example.test"), ClientIDList: []string{"audience"}, ThumbprintList: []string{strings.Repeat("a", 40)}})
	if err != nil {
		t.Fatal(err)
	}
	provider := aws.ToString(created.OpenIDConnectProviderArn)
	trust := `{"Statement":{"Effect":"Allow","Principal":{"Federated":"` + provider + `"},"Action":` + actions + `,"Condition":{"StringEquals":{"federation.example.test:aud":"audience","federation.example.test:sub":"verified-subject"}}}}`
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), Path: aws.String("/federation/"), AssumeRolePolicyDocument: aws.String(trust), MaxSessionDuration: aws.Int32(7200)})
	if err != nil {
		t.Fatal(err)
	}
	return role.Role, provider
}

func federationIntegrationUnsigned(c cloudClients) *sts.Client {
	return sts.New(sts.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: aws.AnonymousCredentials{}, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func federationIntegrationCredentialCount(t *testing.T, repository iamstore.Repository, account, roleID string) int {
	t.Helper()
	count := 0
	if err := repository.View(t.Context(), func(tx iamstore.ReadTx) error {
		records, err := tx.PrincipalCredentials(account, roleID)
		count = len(records)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestOIDCFederationSDKCurrentPoliciesAndClaims(t *testing.T) {
	ctx := t.Context()
	c, source, _ := newFederationIntegrationCloud(t)
	root := c.iam("test", "test", "")
	role, _ := federationIntegrationRole(t, c, "test", "oidc-worker", `["sts:AssumeRoleWithWebIdentity","sts:TagSession","sts:SetSourceIdentity"]`)
	queue, err := c.sqs("test", "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("federated-work")})
	if err != nil {
		t.Fatal(err)
	}
	queueARN := "arn:aws:sqs:us-east-1:000000000000:federated-work"
	rolePolicy := `{"Statement":{"Effect":"Allow","Action":["sqs:SendMessage","sqs:ReceiveMessage"],"Resource":"` + queueARN + `","Condition":{"StringEquals":{"aws:PrincipalTag/team":"blue","aws:SourceIdentity":"token-source","federation.example.test:aud":"audience","federation.example.test:sub":"verified-subject"},"ForAnyValue:StringEquals":{"federation.example.test:amr":"pwd"}}}}`
	putRolePolicy(t, root, "oidc-worker", rolePolicy)
	managed, err := root.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("OIDCSession"), PolicyDocument: aws.String(allow(`"sqs:SendMessage"`, queueARN))})
	if err != nil {
		t.Fatal(err)
	}
	token := source.token(t, map[string]any{"https://aws.amazon.com/source_identity": "token-source", "https://aws.amazon.com/tags": map[string]any{"principal_tags": map[string]any{"team": []string{"blue"}}, "transitive_tag_keys": []string{"team"}}})
	issued, err := federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("web-session"), WebIdentityToken: aws.String(token), PolicyArns: []ststypes.PolicyDescriptorType{{Arn: managed.Policy.Arn}}, DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(issued.SourceIdentity) != "token-source" || aws.ToString(issued.SubjectFromWebIdentityToken) != "verified-subject" || aws.ToString(issued.Audience) != "audience" {
		t.Fatal("verified claims not returned")
	}
	who, err := c.sessionSTS(issued.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(who.Arn) != "arn:aws:sts::000000000000:assumed-role/oidc-worker/web-session" {
		t.Fatalf("issued credentials are unusable: %v %v", who, err)
	}
	sender := c.sessionSQS(issued.Credentials)
	send := func(wantError bool) {
		t.Helper()
		_, err := sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("verified federation")})
		if wantError {
			assertAPIError(t, err, "AccessDenied")
		} else if err != nil {
			t.Fatal(err)
		}
	}
	send(false)
	_, err = sender.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	assertAPIError(t, err, "AccessDenied")
	putRolePolicy(t, root, "oidc-worker", `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)
	send(true)
	putRolePolicy(t, root, "oidc-worker", rolePolicy)
	_, err = root.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{PolicyArn: managed.Policy.Arn, SetAsDefault: true, PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	send(true)
	_, err = root.SetDefaultPolicyVersion(ctx, &iam.SetDefaultPolicyVersionInput{PolicyArn: managed.Policy.Arn, VersionId: aws.String("v1")})
	if err != nil {
		t.Fatal(err)
	}
	send(false)
	boundary, err := root.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("OIDCReadOnly"), PolicyDocument: aws.String(allow(`"sqs:ReceiveMessage"`, queueARN))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.PutRolePermissionsBoundary(ctx, &iam.PutRolePermissionsBoundaryInput{RoleName: role.RoleName, PermissionsBoundary: boundary.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	send(true)
	_, err = root.DeleteRolePermissionsBoundary(ctx, &iam.DeleteRolePermissionsBoundaryInput{RoleName: role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	send(false)
	// Email is available for the trust decision, but is not retained as a
	// service authorization claim in the issued web identity session.
	putRolePolicy(t, root, "oidc-worker", `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"federation.example.test:email":"test@example.test"}}}}`)
	send(true)
}

func TestOIDCFederationSDKFailuresIssueNoCredentials(t *testing.T) {
	c, source, repository := newFederationIntegrationCloud(t)
	role, provider := federationIntegrationRole(t, c, "test", "restricted", `"sts:AssumeRoleWithWebIdentity"`)
	client := federationIntegrationUnsigned(c)
	root := c.iam("test", "test", "")
	for _, tc := range []struct{ name, token, role, code string }{
		{"malformed", "not-a-jwt", aws.ToString(role.Arn), "InvalidIdentityToken"},
		{"wrong-audience", source.token(t, map[string]any{"aud": "not-registered"}), aws.ToString(role.Arn), "InvalidIdentityToken"},
		{"wrong-subject", source.token(t, map[string]any{"sub": "not-trusted"}), aws.ToString(role.Arn), "AccessDenied"},
		{"tags-without-trust", source.token(t, map[string]any{"https://aws.amazon.com/tags": map[string]any{"principal_tags": map[string]any{"team": []string{"blue"}}}}), aws.ToString(role.Arn), "AccessDenied"},
		{"source-without-trust", source.token(t, map[string]any{"https://aws.amazon.com/source_identity": "token-source"}), aws.ToString(role.Arn), "AccessDenied"},
		{"missing-role", source.token(t, nil), "arn:aws:iam::000000000000:role/missing", "AccessDenied"},
		{"other-account", source.token(t, nil), "arn:aws:iam::123456789012:role/restricted", "InvalidIdentityToken"},
		// A generic unsigned endpoint has no authenticated region. The role ARN
		// selects the partition, which must have its own configured provider.
		{"other-partition", source.token(t, nil), "arn:aws-cn:iam::000000000000:role/restricted", "InvalidIdentityToken"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := client.AssumeRoleWithWebIdentity(t.Context(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(tc.role), RoleSessionName: aws.String("failed"), WebIdentityToken: aws.String(tc.token)})
			assertAPIError(t, err, tc.code)
			if out != nil && out.Credentials != nil {
				t.Fatal("failed request returned credentials")
			}
			if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != 0 {
				t.Fatal("failed federation persisted credentials")
			}
		})
	}
	_, err := root.DeleteOpenIDConnectProvider(t.Context(), &iam.DeleteOpenIDConnectProviderInput{OpenIDConnectProviderArn: aws.String(provider)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AssumeRoleWithWebIdentity(t.Context(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("missing-provider"), WebIdentityToken: aws.String(source.token(t, nil))})
	assertAPIError(t, err, "InvalidIdentityToken")
}

func TestOIDCFederationSDKRotationAndRecreationFence(t *testing.T) {
	c, source, repository := newFederationIntegrationCloud(t)
	role, provider := federationIntegrationRole(t, c, "test", "rotating", `"sts:AssumeRoleWithWebIdentity"`)
	client := federationIntegrationUnsigned(c)
	root := c.iam("test", "test", "")
	assume := func(token string) (*sts.AssumeRoleWithWebIdentityOutput, error) {
		return client.AssumeRoleWithWebIdentity(t.Context(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("rotating"), WebIdentityToken: aws.String(token)})
	}
	oldToken := source.token(t, nil)
	if _, err := assume(oldToken); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.key, source.kid = key, "rotated"
	source.mu.Unlock()
	if _, err := assume(source.token(t, nil)); err != nil {
		t.Fatal("new signing key was not refreshed", err)
	}
	_, err = assume(oldToken)
	assertAPIError(t, err, "InvalidIdentityToken")
	before := federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId))
	// A configured thumbprint change forces an uncached verification. During
	// that discovery, replace the actual IAM provider at the same ARN.
	_, err = root.UpdateOpenIDConnectProviderThumbprint(t.Context(), &iam.UpdateOpenIDConnectProviderThumbprintInput{OpenIDConnectProviderArn: aws.String(provider), ThumbprintList: []string{strings.Repeat("b", 40)}})
	if err != nil {
		t.Fatal(err)
	}
	hookErrors := make(chan error, 1)
	source.mu.Lock()
	source.hook = func() {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		_, err := root.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{OpenIDConnectProviderArn: aws.String(provider)})
		if err == nil {
			_, err = root.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{Url: aws.String("https://federation.example.test"), ClientIDList: []string{"audience"}, ThumbprintList: []string{strings.Repeat("b", 40)}})
		}
		hookErrors <- err
	}
	source.mu.Unlock()
	_, err = assume(source.token(t, nil))
	assertAPIError(t, err, "InvalidIdentityToken")
	select {
	case hookErr := <-hookErrors:
		if hookErr != nil {
			t.Fatal(hookErr)
		}
	default:
		t.Fatal("configured provider change did not trigger discovery")
	}
	if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != before {
		t.Fatal("stale provider verification minted credentials")
	}
}

func TestOIDCFederationSDKOrganizationSCP(t *testing.T) {
	c, source, _ := newFederationIntegrationCloud(t)
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	ctx := t.Context()
	if _, err := org.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
		t.Fatal(err)
	}
	account, err := org.CreateAccount(ctx, &organizations.CreateAccountInput{AccountName: aws.String("federation"), Email: aws.String("federation@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	account.CreateAccountStatus = waitAccountCreation(t, org, account.CreateAccountStatus, nil)
	accountID := aws.ToString(account.CreateAccountStatus.AccountId)
	role, _ := federationIntegrationRole(t, c, accountID, "member-web", `"sts:AssumeRoleWithWebIdentity"`)
	putRolePolicy(t, c.iam(accountID, "test", ""), "member-web", allow(`"sqs:SendMessage"`, "*"))
	queue, err := c.sqs(accountID, "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("member-web")})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("member"), WebIdentityToken: aws.String(source.token(t, nil))})
	if err != nil {
		t.Fatal(err)
	}
	sender := c.sessionSQS(issued.Credentials)
	if _, err := sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("before")}); err != nil {
		t.Fatal(err)
	}
	policy, err := org.CreatePolicy(ctx, &organizations.CreatePolicyInput{Name: aws.String("federation-deny-send"), Description: aws.String("session control"), Type: orgtypes.PolicyTypeServiceControlPolicy, Content: aws.String(`{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := org.AttachPolicy(ctx, &organizations.AttachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	_, err = sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("denied")})
	assertAPIError(t, err, "AccessDenied")
	if _, err := org.DetachPolicy(ctx, &organizations.DetachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("after")}); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCFederationSDKProviderAccountScope(t *testing.T) {
	c, source, _ := newFederationIntegrationCloud(t)
	localRole, _ := federationIntegrationRole(t, c, "test", "scoped", `"sts:AssumeRoleWithWebIdentity"`)
	remoteRole, remoteProvider := federationIntegrationRole(t, c, "123456789012", "scoped", `"sts:AssumeRoleWithWebIdentity"`)
	remoteIAM := c.iam("123456789012", "test", "")
	ctx := t.Context()
	if _, err := remoteIAM.RemoveClientIDFromOpenIDConnectProvider(ctx, &iam.RemoveClientIDFromOpenIDConnectProviderInput{OpenIDConnectProviderArn: aws.String(remoteProvider), ClientID: aws.String("audience")}); err != nil {
		t.Fatal(err)
	}
	if _, err := remoteIAM.AddClientIDToOpenIDConnectProvider(ctx, &iam.AddClientIDToOpenIDConnectProviderInput{OpenIDConnectProviderArn: aws.String(remoteProvider), ClientID: aws.String("remote-audience")}); err != nil {
		t.Fatal(err)
	}
	trust := `{"Statement":{"Effect":"Allow","Principal":{"Federated":"` + remoteProvider + `"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"federation.example.test:aud":"remote-audience","federation.example.test:sub":"verified-subject"}}}}`
	if _, err := remoteIAM.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: remoteRole.RoleName, PolicyDocument: aws.String(trust)}); err != nil {
		t.Fatal(err)
	}
	client := federationIntegrationUnsigned(c)
	assume := func(roleARN *string, token string) (*sts.AssumeRoleWithWebIdentityOutput, error) {
		return client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: roleARN, RoleSessionName: aws.String("scoped"), WebIdentityToken: aws.String(token)})
	}
	localToken := source.token(t, nil)
	if _, err := assume(localRole.Arn, localToken); err != nil {
		t.Fatal(err)
	}
	_, err := assume(remoteRole.Arn, localToken)
	assertAPIError(t, err, "InvalidIdentityToken")
	remoteToken := source.token(t, map[string]any{"aud": "remote-audience"})
	remoteSession, err := assume(remoteRole.Arn, remoteToken)
	if err != nil {
		t.Fatal(err)
	}
	who, err := c.sessionSTS(remoteSession.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(who.Account) != "123456789012" || aws.ToString(who.Arn) != "arn:aws:sts::123456789012:assumed-role/scoped/scoped" {
		t.Fatal("federation session escaped the destination account")
	}
	_, err = assume(localRole.Arn, remoteToken)
	assertAPIError(t, err, "InvalidIdentityToken")
}

func TestOIDCFederationSDKTrustChangeDuringVerification(t *testing.T) {
	c, source, repository := newFederationIntegrationCloud(t)
	role, provider := federationIntegrationRole(t, c, "test", "changed-trust", `"sts:AssumeRoleWithWebIdentity"`)
	root := c.iam("test", "test", "")
	hookErrors := make(chan error, 1)
	source.mu.Lock()
	source.hook = func() {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		trust := `{"Statement":{"Effect":"Deny","Principal":{"Federated":"` + provider + `"},"Action":"sts:AssumeRoleWithWebIdentity"}}`
		_, err := root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: role.RoleName, PolicyDocument: aws.String(trust)})
		hookErrors <- err
	}
	source.mu.Unlock()
	out, err := federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(t.Context(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("changed-trust"), WebIdentityToken: aws.String(source.token(t, nil))})
	assertAPIError(t, err, "AccessDenied")
	select {
	case hookErr := <-hookErrors:
		if hookErr != nil {
			t.Fatal(hookErr)
		}
	default:
		t.Fatal("verification did not invoke the issuer")
	}
	if out != nil && out.Credentials != nil {
		t.Fatal("changed trust returned credentials")
	}
	if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != 0 {
		t.Fatal("stale role trust persisted credentials")
	}
}
