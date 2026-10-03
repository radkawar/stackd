package stackd_test

import (
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/storage"
)

func TestSQLiteSAMLRecoversSigningTrustAndPrivateDecryptionMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saml.sqlite")
	backends := &storage.Backends{}
	c, close := openSQLiteCloud(t, path, backends, nil)
	signer := newSAMLIntegrationSigner(t)
	role, provider := samlIntegrationRole(t, c, signer, "durable-saml", true)
	token := signer.token(t, aws.ToString(role.Arn), provider, samlIntegrationClaims{encrypted: true, tags: true, source: "restored-saml"})
	close()
	c, close = openSQLiteCloud(t, path, backends, nil)
	request := &sts.AssumeRoleWithSAMLInput{RoleArn: role.Arn, PrincipalArn: &provider, SAMLAssertion: &token}
	issued, err := federationIntegrationUnsigned(c).AssumeRoleWithSAML(t.Context(), request)
	if err != nil {
		t.Fatal("SAML provider trust or decryption key lost", err)
	}
	putRolePolicy(t, c.iam("test", "test", ""), "durable-saml", `{"Statement":{"Effect":"Allow","Action":"sqs:ListQueues","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"blue","aws:SourceIdentity":"restored-saml","saml:sub":"verified-subject"}}}}`)
	close()
	c, _ = openSQLiteCloud(t, path, backends, nil)
	if _, err := c.sessionSQS(issued.Credentials).ListQueues(t.Context(), &sqs.ListQueuesInput{}); err != nil {
		t.Fatal("verified SAML session claims lost", err)
	}
	if _, err := c.iam("test", "test", "").DeleteSAMLProvider(t.Context(), &iam.DeleteSAMLProviderInput{SAMLProviderArn: &provider}); err != nil {
		t.Fatal(err)
	}
	_, err = federationIntegrationUnsigned(c).AssumeRoleWithSAML(t.Context(), request)
	assertAPIError(t, err, "InvalidIdentityToken")
}

func TestSQLiteOIDCRestoresProviderAndAuthenticatedSessionClaims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oidc.sqlite")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	discovery := &federationIntegrationDiscovery{key: key, kid: "durable"}
	start := func() (cloudClients, func()) {
		backends, closeDatabase := openSQLiteBackends(t, path)
		c := clockCloud(t, stackd.Config{Storage: backends, OIDCDiscovery: discovery})
		close := func() {
			if err := c.server.Config.Handler.(*stackd.Stack).Close(); err != nil {
				t.Error(err)
			}
			c.server.Close()
			closeDatabase()
		}
		t.Cleanup(close)
		return c, close
	}
	c, close := start()
	role, _ := federationIntegrationRole(t, c, "test", "durable-oidc", `"sts:AssumeRoleWithWebIdentity"`)
	putRolePolicy(t, c.iam("test", "test", ""), "durable-oidc", `{"Statement":{"Effect":"Allow","Action":"sqs:ListQueues","Resource":"*","Condition":{"StringEquals":{"federation.example.test:sub":"verified-subject","federation.example.test:aud":"audience"}}}}`)
	token := discovery.token(t, nil)
	close()
	c, close = start()
	issued, err := federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(t.Context(), &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("restored"), WebIdentityToken: &token})
	if err != nil {
		t.Fatal("OIDC configuration or role trust lost", err)
	}
	close()
	c, _ = start()
	if _, err := c.sessionSQS(issued.Credentials).ListQueues(t.Context(), &sqs.ListQueuesInput{}); err != nil {
		t.Fatal("authenticated OIDC session claims lost", err)
	}
}
