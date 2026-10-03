package stackd_test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"stackd"
	"stackd/storage"
	iamstore "stackd/storage/iam"
)

const samlIntegrationIssuer = "https://saml.example.test"
const samlIntegrationAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
const samlIntegrationAttributes = "https://aws.amazon.com/SAML/Attributes/"

type samlIntegrationSigner struct {
	key         *rsa.PrivateKey
	certificate []byte
}

func newSAMLIntegrationSigner(t *testing.T) samlIntegrationSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stackd local SAML integration fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return samlIntegrationSigner{key: key, certificate: der}
}

func (s samlIntegrationSigner) metadata() string {
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + samlIntegrationIssuer + `"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(s.certificate) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + samlIntegrationIssuer + `/login"/></IDPSSODescriptor></EntityDescriptor>`
}

func samlIntegrationChild(parent *etree.Element, name, text string) *etree.Element {
	child := parent.CreateElement(name)
	if text != "" {
		child.SetText(text)
	}
	return child
}

func samlIntegrationXML(t *testing.T, element *etree.Element) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(element)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type samlIntegrationClaims struct {
	subject, recipient, source string
	tags, encrypted            bool
}

func (s samlIntegrationSigner) token(t *testing.T, roleARN, providerARN string, claims samlIntegrationClaims) string {
	t.Helper()
	if claims.subject == "" {
		claims.subject = "verified-subject"
	}
	if claims.recipient == "" {
		claims.recipient = "https://signin.aws.amazon.com/saml"
	}
	now := time.Now().UTC()
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", samlIntegrationAssertionNS)
	a.CreateAttr("ID", "_assertion")
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	samlIntegrationChild(a, "saml:Issuer", samlIntegrationIssuer)
	subject := samlIntegrationChild(a, "saml:Subject", "")
	samlIntegrationChild(subject, "saml:NameID", claims.subject).CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
	confirmation := samlIntegrationChild(subject, "saml:SubjectConfirmation", "")
	confirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	data := samlIntegrationChild(confirmation, "saml:SubjectConfirmationData", "")
	data.CreateAttr("Recipient", claims.recipient)
	data.CreateAttr("NotOnOrAfter", now.Add(5*time.Minute).Format(time.RFC3339))
	conditions := samlIntegrationChild(a, "saml:Conditions", "")
	conditions.CreateAttr("NotBefore", now.Add(-time.Minute).Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", now.Add(5*time.Minute).Format(time.RFC3339))
	samlIntegrationChild(samlIntegrationChild(conditions, "saml:AudienceRestriction", ""), "saml:Audience", "urn:amazon:webservices")
	authn := samlIntegrationChild(a, "saml:AuthnStatement", "")
	authn.CreateAttr("AuthnInstant", now.Add(-time.Minute).Format(time.RFC3339))
	samlIntegrationChild(samlIntegrationChild(authn, "saml:AuthnContext", ""), "saml:AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	attributes := samlIntegrationChild(a, "saml:AttributeStatement", "")
	attribute := func(name, value string) {
		entry := samlIntegrationChild(attributes, "saml:Attribute", "")
		entry.CreateAttr("Name", samlIntegrationAttributes+name)
		samlIntegrationChild(entry, "saml:AttributeValue", value)
	}
	attribute("Role", roleARN+","+providerARN)
	attribute("RoleSessionName", "saml-session")
	if claims.source != "" {
		attribute("SourceIdentity", claims.source)
	}
	if claims.tags {
		attribute("PrincipalTag:team", "blue")
		attribute("TransitiveTagKeys", "team")
	}
	signer, err := dsig.NewSigningContext(s.key, [][]byte{s.certificate})
	if err != nil {
		t.Fatal(err)
	}
	signer.IdAttribute = "ID"
	signer.Hash = crypto.SHA256
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signature, err := signer.ConstructSignature(a, true)
	if err != nil {
		t.Fatal(err)
	}
	a.InsertChildAt(1, signature)
	if claims.encrypted {
		a = s.encrypt(t, a)
	}
	r := etree.NewElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	r.CreateAttr("ID", "_response")
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	issuer := samlIntegrationChild(r, "saml:Issuer", samlIntegrationIssuer)
	issuer.CreateAttr("xmlns:saml", samlIntegrationAssertionNS)
	samlIntegrationChild(samlIntegrationChild(r, "samlp:Status", ""), "samlp:StatusCode", "").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	r.AddChild(a)
	return base64.StdEncoding.EncodeToString(samlIntegrationXML(t, r))
}

func (s samlIntegrationSigner) encrypt(t *testing.T, assertion *etree.Element) *etree.Element {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nonce, nonce, samlIntegrationXML(t, assertion), nil)
	wrapped, err := rsa.EncryptOAEPWithOptions(rand.Reader, &s.key.PublicKey, key, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	encrypted := etree.NewElement("saml:EncryptedAssertion")
	encrypted.CreateAttr("xmlns:saml", samlIntegrationAssertionNS)
	encrypted.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	encrypted.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
	encrypted.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	data := samlIntegrationChild(encrypted, "xenc:EncryptedData", "")
	data.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	samlIntegrationChild(data, "xenc:EncryptionMethod", "").CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#aes256-gcm")
	wrappedElement := samlIntegrationChild(samlIntegrationChild(data, "ds:KeyInfo", ""), "xenc:EncryptedKey", "")
	method := samlIntegrationChild(wrappedElement, "xenc:EncryptionMethod", "")
	method.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#rsa-oaep")
	samlIntegrationChild(method, "ds:DigestMethod", "").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	samlIntegrationChild(method, "xenc11:MGF", "").CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha256")
	samlIntegrationChild(samlIntegrationChild(wrappedElement, "xenc:CipherData", ""), "xenc:CipherValue", base64.StdEncoding.EncodeToString(wrapped))
	samlIntegrationChild(samlIntegrationChild(data, "xenc:CipherData", ""), "xenc:CipherValue", base64.StdEncoding.EncodeToString(ciphertext))
	return encrypted
}

func newSAMLIntegrationCloud(t *testing.T) (cloudClients, iamstore.Repository) {
	t.Helper()
	backends := storage.NewMemory()
	cloud, err := stackd.New(stackd.Config{Storage: backends})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cloud)
	t.Cleanup(func() {
		server.Close()
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
	})
	return cloudClients{server}, backends.IAM
}

func samlIntegrationRole(t *testing.T, c cloudClients, signer samlIntegrationSigner, name string, requiredEncryption bool) (*iamtypes.Role, string) {
	t.Helper()
	root := c.iam("test", "test", "")
	input := &iam.CreateSAMLProviderInput{Name: aws.String(name), SAMLMetadataDocument: aws.String(signer.metadata())}
	if requiredEncryption {
		private, err := x509.MarshalPKCS8PrivateKey(signer.key)
		if err != nil {
			t.Fatal(err)
		}
		input.AddPrivateKey = aws.String(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})))
		input.AssertionEncryptionMode = iamtypes.AssertionEncryptionModeTypeRequired
	}
	provider, err := root.CreateSAMLProvider(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	providerARN := aws.ToString(provider.SAMLProviderArn)
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Federated":%q},"Action":["sts:AssumeRoleWithSAML","sts:TagSession","sts:SetSourceIdentity"],"Condition":{"StringEquals":{"saml:aud":"https://signin.aws.amazon.com/saml","saml:sub":"verified-subject","aws:PrincipalType":"User","aws:PrincipalAccount":"000000000000","aws:userid":%q},"Null":{"aws:PrincipalArn":"true"}}}}`, providerARN, providerARN)
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), Path: aws.String("/saml/"), AssumeRolePolicyDocument: aws.String(trust), MaxSessionDuration: aws.Int32(7200), Tags: []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("red")}}})
	if err != nil {
		t.Fatal(err)
	}
	return role.Role, providerARN
}

func TestSAMLFederationSDKActualIAMAndDownstreamPermissions(t *testing.T) {
	ctx := t.Context()
	c, repository := newSAMLIntegrationCloud(t)
	root := c.iam("test", "test", "")
	signer := newSAMLIntegrationSigner(t)
	role, provider := samlIntegrationRole(t, c, signer, "saml-worker", false)
	queue, err := c.sqs("test", "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("saml-work")})
	if err != nil {
		t.Fatal(err)
	}
	queueARN := "arn:aws:sqs:us-east-1:000000000000:saml-work"
	qualifier := sha1.Sum([]byte(samlIntegrationIssuer + "000000000000/saml-worker"))
	rolePolicy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["sqs:SendMessage","sqs:ReceiveMessage"],"Resource":%q,"Condition":{"StringEquals":{"aws:PrincipalTag/team":"blue","aws:SourceIdentity":"saml-source","saml:sub":"verified-subject","saml:sub_type":"persistent","saml:namequalifier":%q}}}}`, queueARN, base64.StdEncoding.EncodeToString(qualifier[:]))
	putRolePolicy(t, root, "saml-worker", rolePolicy)
	client := federationIntegrationUnsigned(c)
	for _, bad := range []samlIntegrationClaims{{subject: "untrusted-subject"}, {recipient: "https://other.example.test/saml"}} {
		out, err := client.AssumeRoleWithSAML(ctx, &sts.AssumeRoleWithSAMLInput{RoleArn: role.Arn, PrincipalArn: aws.String(provider), SAMLAssertion: aws.String(signer.token(t, aws.ToString(role.Arn), provider, bad))})
		assertAPIError(t, err, "AccessDenied")
		if out != nil && out.Credentials != nil {
			t.Fatal("trust failure returned credentials")
		}
		if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != 0 {
			t.Fatal("trust failure persisted credentials")
		}
	}
	issued, err := client.AssumeRoleWithSAML(ctx, &sts.AssumeRoleWithSAMLInput{RoleArn: role.Arn, PrincipalArn: aws.String(provider), SAMLAssertion: aws.String(signer.token(t, aws.ToString(role.Arn), provider, samlIntegrationClaims{tags: true, source: "saml-source"})), Policy: aws.String(allow(`"sqs:SendMessage"`, queueARN)), DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(issued.NameQualifier) != base64.StdEncoding.EncodeToString(qualifier[:]) || aws.ToString(issued.Subject) != "verified-subject" || aws.ToString(issued.SourceIdentity) != "saml-source" {
		t.Fatal("verified SAML claims were not returned")
	}
	if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != 1 {
		t.Fatal("successful assumption did not persist exactly one credential")
	}
	who, err := c.sessionSTS(issued.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(who.Arn) != "arn:aws:sts::000000000000:assumed-role/saml-worker/saml-session" {
		t.Fatalf("issued credentials cannot sign downstream calls: %v %v", who, err)
	}
	sender := c.sessionSQS(issued.Credentials)
	send := func(denied bool) {
		t.Helper()
		_, err := sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("SAML authorized")})
		if denied {
			assertAPIError(t, err, "AccessDenied")
		} else if err != nil {
			t.Fatal(err)
		}
	}
	send(false)
	_, err = sender.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	assertAPIError(t, err, "AccessDenied")
	putRolePolicy(t, root, "saml-worker", `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)
	send(true)
	putRolePolicy(t, root, "saml-worker", rolePolicy)
	send(false)
	// Recipient is trusted at assumption time but is not available to later
	// resource authorization. Only the documented retained SAML claims survive.
	putRolePolicy(t, root, "saml-worker", `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"saml:aud":"https://signin.aws.amazon.com/saml"}}}}`)
	send(true)
}

func TestSAMLFederationSDKActualIAMProviderRotationAndEncryption(t *testing.T) {
	ctx := t.Context()
	c, repository := newSAMLIntegrationCloud(t)
	root := c.iam("test", "test", "")
	signer := newSAMLIntegrationSigner(t)
	role, provider := samlIntegrationRole(t, c, signer, "encrypted-saml", true)
	client := federationIntegrationUnsigned(c)
	assume := func(token string) (*sts.AssumeRoleWithSAMLOutput, error) {
		return client.AssumeRoleWithSAML(ctx, &sts.AssumeRoleWithSAMLInput{RoleArn: role.Arn, PrincipalArn: aws.String(provider), SAMLAssertion: aws.String(token)})
	}
	_, err := assume(signer.token(t, aws.ToString(role.Arn), provider, samlIntegrationClaims{}))
	assertAPIError(t, err, "InvalidIdentityToken")
	if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != 0 {
		t.Fatal("plaintext issued credentials despite required encryption")
	}
	oldToken := signer.token(t, aws.ToString(role.Arn), provider, samlIntegrationClaims{encrypted: true})
	if _, err := assume(oldToken); err != nil {
		t.Fatal(err)
	}
	before, err := root.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{SAMLProviderArn: aws.String(provider)})
	if err != nil {
		t.Fatal(err)
	}
	replacement := newSAMLIntegrationSigner(t)
	_, err = root.UpdateSAMLProvider(ctx, &iam.UpdateSAMLProviderInput{SAMLProviderArn: aws.String(provider), SAMLMetadataDocument: aws.String(replacement.metadata()), AssertionEncryptionMode: iamtypes.AssertionEncryptionModeTypeAllowed})
	if err != nil {
		t.Fatal(err)
	}
	_, err = assume(oldToken)
	assertAPIError(t, err, "InvalidIdentityToken")
	if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != 1 {
		t.Fatal("retired signing key minted a credential")
	}
	newToken := replacement.token(t, aws.ToString(role.Arn), provider, samlIntegrationClaims{})
	if _, err := assume(newToken); err != nil {
		t.Fatal(err)
	}
	updated, err := root.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{SAMLProviderArn: aws.String(provider)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(updated.SAMLProviderUUID) != aws.ToString(before.SAMLProviderUUID) {
		t.Fatal("metadata rotation changed provider incarnation")
	}
	_, err = root.DeleteSAMLProvider(ctx, &iam.DeleteSAMLProviderInput{SAMLProviderArn: aws.String(provider)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = assume(newToken)
	assertAPIError(t, err, "InvalidIdentityToken")
	_, err = root.CreateSAMLProvider(ctx, &iam.CreateSAMLProviderInput{Name: aws.String("encrypted-saml"), SAMLMetadataDocument: aws.String(replacement.metadata())})
	if err != nil {
		t.Fatal(err)
	}
	recreated, err := root.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{SAMLProviderArn: aws.String(provider)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(recreated.SAMLProviderUUID) == aws.ToString(before.SAMLProviderUUID) {
		t.Fatal("recreation reused provider incarnation")
	}
	// Real AWS preserves ARN-based role trust across provider recreation.
	if _, err := assume(newToken); err != nil {
		t.Fatal("existing role trust rejected replacement provider", err)
	}
	if federationIntegrationCredentialCount(t, repository, "000000000000", aws.ToString(role.RoleId)) != 3 {
		t.Fatal("rotation/recreation credential accounting differs")
	}
	if strings.Contains(aws.ToString(updated.SAMLMetadataDocument), "PRIVATE KEY") {
		t.Fatal("metadata response disclosed private signing material")
	}
}
