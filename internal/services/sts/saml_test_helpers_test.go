package sts

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type samlTestFixture struct {
	key         *rsa.PrivateKey
	certificate []byte
	provider    SAMLProviderSnapshot
	roleARN     string
	now         time.Time
}

func newSAMLTestFixture(t *testing.T) samlTestFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stackd SAML test signing certificate"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return samlTestFixture{key: key, certificate: der, now: now, roleARN: "arn:aws:iam::123456789012:role/saml-test", provider: SAMLProviderSnapshot{ARN: "arn:aws:iam::123456789012:saml-provider/saml-test", ID: "SAMLTESTPROVIDER", Version: "test-v1", AssertionEncryptionMode: "Allowed", Issuers: []SAMLIssuerSnapshot{{EntityID: "https://idp.example.test", SigningCertificates: [][]byte{der}}}, PrivateKeys: []SAMLDecryptionKey{{ID: "test-key", PKCS8DER: private}}}}
}

func samlTestChild(parent *etree.Element, name, text string) *etree.Element {
	child := parent.CreateElement(name)
	if text != "" {
		child.SetText(text)
	}
	return child
}

func (f samlTestFixture) assertion() *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", samlAssertionNS)
	a.CreateAttr("ID", "_assertion")
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", f.now.Format(time.RFC3339))
	samlTestChild(a, "saml:Issuer", f.provider.Issuers[0].EntityID)
	subject := samlTestChild(a, "saml:Subject", "")
	name := samlTestChild(subject, "saml:NameID", "subject-123")
	name.CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
	confirmation := samlTestChild(subject, "saml:SubjectConfirmation", "")
	confirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	data := samlTestChild(confirmation, "saml:SubjectConfirmationData", "")
	data.CreateAttr("Recipient", "https://signin.aws.amazon.com/saml")
	data.CreateAttr("NotOnOrAfter", f.now.Add(5*time.Minute).Format(time.RFC3339))
	conditions := samlTestChild(a, "saml:Conditions", "")
	conditions.CreateAttr("NotBefore", f.now.Add(-time.Minute).Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", f.now.Add(5*time.Minute).Format(time.RFC3339))
	samlTestChild(samlTestChild(conditions, "saml:AudienceRestriction", ""), "saml:Audience", "urn:amazon:webservices")
	authn := samlTestChild(a, "saml:AuthnStatement", "")
	authn.CreateAttr("AuthnInstant", f.now.Add(-time.Minute).Format(time.RFC3339))
	samlTestChild(samlTestChild(authn, "saml:AuthnContext", ""), "saml:AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	samlTestChild(a, "saml:AttributeStatement", "")
	samlTestAttribute(a, "Role", f.roleARN+","+f.provider.ARN)
	samlTestAttribute(a, "RoleSessionName", "saml-session")
	return a
}

func samlTestAttribute(assertion *etree.Element, name string, values ...string) {
	statement := samlChildren(assertion, samlAssertionNS, "AttributeStatement")[0]
	attribute := samlTestChild(statement, "saml:Attribute", "")
	attribute.CreateAttr("Name", samlAttributePrefix+name)
	for _, value := range values {
		samlTestChild(attribute, "saml:AttributeValue", value)
	}
}

func (f samlTestFixture) sign(t *testing.T, element *etree.Element) *etree.Element {
	t.Helper()
	signer, err := dsig.NewSigningContext(f.key, [][]byte{f.certificate})
	if err != nil {
		t.Fatal(err)
	}
	signer.IdAttribute = "ID"
	signer.Hash = crypto.SHA256
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signature, err := signer.ConstructSignature(element, true)
	if err != nil {
		t.Fatal(err)
	}
	signed := element.Copy()
	signed.InsertChildAt(1, signature)
	return signed
}

func (f samlTestFixture) response(assertion *etree.Element) *etree.Element {
	r := etree.NewElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", samlProtocolNS)
	r.CreateAttr("ID", "_response")
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", f.now.Format(time.RFC3339))
	issuer := samlTestChild(r, "saml:Issuer", f.provider.Issuers[0].EntityID)
	issuer.CreateAttr("xmlns:saml", samlAssertionNS)
	samlTestChild(samlTestChild(r, "samlp:Status", ""), "samlp:StatusCode", "").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	r.AddChild(assertion)
	return r
}

func samlTestBytes(t *testing.T, element *etree.Element) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(element.Copy())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f samlTestFixture) encrypt(t *testing.T, assertion *etree.Element, keyBytes int, gcm bool, oaep *rsa.OAEPOptions, legacy bool) *etree.Element {
	t.Helper()
	secret := make([]byte, keyBytes)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := samlTestBytes(t, assertion)
	var ciphertext []byte
	if gcm {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		ciphertext = aead.Seal(nonce, nonce, plaintext, nil)
	} else {
		padding := aes.BlockSize - len(plaintext)%aes.BlockSize
		plaintext = append(plaintext, make([]byte, padding)...)
		plaintext[len(plaintext)-1] = byte(padding)
		ciphertext = make([]byte, aes.BlockSize+len(plaintext))
		if _, err := rand.Read(ciphertext[:aes.BlockSize]); err != nil {
			t.Fatal(err)
		}
		cipher.NewCBCEncrypter(block, ciphertext[:aes.BlockSize]).CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	}
	wrapped, err := rsa.EncryptOAEPWithOptions(rand.Reader, &f.key.PublicKey, secret, oaep)
	if err != nil {
		t.Fatal(err)
	}
	e := etree.NewElement("saml:EncryptedAssertion")
	e.CreateAttr("xmlns:saml", samlAssertionNS)
	e.CreateAttr("xmlns:xenc", samlEncryptionNS)
	e.CreateAttr("xmlns:xenc11", samlEncryption11NS)
	e.CreateAttr("xmlns:ds", samlSignatureNS)
	data := samlTestChild(e, "xenc:EncryptedData", "")
	data.CreateAttr("Type", samlEncryptionNS+"Element")
	data.CreateAttr("Id", "_encrypted")
	algorithm := samlEncryptionNS + "aes128-cbc"
	if keyBytes == 32 {
		algorithm = samlEncryptionNS + "aes256-cbc"
	}
	if gcm {
		algorithm = samlEncryption11NS + "aes128-gcm"
		if keyBytes == 32 {
			algorithm = samlEncryption11NS + "aes256-gcm"
		}
	}
	samlTestChild(data, "xenc:EncryptionMethod", "").CreateAttr("Algorithm", algorithm)
	key := samlTestChild(samlTestChild(data, "ds:KeyInfo", ""), "xenc:EncryptedKey", "")
	method := samlTestChild(key, "xenc:EncryptionMethod", "")
	algorithm = samlEncryption11NS + "rsa-oaep"
	if legacy {
		algorithm = samlEncryptionNS + "rsa-oaep-mgf1p"
	}
	method.CreateAttr("Algorithm", algorithm)
	digest := map[crypto.Hash]string{crypto.SHA1: samlSignatureNS + "sha1", crypto.SHA256: samlEncryptionNS + "sha256", crypto.SHA384: "http://www.w3.org/2001/04/xmldsig-more#sha384", crypto.SHA512: samlEncryptionNS + "sha512"}
	mgf := map[crypto.Hash]string{crypto.SHA1: "mgf1sha1", crypto.SHA256: "mgf1sha256", crypto.SHA384: "mgf1sha384", crypto.SHA512: "mgf1sha512"}
	samlTestChild(method, "ds:DigestMethod", "").CreateAttr("Algorithm", digest[oaep.Hash])
	if !legacy {
		samlTestChild(method, "xenc11:MGF", "").CreateAttr("Algorithm", samlEncryption11NS+mgf[oaep.MGFHash])
	}
	if len(oaep.Label) != 0 {
		samlTestChild(method, "xenc:OAEPparams", base64.StdEncoding.EncodeToString(oaep.Label))
	}
	samlTestChild(samlTestChild(key, "xenc:CipherData", ""), "xenc:CipherValue", base64.StdEncoding.EncodeToString(wrapped))
	samlTestChild(samlTestChild(data, "xenc:CipherData", ""), "xenc:CipherValue", base64.StdEncoding.EncodeToString(ciphertext))
	return e
}
