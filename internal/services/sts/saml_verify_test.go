package sts

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestSAMLSignaturesAndIssuerIsolation(t *testing.T) {
	f := newSAMLTestFixture(t)
	for _, mode := range []string{"assertion", "both"} {
		t.Run(mode, func(t *testing.T) {
			a := f.assertion()
			if mode != "response" {
				a = f.sign(t, a)
			}
			r := f.response(a)
			if mode != "assertion" {
				r = f.sign(t, r)
			}
			parsed, parseErr := parseSAMLXML(samlTestBytes(t, r))
			if parseErr != nil {
				t.Fatalf("parse: %v", parseErr)
			}
			if mode != "response" {
				_, sigErr := verifySAMLSignature(samlChildren(parsed, samlAssertionNS, "Assertion")[0], f.provider.Issuers[0].SigningCertificates, f.now)
				if sigErr != nil {
					t.Fatalf("assertion signature: %v", sigErr)
				}
			}
			c, err := verifySAMLResponse(samlTestBytes(t, r), f.provider, f.roleARN, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if c.SessionName != "saml-session" || c.Subject != "subject-123" || c.SubjectType != "persistent" || c.Audience != "https://signin.aws.amazon.com/saml" || c.NameQualifier == "" {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
	raw := samlTestBytes(t, f.response(f.sign(t, f.assertion())))
	other := newSAMLTestFixture(t)
	tests := []struct {
		name     string
		raw      []byte
		provider SAMLProviderSnapshot
	}{
		{"unsigned", samlTestBytes(t, f.response(f.assertion())), f.provider},
		{"tampered subject", bytes.Replace(raw, []byte("subject-123"), []byte("subject-999"), 1), f.provider},
		{"tampered role", bytes.Replace(raw, []byte("role/saml-test"), []byte("role/administrator"), 1), f.provider},
		{"untrusted KeyInfo", samlTestBytes(t, f.response(other.sign(t, f.assertion()))), f.provider},
	}
	provider := f.provider
	provider.Issuers = []SAMLIssuerSnapshot{{EntityID: "https://other.example.test", SigningCertificates: [][]byte{f.certificate}}, {EntityID: f.provider.Issuers[0].EntityID, SigningCertificates: [][]byte{other.certificate}}}
	tests = append(tests, struct {
		name     string
		raw      []byte
		provider SAMLProviderSnapshot
	}{"certificate belongs to other issuer", raw, provider})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifySAMLResponse(test.raw, test.provider, f.roleARN, f.now); err == nil || err.Code != "InvalidIdentityToken" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSAMLRejectsXMLAmbiguities(t *testing.T) {
	f := newSAMLTestFixture(t)
	valid := f.response(f.sign(t, f.assertion()))
	duplicate := valid.Copy()
	extra := f.assertion()
	extra.CreateAttr("ID", "_extra")
	duplicate.AddChild(extra)
	wrapped := valid.Copy()
	extension := wrapped.CreateElement("extension")
	extra = f.assertion()
	extra.CreateAttr("ID", "_extra")
	extension.AddChild(extra)
	raw := samlTestBytes(t, valid)
	tests := map[string][]byte{
		"two assertions":         samlTestBytes(t, duplicate),
		"wrapped assertion":      samlTestBytes(t, wrapped),
		"duplicate ID":           bytes.Replace(raw, []byte(`ID="_response"`), []byte(`ID="_assertion"`), 1),
		"duplicate ID spelling":  bytes.Replace(raw, []byte(`ID="_response"`), []byte(`ID="_response" xml:id="_assertion"`), 1),
		"duplicate attribute":    bytes.Replace(raw, []byte(`Version="2.0"`), []byte(`Version="2.0" Version="2.0"`), 1),
		"doctype":                append([]byte(`<!DOCTYPE r [<!ENTITY test SYSTEM "file:///etc/passwd">]>`), raw...),
		"external reference":     bytes.Replace(raw, []byte(`URI="#_assertion"`), []byte(`URI="https://idp.example.test/assertion"`), 1),
		"empty reference":        bytes.Replace(raw, []byte(`URI="#_assertion"`), []byte(`URI=""`), 1),
		"multiple roots":         append(append([]byte{}, raw...), raw...),
		"processing instruction": append([]byte(`<?fetch href="https://idp.example.test"?>`), raw...),
		"deep nesting":           []byte(strings.Repeat("<r>", 65) + strings.Repeat("</r>", 65)),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := verifySAMLResponse(raw, f.provider, f.roleARN, f.now); err == nil {
				t.Fatal("ambiguous assertion accepted")
			}
		})
	}
}

func TestSAMLEncryptionAlgorithmsAndRotation(t *testing.T) {
	f := newSAMLTestFixture(t)
	for _, size := range []int{16, 32} {
		for _, gcm := range []bool{false, true} {
			for _, legacy := range []bool{false, true} {
				t.Run(fmt.Sprintf("AES%d/gcm=%v/legacy=%v", size*8, gcm, legacy), func(t *testing.T) {
					options := &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1, Label: []byte("test-label")}
					if !legacy {
						options.MGFHash = crypto.SHA384
					}
					encrypted := f.encrypt(t, f.sign(t, f.assertion()), size, gcm, options, legacy)
					if _, err := verifySAMLResponse(samlTestBytes(t, f.response(encrypted)), f.provider, f.roleARN, f.now); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
	a := f.assertion()
	data := samlChildren(samlChildren(samlChildren(a, samlAssertionNS, "Subject")[0], samlAssertionNS, "SubjectConfirmation")[0], samlAssertionNS, "SubjectConfirmationData")[0]
	data.CreateAttr("Recipient", "https://us-east-1.signin.aws.amazon.com/saml/acs/"+f.provider.ID)
	encrypted := f.encrypt(t, f.sign(t, a), 32, true, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256}, false)
	provider := f.provider
	provider.AssertionEncryptionMode = "Required"
	other := newSAMLTestFixture(t)
	provider.PrivateKeys = append(append([]SAMLDecryptionKey{}, provider.PrivateKeys...), other.provider.PrivateKeys...)
	if _, err := verifySAMLResponse(samlTestBytes(t, f.response(encrypted)), provider, f.roleARN, f.now); err != nil {
		t.Fatalf("old key during rotation: %v", err)
	}
	if _, err := verifySAMLResponse(samlTestBytes(t, f.response(f.sign(t, a))), provider, f.roleARN, f.now); err == nil {
		t.Fatal("required encryption accepted plaintext")
	}
	provider.PrivateKeys = other.provider.PrivateKeys
	if _, err := verifySAMLResponse(samlTestBytes(t, f.response(encrypted)), provider, f.roleARN, f.now); err == nil {
		t.Fatal("wrong decryption key accepted")
	}
	// AWS requires an assertion signature even when the response is signed.
	encrypted = f.encrypt(t, f.assertion(), 16, false, &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}, true)
	if _, err := verifySAMLResponse(samlTestBytes(t, f.sign(t, f.response(encrypted))), f.provider, f.roleARN, f.now); err == nil {
		t.Fatal("unsigned encrypted assertion accepted")
	}
}

func TestSAMLDecryptMalformedCiphertext(t *testing.T) {
	f := newSAMLTestFixture(t)
	for _, gcm := range []bool{true, false} {
		encrypted := f.encrypt(t, f.sign(t, f.assertion()), 16, gcm, &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}, true)
		for _, size := range []int{0, 1, 11, 12, 15, 16, 17, 27, 28, 31, 32, 33} {
			t.Run(fmt.Sprintf("gcm=%v/length=%d", gcm, size), func(t *testing.T) {
				copy := encrypted.Copy()
				data, _ := samlOne(copy, samlEncryptionNS, "EncryptedData")
				cipherData, _ := samlOne(data, samlEncryptionNS, "CipherData")
				value, _ := samlOne(cipherData, samlEncryptionNS, "CipherValue")
				value.SetText(base64.StdEncoding.EncodeToString(make([]byte, size)))
				if _, err := verifySAMLResponse(samlTestBytes(t, f.response(copy)), f.provider, f.roleARN, f.now); err == nil {
					t.Fatal("malformed ciphertext accepted")
				}
			})
		}
	}
}

func TestSAMLClaimsAndSessionContext(t *testing.T) {
	f := newSAMLTestFixture(t)
	a := f.assertion()
	samlTestAttribute(a, "SourceIdentity", "source-123")
	samlTestAttribute(a, "PrincipalTag:team", "engineering")
	samlTestAttribute(a, "TransitiveTagKeys", "team")
	samlTestAttribute(a, "SessionDuration", "1800")
	authn, _ := samlOne(a, samlAssertionNS, "AuthnStatement")
	authn.CreateAttr("SessionNotOnOrAfter", f.now.Add(20*time.Minute).Format(time.RFC3339))
	c, err := verifySAMLResponse(samlTestBytes(t, f.response(f.sign(t, a))), f.provider, f.roleARN, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if c.SourceIdentity != "source-123" || c.Tags["team"] != "engineering" || len(c.TransitiveTagKeys) != 1 || c.NotAfter.Sub(f.now) != 20*time.Minute || c.SessionDuration != 30*time.Minute {
		t.Fatalf("claims: %+v", c)
	}
	if len(c.SessionContext) != 3 || len(c.SessionContext["saml:aud"]) != 0 || c.TrustContext["saml:doc"][0] != "123456789012/saml-test" {
		t.Fatalf("contexts: %+v / %+v", c.SessionContext, c.TrustContext)
	}
	for _, item := range []struct {
		name string
		edit func(*etree.Element)
		code string
	}{
		{"expired", func(a *etree.Element) {
			e, _ := samlOne(a, samlAssertionNS, "Conditions")
			e.CreateAttr("NotOnOrAfter", f.now.Format(time.RFC3339))
		}, "ExpiredTokenException"},
		{"malformed NotBefore", func(a *etree.Element) {
			e, _ := samlOne(a, samlAssertionNS, "Conditions")
			e.CreateAttr("NotBefore", "invalid")
		}, "InvalidIdentityToken"},
		{"wrong role", func(a *etree.Element) {
			statements := samlChildren(a, samlAssertionNS, "AttributeStatement")
			samlChildren(statements[0], samlAssertionNS, "Attribute")[0].ChildElements()[0].SetText("arn:aws:iam::123456789012:role/other," + f.provider.ARN)
		}, "InvalidIdentityToken"},
		{"duplicate session name", func(a *etree.Element) { samlTestAttribute(a, "RoleSessionName", "attacker") }, "InvalidIdentityToken"},
		{"duplicate tag case", func(a *etree.Element) {
			samlTestAttribute(a, "PrincipalTag:team", "a")
			samlTestAttribute(a, "PrincipalTag:TEAM", "b")
		}, "InvalidIdentityToken"},
		{"reserved tag", func(a *etree.Element) { samlTestAttribute(a, "PrincipalTag:aws:team", "a") }, "InvalidIdentityToken"},
		{"nonexistent transitive tag", func(a *etree.Element) { samlTestAttribute(a, "TransitiveTagKeys", "missing") }, "InvalidIdentityToken"},
	} {
		t.Run(item.name, func(t *testing.T) {
			a := f.assertion()
			item.edit(a)
			_, err := verifySAMLResponse(samlTestBytes(t, f.response(f.sign(t, a))), f.provider, f.roleARN, f.now)
			if err == nil || err.Code != item.code {
				t.Fatalf("error=%v; want %s", err, item.code)
			}
		})
	}
}
