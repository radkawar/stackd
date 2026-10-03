package sts

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

func TestSAMLSigningCertificateDatesAreNotTrust(t *testing.T) {
	f := newSAMLTestFixture(t)
	for _, future := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "future"}[future], func(t *testing.T) {
			cert, err := x509.ParseCertificate(f.certificate)
			if err != nil {
				t.Fatal(err)
			}
			cert.NotBefore = f.now.Add(-48 * time.Hour)
			cert.NotAfter = f.now.Add(-24 * time.Hour)
			if future {
				cert.NotBefore = f.now.Add(24 * time.Hour)
				cert.NotAfter = f.now.Add(48 * time.Hour)
			}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &f.key.PublicKey, f.key)
			if err != nil {
				t.Fatal(err)
			}
			copy := f
			copy.certificate = der
			copy.provider.Issuers = []SAMLIssuerSnapshot{{EntityID: f.provider.Issuers[0].EntityID, SigningCertificates: [][]byte{der}}}
			copy.provider.ValidUntil = f.now.Add(-time.Hour)
			if _, err := verifySAMLResponse(samlTestBytes(t, copy.response(copy.sign(t, copy.assertion()))), copy.provider, copy.roleARN, copy.now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSAMLSiblingEncryptedKeyReferences(t *testing.T) {
	f := newSAMLTestFixture(t)
	encrypted := f.encrypt(t, f.sign(t, f.assertion()), 32, true, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256}, false)
	data, _ := samlOne(encrypted, samlEncryptionNS, "EncryptedData")
	info, _ := samlOne(data, samlSignatureNS, "KeyInfo")
	key, _ := samlOne(info, samlEncryptionNS, "EncryptedKey")
	info.RemoveChild(key)
	data.RemoveChild(info)
	encrypted.AddChild(key)
	ref := samlTestChild(samlTestChild(key, "xenc:ReferenceList", ""), "xenc:DataReference", "")
	ref.CreateAttr("URI", "#_encrypted")
	if _, err := verifySAMLResponse(samlTestBytes(t, f.response(encrypted)), f.provider, f.roleARN, f.now); err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{"#unrelated", "https://idp.example.test/key", "file:///etc/passwd"} {
		ref.CreateAttr("URI", uri)
		if _, err := verifySAMLResponse(samlTestBytes(t, f.response(encrypted)), f.provider, f.roleARN, f.now); err == nil {
			t.Fatalf("unbound key reference %q accepted", uri)
		}
	}
}
