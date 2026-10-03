package sts

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

var errSAMLSignature = errors.New("SAML signature validation failed")

// verifySAMLSignature accepts only a direct, enveloped signature with one local
// reference to the selected element. Its return value is the verified subtree;
// callers must not subsequently read claims from the original document.
func verifySAMLSignature(element *etree.Element, certificates [][]byte, now time.Time) (*etree.Element, error) {
	// Preserve namespaces inherited from Response before the verifier copies
	// this subtree. Dropping them changes both signature input and claim names.
	namespaces, err := etreeutils.NSBuildParentContext(element)
	if err != nil {
		return nil, errSAMLSignature
	}
	element, err = etreeutils.NSDetatch(namespaces, element)
	if err != nil {
		return nil, errSAMLSignature
	}
	signature, err := samlOne(element, samlSignatureNS, "Signature")
	if err != nil {
		return nil, errSAMLSignature
	}
	id := element.SelectAttrValue("ID", "")
	if id == "" {
		return nil, errSAMLSignature
	}
	info, err := samlOne(signature, samlSignatureNS, "SignedInfo")
	if err != nil {
		return nil, errSAMLSignature
	}
	ref, err := samlOne(info, samlSignatureNS, "Reference")
	if err != nil || ref.SelectAttrValue("URI", "") != "#"+id {
		return nil, errSAMLSignature
	}
	transforms, err := samlOne(ref, samlSignatureNS, "Transforms")
	if err != nil {
		return nil, errSAMLSignature
	}
	enveloped := false
	for _, transform := range transforms.ChildElements() {
		if transform.NamespaceURI() != samlSignatureNS || transform.Tag != "Transform" {
			return nil, errSAMLSignature
		}
		switch transform.SelectAttrValue("Algorithm", "") {
		case "http://www.w3.org/2000/09/xmldsig#enveloped-signature":
			if enveloped {
				return nil, errSAMLSignature
			}
			enveloped = true
		case "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", "http://www.w3.org/2006/12/xml-c14n11", "http://www.w3.org/2006/12/xml-c14n11#WithComments":
		default:
			return nil, errSAMLSignature
		}
	}
	if !enveloped || len(samlChildren(signature, samlSignatureNS, "Object")) > 0 {
		return nil, errSAMLSignature
	}
	for _, der := range certificates {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		// IAM treats uploaded certificates as pinned signing keys. AWS explicitly
		// does not enforce their X.509 validity dates for SAML authentication.
		certificate.NotBefore = now.Add(-time.Hour)
		certificate.NotAfter = now.Add(time.Hour)
		validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{certificate}})
		validation.IdAttribute = "ID"
		validation.Clock = dsig.NewFakeClockAt(now)
		verified, err := validation.Validate(element)
		if err == nil {
			return verified, nil
		}
	}
	return nil, errSAMLSignature
}
