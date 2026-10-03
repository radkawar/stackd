package sts

import (
	"time"

	"github.com/beevik/etree"

	"stackd/internal/awswire"
)

func samlInvalid(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidIdentityToken", Message: message, StatusCode: 400}
}

func samlExpired() *awswire.Error {
	return &awswire.Error{Code: "ExpiredTokenException", Message: "Response has expired", StatusCode: 400}
}

// verifySAMLResponse never grants authority from unsigned response attributes.
// The issuer first selects pinned metadata certificates, and then is read again
// from the verified assertion before its claims are used.
func verifySAMLResponse(raw []byte, provider SAMLProviderSnapshot, roleARN string, now time.Time) (samlClaims, *awswire.Error) {
	invalid := samlInvalid("The SAML response is invalid or could not be verified.")
	response, err := parseSAMLXML(raw)
	if err != nil || response.NamespaceURI() != samlProtocolNS || response.Tag != "Response" || response.SelectAttrValue("Version", "") != "2.0" {
		return samlClaims{}, invalid
	}
	status, err := samlOne(response, samlProtocolNS, "Status")
	if err != nil {
		return samlClaims{}, invalid
	}
	code, err := samlOne(status, samlProtocolNS, "StatusCode")
	if err != nil || code.SelectAttrValue("Value", "") != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return samlClaims{}, invalid
	}
	plain := samlChildren(response, samlAssertionNS, "Assertion")
	encrypted := samlChildren(response, samlAssertionNS, "EncryptedAssertion")
	if len(plain)+len(encrypted) != 1 || samlCount(response, samlAssertionNS, "Assertion") != len(plain) || samlCount(response, samlAssertionNS, "EncryptedAssertion") != len(encrypted) {
		return samlClaims{}, invalid
	}
	var assertion *etree.Element
	if len(encrypted) == 1 {
		assertion, err = decryptSAMLAssertion(encrypted[0], provider.PrivateKeys)
		if err != nil {
			return samlClaims{}, invalid
		}
	} else {
		if provider.AssertionEncryptionMode == "Required" {
			return samlClaims{}, invalid
		}
		assertion = plain[0]
	}
	issuerElement, err := samlOne(assertion, samlAssertionNS, "Issuer")
	if err != nil {
		return samlClaims{}, invalid
	}
	issuer, err := samlText(issuerElement)
	if err != nil || issuer == "" {
		return samlClaims{}, invalid
	}
	var certificates [][]byte
	for _, configured := range provider.Issuers {
		if configured.EntityID == issuer {
			certificates = append(certificates, configured.SigningCertificates...)
		}
	}
	if len(certificates) == 0 {
		return samlClaims{}, invalid
	}
	responseSigned := len(samlChildren(response, samlSignatureNS, "Signature")) != 0
	assertionSigned := len(samlChildren(assertion, samlSignatureNS, "Signature")) != 0
	if !assertionSigned {
		return samlClaims{}, invalid
	}
	// Reject signatures hidden in extension/object nodes. For dual signatures,
	// the response verifier chooses its direct reference; both must validate.
	expected := 0
	if responseSigned {
		expected++
	}
	if assertionSigned && len(plain) == 1 {
		expected++
	}
	if samlCount(response, samlSignatureNS, "Signature") != expected || samlCount(assertion, samlSignatureNS, "Signature") > 1 {
		return samlClaims{}, invalid
	}
	if responseSigned {
		response, err = verifySAMLSignature(response, certificates, now)
		if err != nil {
			return samlClaims{}, invalid
		}
		if len(plain) == 1 {
			assertion, err = samlOne(response, samlAssertionNS, "Assertion")
			if err != nil {
				return samlClaims{}, invalid
			}
		}
	}
	if assertionSigned {
		assertion, err = verifySAMLSignature(assertion, certificates, now)
		if err != nil {
			return samlClaims{}, invalid
		}
	}
	claims, apiErr := readSAMLClaims(assertion, provider, roleARN, now)
	if apiErr != nil {
		return samlClaims{}, apiErr
	}
	if claims.Issuer != issuer {
		return samlClaims{}, invalid
	}
	return claims, nil
}
