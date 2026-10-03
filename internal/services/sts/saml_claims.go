package sts

import (
	"crypto/sha1" // AWS specifies SHA-1 for the non-secret NameQualifier identifier.
	"encoding/base64"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/beevik/etree"

	"stackd/internal/awswire"
)

type samlClaims struct {
	Issuer, Audience, Subject, SubjectType, NameQualifier string
	AssertionID                                           string
	SessionName, SourceIdentity                           string
	NotAfter                                              time.Time
	AuthenticationNotAfter                                *time.Time
	SessionDuration                                       time.Duration
	Tags                                                  map[string]string
	TransitiveTagKeys                                     []string
	TrustContext, SessionContext                          map[string][]string
}

var samlSessionName = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
var samlTagText = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+@-]*$`)

func readSAMLClaims(assertion *etree.Element, provider SAMLProviderSnapshot, roleARN string, now time.Time) (samlClaims, *awswire.Error) {
	invalid := samlInvalid("The SAML assertion contains invalid or missing claims.")
	c := samlClaims{Tags: make(map[string]string), TrustContext: make(map[string][]string)}
	if assertion.SelectAttrValue("Version", "") != "2.0" || assertion.SelectAttrValue("ID", "") == "" {
		return c, invalid
	}
	c.AssertionID = assertion.SelectAttrValue("ID", "")
	issuer, err := samlOne(assertion, samlAssertionNS, "Issuer")
	if err != nil {
		return c, invalid
	}
	c.Issuer, err = samlText(issuer)
	if err != nil || c.Issuer == "" {
		return c, invalid
	}
	subject, err := samlOne(assertion, samlAssertionNS, "Subject")
	if err != nil {
		return c, invalid
	}
	nameID, err := samlOne(subject, samlAssertionNS, "NameID")
	if err != nil {
		return c, invalid
	}
	c.Subject, err = samlText(nameID)
	if err != nil || c.Subject == "" || len(c.Subject) > 1000 {
		return c, invalid
	}
	format := nameID.SelectAttrValue("Format", "")
	if format == "" {
		return c, invalid
	}
	c.SubjectType = strings.TrimPrefix(format, "urn:oasis:names:tc:SAML:2.0:nameid-format:")
	confirmation, err := samlOne(subject, samlAssertionNS, "SubjectConfirmation")
	if err != nil || confirmation.SelectAttrValue("Method", "") != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return c, invalid
	}
	data, err := samlOne(confirmation, samlAssertionNS, "SubjectConfirmationData")
	if err != nil {
		return c, invalid
	}
	c.Audience = data.SelectAttrValue("Recipient", "")
	parts := strings.SplitN(provider.ARN, ":", 6)
	if len(parts) != 6 || !strings.HasPrefix(parts[5], "saml-provider/") || c.Audience == "" {
		return c, invalid
	}
	subjectExpiry, apiErr := samlValidity(data, now, true)
	if apiErr != nil {
		return c, apiErr
	}
	c.AuthenticationNotAfter = subjectExpiry
	conditions, err := samlOne(assertion, samlAssertionNS, "Conditions")
	if err != nil {
		return c, invalid
	}
	conditionsExpiry, apiErr := samlValidity(conditions, now, false)
	if apiErr != nil {
		return c, apiErr
	}
	if conditionsExpiry != nil && conditionsExpiry.Before(*c.AuthenticationNotAfter) {
		c.AuthenticationNotAfter = conditionsExpiry
	}
	// AWS uses signed SubjectConfirmationData.Recipient as saml:aud and
	// leaves its authorization to the role trust policy. AudienceRestriction,
	// OneTimeUse and ProxyRestriction are accepted by this STS API; the live
	// fixture records each case rather than borrowing browser-SP assumptions.
	for _, condition := range conditions.ChildElements() {
		if condition.NamespaceURI() != samlAssertionNS || (condition.Tag != "AudienceRestriction" && condition.Tag != "OneTimeUse" && condition.Tag != "ProxyRestriction") {
			return c, invalid
		}
	}
	statements := samlChildren(assertion, samlAssertionNS, "AuthnStatement")
	if len(statements) == 0 {
		return c, invalid
	}
	for _, statement := range statements {
		if raw := statement.SelectAttrValue("SessionNotOnOrAfter", ""); raw != "" {
			t, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return c, invalid
			}
			if !now.Before(t) {
				return c, samlExpired()
			}
			if c.NotAfter.IsZero() || t.Before(c.NotAfter) {
				c.NotAfter = t
			}
			if t.Before(*c.AuthenticationNotAfter) {
				c.AuthenticationNotAfter = &t
			}
		}
	}
	attributes, err := samlAttributes(assertion)
	if err != nil {
		return c, invalid
	}
	if !samlRoleAllowed(attributes[samlAttributePrefix+"Role"], roleARN, provider.ARN) {
		return c, samlInvalid("The requested role is not present in the SAML assertion.")
	}
	c.SessionName, err = samlSingleAttribute(attributes, samlAttributePrefix+"RoleSessionName", true)
	if err != nil || !samlSessionName.MatchString(c.SessionName) {
		return c, invalid
	}
	c.SourceIdentity, err = samlSingleAttribute(attributes, samlAttributePrefix+"SourceIdentity", false)
	if err != nil || (c.SourceIdentity != "" && (!samlSessionName.MatchString(c.SourceIdentity) || strings.HasPrefix(strings.ToLower(c.SourceIdentity), "aws:"))) {
		return c, invalid
	}
	if raw, err := samlSingleAttribute(attributes, samlAttributePrefix+"SessionDuration", false); err != nil {
		return c, invalid
	} else if raw != "" {
		seconds, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || seconds < 900 || seconds > 43200 {
			return c, invalid
		}
		c.SessionDuration = time.Duration(seconds) * time.Second
	}
	seenTags := make(map[string]bool)
	for name, values := range attributes {
		if !strings.HasPrefix(name, samlAttributePrefix+"PrincipalTag:") {
			continue
		}
		key := strings.TrimPrefix(name, samlAttributePrefix+"PrincipalTag:")
		folded := strings.ToLower(key)
		if len(values) != 1 || utf8.RuneCountInString(key) < 1 || utf8.RuneCountInString(key) > 128 || utf8.RuneCountInString(values[0]) > 256 || !samlTagText.MatchString(key) || !samlTagText.MatchString(values[0]) || strings.HasPrefix(folded, "aws:") || seenTags[folded] {
			return c, invalid
		}
		seenTags[folded] = true
		c.Tags[key] = values[0]
	}
	if len(c.Tags) > 50 {
		return c, invalid
	}
	seenTransitive := make(map[string]bool)
	for _, key := range attributes[samlAttributePrefix+"TransitiveTagKeys"] {
		folded := strings.ToLower(key)
		if !seenTags[folded] || seenTransitive[folded] {
			return c, invalid
		}
		seenTransitive[folded] = true
		c.TransitiveTagKeys = append(c.TransitiveTagKeys, key)
	}
	slices.Sort(c.TransitiveTagKeys)
	doc := parts[4] + "/" + strings.TrimPrefix(parts[5], "saml-provider/")
	qualifier := sha1.Sum([]byte(c.Issuer + doc))
	c.NameQualifier = base64.StdEncoding.EncodeToString(qualifier[:])
	c.TrustContext["saml:aud"] = []string{c.Audience}
	c.TrustContext["saml:iss"] = []string{c.Issuer}
	c.TrustContext["saml:doc"] = []string{doc}
	c.SessionContext = map[string][]string{"saml:sub": {c.Subject}, "saml:sub_type": {c.SubjectType}, "saml:namequalifier": {c.NameQualifier}}
	for key, values := range c.SessionContext {
		c.TrustContext[key] = slices.Clone(values)
	}
	for attribute, contextKey := range samlAttributeContextKeys {
		if values, ok := attributes[attribute]; ok {
			if _, exists := c.TrustContext[contextKey]; exists {
				return c, invalid
			}
			c.TrustContext[contextKey] = slices.Clone(values)
		}
	}
	return c, nil
}

func samlValidity(element *etree.Element, now time.Time, requireExpiry bool) (*time.Time, *awswire.Error) {
	if raw := element.SelectAttrValue("NotBefore", ""); raw != "" {
		// STS parses NotBefore but does not enforce it. The AWS fixture includes
		// a full day in the future and a malformed value to distinguish these.
		if _, err := time.Parse(time.RFC3339Nano, raw); err != nil {
			return nil, samlInvalid("The SAML assertion validity period is invalid.")
		}
	}
	raw := element.SelectAttrValue("NotOnOrAfter", "")
	if raw == "" && !requireExpiry {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil, samlInvalid("The SAML assertion validity period is invalid.")
	}
	if !now.Before(t) {
		return nil, samlExpired()
	}
	return &t, nil
}

func samlAttributes(assertion *etree.Element) (map[string][]string, error) {
	result := make(map[string][]string)
	for _, statement := range samlChildren(assertion, samlAssertionNS, "AttributeStatement") {
		for _, attribute := range statement.ChildElements() {
			if attribute.NamespaceURI() != samlAssertionNS || attribute.Tag != "Attribute" {
				return nil, errSAMLXML
			}
			name := attribute.SelectAttrValue("Name", "")
			if name == "" {
				return nil, errSAMLXML
			}
			if _, exists := result[name]; exists {
				return nil, errSAMLXML
			}
			result[name] = nil
			for _, value := range attribute.ChildElements() {
				if value.NamespaceURI() != samlAssertionNS || value.Tag != "AttributeValue" {
					return nil, errSAMLXML
				}
				text, err := samlText(value)
				if err != nil {
					return nil, err
				}
				result[name] = append(result[name], text)
			}
		}
	}
	return result, nil
}

func samlSingleAttribute(attributes map[string][]string, name string, required bool) (string, error) {
	values, present := attributes[name]
	if !present && !required {
		return "", nil
	}
	if len(values) != 1 || values[0] == "" {
		return "", errSAMLXML
	}
	return values[0], nil
}

func samlRoleAllowed(values []string, roleARN, providerARN string) bool {
	for _, value := range values {
		pair := strings.Split(value, ",")
		if len(pair) != 2 {
			continue
		}
		a, b := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if (a == roleARN && b == providerARN) || (b == roleARN && a == providerARN) {
			return true
		}
	}
	return false
}
