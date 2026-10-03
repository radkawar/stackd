package iam

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"stackd/internal/awswire"
)

const samlMetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
const xmlSignatureNamespace = "http://www.w3.org/2000/09/xmldsig#"

func parseSAMLMetadata(document string) ([]SAMLIssuerRecord, *awswire.Error) {
	bad := func() ([]SAMLIssuerRecord, *awswire.Error) { return nil, invalidInput("Could not parse metadata") }
	if !utf8.ValidString(document) || strings.HasPrefix(document, "\ufeff") {
		return bad()
	}
	decoder := xml.NewDecoder(strings.NewReader(document))
	var stack []xml.Name
	var issuers []SAMLIssuerRecord
	var entityID string
	entityDepth, idpDepth, keyDepth := 0, 0, 0
	keyUse := ""
	roots := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return bad()
		}
		switch value := token.(type) {
		case xml.Directive:
			return bad()
		case xml.StartElement:
			stack = append(stack, value.Name)
			depth := len(stack)
			if depth == 1 {
				roots++
				if roots != 1 || value.Name.Space != samlMetadataNamespace || (value.Name.Local != "EntityDescriptor" && value.Name.Local != "EntitiesDescriptor") {
					return bad()
				}
			}
			if value.Name.Space == samlMetadataNamespace {
				switch value.Name.Local {
				case "EntityDescriptor":
					if entityDepth != 0 {
						return bad()
					}
					entityDepth = depth
					entityID = ""
					for _, attr := range value.Attr {
						if attr.Name.Space == "" && attr.Name.Local == "entityID" {
							entityID = attr.Value
						}
					}
					if entityID == "" {
						return bad()
					}
				case "IDPSSODescriptor":
					if entityDepth != 0 && depth == entityDepth+1 {
						idpDepth = depth
						issuers = append(issuers, SAMLIssuerRecord{EntityID: entityID, SigningCertificates: make([][]byte, 0)})
					}
				case "KeyDescriptor":
					if idpDepth != 0 && depth == idpDepth+1 {
						keyDepth = depth
						keyUse = ""
						for _, attr := range value.Attr {
							if attr.Name.Local == "use" {
								keyUse = attr.Value
							}
						}
					}
				}
			}
			if value.Name.Space == xmlSignatureNamespace && value.Name.Local == "X509Certificate" {
				var encoded string
				if err := decoder.DecodeElement(&encoded, &value); err != nil {
					return bad()
				}
				stack = stack[:len(stack)-1]
				encoded = strings.Map(func(r rune) rune {
					if unicode.IsSpace(r) {
						return -1
					}
					return r
				}, encoded)
				der, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return bad()
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return bad()
				}
				if key, ok := cert.PublicKey.(*rsa.PublicKey); ok && key.N.BitLen() < 1024 {
					return bad()
				}
				seen := map[string]bool{}
				for _, extension := range cert.Extensions {
					id := extension.Id.String()
					if seen[id] {
						return bad()
					}
					seen[id] = true
				}
				// IAM ignores metadata and certificate expiry. STS checks the assertion's
				// lifetime and binds verification to the matching issuer's signing keys.
				if idpDepth != 0 && keyDepth != 0 && (keyUse == "" || keyUse == "signing") {
					index := len(issuers) - 1
					issuers[index].SigningCertificates = append(issuers[index].SigningCertificates, der)
				}
			}
		case xml.EndElement:
			depth := len(stack)
			if depth == keyDepth {
				keyDepth = 0
				keyUse = ""
			}
			if depth == idpDepth {
				idpDepth = 0
			}
			if depth == entityDepth {
				entityDepth = 0
				entityID = ""
			}
			stack = stack[:depth-1]
		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(value)) != "" {
				return bad()
			}
		}
	}
	if roots != 1 {
		return bad()
	}
	if len(issuers) == 0 {
		return nil, invalidInput("SAML Providers must reference at least one SAML assertion issuer.")
	}
	return issuers, nil
}

func parseSAMLPrivateKey(value string) ([]byte, *awswire.Error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || strings.TrimSpace(string(rest)) != "" || len(block.Headers) != 0 {
		return nil, invalidInput("Invalid private key.")
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, invalidInput("Invalid private key.")
		}
		key = parsed
	case "RSA PRIVATE KEY":
		var err error
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, invalidInput("Invalid private key.")
		}
	case "EC PRIVATE KEY":
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, invalidInput("Invalid private key.")
		}
	default:
		return nil, invalidInput("Invalid private key.")
	}
	if rsaKey, ok := key.(*rsa.PrivateKey); ok && rsaKey.Validate() != nil {
		return nil, invalidInput("Invalid private key.")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, invalidInput("Invalid private key.")
	}
	return der, nil
}
func federationID(prefix string) string {
	var data [10]byte
	_, _ = rand.Read(data[:])
	return prefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data[:])
}
