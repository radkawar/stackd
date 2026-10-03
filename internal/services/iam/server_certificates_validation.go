package iam

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"stackd/internal/awswire"
)

func parseServerPrivateKey(value string) (crypto.Signer, *awswire.Error) {
	block, rest := pem.Decode([]byte(value))
	bad := func() (crypto.Signer, *awswire.Error) {
		return nil, certificateError("MalformedCertificate", "The private key must be an unencrypted PEM RSA or EC private key.")
	}
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return bad()
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return bad()
	}
	if err != nil {
		return bad()
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.Validate() != nil {
			return bad()
		}
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return bad()
	}
}

func validateServerCertificate(body, privateKey, chain string, now time.Time) (time.Time, *awswire.Error) {
	cert, err := parseSigningCertificate(body, now)
	if err != nil {
		return time.Time{}, err
	}
	key, err := parseServerPrivateKey(privateKey)
	if err != nil {
		return time.Time{}, err
	}
	public, marshalErr := x509.MarshalPKIXPublicKey(key.Public())
	if marshalErr != nil {
		return time.Time{}, certificateError("MalformedCertificate", "Unsupported private key.")
	}
	if !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
		return time.Time{}, certificateError("KeyPairMismatch", "The certificate and private key do not match.")
	}
	parent := cert
	intermediates := x509.NewCertPool()
	rest := []byte(chain)
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return time.Time{}, certificateError("MalformedCertificate", "The certificate chain is malformed.")
		}
		issuer, e := x509.ParseCertificate(block.Bytes)
		if e != nil || bytes.Equal(block.Bytes, cert.Raw) || parent.CheckSignatureFrom(issuer) != nil {
			return time.Time{}, certificateError("MalformedCertificate", "The certificate chain does not certify the preceding certificate.")
		}
		intermediates.AddCert(issuer)
		parent = issuer
	}
	// AWS accepts a CA-signed leaf without a supplied chain, and a repeated
	// root in an otherwise valid chain. Uploaded material still has to match
	// its private key; supplied issuers must actually certify their child.
	roots := x509.NewCertPool()
	roots.AddCert(parent)
	if _, e := cert.Verify(x509.VerifyOptions{CurrentTime: now, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); e != nil && strings.TrimSpace(chain) != "" {
		return time.Time{}, certificateError("MalformedCertificate", "The certificate chain is not valid: "+e.Error())
	}
	if _, e := tls.X509KeyPair([]byte(strings.TrimSpace(body)+"\n"+strings.TrimSpace(chain)), []byte(privateKey)); e != nil {
		return time.Time{}, certificateError("MalformedCertificate", "The certificate and key cannot be used for TLS.")
	}
	return cert.NotAfter, nil
}
