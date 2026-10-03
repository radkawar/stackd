package signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	oidData                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA384              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidECDSASHA384         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidContentType         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAlgorithmProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}
	oidSigningJob          = asn1.ObjectIdentifier{1, 3, 187, 137, 1, 2}
	oidExpiry              = asn1.ObjectIdentifier{1, 3, 187, 137, 1, 3}
	oidSigningProfile      = asn1.ObjectIdentifier{1, 3, 187, 137, 1, 4}
)

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	Content          contentInfo
	Certificates     asn1.RawValue `asn1:"tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	Signers          []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	Issuer             issuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	Attributes         asn1.RawValue `asn1:"tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes asn1.RawValue `asn1:"optional,tag:1"`
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type algorithmProtection struct {
	Digest    pkix.AlgorithmIdentifier
	Signature pkix.AlgorithmIdentifier `asn1:"tag:1"`
}

type codeCMS struct {
	data          signedData
	certificates  []*x509.Certificate
	claims        Claims
	messageDigest []byte
}

func parseCodeSignature(envelope []byte) (*codeCMS, error) {
	trimmed := bytes.TrimSpace(envelope)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PKCS7-----")) {
		return nil, errors.New("expected PKCS7 PEM signature")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PKCS7" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid PKCS7 PEM signature")
	}
	der, consumed, err := codeSignatureDER(block.Bytes, 0)
	if err != nil || consumed != len(block.Bytes) {
		return nil, errors.New("invalid CMS BER envelope")
	}
	var outer contentInfo
	if err := unmarshalSignatureDER(der, &outer); err != nil {
		return nil, err
	}
	if !outer.Type.Equal(oidSignedData) || outer.Content.Class != 2 || outer.Content.Tag != 0 {
		return nil, errors.New("expected CMS SignedData")
	}
	cms := new(codeCMS)
	if err := unmarshalSignatureDER(outer.Content.Bytes, &cms.data); err != nil {
		return nil, err
	}
	d := &cms.data
	if d.Version != 1 || len(d.Signers) != 1 || len(d.DigestAlgorithms) != 1 || !signatureAlgorithm(d.DigestAlgorithms[0], oidSHA384) || !d.Content.Type.Equal(oidData) || len(d.Content.Content.FullBytes) != 0 {
		return nil, errors.New("unsupported CMS detached signing format")
	}
	if d.Certificates.Class != 2 || d.Certificates.Tag != 0 || !d.Certificates.IsCompound {
		return nil, errors.New("missing CMS certificate chain")
	}
	cms.certificates, err = x509.ParseCertificates(d.Certificates.Bytes)
	if err != nil {
		return nil, err
	}
	signer := &d.Signers[0]
	if signer.Version != 1 || signer.Issuer.Serial == nil || !signatureAlgorithm(signer.DigestAlgorithm, oidSHA384) || !signatureAlgorithm(signer.SignatureAlgorithm, oidECDSASHA384) || signer.Attributes.Class != 2 || signer.Attributes.Tag != 0 || !signer.Attributes.IsCompound {
		return nil, errors.New("unsupported CMS signer algorithm or identifier")
	}
	attributes := make(map[string]asn1.RawValue)
	remaining := signer.Attributes.Bytes
	var previous []byte
	for len(remaining) != 0 {
		var attr cmsAttribute
		rest, err := asn1.Unmarshal(remaining, &attr)
		if err != nil {
			return nil, err
		}
		encoded := remaining[:len(remaining)-len(rest)]
		if bytes.Compare(previous, encoded) > 0 {
			return nil, errors.New("CMS signed attributes are not a DER ordered set")
		}
		previous, remaining = encoded, rest
		if attr.Values.Class != 0 || attr.Values.Tag != asn1.TagSet || !attr.Values.IsCompound {
			return nil, errors.New("invalid CMS attribute values")
		}
		key := attr.Type.String()
		if _, exists := attributes[key]; exists {
			return nil, errors.New("duplicate CMS signed attribute")
		}
		var value asn1.RawValue
		if err := unmarshalSignatureDER(attr.Values.Bytes, &value); err != nil {
			return nil, errors.New("CMS signed attribute must contain one value")
		}
		attributes[key] = value
	}
	decode := func(oid asn1.ObjectIdentifier, out any) error {
		value, ok := attributes[oid.String()]
		if !ok {
			return fmt.Errorf("missing CMS attribute %s", oid)
		}
		return unmarshalSignatureDER(value.FullBytes, out)
	}
	var contentType asn1.ObjectIdentifier
	if err := decode(oidContentType, &contentType); err != nil || !contentType.Equal(oidData) {
		return nil, errors.New("invalid signed content type")
	}
	if err := decode(oidMessageDigest, &cms.messageDigest); err != nil || len(cms.messageDigest) != sha512.Size384 {
		return nil, errors.New("invalid signed message digest")
	}
	if err := decode(oidSigningTime, &cms.claims.SigningTime); err != nil {
		return nil, err
	}
	if err := decode(oidExpiry, &cms.claims.Expires); err != nil {
		return nil, err
	}
	if err := decode(oidSigningJob, &cms.claims.SigningJobARN); err != nil {
		return nil, err
	}
	if err := decode(oidSigningProfile, &cms.claims.SigningProfileVersionARN); err != nil {
		return nil, err
	}
	if _, ok := attributes[oidAlgorithmProtection.String()]; ok {
		var protection algorithmProtection
		if err := decode(oidAlgorithmProtection, &protection); err != nil || !signatureAlgorithm(protection.Digest, oidSHA384) || !signatureAlgorithm(protection.Signature, oidECDSASHA384) {
			return nil, errors.New("invalid signed algorithm protection")
		}
	}
	if err := validSignatureClaims(cms.claims); err != nil {
		return nil, err
	}
	return cms, nil
}

func (cms *codeCMS) verify(digest [sha512.Size384]byte, now time.Time, trustedRoots [][]byte) (Claims, error) {
	if subtle.ConstantTimeCompare(digest[:], cms.messageDigest) != 1 {
		return Claims{}, errors.New("signed ZIP content digest mismatch")
	}
	if cms.claims.SigningTime.After(now) {
		return Claims{}, errors.New("signature timestamp is in the future")
	}
	signer := &cms.data.Signers[0]
	var leaf *x509.Certificate
	intermediates := x509.NewCertPool()
	for _, cert := range cms.certificates {
		if cert.SerialNumber.Cmp(signer.Issuer.Serial) == 0 && bytes.Equal(cert.RawIssuer, signer.Issuer.Issuer.FullBytes) {
			if leaf != nil {
				return Claims{}, errors.New("ambiguous signing certificate")
			}
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}
	if leaf == nil || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Claims{}, errors.New("missing code signing certificate")
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve.Params().BitSize != 384 {
		return Claims{}, errors.New("AWS Lambda signing requires ECDSA P-384")
	}
	attrs := bytes.Clone(signer.Attributes.FullBytes)
	attrs[0] = 0x31 // RFC 5652: sign the DER SET OF, not its implicit [0] tag.
	if err := leaf.CheckSignature(x509.ECDSAWithSHA384, attrs, signer.Signature); err != nil {
		return Claims{}, err
	}
	roots, err := signatureRoots(trustedRoots)
	if err != nil {
		return Claims{}, err
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: cms.claims.SigningTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err != nil {
		return Claims{}, fmt.Errorf("untrusted signing certificate chain: %w", err)
	}
	claims := cms.claims
	chain := chains[0]
	claims.CertificateHashes = make([]string, len(chain))
	tbs := make([][sha512.Size384]byte, len(chain))
	for i, cert := range chain {
		tbs[i] = sha512.Sum384(cert.RawTBSCertificate)
	}
	for i := range chain {
		parent := min(i+1, len(chain)-1)
		var composite [2 * sha512.Size384]byte
		copy(composite[:], tbs[i][:])
		copy(composite[sha512.Size384:], tbs[parent][:])
		claims.CertificateHashes[i] = hex.EncodeToString(composite[:])
	}
	return claims, nil
}

func validSignatureClaims(claims Claims) error {
	job := strings.SplitN(claims.SigningJobARN, ":", 6)
	profile := strings.SplitN(claims.SigningProfileVersionARN, ":", 6)
	if len(job) != 6 || len(profile) != 6 || job[0] != "arn" || job[1] == "" || job[2] != "signer" || job[3] == "" || len(job[4]) != 12 || strings.Join(job[:5], ":") != strings.Join(profile[:5], ":") || !strings.HasPrefix(job[5], "/signing-jobs/") || len(strings.TrimPrefix(job[5], "/signing-jobs/")) == 0 || !strings.HasPrefix(profile[5], "/signing-profiles/") {
		return errors.New("invalid signed Signer resource ARNs")
	}
	parts := strings.Split(strings.TrimPrefix(profile[5], "/signing-profiles/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || claims.SigningTime.IsZero() || !claims.Expires.After(claims.SigningTime) {
		return errors.New("invalid signed profile version or validity interval")
	}
	return nil
}

func signatureAlgorithm(algorithm pkix.AlgorithmIdentifier, oid asn1.ObjectIdentifier) bool {
	return algorithm.Algorithm.Equal(oid) && (len(algorithm.Parameters.FullBytes) == 0 || bytes.Equal(algorithm.Parameters.FullBytes, []byte{5, 0}))
}

func unmarshalSignatureDER(encoded []byte, out any) error {
	rest, err := asn1.Unmarshal(encoded, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing ASN.1 data")
	}
	return nil
}
