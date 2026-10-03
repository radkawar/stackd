package signature

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"slices"
	"time"
)

// Sign creates an AWS Lambda format ZIP/CMS signature using the authoritative
// Signer owner's key and leaf-first certificate chain. It does not issue keys,
// establish publisher authority, or create profile/job/revocation state.
func Sign(ctx context.Context, code []byte, key crypto.Signer, chain []*x509.Certificate, claims Claims) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validSignatureClaims(claims); err != nil {
		return nil, err
	}
	if key == nil || len(chain) < 2 {
		return nil, errors.New("missing signing key or issuer chain")
	}
	for _, cert := range chain {
		if cert == nil {
			return nil, errors.New("nil signing certificate")
		}
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().BitSize != 384 || !pub.Equal(chain[0].PublicKey) || chain[0].IsCA || chain[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("signing key must match an ECDSA P-384 leaf certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1 : len(chain)-1] {
		intermediates.AddCert(cert)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: claims.SigningTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return nil, err
	}
	archive, err := zip.NewReader(bytes.NewReader(code), int64(len(code)))
	if err != nil {
		return nil, err
	}
	if len(archive.File) == 0 {
		return nil, errors.New("cannot sign an empty ZIP")
	}
	appendDirectory := true
	for _, entry := range archive.File {
		if entry.Name == codeSignatureFile {
			return nil, errors.New("ZIP is already signed")
		}
		if entry.Name == "META_INF/" {
			appendDirectory = false
		}
	}
	digest, err := codeSignatureDigest(ctx, archive, appendDirectory)
	if err != nil {
		return nil, err
	}
	envelope, err := signCodeCMS(key, chain, claims, digest)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.Grow(len(code) + len(envelope) + 512)
	writer := zip.NewWriter(&output)
	for _, entry := range archive.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := writer.Copy(entry); err != nil {
			return nil, err
		}
	}
	if appendDirectory {
		if _, err := writer.CreateHeader(&zip.FileHeader{Name: "META_INF/", Method: zip.Store, Modified: claims.SigningTime}); err != nil {
			return nil, err
		}
	}
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: codeSignatureFile, Method: zip.Deflate, Modified: claims.SigningTime})
	if err != nil {
		return nil, err
	}
	if _, err := entry.Write(envelope); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func signCodeCMS(key crypto.Signer, chain []*x509.Certificate, claims Claims, digest [sha512.Size384]byte) ([]byte, error) {
	values := []struct {
		oid    asn1.ObjectIdentifier
		value  any
		params string
	}{
		{oidContentType, oidData, ""},
		{oidMessageDigest, digest[:], ""},
		{oidSigningTime, signatureTime(claims.SigningTime), ""},
		{oidExpiry, signatureTime(claims.Expires), ""},
		{oidSigningJob, claims.SigningJobARN, "utf8"},
		{oidSigningProfile, claims.SigningProfileVersionARN, "utf8"},
		{oidAlgorithmProtection, algorithmProtection{Digest: pkix.AlgorithmIdentifier{Algorithm: oidSHA384}, Signature: pkix.AlgorithmIdentifier{Algorithm: oidECDSASHA384}}, ""},
	}
	attrs := make([]cmsAttribute, 0, len(values))
	for _, value := range values {
		encoded, err := asn1.MarshalWithParams(value.value, value.params)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, cmsAttribute{Type: value.oid, Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: encoded}})
	}
	encodedAttrs, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return nil, err
	}
	attrsDigest := sha512.Sum384(encodedAttrs)
	signature, err := key.Sign(rand.Reader, attrsDigest[:], crypto.SHA384)
	if err != nil {
		return nil, err
	}
	var rawAttrs asn1.RawValue
	if err := unmarshalSignatureDER(encodedAttrs, &rawAttrs); err != nil {
		return nil, err
	}
	// CertificateSet is SET OF: local DER must use encoded-value ordering even
	// though callers supply a leaf-first chain and native AWS permits BER.
	certificateDER := make([][]byte, len(chain))
	totalCertificateBytes := 0
	for i, cert := range chain {
		certificateDER[i] = cert.Raw
		totalCertificateBytes += len(cert.Raw)
	}
	slices.SortFunc(certificateDER, bytes.Compare)
	certs := make([]byte, 0, totalCertificateBytes)
	for _, encoded := range certificateDER {
		certs = append(certs, encoded...)
	}
	data := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA384}},
		Content:          contentInfo{Type: oidData},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certs},
		Signers: []signerInfo{{
			Version:            1,
			Issuer:             issuerAndSerial{Issuer: asn1.RawValue{FullBytes: chain[0].RawIssuer}, Serial: chain[0].SerialNumber},
			DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA384},
			Attributes:         asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: rawAttrs.Bytes},
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSASHA384},
			Signature:          signature,
		}},
	}
	encodedData, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	encoded, err := asn1.Marshal(contentInfo{Type: oidSignedData, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: encodedData}})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: encoded}), nil
}

func signatureTime(value time.Time) asn1.RawValue {
	return asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(value.UTC().Format("20060102150405.999999999Z"))}
}
