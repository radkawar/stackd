package ec2

import (
	"crypto"
	//lint:ignore SA1019 AWS's legacy IMDS PKCS7 contract requires DSA-SHA1; the rsa2048 endpoint is the modern alternative.
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // Required by the native PKCS7 endpoint, not used for new credentials.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"time"
)

var (
	identityOIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	identityOIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	identityOIDDSA        = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	identityOIDDSASHA1    = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	identityOIDSHA1       = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	identityOIDSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	identityOIDRSASHA256  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// IdentitySigningKeyRecord is an operational emulator key, not an IAM/KMS
// customer resource. Its public certificate must be explicitly trusted locally.
type IdentitySigningKeyRecord struct {
	Kind                          string
	PrivateKeyDER, CertificateDER []byte
}

type instanceIdentitySigner struct {
	kind           string
	key            crypto.PrivateKey
	certificate    *x509.Certificate
	certificatePEM []byte
}

type identityDSAKey struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

type identityDSASignature struct{ R, S *big.Int }

func newIdentitySigningKey(kind string) (IdentitySigningKeyRecord, error) {
	record := IdentitySigningKeyRecord{Kind: kind}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return record, err
	}
	if kind == "dsa" {
		key := &dsa.PrivateKey{}
		if err := dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L1024N160); err != nil {
			return record, err
		}
		if err := dsa.GenerateKey(key, rand.Reader); err != nil {
			return record, err
		}
		record.PrivateKeyDER, err = asn1.Marshal(identityDSAKey{P: key.P, Q: key.Q, G: key.G, Y: key.Y, X: key.X})
		if err != nil {
			return record, err
		}
		record.CertificateDER, err = identityDSACertificate(key, serial)
		return record, err
	}
	bits := 2048
	if kind == "rsa" {
		bits = 1024
	} // The native base64 signature uses the legacy RSA certificate.
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return record, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd EC2 instance identity " + kind}, NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}
	record.CertificateDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return record, err
	}
	record.PrivateKeyDER = x509.MarshalPKCS1PrivateKey(key)
	return record, nil
}

func parseIdentitySigningKey(record IdentitySigningKeyRecord) (*instanceIdentitySigner, error) {
	certificate, err := x509.ParseCertificate(record.CertificateDER)
	if err != nil {
		return nil, err
	}
	signer := &instanceIdentitySigner{kind: record.Kind, certificate: certificate, certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: record.CertificateDER})}
	if record.Kind == "dsa" {
		var encoded identityDSAKey
		if _, err := asn1.Unmarshal(record.PrivateKeyDER, &encoded); err != nil {
			return nil, err
		}
		signer.key = &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: encoded.P, Q: encoded.Q, G: encoded.G}, Y: encoded.Y}, X: encoded.X}
	} else {
		signer.key, err = x509.ParsePKCS1PrivateKey(record.PrivateKeyDER)
		if err != nil {
			return nil, err
		}
	}
	return signer, nil
}

// crypto/x509 no longer creates DSA certificates. This emits the narrow X.509
// v1 DSA form still used by AWS's public IID certificate, using standard DER.
func identityDSACertificate(key *dsa.PrivateKey, serial *big.Int) ([]byte, error) {
	name, err := asn1.Marshal(pkix.Name{CommonName: "stackd EC2 instance identity dsa"}.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	parameters, err := asn1.Marshal(struct{ P, Q, G *big.Int }{key.P, key.Q, key.G})
	if err != nil {
		return nil, err
	}
	public, err := asn1.Marshal(key.Y)
	if err != nil {
		return nil, err
	}
	algorithm := pkix.AlgorithmIdentifier{Algorithm: identityOIDDSASHA1}
	body, err := asn1.Marshal(struct {
		Serial    *big.Int
		Signature pkix.AlgorithmIdentifier
		Issuer    asn1.RawValue
		Validity  struct{ NotBefore, NotAfter time.Time }
		Subject   asn1.RawValue
		PublicKey struct {
			Algorithm pkix.AlgorithmIdentifier
			Key       asn1.BitString
		}
	}{serial, algorithm, asn1.RawValue{FullBytes: name}, struct{ NotBefore, NotAfter time.Time }{time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}, asn1.RawValue{FullBytes: name}, struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: identityOIDDSA, Parameters: asn1.RawValue{FullBytes: parameters}}, asn1.BitString{Bytes: public, BitLength: len(public) * 8}}})
	if err != nil {
		return nil, err
	}
	digest := sha1.Sum(body)
	signature, err := signIdentityDigest(key, crypto.SHA1, digest[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Body      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: body}, algorithm, asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}})
}

func signIdentityDigest(key crypto.PrivateKey, hash crypto.Hash, digest []byte) ([]byte, error) {
	switch key := key.(type) {
	case *dsa.PrivateKey:
		r, s, err := dsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(identityDSASignature{r, s})
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(nil, key, hash, digest)
	default:
		return nil, fmt.Errorf("unsupported EC2 identity signer %T", key)
	}
}

type identityCMSContent struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue
}

type identityCMSAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type identityCMSSigner struct {
	Version         int
	IssuerAndSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	DigestAlgorithm    pkix.AlgorithmIdentifier
	Attributes         asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// signedDocument implements the native content-bearing CMS form. AWS omits
// certificates: verification must use the explicitly trusted public signer,
// not an arbitrary certificate supplied inside the message being verified.
func (s *instanceIdentitySigner) signedDocument(document []byte, at time.Time) ([]byte, error) {
	var h hash.Hash
	hashID := crypto.SHA256
	digestAlgorithm := pkix.AlgorithmIdentifier{Algorithm: identityOIDSHA256}
	signatureAlgorithm := pkix.AlgorithmIdentifier{Algorithm: identityOIDRSASHA256, Parameters: asn1.NullRawValue}
	if s.kind == "dsa" {
		hashID = crypto.SHA1
		h = sha1.New()
		digestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: identityOIDSHA1, Parameters: asn1.NullRawValue}
		signatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: identityOIDDSASHA1}
	} else {
		h = sha256.New()
	}
	_, _ = h.Write(document)
	digest := h.Sum(nil)
	if s.kind == "rsa" {
		return signIdentityDigest(s.key, hashID, digest)
	}
	protection := struct {
		Digest    pkix.AlgorithmIdentifier
		Signature pkix.AlgorithmIdentifier `asn1:"tag:1"`
	}{digestAlgorithm, signatureAlgorithm}
	values := []struct {
		suffix int
		value  any
	}{{3, identityOIDData}, {5, at.UTC().Truncate(time.Second)}, {4, digest}, {52, protection}}
	attributes := make([]identityCMSAttribute, 0, len(values))
	for _, item := range values {
		encoded, err := asn1.Marshal(item.value)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, identityCMSAttribute{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, item.suffix}, Values: []asn1.RawValue{{FullBytes: encoded}}})
	}
	encodedAttributes, err := asn1.MarshalWithParams(attributes, "set")
	if err != nil {
		return nil, err
	}
	var attributeSet asn1.RawValue
	if _, err := asn1.Unmarshal(encodedAttributes, &attributeSet); err != nil {
		return nil, err
	}
	h.Reset()
	_, _ = h.Write(encodedAttributes)
	signature, err := signIdentityDigest(s.key, hashID, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	content, err := asn1.Marshal(document)
	if err != nil {
		return nil, err
	}
	signer := identityCMSSigner{Version: 1, DigestAlgorithm: digestAlgorithm, Attributes: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: attributeSet.Bytes}, SignatureAlgorithm: signatureAlgorithm, Signature: signature}
	signer.IssuerAndSerial.Issuer = asn1.RawValue{FullBytes: s.certificate.RawIssuer}
	signer.IssuerAndSerial.Serial = s.certificate.SerialNumber
	body, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		Content          identityCMSContent
		Signers          []identityCMSSigner `asn1:"set"`
	}{1, []pkix.AlgorithmIdentifier{digestAlgorithm}, identityCMSContent{identityOIDData, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: content}}, []identityCMSSigner{signer}})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(identityCMSContent{identityOIDSignedData, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: body}})
}

// Native IMDS wraps base64 at 76 columns without a trailing newline.
func identityBase64(data []byte) []byte {
	size := base64.StdEncoding.EncodedLen(len(data))
	encoded := make([]byte, size+(size-1)/76)
	input, output := 0, 0
	for len(data)-input > 57 {
		base64.StdEncoding.Encode(encoded[output:output+76], data[input:input+57])
		encoded[output+76] = '\n'
		input += 57
		output += 77
	}
	base64.StdEncoding.Encode(encoded[output:], data[input:])
	return encoded
}
