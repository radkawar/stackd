package acm

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
	"slices"
	"time"
)

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
}
func encodeKey(key crypto.Signer) ([]byte, error) {
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func signer(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("missing private key")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported signing key")
	}
	return s, nil
}
func createAuthority(now time.Time) (Authority, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return Authority{}, e
	}
	serial, e := serialNumber()
	if e != nil {
		return Authority{}, e
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd local ACM authority (not publicly trusted)", Organization: []string{"stackd local development"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(100, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if e != nil {
		return Authority{}, e
	}
	private, e := encodeKey(key)
	return Authority{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), private}, e
}
func (s *Service) authority(ctx context.Context) (Authority, error) {
	var a Authority
	e := s.repository.View(ctx, func(r Reader) error { var e error; a, e = r.Authority(); return e })
	if e == nil {
		return a, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return a, e
	}
	candidate, e := createAuthority(s.clock.Now())
	if e != nil {
		return a, e
	}
	e = s.repository.Update(ctx, func(tx Transaction) error {
		var e error
		a, e = tx.Authority()
		if e == nil {
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		a = candidate
		return tx.PutAuthority(a)
	})
	return a, e
}

// LocalCACertificate exports the public, locally trusted CA only. This is not an AWS trust root.
func (s *Service) LocalCACertificate(ctx context.Context) ([]byte, error) {
	a, e := s.authority(ctx)
	return a.CertificatePEM, e
}
func issue(c CertificateRecord, a Authority, now time.Time) (CertificateRecord, error) {
	parentBlock, _ := pem.Decode(a.CertificatePEM)
	if parentBlock == nil {
		return c, errors.New("missing authority certificate")
	}
	parent, e := x509.ParseCertificate(parentBlock.Bytes)
	if e != nil {
		return c, e
	}
	authorityKey, e := signer(a.PrivateKeyPEM)
	if e != nil {
		return c, e
	}
	var key crypto.Signer
	switch c.KeyAlgorithm {
	case "RSA_2048":
		key, e = rsa.GenerateKey(rand.Reader, 2048)
	case "EC_prime256v1":
		key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EC_secp384r1":
		key, e = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return c, errors.New("unsupported request key")
	}
	if e != nil {
		return c, e
	}
	serial, e := serialNumber()
	if e != nil {
		return c, e
	}
	names := make([]string, len(c.Validations))
	for i, v := range c.Validations {
		names[i] = v.Domain
	}
	c.NotBefore = now.Add(-5 * time.Minute).Truncate(time.Second)
	c.NotAfter = now.Add(certificateLifetime).Truncate(time.Second)
	if c.NotAfter.After(parent.NotAfter) {
		return c, errors.New("local authority has expired")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: c.Domain}, DNSNames: names, NotBefore: c.NotBefore, NotAfter: c.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if _, ok := key.(*rsa.PrivateKey); ok {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	der, e := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), authorityKey)
	if e != nil {
		return c, e
	}
	c.PrivateKeyPEM, e = encodeKey(key)
	if e != nil {
		return c, e
	}
	c.CertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	c.ChainPEM = slices.Clone(a.CertificatePEM)
	c.Issued = now
	c.MaterialVersion++
	c.Status = "ISSUED"
	c.Exported = false
	c.NextCheck = c.NotAfter.Add(-renewalWindow)
	return c, nil
}

// CertificateID returns the immutable owner identity, not a key-material version.
func (s *Service) CertificateID(ctx context.Context, scope Scope, arn string) (string, error) {
	var id string
	e := s.repository.View(ctx, func(r Reader) error {
		c, e := r.CertificateState(arn)
		if e != nil {
			return e
		}
		now := s.clock.Now()
		if c.Scope != scope || c.Status != "ISSUED" || now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return ErrNotFound
		}
		id = c.ID
		return nil
	})
	return id, e
}

// Certificate is a trusted service-consumer boundary, not an IAM API. The caller supplies its own current resource scope and retained identity.
// Returned TLS material is immutable and must not be modified by consumers.
func (s *Service) Certificate(ctx context.Context, scope Scope, arn, id string) (tls.Certificate, error) {
	var out tls.Certificate
	e := s.repository.View(ctx, func(r Reader) error {
		state, e := r.CertificateState(arn)
		if e != nil {
			return e
		}
		now := s.clock.Now()
		if state.Scope != scope || state.ID != id || state.Status != "ISSUED" || now.Before(state.NotBefore) || !now.Before(state.NotAfter) {
			return ErrNotFound
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if cached, ok := s.cache[id]; ok && cached.version == state.MaterialVersion {
			out = cached.certificate
			return nil
		}
		c, e := r.Certificate(arn)
		if e != nil {
			return e
		}
		chain := make([]byte, 0, len(c.CertificatePEM)+len(c.ChainPEM))
		chain = append(chain, c.CertificatePEM...)
		chain = append(chain, c.ChainPEM...)
		out, e = tls.X509KeyPair(chain, c.PrivateKeyPEM)
		if e != nil {
			return e
		}
		s.cache[id] = cachedTLS{state.MaterialVersion, out}
		return nil
	})
	return out, e
}

// encryptPKCS8 emits PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC, independently consumable by OpenSSL.
func encryptPKCS8(keyPEM, password []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("missing PKCS8 key")
	}
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	if _, e := rand.Read(iv); e != nil {
		return nil, e
	}
	const rounds = 210000
	key := pbkdf2.Key(password, salt, rounds, 32, sha256.New)
	aesCipher, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	padding := aes.BlockSize - len(block.Bytes)%aes.BlockSize
	data := make([]byte, len(block.Bytes)+padding)
	copy(data, block.Bytes)
	for i := len(block.Bytes); i < len(data); i++ {
		data[i] = byte(padding)
	}
	cipher.NewCBCEncrypter(aesCipher, iv).CryptBlocks(data, data)
	kdfParams, e := asn1.Marshal(struct {
		Salt       []byte
		Iterations int
		PRF        pkix.AlgorithmIdentifier
	}{salt, rounds, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}, Parameters: asn1.RawValue{Tag: 5}}})
	if e != nil {
		return nil, e
	}
	ivDER, _ := asn1.Marshal(iv)
	params, e := asn1.Marshal(struct{ KDF, Encryption pkix.AlgorithmIdentifier }{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, Parameters: asn1.RawValue{FullBytes: kdfParams}}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, Parameters: asn1.RawValue{FullBytes: ivDER}}})
	if e != nil {
		return nil, e
	}
	der, e := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, Parameters: asn1.RawValue{FullBytes: params}}, data})
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), nil
}
