package acm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"slices"
	api "stackd/internal/awsapi/acm"
)

func keyAlgorithm(key any) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096 {
			return fmt.Sprintf("RSA_%d", bits)
		}
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return "EC_prime256v1"
		case 384:
			return "EC_secp384r1"
		case 521:
			return "EC_secp521r1"
		}
	}
	return ""
}
func (s *Service) importCertificate(tx Transaction, in *api.ImportCertificateRequest) (*api.ImportCertificateResponse, error) {
	arn := value(in.CertificateArn)
	var c CertificateRecord
	var e error
	if arn != "" {
		c, e = s.owned(tx, "ImportCertificate", arn)
		if e != nil {
			return nil, e
		}
		if c.Type != "IMPORTED" {
			return nil, failure("ValidationException", "Only imported certificates can be reimported.")
		}
		if len(in.Tags) > 0 {
			return nil, failure("InvalidTagException", "Tags cannot be supplied on reimport.")
		}
	} else {
		if e = s.authorize(tx, "ImportCertificate", "", nil, in.Tags); e != nil {
			return nil, e
		}
	}
	pair, e := tls.X509KeyPair(in.Certificate, in.PrivateKey)
	if e != nil || len(pair.Certificate) != 1 {
		return nil, failure("ValidationException", "Certificate and unencrypted private key must form one valid key pair.")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, failure("ValidationException", "Invalid certificate.")
	}
	now := s.clock.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA {
		return nil, failure("ValidationException", "An unexpired end-entity certificate valid at current service time is required.")
	}
	algorithm := keyAlgorithm(leaf.PublicKey)
	if algorithm == "" {
		return nil, failure("ValidationException", "Unsupported certificate key algorithm.")
	}
	domains := slices.Clone(leaf.DNSNames)
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = append(domains, leaf.Subject.CommonName)
	}
	if len(domains) == 0 {
		return nil, failure("ValidationException", "A certificate must contain at least one DNS name.")
	}
	for _, d := range domains {
		if _, e = domainName(d); e != nil {
			return nil, e
		}
	}
	previous := leaf
	rest := []byte(in.CertificateChain)
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, failure("ValidationException", "Invalid certificate chain PEM.")
		}
		parent, e := x509.ParseCertificate(block.Bytes)
		if e != nil || previous.CheckSignatureFrom(parent) != nil || now.Before(parent.NotBefore) || !now.Before(parent.NotAfter) {
			return nil, failure("ValidationException", "Certificate chain signature or validity is invalid.")
		}
		previous = parent
	}
	if arn != "" {
		old, e := parseLeaf(c)
		if e != nil {
			return nil, e
		}
		if c.KeyAlgorithm != algorithm {
			return nil, failure("ValidationException", "Reimport cannot change key type or size.")
		}
		required := old.KeyUsage
		if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
			required &^= x509.KeyUsageKeyEncipherment
		}
		if required&leaf.KeyUsage != required {
			return nil, failure("ValidationException", "Reimport cannot remove existing key usages.")
		}
		for _, u := range old.ExtKeyUsage {
			if u != x509.ExtKeyUsageClientAuth && !slices.Contains(leaf.ExtKeyUsage, u) {
				return nil, failure("ValidationException", "Reimport cannot remove existing extended key usages.")
			}
		}
		for _, u := range old.UnknownExtKeyUsage {
			found := false
			for _, n := range leaf.UnknownExtKeyUsage {
				found = found || n.Equal(u)
			}
			if !found {
				return nil, failure("ValidationException", "Reimport cannot remove existing extended key usages.")
			}
		}
	} else {
		scope := scopeFor(tx.Context())
		id := uuid.NewString()
		tags, e := tagsFrom(in.Tags)
		if e != nil {
			return nil, e
		}
		c = CertificateRecord{Scope: scope, ID: id, ARN: "arn:" + scope.Partition + ":acm:" + scope.Region + ":" + scope.AccountID + ":certificate/" + id, Created: now, Tags: tags, Type: "IMPORTED", ExportOption: "DISABLED", Transparency: "DISABLED"}
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, failure("ValidationException", "Unsupported private key.")
	}
	c.PrivateKeyPEM, e = encodeKey(key)
	if e != nil {
		return nil, e
	}
	c.CertificatePEM = slices.Clone(in.Certificate)
	c.ChainPEM = slices.Clone(in.CertificateChain)
	c.Domain = domains[0]
	c.Validations = nil
	for _, d := range domains {
		c.Validations = append(c.Validations, Validation{Domain: d, Status: "SUCCESS"})
	}
	c.Status = "ISSUED"
	c.Imported = now
	c.NotBefore = leaf.NotBefore
	c.NotAfter = leaf.NotAfter
	c.NextCheck = c.NotAfter
	c.KeyAlgorithm = algorithm
	c.MaterialVersion++
	c.Version++
	if e = tx.PutCertificate(c); e != nil {
		return nil, e
	}
	return &api.ImportCertificateResponse{CertificateArn: new(api.Arn(c.ARN))}, nil
}
func (s *Service) exportCertificate(tx Transaction, in *api.ExportCertificateRequest) (*api.ExportCertificateResponse, error) {
	c, e := s.owned(tx, "ExportCertificate", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	if len(c.CertificatePEM) == 0 {
		return nil, failure("RequestInProgressException", "Certificate has not been issued.")
	}
	if c.Type != "AMAZON_ISSUED" || c.ExportOption != "ENABLED" {
		return nil, failure("ValidationException", "Certificate is not exportable.")
	}
	if len(in.Passphrase) < 4 || len(in.Passphrase) > 128 {
		return nil, failure("ValidationException", "Passphrase must contain 4 to 128 ASCII characters.")
	}
	for _, b := range in.Passphrase {
		if b > 127 || b == '#' || b == '$' || b == '%' {
			return nil, failure("ValidationException", "Passphrase contains disallowed characters.")
		}
	}
	encrypted, e := encryptPKCS8(c.PrivateKeyPEM, in.Passphrase)
	if e != nil {
		return nil, e
	}
	c.Exported = true
	c.Version++
	if e = tx.PutCertificate(c); e != nil {
		return nil, e
	}
	return &api.ExportCertificateResponse{Certificate: new(api.CertificateBody(c.CertificatePEM)), CertificateChain: new(api.CertificateChain(c.ChainPEM)), PrivateKey: new(api.PrivateKey(encrypted))}, nil
}
