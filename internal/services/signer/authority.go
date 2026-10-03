package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"time"
)

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
}
func (s *Service) ensureAuthority(t Transaction, sc Scope) (Authority, error) {
	a, e := t.Authority(sc)
	if e == nil {
		return a, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return a, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		return a, e
	}
	serial, e := serialNumber()
	if e != nil {
		return a, e
	}
	now := s.clock.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Stackd AWS Signer " + sc.AccountID + " " + sc.Region}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(40, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return a, e
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return a, e
	}
	a = Authority{Scope: sc, Certificate: der, PrivateKey: private}
	return a, t.PutAuthority(a)
}
func (s *Service) issueProfile(t Transaction, v *Profile) error {
	a, e := s.ensureAuthority(t, v.Scope)
	if e != nil {
		return e
	}
	root, e := x509.ParseCertificate(a.Certificate)
	if e != nil {
		return e
	}
	issuer, e := x509.ParsePKCS8PrivateKey(a.PrivateKey)
	if e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := serialNumber()
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: v.VersionARN}, NotBefore: v.Created.Add(-time.Minute), NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true}
	v.Certificate, e = x509.CreateCertificate(rand.Reader, cert, root, &key.PublicKey, issuer)
	if e != nil {
		return e
	}
	v.PrivateKey, e = x509.MarshalPKCS8PrivateKey(key)
	return e
}

// CodeSigningRoots exposes only roots retained by this owner. Customer supplied
// certificates and ambient machine roots are never signing authorities.
func (s *Service) CodeSigningRoots(ctx context.Context) ([][]byte, error) {
	var out [][]byte
	err := s.repository.View(ctx, func(r Reader) error {
		rows, e := r.Authorities()
		if e != nil {
			return e
		}
		for _, a := range rows {
			out = append(out, a.Certificate)
		}
		return nil
	})
	return out, err
}
func certificateHashes(chain []*x509.Certificate) []string {
	out := make([]string, len(chain))
	for i, c := range chain {
		parent := c
		if i+1 < len(chain) {
			parent = chain[i+1]
		}
		childSum := sha512.Sum384(c.RawTBSCertificate)
		parentSum := sha512.Sum384(parent.RawTBSCertificate)
		out[i] = hex.EncodeToString(childSum[:]) + hex.EncodeToString(parentSum[:])
	}
	return out
}
