package valkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"time"
)

// Managed leaves use the installed trust root, never a replacement self-signed
// certificate or an insecure controller connection.
func (d *Docker) managedCertificate(address netip.Addr) ([]byte, []byte, error) {
	if d.ca == nil || d.caKey == nil || !d.ca.IsCA || d.ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("managed Valkey TLS requires the configured signing CA and private key")
	}
	now := time.Now()
	if now.Before(d.ca.NotBefore) || !now.Before(d.ca.NotAfter) {
		return nil, nil, errors.New("managed Valkey signing CA is not currently valid")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	expires := now.AddDate(1, 0, 0)
	if d.ca.NotAfter.Before(expires) {
		expires = d.ca.NotAfter
	}
	notBefore := now.Add(-time.Minute)
	if d.ca.NotBefore.After(notBefore) {
		notBefore = d.ca.NotBefore
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd-valkey-" + address.String()}, NotBefore: notBefore, NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.IP(address.AsSlice())}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, d.ca, &key.PublicKey, d.caKey)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate = append(certificate, d.certificate...)
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}
