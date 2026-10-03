package signature

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
)

// This public root was captured from authenticated AWS Signer StartSigningJob
// output in us-east-1. Original signed captures are preserved in the private
// backup; the published *_local.json vectors are locally re-signed regressions.
// Never promote the root offered by an incoming ZIP to a trusted root. Other AWS
// partitions/root rotations require a separately authenticated trust update.
const nativeSignerRoot = `-----BEGIN CERTIFICATE-----
MIICRDCCAcqgAwIBAgIRALAP6UoUaRkbgz38BprRG5swCgYIKoZIzj0EAwMwYjEL
MAkGA1UEBhMCVVMxDDAKBgNVBAoMA0FXUzEVMBMGA1UECwwMQ3J5cHRvZ3JhcGh5
MQswCQYDVQQIDAJXQTEhMB8GA1UEAwwYU2lnbmVyIHVzLXdlc3QtMiBST09UIENB
MCAXDTIwMDcxNjE4MjE0N1oYDzIxMjAwNzE2MTkyMTQ3WjBiMQswCQYDVQQGEwJV
UzEMMAoGA1UECgwDQVdTMRUwEwYDVQQLDAxDcnlwdG9ncmFwaHkxCzAJBgNVBAgM
AldBMSEwHwYDVQQDDBhTaWduZXIgdXMtd2VzdC0yIFJPT1QgQ0EwdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAARlUdWWMHRVx1EczSLL9+auryItIDhbWbJE+UbsQMRcPmPB
nTknehZx40n1FCMeFJEFQRa7VQSEYnwZJBwTQKhPaqnmooWMGs/JEP0vcr3D9ki6
ZC9iy6/fTOUkM/Kjhe6jQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFHns
aZ30sP0iN/svM0Y/QbEI9qFfMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAwNo
ADBlAjEA5nanIDSNdN6PtqQbW3Pf89B25uLoD71mHMzHiQha9138B+XALLfeG9U8
OhZtUby8AjAevBIAX9zK8OmZKdsmaWXmAeTSylxPXtjkEQSRdIQ2WxqN0MuN70mM
aC9pR1Uuoxw=
-----END CERTIFICATE-----
`

var nativeSignatureRoots = sync.OnceValues(func() (*x509.CertPool, error) {
	block, _ := pem.Decode([]byte(nativeSignerRoot))
	if block == nil {
		return nil, errors.New("invalid pinned AWS Signer root")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return roots, nil
})

func signatureRoots(authorityRoots [][]byte) (*x509.CertPool, error) {
	roots, err := nativeSignatureRoots()
	if err != nil || len(authorityRoots) == 0 {
		return roots, err
	}
	roots = roots.Clone()
	for _, der := range authorityRoots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
			return nil, errors.New("signer authority provided an invalid trust root")
		}
		roots.AddCert(cert)
	}
	return roots, nil
}
