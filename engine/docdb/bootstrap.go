package docdb

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"
)

type nativeFile struct {
	name      string
	body      []byte
	mode      int64
	directory bool
}

func (d *Docker) putFiles(ctx context.Context, id string, files []nativeFile) error {
	var content bytes.Buffer
	archive := tar.NewWriter(&content)
	for _, file := range files {
		header := &tar.Header{Name: file.name, Mode: file.mode, Size: int64(len(file.body)), Uid: 999, Gid: 999}
		if file.directory {
			header.Typeflag = tar.TypeDir
		}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		if _, err := archive.Write(file.body); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	response, err := d.client.Request(ctx, http.MethodPut, "/containers/"+url.PathEscape(id)+"/archive?path=/", &content, "application/x-tar")
	if err != nil {
		return err
	}
	return response.Body.Close()
}
func (d *Docker) readFile(ctx context.Context, id, path string) ([]byte, error) {
	response, err := d.client.Request(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(path), nil, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	archive := tar.NewReader(response.Body)
	header, err := archive.Next()
	if err != nil {
		return nil, err
	}
	if !header.FileInfo().Mode().IsRegular() || header.Size > 64<<10 {
		return nil, errors.New("invalid native DocumentDB security file")
	}
	return io.ReadAll(io.LimitReader(archive, 64<<10))
}
func (d *Docker) exists(ctx context.Context, id, path string) (bool, error) {
	response, err := d.client.Request(ctx, http.MethodHead, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(path), nil, "")
	if dockerStatus(err, http.StatusNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	response.Body.Close()
	return true, nil
}
func certificates() (ca, server []byte, err error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd local DocumentDB CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, root, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	server = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	server = append(server, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})...)
	return ca, server, nil
}
func (d *Docker) initializeContainer(ctx context.Context, state containerState, spec Specification) error {
	present, err := d.exists(ctx, state.ID, "/data/db/security/ca.pem")
	if err != nil {
		return err
	}
	if !present {
		ca, server, err := certificates()
		if err != nil {
			return err
		}
		key := make([]byte, 512)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		// The CA is written last: interrupted setup is regenerated before the
		// process can start, while retained material is never silently rotated.
		files := []nativeFile{{name: "data/db/security", mode: 0700, directory: true}, {name: "data/db/security/server.pem", body: server, mode: 0400}, {name: "data/db/security/keyfile", body: []byte(base64.StdEncoding.EncodeToString(key)), mode: 0400}, {name: "data/db/security/ca.pem", body: ca, mode: 0444}}
		if err := d.putFiles(ctx, state.ID, files); err != nil {
			return err
		}
	}
	// The upstream entrypoint bootstraps on container-only loopback port 27017,
	// never the published endpoint. Its literal quoting handles supported SCRAM
	// credentials; SASLprep admission already excludes trailing newlines.
	return d.putFiles(ctx, state.ID, []nativeFile{{name: "data/db/database", mode: 0700, directory: true}, {name: "run/stackd-docdb-bootstrap", body: []byte(spec.Password), mode: 0400}})
}
