package rds

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Security material is in the exact-owned data volume, outside the database
// directory copied by snapshots. Restores therefore get their own trust root,
// while process replacement and controller restarts retain existing trust.
const postgresSecurity = "/var/lib/postgresql/data/security"

func postgresHBA(parameters map[string]string) string {
	// The upstream first-init temporary server uses only a Unix socket.
	const local = "local all all trust\n"
	if parameters["rds.force_ssl"] == "0" {
		return local + "host all all all scram-sha-256\n"
	}
	return local + "hostnossl all all all reject\nhostssl all all all scram-sha-256\n"
}

// TODO: Comeback implement managed CA selection and certificate rotation;
// retained per-incarnation local trust is not the AWS certificate lifecycle.
func postgresCertificates(host string) (ca, certificate, key []byte, err error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd local PostgreSQL CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, root, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	der, err = x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return nil, nil, nil, err
	}
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return ca, certificate, key, nil
}

func (d *Docker) securityFile(ctx context.Context, id, name string) ([]byte, error) {
	response, err := d.client.Request(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(postgresSecurity+"/"+name), nil, "")
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
		return nil, errors.New("invalid native PostgreSQL security file")
	}
	return io.ReadAll(io.LimitReader(archive, 64<<10))
}

func (d *Docker) initializePostgresTLS(ctx context.Context, state containerState, parameters map[string]string) error {
	ca, err := d.securityFile(ctx, state.ID, "ca.pem")
	if err == nil {
		// Never silently rotate retained trust, including on endpoint-host changes.
		certificate, err := d.securityFile(ctx, state.ID, "server.crt")
		if err != nil {
			return err
		}
		key, err := d.securityFile(ctx, state.ID, "server.key")
		if err != nil {
			return err
		}
		pair, err := tls.X509KeyPair(certificate, key)
		if err != nil {
			return errors.New("invalid retained PostgreSQL key pair")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return errors.New("invalid retained PostgreSQL CA")
		}
		_, err = pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: d.endpointHost})
		return err
	}
	if !dockerStatus(err, http.StatusNotFound) {
		return err
	}
	ca, certificate, key, err := postgresCertificates(d.endpointHost)
	if err != nil {
		return err
	}
	files := []postgresSecurityFile{
		{"server.crt", certificate, 0444},
		{"server.key", key, 0400},
		{"pg_hba.conf", []byte(postgresHBA(parameters)), 0400},
		// Publish the public CA last, matching the DocDB initialization marker.
		{"ca.pem", ca, 0444},
	}
	return d.putPostgresSecurity(ctx, state.ID, files)
}

type postgresSecurityFile struct {
	name string
	body []byte
	mode int64
}

func (d *Docker) applyPostgresHBA(ctx context.Context, id string, parameters map[string]string) error {
	desired := postgresHBA(parameters)
	current, err := d.securityFile(ctx, id, "pg_hba.conf")
	if err != nil {
		return err
	}
	if string(current) == desired {
		return nil
	}
	return d.putPostgresSecurity(ctx, id, []postgresSecurityFile{{"pg_hba.conf", []byte(desired), 0400}})
}

func (d *Docker) putPostgresSecurity(ctx context.Context, id string, files []postgresSecurityFile) error {
	var content bytes.Buffer
	archive := tar.NewWriter(&content)
	directory := postgresSecurity[1:]
	if err := archive.WriteHeader(&tar.Header{Name: directory, Typeflag: tar.TypeDir, Mode: 0700, Uid: 999, Gid: 999}); err != nil {
		return err
	}
	for _, file := range files {
		if err := archive.WriteHeader(&tar.Header{Name: directory + "/" + file.name, Mode: file.mode, Size: int64(len(file.body)), Uid: 999, Gid: 999}); err != nil {
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

// endpoint reads only public trust from a container whose identity and exact
// durable mount have already been checked by the caller.
func (d *Docker) endpoint(ctx context.Context, state containerState, engine string) (Endpoint, error) {
	endpoint, err := state.endpoint(d.endpointHost, engine)
	if err != nil {
		return Endpoint{}, err
	}
	kind, _ := family(engine)
	if kind == "postgres" {
		endpoint.CA, err = d.securityFile(ctx, state.ID, "ca.pem")
	}
	return endpoint, err
}
