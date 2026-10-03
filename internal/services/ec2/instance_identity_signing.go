package ec2

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

// identitySigningMaterial follows the existing operational SNS signer pattern:
// generate outside resource transactions, retain through the typed repository,
// and cache parsed keys only for this service instance.
func (s *Service) identitySigningMaterial(ctx context.Context, kind string) (*instanceIdentitySigner, error) {
	s.identitySigningMu.Lock()
	defer s.identitySigningMu.Unlock()
	if signer := s.identitySigningKeys[kind]; signer != nil {
		return signer, nil
	}
	var record IdentitySigningKeyRecord
	err := s.repository.View(ctx, func(reader Reader) error {
		var err error
		record, err = reader.IdentitySigningKey(kind)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		record, err = newIdentitySigningKey(kind)
		if err != nil {
			return nil, err
		}
		if err = s.repository.Update(ctx, func(tx Transaction) error { return tx.PutIdentitySigningKey(record) }); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	signer, err := parseIdentitySigningKey(record)
	if err != nil {
		return nil, err
	}
	if s.identitySigningKeys == nil {
		s.identitySigningKeys = make(map[string]*instanceIdentitySigner, 3)
	}
	s.identitySigningKeys[kind] = signer
	return signer, nil
}

func (s *Service) instanceIdentityMetadata(ctx context.Context, record InstanceRecord, item string) ([]byte, string, int) {
	if item == "" {
		return metadataText("document\npkcs7\nrsa2048\nsignature")
	}
	var kind string
	switch item {
	case "document":
	case "signature":
		kind = "rsa"
	case "pkcs7":
		kind = "dsa"
	case "rsa2048":
		kind = "rsa2048"
	default:
		return nil, "", http.StatusNotFound
	}
	document, err := instanceIdentityDocument(record)
	if err != nil {
		return nil, "", http.StatusInternalServerError
	}
	if kind == "" {
		return document, "text/plain", http.StatusOK
	}
	signer, err := s.identitySigningMaterial(ctx, kind)
	if err == nil {
		var signature []byte
		signature, err = signer.signedDocument(document, s.clock.Now())
		if err == nil {
			return identityBase64(signature), "text/plain", http.StatusOK
		}
	}
	slog.Error("EC2 instance identity signing failed", "instance", resourceARN(record.Key.Scope, "instance", record.Key.ID), "kind", kind, "error", err)
	return nil, "", http.StatusInternalServerError
}

// ServeInstanceIdentityCertificate exports only public local-authority material
// on an explicit stackd control path. These certificates are not AWS identities;
// consumers must deliberately configure their own trust in this emulator.
func (s *Service) ServeInstanceIdentityCertificate(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/_stackd/ec2/identity-certificates/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	var kind string
	switch strings.TrimPrefix(r.URL.Path, prefix) {
	case "dsa.pem":
		kind = "dsa"
	case "rsa.pem":
		kind = "rsa"
	case "rsa2048.pem":
		kind = "rsa2048"
	default:
		http.NotFound(w, r)
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	signer, err := s.identitySigningMaterial(r.Context(), kind)
	if err != nil {
		slog.Error("EC2 identity certificate unavailable", "kind", kind, "error", err)
		http.Error(w, "Unable to load instance identity certificate.", http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(signer.certificatePEM)
	}
	return true
}

func cloneIdentitySigningKey(record IdentitySigningKeyRecord) IdentitySigningKeyRecord {
	record.PrivateKeyDER = slices.Clone(record.PrivateKeyDER)
	record.CertificateDER = slices.Clone(record.CertificateDER)
	return record
}

func (r memoryReader) IdentitySigningKey(kind string) (IdentitySigningKeyRecord, error) {
	return getRecord(r.tx, r.s.identitySigningKeys, kind, cloneIdentitySigningKey)
}

func (w memoryWriter) PutIdentitySigningKey(record IdentitySigningKeyRecord) error {
	return putRecord(w.tx, w.s.identitySigningKeys, record.Kind, record, cloneIdentitySigningKey)
}
