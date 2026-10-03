package sns

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // SNS SignatureVersion 1 requires RSA-SHA1.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// signingMaterial generates the protocol key outside a resource transaction.
// Backends belong to one active instance; the mutex coordinates this instance's
// publishers while the repository keeps the native certificate across restart.
func (s *Service) signingMaterial(ctx context.Context, create bool) (*rsa.PrivateKey, SigningKeyRecord, error) {
	s.signingMu.Lock()
	defer s.signingMu.Unlock()
	if s.signingKey != nil {
		return s.signingKey, s.signingRecord, nil
	}
	var record SigningKeyRecord
	err := s.repository.View(ctx, func(r Reader) error { var err error; record, err = r.SigningKey(); return err })
	if errors.Is(err, ErrNotFound) && create {
		var key *rsa.PrivateKey
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, record, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, record, err
		}
		// This is the emulator's operational certificate, not a simulated AWS
		// customer resource. Its validity is independent of virtual service time.
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd SNS notification signer"}, NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return nil, record, err
		}
		record = SigningKeyRecord{ID: strings.ReplaceAll(identifier(), "-", ""), PrivateKeyDER: x509.MarshalPKCS1PrivateKey(key), CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
		if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutSigningKey(record) }); err != nil {
			return nil, record, err
		}
		s.signingKey, s.signingRecord = key, record
		return key, record, nil
	}
	if err != nil {
		return nil, record, err
	}
	key, err := x509.ParsePKCS1PrivateKey(record.PrivateKeyDER)
	if err != nil {
		return nil, record, err
	}
	s.signingKey, s.signingRecord = key, record
	return key, record, nil
}

func signNotification(message *MessageRecord, key *rsa.PrivateKey, keyID string) error {
	var h hash.Hash
	algorithm := crypto.SHA1
	if message.SignatureVersion == "2" {
		algorithm = crypto.SHA256
		h = sha256.New()
	} else {
		h = sha1.New()
	}
	field := func(name, value string) {
		_, _ = io.WriteString(h, name)
		_, _ = io.WriteString(h, "\n")
		_, _ = io.WriteString(h, value)
		_, _ = io.WriteString(h, "\n")
	}
	field("Message", message.Body)
	field("MessageId", message.Key.ID)
	if message.Subject != nil {
		field("Subject", *message.Subject)
	}
	if message.Type != "" {
		field("SubscribeURL", message.SubscribeURL)
	}
	field("Timestamp", notificationTimestamp(message.Published))
	if message.Type != "" {
		field("Token", message.Token)
	}
	field("TopicArn", message.Topic.ARN())
	kind := message.Type
	if kind == "" {
		kind = "Notification"
	}
	field("Type", kind)
	signature, err := rsa.SignPKCS1v15(nil, key, algorithm, h.Sum(nil))
	if err != nil {
		return err
	}
	message.Signature = base64.StdEncoding.EncodeToString(signature)
	message.SigningKeyID = keyID
	return nil
}

func notificationTimestamp(at time.Time) string { return at.UTC().Format("2006-01-02T15:04:05.000Z") }
func (s *Service) certificateURL(id string) string {
	return s.publicEndpoint + "/SimpleNotificationService-" + id + ".pem"
}
func (s *Service) unsubscribeURL(k SubscriptionKey) string {
	return s.publicEndpoint + "/?Action=Unsubscribe&SubscriptionArn=" + url.QueryEscape(k.ARN())
}

// ServeSigningCertificate handles only the native SNS public-certificate path.
// Certificate retrieval is public; no other SNS operation bypasses authentication.
// Consumers must explicitly trust this instance's certificate/origin rather than
// treating a localhost URL or self-signed certificate as an AWS identity.
func (s *Service) ServeSigningCertificate(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/SimpleNotificationService-"
	if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, ".pem") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	_, record, err := s.signingMaterial(r.Context(), false)
	if errors.Is(err, ErrNotFound) || err == nil && r.URL.Path != prefix+record.ID+".pem" {
		http.NotFound(w, r)
		return true
	}
	if err != nil {
		http.Error(w, "Unable to load SNS certificate.", http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(record.CertificatePEM)
	}
	return true
}
