package codebuild

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"net/http"
	"stackd/internal/identity"
	"strings"
	"time"
)

// CredentialsHandler is a build-owned metadata endpoint, not an unsigned AWS
// API. The native loopback proxy forwards the accepted build capability here.
func (s *Service) CredentialsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		encoded, ok := strings.CutPrefix(r.URL.Path, "/_stackd/codebuild/credentials/")
		if !ok || strings.Contains(encoded, "/") {
			http.NotFound(w, r)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		resource, err := arn.Parse(string(raw))
		if err != nil || resource.Service != "codebuild" || !strings.HasPrefix(resource.Resource, "build/") {
			http.NotFound(w, r)
			return
		}
		key := BuildKey{Scope: Scope{resource.Partition, resource.AccountID, resource.Region}, ID: strings.TrimPrefix(resource.Resource, "build/")}
		var record BuildRecord
		err = s.repository.View(r.Context(), func(reader Reader) error { var err error; record, err = reader.Build(key); return err })
		token := r.Header.Get("Authorization")
		if err != nil || complete(record) || record.StopRequested || record.CredentialToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(record.CredentialToken)) != 1 {
			http.NotFound(w, r)
			return
		}
		if _, err = s.controller.roleContext(ownerContext(r.Context(), record), record); err != nil {
			http.Error(w, "Execution role credentials are unavailable.", http.StatusServiceUnavailable)
			return
		}
		s.controller.mu.Lock()
		credential := s.controller.sessions[key].credential
		s.controller.mu.Unlock()
		if credential.IssuerARN != value(record.Data.ServiceRole) || credential.AccountID != key.AccountID || credential.SessionType != identity.SessionTypeAssumeRole || credential.AccessKeyID == "" || credential.SecretAccessKey == "" || credential.SessionToken == "" || !credential.Expiration.After(s.clock.Now()) {
			http.Error(w, "Execution role credentials are unavailable.", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			RoleArn         string
			AccessKeyId     string
			SecretAccessKey string
			Token           string
			Expiration      string
		}{credential.IssuerARN, credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken, credential.Expiration.UTC().Format(time.RFC3339)})
	})
}
