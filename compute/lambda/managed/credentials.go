package managed

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	runtime "stackd/compute/lambda"
)

func newCredentialsToken() string { return uuid.NewString() + uuid.NewString() }
func validCredentials(c runtime.Credentials) bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != "" && c.SessionToken != "" && !c.Expiration.IsZero()
}
func (e *environment) restoreCredentials() error {
	raw, err := os.ReadFile(filepath.Join(e.directory, "credentials.json"))
	if errors.Is(err, os.ErrNotExist) {
		return e.updateCredentials(e.deployment.Specification.Credentials)
	}
	if err != nil {
		return err
	}
	var saved runtime.Credentials
	if err = json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	if !validCredentials(saved) {
		return errors.New("retained execution-role credentials are invalid")
	}
	if e.deployment.Specification.Credentials.Expiration.After(saved.Expiration) {
		saved = e.deployment.Specification.Credentials
	}
	return e.updateCredentials(saved)
}
func (e *environment) updateCredentials(c runtime.Credentials) error {
	if !validCredentials(c) {
		return &RemoteError{400, "Execution-role session credentials are required"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c.Expiration.Before(e.credentials.Expiration) {
		return &RemoteError{409, "Execution-role credential update is stale"}
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err = atomicPrivateFile(filepath.Join(e.directory, "credentials.json"), encoded); err != nil {
		return err
	}
	e.credentials = c
	return nil
}
func (e *environment) credentialsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(e.credentialsToken)) != 1 {
		http.Error(w, "Execution environment credentials token rejected", http.StatusForbidden)
		return
	}
	e.mu.Lock()
	credentials := e.credentials
	e.mu.Unlock()
	if !time.Now().Before(credentials.Expiration) {
		http.Error(w, "Execution-role credentials have expired", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	guestJSON(w, struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string
		Token           string
		Expiration      time.Time
	}{credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, credentials.Expiration})
}
