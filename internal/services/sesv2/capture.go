package sesv2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

const VerificationPath = "/_stackd/ses/verify-email-identity"

// CapturePath is the stable local RFC 5322 artifact boundary. The retained MIME is
// authoritative; replacing this file after a crash is safe and idempotent.
func CapturePath(root string, k ResourceKey) string {
	return filepath.Join(root, k.Partition, k.AccountID, k.Region, k.Name+".eml")
}

type captureJobs struct{ s *Service }

func (j captureJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var out scheduler.Job
	var found bool
	if j.s.captureDirectory == "" {
		return out, false, nil
	}
	e := j.s.repository.View(ctx, func(r Reader) error {
		m, ok, e := r.NextCapture()
		found = ok
		if ok {
			out = scheduler.Job{Key: m.Key.ARN("message"), Due: m.Due}
		}
		return e
	})
	return out, found, e
}
func (j captureJobs) Run(ctx context.Context, job scheduler.Job) error {
	var m Message
	e := j.s.repository.View(ctx, func(r Reader) error {
		var ok bool
		var e error
		m, ok, e = r.NextCapture()
		if !ok || m.Key.ARN("message") != job.Key || m.Due.After(j.s.clock.Now()) {
			m = Message{}
		}
		return e
	})
	if e != nil || m.Key.Name == "" {
		return e
	}
	// File creation is deliberately outside the shared resource transaction. A
	// crash before acknowledging capture only causes replacement with identical bytes.
	path := CapturePath(j.s.captureDirectory, m.Key)
	captureErr := writeCapture(ctx, path, m.MIME)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Message(m.Key)
		if e != nil {
			return e
		}
		if !current.CapturePending {
			return nil
		}
		if captureErr == nil {
			current.CapturePending = false
			current.CaptureError = ""
		} else {
			current.Due = j.s.clock.Now().Add(time.Second)
			current.CaptureError = captureErr.Error()
		}
		return tx.PutMessage(current)
	})
}
func writeCapture(ctx context.Context, path string, mime []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".mail-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(mime)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// VerificationHandler completes only an unexpired, single-use identity token.
// The bearer route is not an administrator identity override or mailbox API.
func (s *Service) VerificationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != VerificationPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		token := r.URL.Query().Get("token")
		if len(token) != 48 {
			http.Error(w, "Invalid verification token", 400)
			return
		}
		e := s.repository.Update(r.Context(), func(tx Transaction) error {
			id, e := tx.IdentityByToken(token)
			if e != nil {
				return e
			}
			if id.Verified || !s.clock.Now().Before(id.VerificationExpires) {
				return ErrNotFound
			}
			id.Verified = true
			id.VerificationToken = ""
			return tx.PutIdentity(id)
		})
		if e != nil {
			if errors.Is(e, ErrNotFound) {
				http.Error(w, "Invalid or expired verification token", 400)
			} else {
				http.Error(w, "Unable to verify identity", 500)
			}
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "Email identity verified.")
	})
}
func (s *Service) verificationURL(token string) string {
	return strings.TrimRight(s.publicEndpoint, "/") + VerificationPath + "?token=" + token
}
