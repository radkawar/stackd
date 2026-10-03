package lambda

import (
	"crypto/md5" // S3's single-part object ETag, not an authentication primitive.
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/identity"
)

// ServeCodeDownload owns Lambda's private code-archive path. Only the signed
// archive capability is accepted; this does not expose a public S3 bucket or
// bypass authentication for any Lambda API operation.
func (s *Service) ServeCodeDownload(w http.ResponseWriter, r *http.Request) bool {
	path, handled := strings.CutPrefix(r.URL.Path, codeDownloadPrefix)
	if !handled {
		return false
	}
	requestID := uuid.NewString()
	r = r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{RequestID: requestID}))
	model, _ := awscatalog.LookupService("s3")
	fail := func(wire *awswire.Error) { awswire.RESTXMLError(w, r, &model, wire) }
	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		fail(failure("AccessDenied", "Access Denied", 403))
		return true
	}
	digest, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(digest) != 32 {
		fail(failure("AccessDenied", "Access Denied", 403))
		return true
	}
	key := CodeArchiveKey{Scope: Scope{Partition: parts[0], Account: parts[1], Region: parts[2]}, SHA256: base64.StdEncoding.EncodeToString(digest)}
	var signing CodeSigningKey
	err = s.repository.View(r.Context(), func(reader Reader) error {
		var err error
		signing, err = reader.CodeSigningKey(key.Scope)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			fail(failure("AccessDenied", "Access Denied", 403))
		} else {
			fail(wireError(err))
		}
		return true
	}
	// A download has no input payload. Authenticate its actual method, host and
	// URL without reading an attacker-supplied body into memory.
	signed := *r
	signed.Body = http.NoBody
	now := s.clock.Now()
	wire := gateway.VerifyS3PresignedRequest(&signed, identity.Credential{AccessKeyID: signing.AccessKeyID, SecretAccessKey: signing.SecretAccessKey}, key.Region, now)
	if wire != nil {
		if wire.Code == "RequestExpired" {
			wire = failure("AccessDenied", "Request has expired", 403)
		}
		fail(wire)
		return true
	}
	if r.Method != http.MethodGet {
		fail(failure("AccessDenied", "Access Denied", 403))
		return true
	}
	var archive CodeArchive
	err = s.repository.View(r.Context(), func(reader Reader) error {
		var err error
		archive, err = reader.CodeArchive(key)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			fail(failure("NoSuchKey", "The specified key does not exist.", 404))
		} else {
			fail(wireError(err))
		}
		return true
	}
	size := int64(len(archive.Code))
	start, end, wire := awswire.ByteRange(r.Header.Get("Range"), size)
	if wire != nil {
		fail(wire)
		return true
	}
	etag := md5.Sum(archive.Code)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.FormatInt(end-start, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", `"`+hex.EncodeToString(etag[:])+`"`)
	w.Header().Set("Last-Modified", archive.CreatedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("X-Amz-Request-Id", requestID)
	w.Header().Set("X-Amz-Id-2", base64.StdEncoding.EncodeToString([]byte(requestID)))
	if r.Header.Get("Range") != "" {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end-1, size))
		w.WriteHeader(http.StatusPartialContent)
	}
	_, _ = w.Write(archive.Code[start:end])
	return true
}
