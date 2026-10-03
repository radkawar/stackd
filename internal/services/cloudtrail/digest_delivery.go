package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type digestLogFile struct {
	Bucket    string `json:"s3Bucket"`
	Object    string `json:"s3Object"`
	Hash      string `json:"hashValue"`
	Algorithm string `json:"hashAlgorithm"`
	Newest    string `json:"newestEventTime"`
	Oldest    string `json:"oldestEventTime"`
}

type digestDocument struct {
	AccountID         string          `json:"awsAccountId"`
	Start             string          `json:"digestStartTime"`
	End               string          `json:"digestEndTime"`
	Bucket            string          `json:"digestS3Bucket"`
	Object            string          `json:"digestS3Object"`
	Fingerprint       string          `json:"digestPublicKeyFingerprint"`
	Algorithm         string          `json:"digestSignatureAlgorithm"`
	Newest            *string         `json:"newestEventTime"`
	Oldest            *string         `json:"oldestEventTime"`
	PreviousBucket    *string         `json:"previousDigestS3Bucket"`
	PreviousObject    *string         `json:"previousDigestS3Object"`
	PreviousHash      *string         `json:"previousDigestHashValue"`
	PreviousAlgorithm *string         `json:"previousDigestHashAlgorithm"`
	PreviousSignature *string         `json:"previousDigestSignature"`
	Logs              []digestLogFile `json:"logFiles"`
}

func digestTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }
func digestHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func buildDigest(stream *DigestStream, logs []DigestLog, key DigestKeyRecord) error {
	prefix := stream.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	prefix += "AWSLogs/"
	if stream.OrganizationID != "" {
		prefix += stream.OrganizationID + "/"
	}
	object := prefix + stream.AccountID + "/CloudTrail-Digest/" + stream.Region + "/" + stream.End.UTC().Format("2006/01/02/") + stream.AccountID + "_CloudTrail-Digest_" + stream.Region + "_" + stream.Trail.Name + "_" + stream.Trail.Region + "_" + stream.End.UTC().Format("20060102T150405Z") + ".json.gz"
	doc := digestDocument{
		AccountID: stream.AccountID, Start: digestTime(stream.Start), End: digestTime(stream.End),
		Bucket: stream.Bucket, Object: object, Fingerprint: key.Fingerprint,
		Algorithm: "SHA256withRSA", Logs: make([]digestLogFile, 0, len(logs)),
	}
	if stream.PreviousObject != "" {
		doc.PreviousBucket, doc.PreviousObject = new(stream.PreviousBucket), new(stream.PreviousObject)
		doc.PreviousHash, doc.PreviousAlgorithm = new(stream.PreviousHash), new("SHA-256")
		doc.PreviousSignature = new(stream.PreviousSignature)
	}
	var oldest, newest time.Time
	for _, log := range logs {
		doc.Logs = append(doc.Logs, digestLogFile{
			Bucket: log.Bucket, Object: log.Object, Hash: log.Hash, Algorithm: "SHA-256",
			Oldest: digestTime(log.Oldest), Newest: digestTime(log.Newest),
		})
		if oldest.IsZero() || log.Oldest.Before(oldest) {
			oldest = log.Oldest
		}
		if newest.IsZero() || log.Newest.After(newest) {
			newest = log.Newest
		}
	}
	if len(logs) > 0 {
		doc.Oldest, doc.Newest = new(digestTime(oldest)), new(digestTime(newest))
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	hash := digestHash(data)
	// AWS CLI validation canonicalizes a starting digest's JSON null signature
	// as the literal "null", matching the native Java signer.
	previousSignature := stream.PreviousSignature
	if doc.PreviousSignature == nil {
		previousSignature = "null"
	}
	signing := sha256.Sum256([]byte(doc.End + "\n" + doc.Bucket + "/" + doc.Object + "\n" + hash + "\n" + previousSignature))
	private, err := x509.ParsePKCS1PrivateKey(key.PrivateDER)
	if err != nil {
		return err
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, signing[:])
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	stream.Pending, stream.PendingObject = compressed.Bytes(), object
	stream.PendingHash, stream.PendingSignature = hash, hex.EncodeToString(signature)
	return nil
}

func (s *Service) runDigest(ctx context.Context, job scheduler.Job) error {
	var selected DigestStream
	var logs []DigestLog
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		selected, err = tx.DigestStream(strings.TrimPrefix(job.Key, "digest:"))
		if err != nil {
			return err
		}
		if selected.Version != job.Version || selected.Due.After(s.clock.Now()) {
			return nil
		}
		trail, err := tx.Trail(selected.Trail)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		// The owner's home chain reconciles empty-hour member/region changes.
		// Other regional chains need not repeat that authoritative enumeration.
		if err == nil && trail.ID == selected.TrailID && selected.AccountID == trail.Key.AccountID && selected.Region == trail.Key.Region {
			if err := s.reconcileDigests(tx, trail); err != nil {
				return err
			}
		}
		selected, err = tx.DigestStream(selected.ID)
		if err != nil {
			return err
		}
		if len(selected.Pending) == 0 {
			logs, err = tx.DigestLogs(selected.ID, selected.End)
		}
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if selected.Version != job.Version || selected.Due.After(s.clock.Now()) {
		return nil
	}
	if len(selected.Pending) == 0 {
		// Only unsealed work adopts the current destination. Changing the S3
		// location of retained signed bytes would invalidate the signature.
		err = s.repository.View(ctx, func(r Reader) error {
			trail, err := r.Trail(selected.Trail)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if trail.ID == selected.TrailID {
				selected.Bucket, selected.Prefix, selected.KMSKeyID = trail.Bucket, trail.Prefix, trail.KMSKeyID
			}
			return nil
		})
		if err != nil {
			return err
		}
		key, err := s.digestKey(ctx, selected.Trail.Partition, selected.Region, selected.End)
		if err != nil {
			return err
		}
		if err := buildDigest(&selected, logs, key); err != nil {
			return err
		}
		committed := false
		err = s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.DigestStream(selected.ID)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if current.Version != selected.Version {
				return nil
			}
			selected.Version++
			committed = true
			return tx.PutDigestStream(selected)
		})
		if err != nil || !committed {
			return err
		}
	}
	keyID := selected.KMSKeyID
	// KMS recovery can adopt a current key without changing signed plaintext.
	err = s.repository.View(ctx, func(r Reader) error {
		trail, err := r.Trail(selected.Trail)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if trail.ID == selected.TrailID {
			keyID = trail.KMSKeyID
		}
		return nil
	})
	if err != nil {
		return err
	}
	var result *awswire.Error
	if s.destination == nil {
		result = unsupported("No S3 log destination is configured.")
	} else {
		result = s.destination.Write(ctx, DeliveryRecord{
			Trail: selected.Trail, TrailID: selected.TrailID, AccountID: selected.AccountID,
			Region: selected.Region, OrganizationID: selected.OrganizationID,
			Bucket: selected.Bucket, ObjectKey: selected.PendingObject,
			Destination: DestinationDigest, DigestSignature: selected.PendingSignature,
		}, keyID, selected.Pending, "")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.finishDigest(ctx, selected, result)
}

func (s *Service) finishDigest(ctx context.Context, selected DigestStream, result *awswire.Error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.DigestStream(selected.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != selected.Version {
			return nil
		}
		now := s.clock.Now()
		trail, err := tx.Trail(current.Trail)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && trail.ID == current.TrailID {
			status, err := tx.DigestStatus(current.TrailID, current.AccountID, current.Region)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			status.TrailID, status.LastAttempt = current.TrailID, new(now)
			status.AccountID, status.Region = current.AccountID, current.Region
			if result == nil {
				status.LastSuccess, status.LastError = new(now), ""
			} else {
				status.LastError = result.Code
			}
			if err := tx.PutDigestStatus(status); err != nil {
				return err
			}
		}
		current.Version++
		if result != nil {
			current.Due = now.Add(time.Minute)
			return tx.PutDigestStream(current)
		}
		if err := tx.DeleteDigestLogs(current.ID, current.End); err != nil {
			return err
		}
		if current.Closed && !current.End.Before(current.ClosedAt) {
			return tx.DeleteDigestStream(current.ID)
		}
		current.PreviousBucket, current.PreviousObject = current.Bucket, current.PendingObject
		current.PreviousHash, current.PreviousSignature = current.PendingHash, current.PendingSignature
		current.Pending = nil
		current.PendingObject, current.PendingHash, current.PendingSignature = "", "", ""
		current.Start, current.End = current.End, current.End.Add(time.Hour)
		current.Due = current.End
		return tx.PutDigestStream(current)
	})
}
