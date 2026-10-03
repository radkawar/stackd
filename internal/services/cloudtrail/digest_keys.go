package cloudtrail

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Keys rotate in retained thirty-day service-time intervals. Generation is outside
// repository transactions; the second lookup elects one key if callers race.
func (s *Service) digestKey(ctx context.Context, partition, region string, at time.Time) (DigestKeyRecord, error) {
	var found DigestKeyRecord
	lookup := func(r Reader) error {
		keys, err := r.DigestKeys(partition, region)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if !at.Before(key.Start) && at.Before(key.End) {
				found = key
				break
			}
		}
		return nil
	}
	if err := s.repository.View(ctx, lookup); err != nil || found.Fingerprint != "" {
		return found, err
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return found, err
	}
	public := x509.MarshalPKCS1PublicKey(&private.PublicKey)
	// Native ListPublicKeys fingerprints are MD5 of the returned PKCS#1 DER.
	// This identifier is not the SHA-256 integrity hash used for signing.
	fingerprint := md5.Sum(public)
	start := at.UTC().Truncate(30 * 24 * time.Hour)
	generated := DigestKeyRecord{
		Partition: partition, Region: region, Fingerprint: hex.EncodeToString(fingerprint[:]),
		Start: start, End: start.Add(30 * 24 * time.Hour),
		PrivateDER: x509.MarshalPKCS1PrivateKey(private), PublicDER: public,
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		if err := lookup(tx); err != nil {
			return err
		}
		if found.Fingerprint != "" {
			return nil
		}
		found = generated
		return tx.PutDigestKey(generated)
	})
	return found, err
}

func (s *Service) listPublicKeys(ctx context.Context, in *api.ListPublicKeysInput) (*api.ListPublicKeysOutput, *awswire.Error) {
	if wire := s.authorizer.Authorize(ctx, authorization.Request{Action: "cloudtrail:ListPublicKeys", ResourceARN: "*"}); wire != nil {
		return nil, wire
	}
	now := s.clock.Now()
	start, end := now, now
	if in.StartTime != nil {
		start = *in.StartTime
	}
	if in.EndTime != nil {
		end = *in.EndTime
	}
	if start.After(end) {
		return nil, failure("InvalidTimeRangeException", "The start time must not be after the end time.")
	}
	// NextToken is reserved; the native service ignores a supplied token.
	m := awsctx.FromContext(ctx)
	// Discovery returns a usable current regional key even before a trail exists.
	if _, err := s.digestKey(ctx, m.Partition, m.Region, now); err != nil {
		return nil, wireError(err)
	}
	out := &api.ListPublicKeysOutput{PublicKeyList: api.PublicKeyList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		keys, err := r.DigestKeys(m.Partition, m.Region)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if !key.Start.After(end) && !key.End.Before(start) {
				out.PublicKeyList = append(out.PublicKeyList, api.PublicKey{
					Fingerprint: str(key.Fingerprint), Value: api.ByteBuffer(key.PublicDER),
					ValidityStartTime: new(key.Start), ValidityEndTime: new(key.End),
				})
			}
		}
		return nil
	})
	return out, wireError(err)
}
