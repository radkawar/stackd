package signer

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"stackd/compute/lambda/signature"
	api "stackd/internal/awsapi/signer"
	"stackd/internal/awsctx"
	"strings"
	"sync"
	"time"
)

func registerJobs(s *Service) {
	registerDetached(s, "StartSigningJob", s.startJob, false)
	register(s, "DescribeSigningJob", s.describeJob)
	register(s, "ListSigningJobs", s.listJobs)
}
func jobARN(sc Scope, id string) string {
	return "arn:" + sc.Partition + ":signer:" + sc.Region + ":" + sc.AccountID + ":/signing-jobs/" + id
}
func (s *Service) startJob(ctx context.Context, in *api.StartSigningJobInput) (*api.StartSigningJobOutput, error) {
	if s.objects == nil {
		return nil, invalid("An authoritative S3 object provider is required")
	}
	if in.Source == nil || in.Source.S3 == nil || in.Destination == nil || in.Destination.S3 == nil {
		return nil, invalid("An S3 source and destination are required")
	}
	src, dst := in.Source.S3, in.Destination.S3
	if value(src.BucketName) == "" || value(src.Key) == "" || value(src.Version) == "" || value(dst.BucketName) == "" || value(in.ClientRequestToken) == "" {
		return nil, invalid("A versioned S3 source, destination bucket and client token are required")
	}
	var job Job
	var profile Profile
	var authority Authority
	err := s.repository.Update(ctx, func(t Transaction) error {
		var e error
		profile, e = s.loadProfile(t.Context(), t, value(in.ProfileName), "", value(in.ProfileOwner), "StartSigningJob")
		if e != nil {
			return e
		}
		if profile.Status != "Active" {
			return invalid("The signing profile is not Active")
		}
		rows, e := t.Jobs(scopeFor(ctx))
		if e != nil {
			return e
		}
		for _, v := range rows {
			if v.Token != value(in.ClientRequestToken) {
				continue
			}
			if v.ProfileName != profile.Name || v.SourceBucket != value(src.BucketName) || v.SourceKey != value(src.Key) || v.SourceVersion != value(src.Version) || v.DestinationBucket != value(dst.BucketName) || v.DestinationPrefix != value(dst.Prefix) {
				return invalid("clientRequestToken was already used with different signing parameters")
			}
			job = v
			profile, e = t.Profile(v.Scope, v.ProfileName, v.ProfileVersion)
			if e != nil {
				return e
			}
			authority, e = t.Authority(v.Scope)
			return e
		}
		sc := scopeFor(ctx)
		id := uuid.NewString()
		now := s.clock.Now().UTC().Truncate(time.Second)
		job = Job{Scope: sc, ID: id, ARN: jobARN(sc, id), ProfileName: profile.Name, ProfileVersion: profile.Version, ProfileVersionARN: profile.VersionARN, Token: value(in.ClientRequestToken), SourceBucket: value(src.BucketName), SourceKey: value(src.Key), SourceVersion: value(src.Version), DestinationBucket: value(dst.BucketName), DestinationPrefix: value(dst.Prefix), DestinationKey: value(dst.Prefix) + id + ".zip", Status: "InProgress", RequestedBy: awsctx.FromContext(ctx).PrincipalARN, Created: now, Expires: signatureExpiry(now, profile)}
		authority, e = t.Authority(sc)
		if e != nil {
			return e
		}
		return t.PutJob(job)
	})
	if err != nil {
		return nil, err
	}
	if job.Status == "InProgress" {
		lock, _ := s.flights.LoadOrStore(job.ARN, new(sync.Mutex))
		mu := lock.(*sync.Mutex)
		mu.Lock()
		defer mu.Unlock()
		defer s.flights.Delete(job.ARN)
		if err = s.repository.View(ctx, func(r Reader) error {
			current, e := r.Job(job.Scope, job.ID)
			if e == nil {
				job = current
			}
			return e
		}); err != nil {
			return nil, err
		}
		if job.Status == "InProgress" {
			if err = s.completeJob(ctx, job, profile, authority); err != nil {
				return nil, err
			}
		}
	}
	return &api.StartSigningJobOutput{JobId: new(api.JobId(job.ID)), JobOwner: new(api.AccountId(job.AccountID))}, nil
}
func (s *Service) completeJob(ctx context.Context, job Job, profile Profile, authority Authority) error {
	body, err := s.objects.Read(ctx, job.SourceBucket, job.SourceKey, job.SourceVersion)
	if err == nil && len(body) > 250*1024*1024 {
		err = invalid("Signing source exceeds the platform's 250 MB limit")
	}
	var signed []byte
	if err == nil {
		leaf, e := x509.ParseCertificate(profile.Certificate)
		if e != nil {
			return e
		}
		root, e := x509.ParseCertificate(authority.Certificate)
		if e != nil {
			return e
		}
		private, e := x509.ParsePKCS8PrivateKey(profile.PrivateKey)
		if e != nil {
			return e
		}
		key, ok := private.(crypto.Signer)
		if !ok {
			return errors.New("retained signing key is not a signer")
		}
		chain := []*x509.Certificate{leaf, root}
		job.CertificateHashes = certificateHashes(chain)
		signed, err = signature.Sign(ctx, body, key, chain, signature.Claims{SigningProfileVersionARN: job.ProfileVersionARN, SigningJobARN: job.ARN, SigningTime: job.Created, Expires: job.Expires})
	}
	if err == nil {
		err = s.repository.View(ctx, func(r Reader) error {
			current, e := r.Profile(job.Scope, job.ProfileName, job.ProfileVersion)
			if e != nil {
				return e
			}
			if current.Status != "Active" {
				return invalid("The signing profile is no longer Active")
			}
			return s.authorize(r.Context(), "StartSigningJob", current.ARN, current.Tags, nil)
		})
	}
	if err == nil {
		err = s.objects.Write(ctx, job.DestinationBucket, job.DestinationKey, signed)
	}
	job.Completed = s.clock.Now().UTC().Truncate(time.Second)
	job.Status = "Succeeded"
	job.StatusReason = "Signing job completed."
	if err != nil {
		job.Status = "Failed"
		job.StatusReason = err.Error()
		job.CertificateHashes = nil
	}
	// Complete with a detached context after an accepted caller cancels, retaining
	// the real outcome instead of stranding an accepted job as a false success.
	completion, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return s.repository.Update(completion, func(t Transaction) error {
		current, e := t.Job(job.Scope, job.ID)
		if e != nil {
			return e
		}
		if current.Status != "InProgress" {
			return nil
		}
		job.RevokedAt = current.RevokedAt
		job.RevocationReason = current.RevocationReason
		job.RevokedBy = current.RevokedBy
		return t.PutJob(job)
	})
}
func (s *Service) loadJob(ctx context.Context, r Reader, id, action string) (Job, error) {
	v, e := r.Job(scopeFor(ctx), id)
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, v.ARN, nil, nil)
}
func source(v Job) *api.Source {
	return &api.Source{S3: &api.S3Source{BucketName: new(api.BucketName(v.SourceBucket)), Key: new(api.Key(v.SourceKey)), Version: new(api.Version(v.SourceVersion))}}
}
func signedObject(v Job) *api.SignedObject {
	if v.Status != "Succeeded" {
		return nil
	}
	return &api.SignedObject{S3: &api.S3SignedObject{BucketName: new(api.BucketName(v.DestinationBucket)), Key: new(api.Key(v.DestinationKey))}}
}
func (s *Service) describeJob(ctx context.Context, t Transaction, in *api.DescribeSigningJobInput) (*api.DescribeSigningJobOutput, error) {
	v, e := s.loadJob(ctx, t, value(in.JobId), "DescribeSigningJob")
	if e != nil {
		return nil, e
	}
	o := &api.DescribeSigningJobOutput{CreatedAt: &v.Created, Source: source(v), SignedObject: signedObject(v)}
	text(&o.JobId, v.ID)
	text(&o.JobOwner, v.AccountID)
	text(&o.JobInvoker, v.AccountID)
	text(&o.ProfileName, v.ProfileName)
	text(&o.ProfileVersion, v.ProfileVersion)
	text(&o.PlatformId, LambdaPlatform)
	text(&o.PlatformDisplayName, "AWS Lambda")
	text(&o.Status, v.Status)
	text(&o.StatusReason, v.StatusReason)
	text(&o.RequestedBy, v.RequestedBy)
	if !v.Completed.IsZero() {
		o.CompletedAt = &v.Completed
	}
	if v.Status == "Succeeded" {
		o.SignatureExpiresAt = &v.Expires
	}
	if !v.RevokedAt.IsZero() {
		o.RevocationRecord = &api.SigningJobRevocationRecord{RevokedAt: &v.RevokedAt, Reason: new(api.String(v.RevocationReason)), RevokedBy: new(api.String(v.RevokedBy))}
	}
	return o, nil
}
func (s *Service) listJobs(ctx context.Context, t Transaction, in *api.ListSigningJobsInput) (*api.ListSigningJobsOutput, error) {
	if e := s.authorize(ctx, "ListSigningJobs", "", nil, nil); e != nil {
		return nil, e
	}
	limit, after, e := page(in.MaxResults, value(in.NextToken))
	if e != nil {
		return nil, e
	}
	rows, e := t.Jobs(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	o := &api.ListSigningJobsOutput{Jobs: api.SigningJobs{}}
	for _, v := range rows {
		revoked := !v.RevokedAt.IsZero()
		if v.ID <= after || value(in.PlatformId) != "" && value(in.PlatformId) != LambdaPlatform || value(in.Status) != "" && value(in.Status) != v.Status || value(in.RequestedBy) != "" && value(in.RequestedBy) != v.RequestedBy || value(in.JobInvoker) != "" && value(in.JobInvoker) != v.AccountID || in.IsRevoked != nil && bool(*in.IsRevoked) != revoked || in.SignatureExpiresAfter != nil && !v.Expires.After(*in.SignatureExpiresAfter) || in.SignatureExpiresBefore != nil && !v.Expires.Before(*in.SignatureExpiresBefore) {
			continue
		}
		if len(o.Jobs) == limit {
			text(&o.NextToken, base64.RawURLEncoding.EncodeToString([]byte(value(o.Jobs[len(o.Jobs)-1].JobId))))
			break
		}
		j := api.SigningJob{CreatedAt: &v.Created, IsRevoked: new(api.Bool(revoked)), Source: source(v), SignedObject: signedObject(v)}
		text(&j.JobId, v.ID)
		text(&j.JobOwner, v.AccountID)
		text(&j.JobInvoker, v.AccountID)
		text(&j.ProfileName, v.ProfileName)
		text(&j.ProfileVersion, v.ProfileVersion)
		text(&j.PlatformId, LambdaPlatform)
		text(&j.PlatformDisplayName, "AWS Lambda")
		text(&j.Status, v.Status)
		if v.Status == "Succeeded" {
			j.SignatureExpiresAt = &v.Expires
		}
		o.Jobs = append(o.Jobs, j)
	}
	return o, nil
}
func parseResourceARN(arn, kind string) (Scope, string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "signer" || parts[1] == "" || parts[3] == "" || parts[4] == "" || !strings.HasPrefix(parts[5], "/"+kind+"/") {
		return Scope{}, "", invalid("Invalid Signer resource ARN")
	}
	return Scope{parts[1], parts[4], parts[3]}, strings.TrimPrefix(parts[5], "/"+kind+"/"), nil
}
