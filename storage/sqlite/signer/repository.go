package signer

import (
	"context"
	"database/sql"
	"errors"
	domain "stackd/storage/signer"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/signer/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, f func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, t *sql.Tx) error { return f(reader{ctx, sqlcgen.New(t)}) })
}
func (r *Repository) Update(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}
func (r *Repository) Attempt(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func authority(v sqlcgen.SignerAuthority) domain.Authority {
	return domain.Authority{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Certificate: v.Certificate, PrivateKey: v.PrivateKey}
}
func (r reader) Authority(sc domain.Scope) (domain.Authority, error) {
	v, e := r.q.GetAuthority(r.ctx, sqlcgen.GetAuthorityParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	return authority(v), missing(e)
}
func (r reader) Authorities() ([]domain.Authority, error) {
	rows, e := r.q.ListAuthorities(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Authority, 0, len(rows))
	for _, v := range rows {
		out = append(out, authority(v))
	}
	return out, nil
}
func (w writer) PutAuthority(v domain.Authority) error {
	return w.q.PutAuthority(w.ctx, sqlcgen.PutAuthorityParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Certificate: v.Certificate, PrivateKey: v.PrivateKey})
}
func (r reader) Profile(sc domain.Scope, name, version string) (domain.Profile, error) {
	var row sqlcgen.SignerProfile
	var e error
	if version == "" {
		row, e = r.q.GetCurrentProfile(r.ctx, sqlcgen.GetCurrentProfileParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Name: name})
	} else {
		row, e = r.q.GetProfile(r.ctx, sqlcgen.GetProfileParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Name: name, Version: version})
	}
	if e != nil {
		return domain.Profile{}, missing(e)
	}
	return r.profile(row)
}
func (r reader) Profiles(sc domain.Scope) ([]domain.Profile, error) {
	rows, e := r.q.ListProfiles(r.ctx, sqlcgen.ListProfilesParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Profile, 0, len(rows))
	for _, row := range rows {
		v, e := r.profile(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) profile(v sqlcgen.SignerProfile) (domain.Profile, error) {
	out := domain.Profile{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name, ARN: v.Arn, Version: v.Version, VersionARN: v.VersionArn, Status: v.Status, Current: v.IsCurrent, ValidityValue: v.ValidityValue, ValidityType: v.ValidityType, Created: v.Created, RevokedAt: v.RevokedAt, EffectiveTime: v.EffectiveTime, RevocationReason: v.RevocationReason, RevokedBy: v.RevokedBy, Certificate: v.Certificate, PrivateKey: v.PrivateKey, Tags: map[string]string{}}
	tags, e := r.q.ListProfileTags(r.ctx, v.VersionArn)
	if e != nil {
		return out, e
	}
	for _, tag := range tags {
		out.Tags[tag.TagKey] = tag.TagValue
	}
	return out, nil
}
func (w writer) PutProfile(v domain.Profile) error {
	e := w.q.PutProfile(w.ctx, sqlcgen.PutProfileParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: v.Name, Arn: v.ARN, Version: v.Version, VersionArn: v.VersionARN, Status: v.Status, IsCurrent: v.Current, ValidityValue: v.ValidityValue, ValidityType: v.ValidityType, Created: v.Created, RevokedAt: v.RevokedAt, EffectiveTime: v.EffectiveTime, RevocationReason: v.RevocationReason, RevokedBy: v.RevokedBy, Certificate: v.Certificate, PrivateKey: v.PrivateKey})
	if e != nil {
		return e
	}
	if e = w.q.DeleteProfileTags(w.ctx, v.VersionARN); e != nil {
		return e
	}
	for key, value := range v.Tags {
		if e = w.q.PutProfileTag(w.ctx, sqlcgen.PutProfileTagParams{VersionArn: v.VersionARN, TagKey: key, TagValue: value}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) Job(sc domain.Scope, id string) (domain.Job, error) {
	v, e := r.q.GetJob(r.ctx, sqlcgen.GetJobParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ID: id})
	if e != nil {
		return domain.Job{}, missing(e)
	}
	return r.job(v)
}
func (r reader) Jobs(sc domain.Scope) ([]domain.Job, error) {
	rows, e := r.q.ListJobs(r.ctx, sqlcgen.ListJobsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Job, 0, len(rows))
	for _, row := range rows {
		v, e := r.job(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) job(v sqlcgen.SignerJob) (domain.Job, error) {
	out := domain.Job{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, ARN: v.Arn, ProfileName: v.ProfileName, ProfileVersion: v.ProfileVersion, ProfileVersionARN: v.ProfileVersionArn, Token: v.Token, SourceBucket: v.SourceBucket, SourceKey: v.SourceKey, SourceVersion: v.SourceVersion, DestinationBucket: v.DestinationBucket, DestinationPrefix: v.DestinationPrefix, DestinationKey: v.DestinationKey, Status: v.Status, StatusReason: v.StatusReason, RequestedBy: v.RequestedBy, Created: v.Created, Completed: v.Completed, Expires: v.Expires, RevokedAt: v.RevokedAt, RevocationReason: v.RevocationReason, RevokedBy: v.RevokedBy}
	var e error
	out.CertificateHashes, e = r.q.ListJobCertificates(r.ctx, v.Arn)
	return out, e
}
func (w writer) PutJob(v domain.Job) error {
	e := w.q.PutJob(w.ctx, sqlcgen.PutJobParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Arn: v.ARN, ProfileName: v.ProfileName, ProfileVersion: v.ProfileVersion, ProfileVersionArn: v.ProfileVersionARN, Token: v.Token, SourceBucket: v.SourceBucket, SourceKey: v.SourceKey, SourceVersion: v.SourceVersion, DestinationBucket: v.DestinationBucket, DestinationPrefix: v.DestinationPrefix, DestinationKey: v.DestinationKey, Status: v.Status, StatusReason: v.StatusReason, RequestedBy: v.RequestedBy, Created: v.Created, Completed: v.Completed, Expires: v.Expires, RevokedAt: v.RevokedAt, RevocationReason: v.RevocationReason, RevokedBy: v.RevokedBy})
	if e != nil {
		return e
	}
	if e = w.q.DeleteJobCertificates(w.ctx, v.ARN); e != nil {
		return e
	}
	for i, hash := range v.CertificateHashes {
		if e = w.q.PutJobCertificate(w.ctx, sqlcgen.PutJobCertificateParams{JobArn: v.ARN, Position: int64(i), CertificateHash: hash}); e != nil {
			return e
		}
	}
	return nil
}

var _ domain.Repository = (*Repository)(nil)
