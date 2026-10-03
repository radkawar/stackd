package cloudtrail

import (
	domain "stackd/storage/cloudtrail"
	"stackd/storage/sqlite/cloudtrail/internal/sqlcgen"
	"time"
)

func (r reader) DigestKeys(partition, region string) ([]domain.DigestKeyRecord, error) {
	rows, err := r.q.ListDigestKeys(r.ctx, sqlcgen.ListDigestKeysParams{Partition: partition, Region: region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DigestKeyRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.DigestKeyRecord{Partition: v.Partition, Region: v.Region, Fingerprint: v.Fingerprint, Start: v.Start, End: v.End, PrivateDER: v.PrivateDer, PublicDER: v.PublicDer})
	}
	return out, nil
}
func (w writer) PutDigestKey(v domain.DigestKeyRecord) error {
	return w.q.PutDigestKey(w.ctx, sqlcgen.PutDigestKeyParams{Partition: v.Partition, Region: v.Region, Fingerprint: v.Fingerprint, Start: v.Start, End: v.End, PrivateDer: v.PrivateDER, PublicDer: v.PublicDER})
}
func digestStream(v sqlcgen.CloudtrailDigestStream) domain.DigestStream {
	return domain.DigestStream{ID: v.ID, TrailID: v.TrailID, Trail: domain.TrailKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.TrailAccount, Region: v.HomeRegion}, Name: v.TrailName}, AccountID: v.AccountID, Region: v.Region, OrganizationID: v.OrganizationID, Bucket: v.Bucket, Prefix: v.Prefix, KMSKeyID: v.KmsKeyID, Start: v.Start, End: v.End, Due: v.Due, Closed: v.Closed, ClosedAt: v.ClosedAt, Version: uint64(v.Version), PreviousBucket: v.PreviousBucket, PreviousObject: v.PreviousObject, PreviousHash: v.PreviousHash, PreviousSignature: v.PreviousSignature, Pending: v.Pending, PendingObject: v.PendingObject, PendingHash: v.PendingHash, PendingSignature: v.PendingSignature}
}
func (r reader) DigestStream(id string) (domain.DigestStream, error) {
	v, err := r.q.GetDigestStream(r.ctx, id)
	return digestStream(v), notFound(err)
}
func (r reader) DigestStreams(id string) ([]domain.DigestStream, error) {
	rows, err := r.q.ListDigestStreams(r.ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DigestStream, 0, len(rows))
	for _, v := range rows {
		out = append(out, digestStream(v))
	}
	return out, nil
}
func (r reader) NextDigest() (domain.DigestStream, error) {
	v, err := r.q.NextDigest(r.ctx)
	return digestStream(v), notFound(err)
}
func (w writer) PutDigestStream(v domain.DigestStream) error {
	pending := v.Pending
	if pending == nil {
		pending = []byte{}
	}
	return w.q.PutDigestStream(w.ctx, sqlcgen.PutDigestStreamParams{ID: v.ID, TrailID: v.TrailID, Partition: v.Trail.Partition, TrailAccount: v.Trail.AccountID, HomeRegion: v.Trail.Region, TrailName: v.Trail.Name, AccountID: v.AccountID, Region: v.Region, OrganizationID: v.OrganizationID, Bucket: v.Bucket, Prefix: v.Prefix, KmsKeyID: v.KMSKeyID, Start: v.Start, End: v.End, Due: v.Due, Closed: v.Closed, ClosedAt: v.ClosedAt, Version: int64(v.Version), PreviousBucket: v.PreviousBucket, PreviousObject: v.PreviousObject, PreviousHash: v.PreviousHash, PreviousSignature: v.PreviousSignature, Pending: pending, PendingObject: v.PendingObject, PendingHash: v.PendingHash, PendingSignature: v.PendingSignature})
}
func (w writer) DeleteDigestStream(id string) error { return w.q.DeleteDigestStream(w.ctx, id) }
func (r reader) DigestLogs(id string, end time.Time) ([]domain.DigestLog, error) {
	rows, err := r.q.ListDigestLogs(r.ctx, sqlcgen.ListDigestLogsParams{StreamID: id, Delivered: end})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DigestLog, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.DigestLog{StreamID: v.StreamID, DeliveryID: v.DeliveryID, Bucket: v.Bucket, Object: v.Object, Hash: v.Hash, Delivered: v.Delivered, Oldest: v.Oldest, Newest: v.Newest})
	}
	return out, nil
}
func (w writer) PutDigestLog(v domain.DigestLog) error {
	return w.q.PutDigestLog(w.ctx, sqlcgen.PutDigestLogParams{StreamID: v.StreamID, DeliveryID: v.DeliveryID, Bucket: v.Bucket, Object: v.Object, Hash: v.Hash, Delivered: v.Delivered, Oldest: v.Oldest, Newest: v.Newest})
}
func (w writer) DeleteDigestLogs(id string, end time.Time) error {
	return w.q.DeleteDigestLogs(w.ctx, sqlcgen.DeleteDigestLogsParams{StreamID: id, Delivered: end})
}
func (r reader) DigestStatus(trailID, accountID, region string) (domain.DigestStatus, error) {
	v, err := r.q.GetDigestStatus(r.ctx, sqlcgen.GetDigestStatusParams{TrailID: trailID, AccountID: accountID, Region: region})
	return domain.DigestStatus{TrailID: v.TrailID, LastAttempt: v.LastAttempt, LastSuccess: v.LastSuccess, LastError: v.LastError, AccountID: v.AccountID, Region: v.Region}, notFound(err)
}
func (w writer) PutDigestStatus(v domain.DigestStatus) error {
	return w.q.PutDigestStatus(w.ctx, sqlcgen.PutDigestStatusParams{TrailID: v.TrailID, AccountID: v.AccountID, Region: v.Region, LastAttempt: v.LastAttempt, LastSuccess: v.LastSuccess, LastError: v.LastError})
}
