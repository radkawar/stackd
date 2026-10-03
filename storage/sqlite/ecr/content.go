package ecr

import (
	domain "stackd/storage/ecr"
	"stackd/storage/sqlite/ecr/internal/sqlcgen"
	"time"
)

func imageRow(v sqlcgen.EcrImage) (domain.ImageRecord, error) {
	out := domain.ImageRecord{Key: domain.ImageKey{Repository: domain.RepositoryKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Repository}, Digest: v.Digest}, MediaType: v.MediaType, ArtifactMediaType: v.ArtifactMediaType, Payload: v.Payload, Size: v.Size, Pushed: timestamp(v.Pushed), LastPull: timestamp(v.LastPull), ScanID: v.ScanID, ScanStatus: v.ScanStatus, ScanDescription: v.ScanDescription, ScanStarted: timestamp(v.ScanStarted), ScanCompleted: timestamp(v.ScanCompleted), VulnerabilityUpdated: timestamp(v.VulnerabilityUpdated)}
	j := jsonFields{}
	j.decode(v.Tags, &out.Tags)
	j.decode(v.Refs, &out.References)
	j.decode(v.Layers, &out.Layers)
	j.decode(v.Findings, &out.Findings)
	return out, j.err
}
func (r reader) Image(k domain.ImageKey) (domain.ImageRecord, error) {
	v, e := r.q.GetImage(r.ctx, sqlcgen.GetImageParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, Digest: k.Digest})
	if e != nil {
		return domain.ImageRecord{}, missing(e)
	}
	return imageRow(v)
}
func (r reader) Images(k domain.RepositoryKey) ([]domain.ImageRecord, error) {
	rows, e := r.q.ListImages(r.ctx, sqlcgen.ListImagesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Repository: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ImageRecord, 0, len(rows))
	for _, v := range rows {
		image, e := imageRow(v)
		if e != nil {
			return nil, e
		}
		out = append(out, image)
	}
	return out, nil
}
func (w writer) PutImage(v domain.ImageRecord) error {
	j := jsonFields{}
	k := v.Key
	p := sqlcgen.PutImageParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, Digest: k.Digest, MediaType: v.MediaType, ArtifactMediaType: v.ArtifactMediaType, Payload: binary(v.Payload), Size: v.Size, Pushed: instant(v.Pushed), LastPull: instant(v.LastPull), Tags: j.encode(v.Tags), Refs: j.encode(v.References), Layers: j.encode(v.Layers), ScanID: v.ScanID, ScanStatus: v.ScanStatus, ScanDescription: v.ScanDescription, ScanStarted: instant(v.ScanStarted), ScanCompleted: instant(v.ScanCompleted), VulnerabilityUpdated: instant(v.VulnerabilityUpdated), Findings: j.encode(v.Findings)}
	if j.err != nil {
		return j.err
	}
	return w.q.PutImage(w.ctx, p)
}
func (w writer) DeleteImage(k domain.ImageKey) error {
	return w.q.DeleteImage(w.ctx, sqlcgen.DeleteImageParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, Digest: k.Digest})
}
func (r reader) Blob(k domain.ImageKey) (domain.BlobRecord, error) {
	v, e := r.q.GetBlob(r.ctx, sqlcgen.GetBlobParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, Digest: k.Digest})
	if e != nil {
		return domain.BlobRecord{}, missing(e)
	}
	return domain.BlobRecord{Key: k, Payload: v.Payload, Size: v.Size}, nil
}
func (w writer) PutBlob(v domain.BlobRecord) error {
	k := v.Key
	return w.q.PutBlob(w.ctx, sqlcgen.PutBlobParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, Digest: k.Digest, Payload: binary(v.Payload), Size: v.Size})
}
func (r reader) Upload(k domain.UploadKey) (domain.UploadRecord, error) {
	v, e := r.q.GetUpload(r.ctx, sqlcgen.GetUploadParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, ID: k.ID})
	if e != nil {
		return domain.UploadRecord{}, missing(e)
	}
	return domain.UploadRecord{Key: k, Payload: v.Payload, Size: v.Size, Expires: timestamp(v.Expires)}, nil
}
func (w writer) PutUpload(v domain.UploadRecord) error {
	k := v.Key
	return w.q.PutUpload(w.ctx, sqlcgen.PutUploadParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, ID: k.ID, Payload: binary(v.Payload), Size: v.Size, Expires: instant(v.Expires)})
}
func (w writer) DeleteUpload(k domain.UploadKey) error {
	return w.q.DeleteUpload(w.ctx, sqlcgen.DeleteUploadParams{Partition: k.Repository.Partition, AccountID: k.Repository.AccountID, Region: k.Repository.Region, Repository: k.Repository.Name, ID: k.ID})
}
func (r reader) Token(hash string) (domain.TokenRecord, error) {
	v, e := r.q.GetToken(r.ctx, hash)
	if e != nil {
		return domain.TokenRecord{}, missing(e)
	}
	out := domain.TokenRecord{Hash: v.Hash, Partition: v.Partition, Region: v.Region, Expires: timestamp(v.Expires), DownloadRepository: domain.RepositoryKey{Scope: domain.Scope{Partition: v.DownloadPartition, AccountID: v.DownloadAccount, Region: v.DownloadRegion}, Name: v.DownloadRepository}, DownloadDigest: v.DownloadDigest}
	j := jsonFields{}
	j.decode(v.Identity, &out.Identity)
	return out, j.err
}
func (w writer) PutToken(v domain.TokenRecord) error {
	j := jsonFields{}
	p := sqlcgen.PutTokenParams{Hash: v.Hash, Partition: v.Partition, Region: v.Region, Identity: j.encode(v.Identity), Expires: instant(v.Expires), DownloadPartition: v.DownloadRepository.Partition, DownloadAccount: v.DownloadRepository.AccountID, DownloadRegion: v.DownloadRepository.Region, DownloadRepository: v.DownloadRepository.Name, DownloadDigest: v.DownloadDigest}
	if j.err != nil {
		return j.err
	}
	return w.q.PutToken(w.ctx, p)
}
func (w writer) DeleteExpiredTokens(now time.Time) error {
	return w.q.DeleteExpiredTokens(w.ctx, instant(now))
}
func (r reader) Replications() ([]domain.ReplicationRecord, error) {
	rows, err := r.q.ListReplications(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReplicationRecord, 0, len(rows))
	for _, v := range rows {
		record := domain.ReplicationRecord{Key: domain.ReplicationKey{Source: domain.ImageKey{Repository: domain.RepositoryKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Repository}, Digest: v.Digest}, Destination: domain.Scope{Partition: v.DestinationPartition, AccountID: v.DestinationAccount, Region: v.DestinationRegion}}, Due: timestamp(v.Due), Status: v.Status, Error: v.Error}
		j := jsonFields{}
		j.decode(v.Tags, &record.Tags)
		j.decode(v.Origin, &record.Origin)
		if j.err != nil {
			return nil, j.err
		}
		out = append(out, record)
	}
	return out, nil
}
func (w writer) PutReplication(v domain.ReplicationRecord) error {
	j := jsonFields{}
	k := v.Key
	p := sqlcgen.PutReplicationParams{Partition: k.Source.Repository.Partition, AccountID: k.Source.Repository.AccountID, Region: k.Source.Repository.Region, Repository: k.Source.Repository.Name, Digest: k.Source.Digest, DestinationPartition: k.Destination.Partition, DestinationAccount: k.Destination.AccountID, DestinationRegion: k.Destination.Region, Tags: j.encode(v.Tags), Due: instant(v.Due), Status: v.Status, Error: v.Error, Origin: j.encode(v.Origin)}
	if j.err != nil {
		return j.err
	}
	return w.q.PutReplication(w.ctx, p)
}
