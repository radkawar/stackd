package ecr

import (
	"errors"
	"net/url"
	api "stackd/internal/awsapi/ecr"
	"time"
)

const maxLayerSize int64 = 512 * 1024 * 1024

func (s *Service) initiateLayerUpload(tx Transaction, in *api.InitiateLayerUploadInput) (*api.InitiateLayerUploadOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "InitiateLayerUpload")
	if err != nil {
		return nil, err
	}
	id := identifier()
	payload, err := s.sealPayload(tx.Context(), repo, "upload:"+id, nil)
	if err != nil {
		return nil, err
	}
	if err = tx.PutUpload(UploadRecord{Key: UploadKey{repo.Key, id}, Payload: payload, Expires: s.clock.Now().Add(24 * time.Hour)}); err != nil {
		return nil, err
	}
	return &api.InitiateLayerUploadOutput{UploadId: new(api.UploadId(id)), PartSize: new(api.PartSize(10 * 1024 * 1024))}, nil
}
func (s *Service) upload(tx Transaction, repo RepositoryRecord, id string) (UploadRecord, error) {
	u, err := tx.Upload(UploadKey{repo.Key, id})
	if errors.Is(err, ErrNotFound) || err == nil && !s.clock.Now().Before(u.Expires) {
		return UploadRecord{}, failure("UploadNotFoundException", "The upload does not exist or has expired.")
	}
	return u, err
}
func (s *Service) appendUpload(tx Transaction, repo RepositoryRecord, u UploadRecord, part []byte, first, last int64) (UploadRecord, error) {
	if first != u.Size || last-first+1 != int64(len(part)) || len(part) == 0 {
		return UploadRecord{}, failure("InvalidLayerPartException", "Upload ranges must be contiguous and match the supplied bytes.")
	}
	if u.Size+int64(len(part)) > maxLayerSize {
		return UploadRecord{}, failure("LimitExceededException", "This registry's layer size limit is 512 MiB.")
	}
	plain, err := s.openPayload(tx.Context(), repo, "upload:"+u.Key.ID, u.Payload)
	if err != nil {
		return UploadRecord{}, err
	}
	plain = append(plain, part...)
	u.Payload, err = s.sealPayload(tx.Context(), repo, "upload:"+u.Key.ID, plain)
	if err != nil {
		return UploadRecord{}, err
	}
	u.Size = int64(len(plain))
	if err = tx.PutUpload(u); err != nil {
		return UploadRecord{}, err
	}
	return u, nil
}
func (s *Service) uploadLayerPart(tx Transaction, in *api.UploadLayerPartInput) (*api.UploadLayerPartOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "UploadLayerPart")
	if err != nil {
		return nil, err
	}
	u, err := s.upload(tx, repo, value(in.UploadId))
	if err != nil {
		return nil, err
	}
	if in.PartFirstByte == nil || in.PartLastByte == nil || len(in.LayerPartBlob) > 20*1024*1024 {
		return nil, failure("InvalidParameterException", "Layer parts require explicit byte bounds and at most 20 MiB.")
	}
	u, err = s.appendUpload(tx, repo, u, in.LayerPartBlob, int64(*in.PartFirstByte), int64(*in.PartLastByte))
	if err != nil {
		return nil, err
	}
	return &api.UploadLayerPartOutput{UploadId: in.UploadId, RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: in.RepositoryName, LastByteReceived: new(api.PartSize(u.Size - 1))}, nil
}
func (s *Service) finishUpload(tx Transaction, repo RepositoryRecord, u UploadRecord, digest string) (BlobRecord, error) {
	if !digestPattern.MatchString(digest) {
		return BlobRecord{}, failure("InvalidDigestException", "The layer digest must be a SHA-256 digest.")
	}
	if u.Size == 0 {
		return BlobRecord{}, failure("EmptyUploadException", "The upload contains no bytes.")
	}
	plain, err := s.openPayload(tx.Context(), repo, "upload:"+u.Key.ID, u.Payload)
	if err != nil {
		return BlobRecord{}, err
	}
	if digestBytes(plain) != digest {
		return BlobRecord{}, failure("InvalidLayerException", "The supplied digest does not match the uploaded bytes.")
	}
	blob, err := tx.Blob(ImageKey{repo.Key, digest})
	if err == nil {
		return blob, failure("LayerAlreadyExistsException", "The layer already exists in this repository.")
	}
	if !errors.Is(err, ErrNotFound) {
		return BlobRecord{}, err
	}
	payload, err := s.sealPayload(tx.Context(), repo, "blob:"+digest, plain)
	if err != nil {
		return BlobRecord{}, err
	}
	blob = BlobRecord{Key: ImageKey{repo.Key, digest}, Payload: payload, Size: u.Size}
	if err = tx.PutBlob(blob); err != nil {
		return BlobRecord{}, err
	}
	if err = tx.DeleteUpload(u.Key); err != nil {
		return BlobRecord{}, err
	}
	return blob, nil
}
func (s *Service) completeLayerUpload(tx Transaction, in *api.CompleteLayerUploadInput) (*api.CompleteLayerUploadOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "CompleteLayerUpload")
	if err != nil {
		return nil, err
	}
	if len(in.LayerDigests) != 1 {
		return nil, failure("InvalidParameterException", "Exactly one layer digest is required.")
	}
	u, err := s.upload(tx, repo, value(in.UploadId))
	if err != nil {
		return nil, err
	}
	blob, err := s.finishUpload(tx, repo, u, string(in.LayerDigests[0]))
	if err != nil {
		return nil, err
	}
	return &api.CompleteLayerUploadOutput{UploadId: in.UploadId, RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: in.RepositoryName, LayerDigest: new(api.LayerDigest(blob.Key.Digest))}, nil
}
func (s *Service) batchCheckLayerAvailability(tx Transaction, in *api.BatchCheckLayerAvailabilityInput) (*api.BatchCheckLayerAvailabilityOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "BatchCheckLayerAvailability")
	if err != nil {
		return nil, err
	}
	out := &api.BatchCheckLayerAvailabilityOutput{Layers: api.LayerList{}, Failures: api.LayerFailureList{}}
	for _, d := range in.LayerDigests {
		digest := string(d)
		if !digestPattern.MatchString(digest) {
			out.Failures = append(out.Failures, api.LayerFailure{LayerDigest: new(d), FailureCode: new(api.LayerFailureCodeInvalidLayerDigest), FailureReason: new(api.LayerFailureReason("Invalid layer digest."))})
			continue
		}
		blob, err := tx.Blob(ImageKey{repo.Key, digest})
		if errors.Is(err, ErrNotFound) {
			out.Layers = append(out.Layers, api.Layer{LayerDigest: new(api.LayerDigest(digest)), LayerAvailability: new(api.LayerAvailabilityUNAVAILABLE)})
			continue
		}
		if err != nil {
			return nil, err
		}
		out.Layers = append(out.Layers, api.Layer{LayerDigest: new(api.LayerDigest(digest)), LayerAvailability: new(api.LayerAvailabilityAVAILABLE), LayerSize: new(api.LayerSizeInBytes(blob.Size))})
	}
	return out, nil
}
func (s *Service) getDownloadURLForLayer(tx Transaction, in *api.GetDownloadUrlForLayerInput) (*api.GetDownloadUrlForLayerOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "GetDownloadUrlForLayer")
	if err != nil {
		return nil, err
	}
	digest := value(in.LayerDigest)
	if !digestPattern.MatchString(digest) {
		return nil, failure("InvalidParameterException", "Invalid layer digest.")
	}
	blob, err := tx.Blob(ImageKey{repo.Key, digest})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("LayersNotFoundException", "The layer does not exist in this repository.")
	}
	if err != nil {
		return nil, err
	}
	if _, err = s.openPayload(tx.Context(), repo, "blob:"+digest, blob.Payload); err != nil {
		return nil, err
	}
	origin, err := s.origin()
	if err != nil {
		return nil, err
	}
	password, _, err := s.issueToken(tx, repo.Key, digest, time.Hour)
	if err != nil {
		return nil, err
	}
	return &api.GetDownloadUrlForLayerOutput{LayerDigest: in.LayerDigest, DownloadUrl: new(api.Url(origin + registryPath(repo.Key) + "/blobs/" + digest + "?token=" + url.QueryEscape(password)))}, nil
}
