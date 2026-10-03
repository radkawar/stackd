package ecr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"slices"
	api "stackd/internal/awsapi/ecr"
	"strings"
)

const ociManifest = "application/vnd.oci.image.manifest.v1+json"
const dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
const ociIndex = "application/vnd.oci.image.index.v1+json"
const dockerIndex = "application/vnd.docker.distribution.manifest.list.v2+json"

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var tagPattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$`)

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type descriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	URLs      []string `json:"urls"`
}
type manifestDocument struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType"`
	Config        *descriptor  `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
	Subject       *descriptor  `json:"subject"`
}

func (s *Service) putImage(tx Transaction, in *api.PutImageInput) (*api.PutImageOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "PutImage")
	if err != nil {
		return nil, err
	}
	data := []byte(value(in.ImageManifest))
	if len(data) == 0 || len(data) > 4*1024*1024 {
		return nil, failure("InvalidParameterException", "Image manifest must contain between 1 byte and 4 MiB.")
	}
	digest := digestBytes(data)
	if in.ImageDigest != nil && value(in.ImageDigest) != digest {
		return nil, failure("ImageDigestDoesNotMatchException", "The provided digest does not match the manifest bytes.")
	}
	var doc manifestDocument
	if json.Unmarshal(data, &doc) != nil || doc.SchemaVersion != 2 {
		return nil, failure("InvalidParameterException", "A valid schema version 2 image manifest is required.")
	}
	media := doc.MediaType
	if media == "" {
		media = value(in.ImageManifestMediaType)
	}
	if media == "" {
		return nil, failure("InvalidParameterException", "The image manifest media type is required.")
	}
	if in.ImageManifestMediaType != nil && doc.MediaType != "" && value(in.ImageManifestMediaType) != doc.MediaType {
		return nil, failure("InvalidParameterException", "Conflicting manifest media types.")
	}
	image := ImageRecord{Key: ImageKey{repo.Key, digest}, MediaType: media, ArtifactMediaType: doc.ArtifactType, Pushed: s.clock.Now()}
	switch media {
	case ociManifest, dockerManifest:
		if doc.Config == nil || doc.Config.Digest == "" || doc.Layers == nil {
			return nil, failure("InvalidParameterException", "Image manifests require config and layers descriptors.")
		}
		image.ArtifactMediaType = doc.Config.MediaType
		if doc.ArtifactType != "" {
			image.ArtifactMediaType = doc.ArtifactType
		}
		descriptors := make([]descriptor, 0, 1+len(doc.Layers))
		descriptors = append(descriptors, *doc.Config)
		descriptors = append(descriptors, doc.Layers...)
		for _, d := range descriptors {
			if !digestPattern.MatchString(d.Digest) || d.Size < 0 {
				return nil, failure("InvalidParameterException", "Invalid manifest descriptor.")
			}
			blob, err := tx.Blob(ImageKey{repo.Key, d.Digest})
			if errors.Is(err, ErrNotFound) {
				return nil, failure("LayersNotFoundException", "A layer or configuration blob referenced by the manifest is unavailable: "+d.Digest)
			}
			if err != nil {
				return nil, err
			}
			if blob.Size != d.Size {
				return nil, failure("InvalidParameterException", "Descriptor size does not match the stored blob: "+d.Digest)
			}
			image.Size += blob.Size
			image.Layers = append(image.Layers, d.Digest)
		}
	case ociIndex, dockerIndex:
		if len(doc.Manifests) == 0 {
			return nil, failure("InvalidParameterException", "A manifest index must reference at least one image.")
		}
		for _, d := range doc.Manifests {
			if !digestPattern.MatchString(d.Digest) {
				return nil, failure("InvalidParameterException", "Invalid referenced image digest.")
			}
			child, err := tx.Image(ImageKey{repo.Key, d.Digest})
			if errors.Is(err, ErrNotFound) {
				return nil, failure("ReferencedImagesNotFoundException", "A referenced image is unavailable: "+d.Digest)
			}
			if err != nil {
				return nil, err
			}
			plain, err := s.openPayload(tx.Context(), repo, "manifest:"+d.Digest, child.Payload)
			if err != nil {
				return nil, err
			}
			if int64(len(plain)) != d.Size || child.MediaType != d.MediaType {
				return nil, failure("InvalidParameterException", "Referenced manifest descriptor does not match stored content.")
			}
			image.References = append(image.References, d.Digest)
			image.Size = max(image.Size, child.Size)
		}
	default:
		return nil, failure("InvalidParameterException", "Unsupported image manifest media type: "+media)
	}
	tag := value(in.ImageTag)
	if tag != "" && !tagPattern.MatchString(tag) {
		return nil, failure("InvalidParameterException", "Invalid image tag.")
	}
	images, err := tx.Images(repo.Key)
	if err != nil {
		return nil, err
	}
	existing, lookup := tx.Image(image.Key)
	if lookup != nil && !errors.Is(lookup, ErrNotFound) {
		return nil, lookup
	}
	if lookup == nil {
		image = existing
	}
	for _, old := range images {
		if tag == "" || !slices.Contains(old.Tags, tag) {
			continue
		}
		if old.Key.Digest == digest {
			return nil, failure("ImageAlreadyExistsException", "The image is already stored with this tag.")
		}
		if tagImmutable(repo, tag) {
			return nil, failure("ImageTagAlreadyExistsException", "The image tag already exists in an immutable repository.")
		}
		old.Tags = slices.DeleteFunc(old.Tags, func(v string) bool { return v == tag })
		if err = tx.PutImage(old); err != nil {
			return nil, err
		}
	}
	if tag != "" {
		image.Tags = append(image.Tags, tag)
		slices.Sort(image.Tags)
	} else if lookup == nil {
		return nil, failure("ImageAlreadyExistsException", "The image is already stored.")
	}
	if lookup != nil {
		image.Payload, err = s.sealPayload(tx.Context(), repo, "manifest:"+digest, data)
		if err != nil {
			return nil, err
		}
		if err = s.scanOnPush(tx, repo, &image); err != nil {
			return nil, err
		}
	}
	if err = tx.PutImage(image); err != nil {
		return nil, err
	}
	if err = s.replicateImage(tx, repo, image); err != nil {
		return nil, err
	}
	if err = s.publishImageAction(tx.Context(), image.Key, "PUSH", tag); err != nil {
		return nil, err
	}
	return &api.PutImageOutput{Image: &api.Image{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: new(api.RepositoryName(repo.Key.Name)), ImageId: &api.ImageIdentifier{ImageDigest: new(api.ImageDigest(digest)), ImageTag: in.ImageTag}, ImageManifest: in.ImageManifest, ImageManifestMediaType: new(api.MediaType(media))}}, nil
}
func tagImmutable(repo RepositoryRecord, tag string) bool {
	immutable := strings.HasPrefix(repo.Mutability, "IMMUTABLE")
	if strings.HasSuffix(repo.Mutability, "_WITH_EXCLUSION") {
		for _, f := range repo.Exclusions {
			if matched, _ := path.Match(value(f.Filter), tag); matched {
				return !immutable
			}
		}
	}
	return immutable
}
func resolveImage(r Reader, key RepositoryKey, id api.ImageIdentifier) (ImageRecord, error) {
	digest, tag := value(id.ImageDigest), value(id.ImageTag)
	if digest == "" && tag == "" {
		return ImageRecord{}, failure("InvalidParameterException", "An image digest or tag is required.")
	}
	if digest != "" && !digestPattern.MatchString(digest) {
		return ImageRecord{}, failure("InvalidParameterException", "Invalid image digest.")
	}
	if tag != "" && !tagPattern.MatchString(tag) {
		return ImageRecord{}, failure("InvalidParameterException", "Invalid image tag.")
	}
	if digest != "" {
		v, err := r.Image(ImageKey{key, digest})
		if err != nil {
			return ImageRecord{}, err
		}
		if tag != "" && !slices.Contains(v.Tags, tag) {
			return ImageRecord{}, failure("ImageTagDoesNotMatchDigest", "The tag does not identify the supplied digest.")
		}
		return v, nil
	}
	rows, err := r.Images(key)
	if err != nil {
		return ImageRecord{}, err
	}
	for _, v := range rows {
		if slices.Contains(v.Tags, tag) {
			return v, nil
		}
	}
	return ImageRecord{}, ErrNotFound
}
func imageFailure(id api.ImageIdentifier, err error) api.ImageFailure {
	code := "ImageNotFound"
	reason := "The requested image does not exist."
	if !errors.Is(err, ErrNotFound) {
		e := wireError(err)
		reason = e.Message
		switch e.Code {
		case "InvalidParameterException":
			if id.ImageDigest != nil && !digestPattern.MatchString(value(id.ImageDigest)) {
				code = "InvalidImageDigest"
			} else {
				code = "InvalidImageTag"
			}
		case "ImageTagDoesNotMatchDigest":
			code = e.Code
		case "ImageReferencedByManifestList":
			code = e.Code
		default:
			code = "ImageInaccessible"
		}
	}
	return api.ImageFailure{ImageId: &id, FailureCode: new(api.ImageFailureCode(code)), FailureReason: new(api.ImageFailureReason(reason))}
}
func (s *Service) batchGetImage(tx Transaction, in *api.BatchGetImageInput) (*api.BatchGetImageOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "BatchGetImage")
	if err != nil {
		return nil, err
	}
	out := &api.BatchGetImageOutput{Images: api.ImageList{}, Failures: api.ImageFailureList{}}
	for _, id := range in.ImageIds {
		image, err := resolveImage(tx, repo.Key, id)
		if err != nil {
			out.Failures = append(out.Failures, imageFailure(id, err))
			continue
		}
		if len(in.AcceptedMediaTypes) > 0 && !slices.Contains(in.AcceptedMediaTypes, api.MediaType(image.MediaType)) {
			out.Failures = append(out.Failures, api.ImageFailure{ImageId: &id, FailureCode: new(api.ImageFailureCodeMissingDigestAndTag), FailureReason: new(api.ImageFailureReason("The image media type is not accepted; manifest transcoding is unavailable."))})
			continue
		}
		plain, err := s.openPayload(tx.Context(), repo, "manifest:"+image.Key.Digest, image.Payload)
		if err != nil {
			return nil, err
		}
		image.LastPull = s.clock.Now()
		if err = tx.PutImage(image); err != nil {
			return nil, err
		}
		out.Images = append(out.Images, api.Image{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: new(api.RepositoryName(repo.Key.Name)), ImageId: &api.ImageIdentifier{ImageDigest: new(api.ImageDigest(image.Key.Digest)), ImageTag: id.ImageTag}, ImageManifest: new(api.ImageManifest(plain)), ImageManifestMediaType: new(api.MediaType(image.MediaType))})
	}
	return out, nil
}
func imageReferenced(images []ImageRecord, digest string) bool {
	for _, v := range images {
		if slices.Contains(v.References, digest) {
			return true
		}
	}
	return false
}
func (s *Service) batchDeleteImage(tx Transaction, in *api.BatchDeleteImageInput) (*api.BatchDeleteImageOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "BatchDeleteImage")
	if err != nil {
		return nil, err
	}
	out := &api.BatchDeleteImageOutput{ImageIds: api.ImageIdentifierList{}, Failures: api.ImageFailureList{}}
	for _, id := range in.ImageIds {
		image, err := resolveImage(tx, repo.Key, id)
		if err != nil {
			out.Failures = append(out.Failures, imageFailure(id, err))
			continue
		}
		remove := id.ImageDigest != nil || len(image.Tags) <= 1
		rows, err := tx.Images(repo.Key)
		if err != nil {
			return nil, err
		}
		if remove && imageReferenced(rows, image.Key.Digest) {
			out.Failures = append(out.Failures, imageFailure(id, failure("ImageReferencedByManifestList", "Delete referencing manifest lists before deleting this image.")))
			continue
		}
		if remove {
			if err = tx.DeleteImage(image.Key); err != nil {
				return nil, err
			}
		} else {
			image.Tags = slices.DeleteFunc(image.Tags, func(t string) bool { return t == value(id.ImageTag) })
			if err = tx.PutImage(image); err != nil {
				return nil, err
			}
		}
		if id.ImageTag != nil || len(image.Tags) == 0 {
			if err = s.publishImageAction(tx.Context(), image.Key, "DELETE", value(id.ImageTag)); err != nil {
				return nil, err
			}
		} else {
			for _, tag := range image.Tags {
				if err = s.publishImageAction(tx.Context(), image.Key, "DELETE", tag); err != nil {
					return nil, err
				}
			}
		}
		out.ImageIds = append(out.ImageIds, api.ImageIdentifier{ImageDigest: new(api.ImageDigest(image.Key.Digest)), ImageTag: id.ImageTag})
	}
	return out, nil
}
func describeImage(image ImageRecord) api.ImageDetail {
	tags := make(api.ImageTagList, len(image.Tags))
	for i, t := range image.Tags {
		tags[i] = api.ImageTag(t)
	}
	out := api.ImageDetail{RegistryId: new(api.RegistryId(image.Key.Repository.AccountID)), RepositoryName: new(api.RepositoryName(image.Key.Repository.Name)), ImageDigest: new(api.ImageDigest(image.Key.Digest)), ImageTags: tags, ImagePushedAt: new(image.Pushed), ImageSizeInBytes: new(api.ImageSizeInBytes(image.Size)), ImageManifestMediaType: new(api.MediaType(image.MediaType)), ArtifactMediaType: new(api.MediaType(image.ArtifactMediaType))}
	if !image.LastPull.IsZero() {
		out.LastRecordedPullTime = new(image.LastPull)
	}
	return out
}
func filterImages(rows []ImageRecord, status string) []ImageRecord {
	return slices.DeleteFunc(rows, func(v ImageRecord) bool {
		return status == "TAGGED" && len(v.Tags) == 0 || status == "UNTAGGED" && len(v.Tags) != 0
	})
}
func (s *Service) describeImages(tx Transaction, in *api.DescribeImagesInput) (*api.DescribeImagesOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "DescribeImages")
	if err != nil {
		return nil, err
	}
	out := &api.DescribeImagesOutput{ImageDetails: api.ImageDetailList{}}
	if len(in.ImageIds) > 0 {
		if in.MaxResults != nil || in.NextToken != nil {
			return nil, failure("InvalidParameterException", "Image IDs cannot be combined with pagination.")
		}
		seen := map[string]bool{}
		for _, id := range in.ImageIds {
			v, err := resolveImage(tx, repo.Key, id)
			if errors.Is(err, ErrNotFound) {
				return nil, failure("ImageNotFoundException", "The specified image does not exist.")
			}
			if err != nil {
				return nil, err
			}
			if !seen[v.Key.Digest] {
				out.ImageDetails = append(out.ImageDetails, describeImage(v))
				seen[v.Key.Digest] = true
			}
		}
		return out, nil
	}
	rows, err := tx.Images(repo.Key)
	if err != nil {
		return nil, err
	}
	status := ""
	if in.Filter != nil {
		status = value(in.Filter.TagStatus)
		if imageStatus := value(in.Filter.ImageStatus); imageStatus != "" && imageStatus != "ACTIVE" && imageStatus != "ANY" {
			rows = nil
		}
	}
	rows = filterImages(rows, status)
	start, end, next, err := pageBounds("DescribeImages", repo.Key, in.Filter, in.MaxResults, in.NextToken, len(rows))
	if err != nil {
		return nil, err
	}
	for _, v := range rows[start:end] {
		out.ImageDetails = append(out.ImageDetails, describeImage(v))
	}
	out.NextToken = next
	return out, nil
}
func (s *Service) listImages(tx Transaction, in *api.ListImagesInput) (*api.ListImagesOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ListImages")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Images(repo.Key)
	if err != nil {
		return nil, err
	}
	status := ""
	if in.Filter != nil {
		status = value(in.Filter.TagStatus)
		if imageStatus := value(in.Filter.ImageStatus); imageStatus != "" && imageStatus != "ACTIVE" && imageStatus != "ANY" {
			rows = nil
		}
	}
	rows = filterImages(rows, status)
	ids := api.ImageIdentifierList{}
	for _, v := range rows {
		if len(v.Tags) == 0 {
			ids = append(ids, api.ImageIdentifier{ImageDigest: new(api.ImageDigest(v.Key.Digest))})
		}
		for _, tag := range v.Tags {
			ids = append(ids, api.ImageIdentifier{ImageDigest: new(api.ImageDigest(v.Key.Digest)), ImageTag: new(api.ImageTag(tag))})
		}
	}
	start, end, next, err := pageBounds("ListImages", repo.Key, in.Filter, in.MaxResults, in.NextToken, len(ids))
	if err != nil {
		return nil, err
	}
	return &api.ListImagesOutput{ImageIds: ids[start:end], NextToken: next}, nil
}
