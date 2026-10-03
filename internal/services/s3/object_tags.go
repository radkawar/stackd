package s3

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// Tag mutations do not rewrite object metadata or allocate object sequencers.
// The selected version, tags, authorization and event snapshot share a transaction.
type objectTagSelection struct {
	bucket      BucketRecord
	object      ObjectRecord
	tags        []Tag
	replacement []Tag
}

type objectTagResponse[O any] struct {
	output        O
	response      preparedResponse
	markerVersion string
}

func (r *objectTagResponse[O]) responseWithHeaders(headers http.Header) any {
	if r.markerVersion != "" {
		headers.Set("x-amz-delete-marker", "true")
		headers.Set("x-amz-version-id", r.markerVersion)
		headers.Set("Allow", http.MethodDelete)
	}
	return &r.response
}

func (r *objectTagResponse[O]) modeledOutput() any { return &r.output }

func requestedTagConditions(tags []Tag) map[string][]string {
	conditions := make(map[string][]string, len(tags)+1)
	if len(tags) != 0 {
		keys := make([]string, 0, len(tags))
		for _, tag := range tags {
			keys = append(keys, tag.Key)
			conditions["s3:RequestObjectTag/"+tag.Key] = []string{tag.Value}
		}
		conditions["s3:RequestObjectTagKeys"] = keys
	}
	return conditions
}

func existingTagConditions(conditions map[string][]string, tags []Tag) {
	for _, tag := range tags {
		conditions["s3:ExistingObjectTag/"+tag.Key] = []string{tag.Value}
	}
}

func (s *Service) taggingObject(r Reader, c *apiCall, expected string, version *api.ObjectVersionId, requested *api.Tagging) (objectTagSelection, error) {
	var selected objectTagSelection
	if version != nil {
		c.params["versionId"] = value(version)
	}
	bucket, err := s.bucket(r, c, expected)
	if err != nil {
		return selected, err
	}
	selected.bucket = bucket
	if c.name == "PutObjectTagging" {
		var wire *awswire.Error
		selected.replacement, wire = validateObjectTags(requested)
		if wire != nil {
			return selected, wire
		}
	}
	if wire := validateKey(c.key); wire != nil {
		return selected, wire
	}
	conditions := requestedTagConditions(selected.replacement)
	action := c.name
	if version != nil {
		id := value(version)
		conditions["s3:VersionId"] = []string{id}
		action = strings.Replace(action, "ObjectTagging", "ObjectVersionTagging", 1)
	}
	selected.object, err = selectObjectVersion(r, ObjectKey{bucket.Key, c.key}, version)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return selected, err
	}
	// Missing objects and delete markers are disclosed through ListBucket,
	// even for explicit versions and even when the tagging action is denied.
	// Native live-object tag access instead uses the selected tagging action.
	if errors.Is(err, ErrNotFound) || selected.object.DeleteMarker {
		if wire := s.authorize(r.Context(), c, bucket, "ListBucket", "", nil); wire != nil {
			return objectTagSelection{bucket: bucket}, wire
		}
	}
	if errors.Is(err, ErrNotFound) {
		if version != nil {
			wire := failure("NoSuchVersion", "The specified version does not exist.", 404)
			wire.Key, wire.VersionID = c.bucket+"/"+c.key, value(version)
			return selected, wire
		}
		return selected, noSuchKey(c.key)
	}
	if selected.object.DeleteMarker {
		wire := failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
		wire.Method = strings.ToUpper(strings.TrimSuffix(c.name, "ObjectTagging"))
		wire.ResourceType = "DeleteMarker"
		return selected, wire
	}
	selected.tags, err = r.ObjectTags(selected.object.VersionKey())
	if err != nil {
		return selected, err
	}
	existingTagConditions(conditions, selected.tags)
	if wire := s.authorizeObject(r.Context(), c, bucket, selected.object, action, conditions); wire != nil {
		return objectTagSelection{bucket: bucket}, wire
	}
	return selected, nil
}

func tagResponseVersion(selected objectTagSelection) *api.ObjectVersionId {
	if selected.bucket.Versioning == "" {
		return nil
	}
	return new(api.ObjectVersionId(selected.object.VersionID))
}

func (s *Service) getObjectTagging(ctx context.Context, in *api.GetObjectTaggingInput) (*objectTagResponse[api.GetObjectTaggingOutput], *awswire.Error) {
	c := call(ctx, "GetObjectTagging", value(in.Bucket), value(in.Key))
	c.params["tagging"] = ""
	out := &objectTagResponse[api.GetObjectTaggingOutput]{}
	err := s.repository.View(ctx, func(r Reader) error {
		selected, err := s.taggingObject(r, c, value(in.ExpectedBucketOwner), in.VersionId, nil)
		if selected.object.DeleteMarker {
			out.markerVersion = selected.object.VersionID
		}
		if err != nil {
			return err
		}
		out.output.TagSet = outputTags(selected.tags)
		out.output.VersionId = tagResponseVersion(selected)
		return out.response.prepare(c, &out.output)
	})
	return out, s.complete(ctx, c, err)
}

func (s *Service) putObjectTagging(ctx context.Context, in *api.PutObjectTaggingInput) (*objectTagResponse[api.PutObjectTaggingOutput], *awswire.Error) {
	c := call(ctx, "PutObjectTagging", value(in.Bucket), value(in.Key))
	c.params["tagging"] = ""
	out := &objectTagResponse[api.PutObjectTaggingOutput]{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		selected, err := s.taggingObject(tx, c, value(in.ExpectedBucketOwner), in.VersionId, in.Tagging)
		if selected.object.DeleteMarker {
			out.markerVersion = selected.object.VersionID
		}
		if err != nil {
			return err
		}
		if err := tx.ReplaceObjectTags(selected.object.VersionKey(), selected.replacement); err != nil {
			return err
		}
		c.requestMetricTags(selected.replacement)
		out.output.VersionId = tagResponseVersion(selected)
		if out.output.VersionId != nil {
			c.response = map[string]any{"x-amz-version-id": value(out.output.VersionId)}
		}
		request, _ := awsapi.FromContext(ctx)
		c.additional = map[string]any{"bytesTransferredIn": len(request.Body)}
		if err := out.response.prepare(c, &out.output); err != nil {
			return err
		}
		if err := s.enqueueObjectReplication(tx, c, selected.bucket, selected.object, ReplicationTags); err != nil {
			return err
		}
		return s.notifyObject(tx, c, selected.bucket, selected.object, "ObjectTagging:Put")
	})
	return out, wire
}

func (s *Service) deleteObjectTagging(ctx context.Context, in *api.DeleteObjectTaggingInput) (*objectTagResponse[api.DeleteObjectTaggingOutput], *awswire.Error) {
	c := call(ctx, "DeleteObjectTagging", value(in.Bucket), value(in.Key))
	c.params["tagging"] = ""
	out := &objectTagResponse[api.DeleteObjectTaggingOutput]{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		selected, err := s.taggingObject(tx, c, value(in.ExpectedBucketOwner), in.VersionId, nil)
		if selected.object.DeleteMarker {
			out.markerVersion = selected.object.VersionID
		}
		if err != nil {
			return err
		}
		if err := tx.ReplaceObjectTags(selected.object.VersionKey(), nil); err != nil {
			return err
		}
		c.requestMetricTags(nil)
		out.output.VersionId = tagResponseVersion(selected)
		if out.output.VersionId != nil {
			c.response = map[string]any{"x-amz-version-id": value(out.output.VersionId)}
		}
		if err := out.response.prepare(c, &out.output); err != nil {
			return err
		}
		if err := s.enqueueObjectReplication(tx, c, selected.bucket, selected.object, ReplicationTags); err != nil {
			return err
		}
		return s.notifyObject(tx, c, selected.bucket, selected.object, "ObjectTagging:Delete")
	})
	return out, wire
}
