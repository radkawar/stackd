package s3

import (
	"context"
	"errors"
	"net/url"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// copySource is the decoded identity, retaining explicit null-version selection.
// The header is form-decoded once; an encoded question mark remains part of a key.
type copySource struct {
	bucket  string
	key     string
	version *api.ObjectVersionId
}

func parseCopySource(header string) (copySource, *awswire.Error) {
	var source copySource
	path, query, hasQuery := strings.Cut(header, "?")
	decoded, err := url.QueryUnescape(path)
	if err != nil {
		return source, argumentError("x-amz-copy-source", "x-amz-copy-source", "Invalid copy source encoding")
	}
	decoded = strings.TrimPrefix(decoded, "/")
	var ok bool
	if strings.HasPrefix(decoded, "arn:") {
		source.bucket, source.key, ok = strings.Cut(decoded, "/object/")
	} else {
		source.bucket, source.key, ok = strings.Cut(decoded, "/")
	}
	if !ok || source.bucket == "" || source.key == "" {
		return source, invalid("The copy source must identify a bucket and object key.")
	}
	if hasQuery {
		values, err := url.ParseQuery(query)
		if err != nil || len(values) != 1 || len(values["versionId"]) != 1 {
			return source, invalid("The copy source query must identify one versionId.")
		}
		source.version = new(api.ObjectVersionId(values.Get("versionId")))
	}
	return source, nil
}

// copiedObject owns one detached version/tag/content snapshot. On successful
// return from readCopySource, body is plaintext and the caller owns its lifetime.
type copiedObject struct {
	bucket     BucketRecord
	object     ObjectRecord
	tags       []Tag
	body       []byte
	conditions map[string][]string
}

func (s *Service) readCopySource(ctx context.Context, c *apiCall, source copySource, owner string, in *api.CopyObjectInput) (copiedObject, error) {
	var selected copiedObject
	var encrypted [][]byte
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		selected, err = s.selectCopySource(r, c, source, owner)
		if err != nil {
			return err
		}
		if wire := readConditions(selected.object, in.CopySourceIfMatch, in.CopySourceIfNoneMatch, in.CopySourceIfModifiedSince, in.CopySourceIfUnmodifiedSince, s.clock.Now()); wire != nil {
			return preconditionFailed("x-amz-copy-source-" + wire.Condition)
		}
		restore, err := objectRestoreForRead(r, selected.object)
		if err != nil {
			return err
		}
		if wire := objectPayloadError(selected.object, restore, s.clock.Now(), true); wire != nil {
			return wire
		}
		if value(in.TaggingDirective) != "REPLACE" && len(selected.tags) != 0 {
			action := "GetObjectTagging"
			if source.version != nil {
				action = "GetObjectVersionTagging"
			}
			if wire := s.authorizeObject(r.Context(), c, selected.bucket, selected.object, action, selected.conditions); wire != nil {
				return wire
			}
		}
		encrypted, err = r.ObjectData(selected.object.VersionKey())
		return err
	})
	if err != nil {
		return selected, err
	}
	customer, wire := readCustomerKey(selected.object, customerHeaders(in.CopySourceSSECustomerAlgorithm, in.CopySourceSSECustomerKey, in.CopySourceSSECustomerKeyMD5), true, false)
	if wire != nil {
		return selected, wire
	}
	defer clear(customer)
	key, wire := s.objectDataKey(ctx, selected.bucket, selected.object, customer)
	if wire != nil {
		return selected, wire
	}
	defer clear(key)
	selected.body, err = decryptObject(key, encrypted)
	return selected, err
}

// Source selection has no KMS effects or tag-read permission requirement.
// Whole-object and part copies impose their distinct destination/tag checks
// before decrypting the detached source ciphertext.
func (s *Service) selectCopySource(r Reader, c *apiCall, source copySource, owner string) (copiedObject, error) {
	var selected copiedObject
	var err error
	selected.bucket, err = s.bucket(r, c, owner)
	if err != nil {
		return selected, err
	}
	if wire := validateKey(source.key); wire != nil {
		return selected, wire
	}
	key := ObjectKey{Bucket: selected.bucket.Key, Name: source.key}
	selected.object, err = selectObjectVersion(r, key, source.version)
	var invalidVersion *awswire.Error
	if source.version != nil && errors.As(err, &invalidVersion) {
		return selected, failure("InvalidRequest", "Invalid Request", 400)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return selected, err
	}
	if errors.Is(err, ErrNotFound) {
		selected.object.Key = key
	}
	selected.conditions = map[string][]string{}
	action := "GetObject"
	if source.version != nil {
		action = "GetObjectVersion"
		selected.conditions["s3:VersionId"] = []string{value(source.version)}
	}
	if err == nil && !selected.object.DeleteMarker {
		selected.tags, err = r.ObjectTags(selected.object.VersionKey())
		if err != nil {
			return selected, err
		}
		existingTagConditions(selected.conditions, selected.tags)
	}
	if wire := s.authorizeObject(r.Context(), c, selected.bucket, selected.object, action, selected.conditions); wire != nil {
		return selected, wire
	}
	if errors.Is(err, ErrNotFound) || selected.object.DeleteMarker {
		if source.version != nil && !selected.object.DeleteMarker {
			return selected, failure("NoSuchVersion", "The specified version does not exist.", 404)
		}
		if selected.object.DeleteMarker && source.version != nil {
			return selected, failure("InvalidRequest", "The source of a copy request may not specifically refer to a delete marker by version id.", 400)
		}
		if wire := s.authorize(r.Context(), c, selected.bucket, "ListBucket", "", nil); wire != nil {
			return selected, wire
		}
		return selected, noSuchKey(source.key)
	}
	return selected, nil
}
