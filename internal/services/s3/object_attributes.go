package s3

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) getObjectAttributes(ctx context.Context, in *api.GetObjectAttributesInput) (*preparedResponse, *awswire.Error) {
	c := s.transferCall(ctx, "GetObjectAttributes", value(in.Bucket), value(in.Key))
	c.params["attributes"] = ""
	response := &preparedResponse{}
	if len(in.ObjectAttributes) == 0 {
		return response, s.complete(ctx, c, failure("InvalidRequest", "The x-amz-object-attributes header specifying the attributes to be retrieved is either missing or empty", 400))
	}
	attributes := make(map[api.ObjectAttributes]bool, len(in.ObjectAttributes))
	for _, attribute := range in.ObjectAttributes {
		switch attribute {
		case "ETag", "Checksum", "ObjectParts", "StorageClass", "ObjectSize":
			attributes[attribute] = true
		default:
			return response, s.complete(ctx, c, argumentError("x-amz-object-attributes", string(attribute), "Invalid attribute name specified."))
		}
	}
	limit := int64(1000)
	if in.MaxParts != nil {
		limit = int64(*in.MaxParts)
	}
	var marker int64
	if in.PartNumberMarker != nil {
		text := value(in.PartNumberMarker)
		var err error
		marker, err = strconv.ParseInt(text, 10, 32)
		if err != nil {
			return response, s.complete(ctx, c, argumentError("x-amz-part-number-marker", text, "Provided x-amz-part-number-marker not an integer or within integer range"))
		}
	}
	var read objectRead
	var parts []PartRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		// readObject retains version/delete-marker precedence, existing-tag IAM
		// conditions, and both GetObject[Version] and its Attributes action.
		read, err = s.readObject(r, c, &api.GetObjectInput{
			Bucket: in.Bucket, Key: in.Key, VersionId: in.VersionId,
			ExpectedBucketOwner: in.ExpectedBucketOwner, RequestPayer: in.RequestPayer,
			SSECustomerAlgorithm: in.SSECustomerAlgorithm, SSECustomerKey: in.SSECustomerKey,
			SSECustomerKeyMD5: in.SSECustomerKeyMD5,
		})
		if err != nil {
			return err
		}
		if attributes["ObjectParts"] && read.object.UploadID != "" {
			parts, err = r.ObjectParts(read.object.VersionKey())
		}
		return err
	})
	defer clear(read.customerKey)
	record := read.object
	if record.DeleteMarker {
		wire := wireError(err)
		wire.ResponseHeader = http.Header{
			"X-Amz-Delete-Marker": {"true"},
			"X-Amz-Version-Id":    {record.VersionID},
		}
		if in.VersionId != nil {
			wire.ResponseHeader.Set("Allow", "DELETE")
		}
		return response, s.complete(ctx, c, wire)
	}
	if err != nil {
		return response, s.complete(ctx, c, err)
	}
	// Native KMS attributes require Decrypt even for metadata-only selections;
	// no ciphertext is fetched and GenerateDataKey is not required.
	if record.EncryptionAlgorithm == "aws:kms" {
		effectContext := ctx
		if c.eventID != "" {
			m := awsctx.FromContext(ctx)
			m.ParentEventID = c.eventID
			effectContext = awsctx.WithMetadata(ctx, m)
		}
		key, wire := s.objectDataKey(effectContext, read.bucket, record, nil)
		clear(key)
		if wire != nil {
			return response, s.complete(ctx, c, wire)
		}
	}
	out := &api.GetObjectAttributesOutput{LastModified: new(record.Modified)}
	if read.bucket.Versioning != "" {
		out.VersionId = new(api.ObjectVersionId(record.VersionID))
	}
	if attributes["ETag"] {
		out.ETag = new(api.ETag(strings.Trim(record.ETag, "\"")))
	}
	if attributes["ObjectSize"] {
		out.ObjectSize = new(api.ObjectSize(record.Size))
	}
	if attributes["StorageClass"] {
		out.StorageClass = new(api.StorageClass(storageClassName(record.StorageClass)))
	}
	if attributes["Checksum"] && record.Checksum != "" {
		sum := record.Checksum
		if objectChecksumType(record) == "COMPOSITE" {
			// Native attributes project the digest without GetObject's -N suffix.
			sum, _, _ = strings.Cut(sum, "-")
		}
		out.Checksum = &api.Checksum{ChecksumType: new(api.ChecksumType(objectChecksumType(record)))}
		out.Checksum.SetChecksum(record.ChecksumAlgorithm, sum)
	}
	if attributes["ObjectParts"] && record.UploadID != "" {
		out.ObjectParts = &api.GetObjectAttributesParts{TotalPartsCount: new(api.PartsCount(len(parts)))}
		// Native FULL_OBJECT CRC32/CRC64 objects expose only PartsCount, not
		// per-part checksums or pagination (controls reader-full/gap-attributes).
		if objectChecksumType(record) == "COMPOSITE" {
			if marker < 0 {
				// The retained negative-marker request returned InternalError.
				// Reject safely without indexing a negative ordinal.
				return response, s.complete(ctx, c, failure("InternalError", "We encountered an internal error. Please try again.", 500))
			}
			page := out.ObjectParts
			page.PartNumberMarker = new(api.PartNumberMarker(strconv.FormatInt(marker, 10)))
			page.NextPartNumberMarker = new(api.NextPartNumberMarker("0"))
			page.MaxParts = new(api.MaxParts(limit))
			page.IsTruncated = new(api.IsTruncated(false))
			if limit != 0 && marker < int64(len(parts)) {
				end := min(marker+limit, int64(len(parts)))
				page.NextPartNumberMarker = new(api.NextPartNumberMarker(strconv.FormatInt(end, 10)))
				page.IsTruncated = new(api.IsTruncated(end < int64(len(parts))))
				for ordinal := marker; ordinal < end; ordinal++ {
					part := parts[ordinal]
					item := api.ObjectPart{
						PartNumber: new(api.PartNumber(ordinal + 1)), Size: new(api.Size(part.Size)),
					}
					item.SetChecksum(record.ChecksumAlgorithm, part.Checksum)
					page.Parts = append(page.Parts, item)
				}
			}
		}
	}
	return response, s.complete(ctx, c, response.prepare(c, out))
}
