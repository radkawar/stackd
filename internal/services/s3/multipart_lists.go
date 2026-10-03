package s3

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func multipartMarker(id string) (*int64, *awswire.Error) {
	encoded, ok := strings.CutPrefix(id, "mp1_")
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if !ok || err != nil || len(raw) != 32 || int64(binary.BigEndian.Uint64(raw[:8])) <= 0 {
		return nil, argumentError("upload-id-marker", id, "Invalid upload id marker specified.")
	}
	return new(int64(binary.BigEndian.Uint64(raw[:8]))), nil
}

func multipartInitiator(id string) *api.Initiator {
	out := &api.Initiator{ID: new(api.ID(id))}
	if strings.HasPrefix(id, "arn:") {
		if _, name, ok := strings.Cut(id, "/"); ok {
			out.DisplayName = new(api.DisplayName(name))
		}
	}
	return out
}

func (s *Service) listMultipartUploads(ctx context.Context, in *api.ListMultipartUploadsInput) (*preparedResponse, *awswire.Error) {
	c := s.multipartCall(ctx, "ListMultipartUploads", value(in.Bucket), "", "")
	response := &preparedResponse{}
	prefix, delimiter, after, afterID, encoding := value(in.Prefix), value(in.Delimiter), value(in.KeyMarker), value(in.UploadIdMarker), value(in.EncodingType)
	if in.Prefix != nil {
		c.params["prefix"] = prefix
	}
	if in.Delimiter != nil {
		c.params["delimiter"] = delimiter
	}
	if in.KeyMarker != nil {
		c.params["key-marker"] = after
	}
	if in.UploadIdMarker != nil {
		c.params["upload-id-marker"] = afterID
	}
	if in.MaxUploads != nil {
		c.params["max-uploads"] = strconv.Itoa(int(*in.MaxUploads))
	}
	if in.EncodingType != nil {
		c.params["encoding-type"] = encoding
	}
	err := s.repository.View(ctx, func(r Reader) error {
		b, err := s.bucket(r, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(r.Context(), c, b, "ListBucketMultipartUploads", "", nil); wire != nil {
			return wire
		}
		limit := 1000
		if in.MaxUploads != nil {
			if *in.MaxUploads < 0 {
				return invalid("MaxUploads must not be negative.")
			}
			limit = min(limit, int(*in.MaxUploads))
		}
		if encoding != "" && encoding != "url" {
			return invalid("EncodingType must be url.")
		}
		scanKey := after
		var scanOrder *int64
		if after != "" && afterID != "" {
			var wire *awswire.Error
			scanOrder, wire = multipartMarker(afterID)
			if wire != nil {
				return wire
			}
		}
		out := &api.ListMultipartUploadsOutput{
			Bucket:             new(api.BucketName(b.Key.Name)),
			KeyMarker:          new(api.KeyMarker(versionListEncode(after, encoding))),
			UploadIdMarker:     new(api.UploadIdMarker(afterID)),
			NextKeyMarker:      new(api.NextKeyMarker("")),
			NextUploadIdMarker: new(api.NextUploadIdMarker("")),
			MaxUploads:         new(api.MaxUploads(limit)),
			IsTruncated:        new(api.IsTruncated(false)),
			EncodingType:       in.EncodingType,
		}
		if in.Prefix != nil {
			out.Prefix = new(api.Prefix(versionListEncode(prefix, encoding)))
		}
		if in.Delimiter != nil {
			out.Delimiter = new(api.Delimiter(versionListEncode(delimiter, encoding)))
		}
		if limit == 0 {
			return response.prepare(c, out)
		}
		lastPrefix, count := "", 0
		for {
			uploads, err := r.MultipartUploads(MultipartQuery{Bucket: b.Key, Prefix: prefix, AfterKey: scanKey, AfterOrder: scanOrder, Limit: 1000})
			if err != nil {
				return err
			}
			for _, upload := range uploads {
				name := upload.Key.Name
				scanKey, scanOrder = name, new(upload.CreatedOrder)
				common := ""
				if delimiter != "" {
					if index := strings.Index(strings.TrimPrefix(name, prefix), delimiter); index >= 0 {
						common = name[:len(prefix)+index+len(delimiter)]
					}
				}
				if common != "" {
					if common <= after || common == lastPrefix {
						continue
					}
					lastPrefix = common
				}
				if count == limit {
					out.IsTruncated = new(api.IsTruncated(true))
					return response.prepare(c, out)
				}
				if common != "" {
					out.CommonPrefixes = append(out.CommonPrefixes, api.CommonPrefix{Prefix: new(api.Prefix(versionListEncode(common, encoding)))})
				} else {
					item := api.MultipartUpload{
						Key:          new(api.ObjectKey(versionListEncode(name, encoding))),
						UploadId:     new(api.MultipartUploadId(upload.UploadID)),
						Initiator:    multipartInitiator(upload.Initiator),
						Owner:        objectOwner(b, upload.ObjectRecord),
						StorageClass: new(api.StorageClass(storageClassName(upload.StorageClass))),
						Initiated:    new(upload.Modified.UTC()),
					}
					if upload.ChecksumAlgorithm != "" {
						item.ChecksumAlgorithm = new(api.ChecksumAlgorithm(upload.ChecksumAlgorithm))
						item.ChecksumType = new(api.ChecksumType(upload.ChecksumType))
					}
					out.Uploads = append(out.Uploads, item)
					out.NextKeyMarker = new(api.NextKeyMarker(versionListEncode(name, encoding)))
					out.NextUploadIdMarker = new(api.NextUploadIdMarker(upload.UploadID))
				}
				count++
			}
			if len(uploads) < 1000 {
				return response.prepare(c, out)
			}
		}
	})
	return response, s.complete(ctx, c, err)
}

func (s *Service) listParts(ctx context.Context, in *api.ListPartsInput) (*preparedResponse, *awswire.Error) {
	c := s.multipartCall(ctx, "ListParts", value(in.Bucket), value(in.Key), value(in.UploadId))
	response := &preparedResponse{}
	if in.MaxParts != nil {
		c.params["max-parts"] = strconv.Itoa(int(*in.MaxParts))
	}
	if in.PartNumberMarker != nil {
		c.params["part-number-marker"] = value(in.PartNumberMarker)
	}
	var bucket BucketRecord
	var upload MultipartUploadRecord
	var out *api.ListPartsOutput
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		bucket, err = s.bucket(r, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(r.Context(), c, bucket, "ListMultipartUploadParts", c.key, nil); wire != nil {
			return wire
		}
		limit := 1000
		if in.MaxParts != nil {
			if *in.MaxParts < 0 {
				return invalid("MaxParts must not be negative.")
			}
			limit = min(limit, int(*in.MaxParts))
		}
		var marker int64
		if in.PartNumberMarker != nil {
			marker, err = strconv.ParseInt(value(in.PartNumberMarker), 10, 32)
			if err != nil || marker < 0 {
				return argumentError("part-number-marker", value(in.PartNumberMarker), "Provided part-number-marker not an integer or within integer range")
			}
		}
		upload, err = multipartUpload(r, MultipartUploadKey{ObjectKey: ObjectKey{bucket.Key, c.key}, UploadID: value(in.UploadId)})
		if err != nil {
			return err
		}
		out = &api.ListPartsOutput{
			Bucket:               new(api.BucketName(bucket.Key.Name)),
			Key:                  in.Key,
			UploadId:             in.UploadId,
			Initiator:            multipartInitiator(upload.Initiator),
			Owner:                objectOwner(bucket, upload.ObjectRecord),
			StorageClass:         new(api.StorageClass(storageClassName(upload.StorageClass))),
			PartNumberMarker:     new(api.PartNumberMarker(strconv.FormatInt(marker, 10))),
			NextPartNumberMarker: new(api.NextPartNumberMarker("0")),
			MaxParts:             new(api.MaxParts(limit)),
			IsTruncated:          new(api.IsTruncated(false)),
		}
		if upload.ChecksumAlgorithm != "" {
			out.ChecksumAlgorithm = new(api.ChecksumAlgorithm(upload.ChecksumAlgorithm))
			out.ChecksumType = new(api.ChecksumType(upload.ChecksumType))
		}
		if limit == 0 {
			return nil
		}
		parts, err := r.MultipartParts(upload.UploadKey(), int32(marker), limit+1)
		if err != nil {
			return err
		}
		if len(parts) > limit {
			out.IsTruncated = new(api.IsTruncated(true))
			parts = parts[:limit]
		}
		for _, part := range parts {
			item := api.Part{
				PartNumber:   new(api.PartNumber(part.Number)),
				LastModified: new(part.Modified.UTC()),
				ETag:         new(api.ETag(part.ETag)),
				Size:         new(api.Size(part.Size)),
			}
			item.SetChecksum(upload.ChecksumAlgorithm, part.Checksum)
			out.Parts = append(out.Parts, item)
			out.NextPartNumberMarker = new(api.NextPartNumberMarker(strconv.FormatInt(int64(part.Number), 10)))
		}
		return nil
	})
	if err != nil {
		return response, s.complete(ctx, c, err)
	}
	customer := customerHeaders(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5)
	// Ordinary listings expose only part metadata; explicit checksum listings
	// require proof of the customer key even though no payload is decrypted.
	if upload.ChecksumAlgorithm != "" || upload.CustomerKey == nil {
		key, wire := readCustomerKey(upload.ObjectRecord, customer, false, false)
		clear(key)
		if wire != nil {
			if upload.CustomerKey != nil {
				if wire.Code == "AccessDenied" {
					wire = failure("InvalidRequest", "The provided encryption parameters did not match the ones used originally.", 400)
				} else if wire.Code == "InvalidRequest" && !customer.supplied {
					wire = failure("InvalidRequest", "To retrieve Part Checksum data requests must include appropriate encryption parameters.", 400)
				}
			}
			return response, s.complete(ctx, c, wire)
		}
	}
	// Explicit checksums require caller-scoped KMS authority; ordinary uploads
	// remain listable without consulting the retained key. No part payload is read.
	if upload.EncryptionAlgorithm == "aws:kms" && upload.ChecksumAlgorithm != "" {
		key, wire := s.objectDataKey(ctx, bucket, upload.ObjectRecord, nil)
		clear(key)
		if wire != nil {
			return response, s.complete(ctx, c, wire)
		}
	}
	return response, s.complete(ctx, c, response.prepare(c, out))
}
