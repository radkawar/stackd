package s3

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

type listCursor struct{ Bucket, Prefix, Delimiter, After string }

func encodeCursor(cursor listCursor) string {
	data, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(data)
}
func decodeCursor(token, bucket, prefix, delimiter string) (string, *awswire.Error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", invalid("Invalid continuation token.")
	}
	var cursor listCursor
	if json.Unmarshal(data, &cursor) != nil || cursor.Bucket != bucket || cursor.Prefix != prefix || cursor.Delimiter != delimiter || cursor.After == "" {
		return "", invalid("Invalid continuation token.")
	}
	return cursor.After, nil
}
func listEncode(value, encoding string) string {
	if encoding != "url" {
		return value
	}
	return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(value), "+", "%20"), "%2F", "/")
}
func listLimit(requested *api.MaxKeys) (int, *awswire.Error) {
	if requested == nil {
		return 1000, nil
	}
	if *requested < 0 {
		return 0, invalid("MaxKeys must not be negative.")
	}
	return min(1000, int(*requested)), nil
}

type objectPage struct {
	objects   api.ObjectList
	prefixes  api.CommonPrefixList
	last      string
	truncated bool
}

func (s *Service) objectPage(tx Transaction, c *apiCall, expected, prefix, delimiter, after, encoding string, limit int, fetchOwner, fetchRestoreStatus bool, token *api.Token) (objectPage, error) {
	page := objectPage{}
	b, err := s.bucket(tx, c, expected)
	if err != nil {
		return page, err
	}
	if token != nil {
		var wire *awswire.Error
		after, wire = decodeCursor(value(token), b.Key.Name, prefix, delimiter)
		if wire != nil {
			return page, wire
		}
	}
	conditions := map[string][]string{"s3:prefix": {prefix}, "s3:delimiter": {delimiter}, "s3:max-keys": {strconv.Itoa(limit)}}
	if w := s.authorize(tx.Context(), c, b, "ListBucket", "", conditions); w != nil {
		return page, w
	}
	if encoding != "" && encoding != "url" {
		return page, invalid("EncodingType must be url.")
	}
	if limit == 0 {
		return page, nil
	}
	scanAfter := after
	lastPrefix := ""
	count := 0
	for {
		records, err := tx.Objects(ObjectQuery{Bucket: b.Key, Prefix: prefix, After: scanAfter, Limit: 1000})
		if err != nil {
			return page, err
		}
		for _, record := range records {
			name := record.Key.Name
			scanAfter = name
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
				name = common
			}
			if count == limit {
				page.truncated = true
				return page, nil
			}
			if common != "" {
				page.prefixes = append(page.prefixes, api.CommonPrefix{Prefix: new(api.Prefix(listEncode(common, encoding)))})
			} else {
				object := api.Object{Key: new(api.ObjectKey(listEncode(name, encoding))), LastModified: new(record.Modified), ETag: new(api.ETag(record.ETag)), Size: new(api.Size(record.Size)), StorageClass: new(api.ObjectStorageClass(storageClassName(record.StorageClass)))}
				if record.ChecksumAlgorithm != "" {
					object.ChecksumAlgorithm = api.ChecksumAlgorithmList{api.ChecksumAlgorithm(record.ChecksumAlgorithm)}
					object.ChecksumType = new(api.ChecksumType(objectChecksumType(record)))
				}
				if fetchOwner {
					object.Owner = objectOwner(b, record)
				}
				if fetchRestoreStatus {
					restore, err := objectRestoreForRead(tx, record)
					if err != nil {
						return page, err
					}
					object.RestoreStatus = restoreStatus(restore, s.clock.Now())
				}
				page.objects = append(page.objects, object)
			}
			page.last = name
			count++
		}
		if len(records) < 1000 {
			return page, nil
		}
	}
}
func (s *Service) listObjects(ctx context.Context, in *api.ListObjectsInput) (*preparedResponse, *awswire.Error) {
	c := s.transferCall(ctx, "ListObjects", value(in.Bucket), "")
	response := &preparedResponse{}
	out := &api.ListObjectsOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		limit, w := listLimit(in.MaxKeys)
		if w != nil {
			return w
		}
		prefix, delimiter, after, encoding := value(in.Prefix), value(in.Delimiter), value(in.Marker), value(in.EncodingType)
		if in.Prefix != nil {
			c.params["prefix"] = prefix
		}
		if in.Delimiter != nil {
			c.params["delimiter"] = delimiter
		}
		if in.Marker != nil {
			c.params["marker"] = after
		}
		if in.MaxKeys != nil {
			c.params["max-keys"] = strconv.Itoa(int(*in.MaxKeys))
		}
		if in.EncodingType != nil {
			c.params["encoding-type"] = encoding
		}
		page, err := s.objectPage(tx, c, value(in.ExpectedBucketOwner), prefix, delimiter, after, encoding, limit, true, slices.Contains(in.OptionalObjectAttributes, "RestoreStatus"), nil)
		if err != nil {
			return err
		}
		out.Name = new(api.BucketName(c.bucket))
		out.Prefix = new(api.Prefix(listEncode(prefix, encoding)))
		out.Marker = new(api.Marker(listEncode(after, encoding)))
		out.MaxKeys = new(api.MaxKeys(limit))
		out.IsTruncated = new(api.IsTruncated(page.truncated))
		out.Contents = page.objects
		out.CommonPrefixes = page.prefixes
		out.EncodingType = in.EncodingType
		if in.Delimiter != nil {
			out.Delimiter = new(api.Delimiter(listEncode(delimiter, encoding)))
		}
		if page.truncated && delimiter != "" {
			out.NextMarker = new(api.NextMarker(listEncode(page.last, encoding)))
		}
		return response.prepare(c, out)
	})
	return response, wire
}

// ListObjectsV2 applies the ordinary listing authorization and cursor semantics
// for in-process consumers without introducing a separate bucket inventory.
func (s *Service) ListObjectsV2(ctx context.Context, in *api.ListObjectsV2Input) (*api.ListObjectsV2Output, *awswire.Error) {
	out := &api.ListObjectsV2Output{}
	_, wire := s.listObjectsV2Response(ctx, in, out)
	return out, wire
}

func (s *Service) listObjectsV2(ctx context.Context, in *api.ListObjectsV2Input) (*preparedResponse, *awswire.Error) {
	return s.listObjectsV2Response(ctx, in, &api.ListObjectsV2Output{})
}

func (s *Service) listObjectsV2Response(ctx context.Context, in *api.ListObjectsV2Input, out *api.ListObjectsV2Output) (*preparedResponse, *awswire.Error) {
	c := s.transferCall(ctx, "ListObjectsV2", value(in.Bucket), "")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		limit, w := listLimit(in.MaxKeys)
		if w != nil {
			return w
		}
		prefix, delimiter, after, encoding := value(in.Prefix), value(in.Delimiter), value(in.StartAfter), value(in.EncodingType)
		c.params["list-type"] = "2"
		if in.Prefix != nil {
			c.params["prefix"] = prefix
		}
		if in.Delimiter != nil {
			c.params["delimiter"] = delimiter
		}
		if in.MaxKeys != nil {
			c.params["max-keys"] = strconv.Itoa(int(*in.MaxKeys))
		}
		if in.EncodingType != nil {
			c.params["encoding-type"] = encoding
		}
		if in.ContinuationToken != nil {
			c.params["continuation-token"] = value(in.ContinuationToken)
		}
		if in.StartAfter != nil {
			c.params["start-after"] = value(in.StartAfter)
		}
		if in.FetchOwner != nil {
			c.params["fetch-owner"] = strconv.FormatBool(bool(*in.FetchOwner))
		}
		page, err := s.objectPage(tx, c, value(in.ExpectedBucketOwner), prefix, delimiter, after, encoding, limit, in.FetchOwner != nil && bool(*in.FetchOwner), slices.Contains(in.OptionalObjectAttributes, "RestoreStatus"), in.ContinuationToken)
		if err != nil {
			return err
		}
		out.Name = new(api.BucketName(c.bucket))
		out.Prefix = new(api.Prefix(listEncode(prefix, encoding)))
		out.MaxKeys = new(api.MaxKeys(limit))
		out.IsTruncated = new(api.IsTruncated(page.truncated))
		out.KeyCount = new(api.KeyCount(len(page.objects) + len(page.prefixes)))
		out.Contents = page.objects
		out.CommonPrefixes = page.prefixes
		out.EncodingType = in.EncodingType
		out.ContinuationToken = in.ContinuationToken
		if in.Delimiter != nil {
			out.Delimiter = new(api.Delimiter(listEncode(delimiter, encoding)))
		}
		if in.StartAfter != nil {
			out.StartAfter = new(api.StartAfter(listEncode(value(in.StartAfter), encoding)))
		}
		if page.truncated {
			out.NextContinuationToken = new(api.NextToken(encodeCursor(listCursor{c.bucket, prefix, delimiter, page.last})))
		}
		return response.prepare(c, out)
	})
	return response, wire
}
