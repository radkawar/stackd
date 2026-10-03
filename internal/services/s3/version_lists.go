package s3

import (
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// Native ListObjectVersions uses form-style space encoding, unlike the
// percent-space spelling used by current-object listings.
func versionListEncode(text, encoding string) string {
	if encoding != "url" {
		return text
	}
	return strings.ReplaceAll(url.QueryEscape(text), "%2F", "/")
}

func (s *Service) listObjectVersions(ctx context.Context, in *api.ListObjectVersionsInput) (*api.ListObjectVersionsOutput, *awswire.Error) {
	c := call(ctx, "ListObjectVersions", value(in.Bucket), "")
	c.params["versions"] = ""
	out := &api.ListObjectVersionsOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		limit, w := listLimit(in.MaxKeys)
		if w != nil {
			return w
		}
		prefix, delimiter, encoding := value(in.Prefix), value(in.Delimiter), value(in.EncodingType)
		afterKey, afterVersion := value(in.KeyMarker), value(in.VersionIdMarker)
		for _, item := range [][2]string{{"prefix", prefix}, {"delimiter", delimiter}, {"key-marker", afterKey}, {"version-id-marker", afterVersion}, {"encoding-type", encoding}} {
			if item[1] != "" {
				c.params[item[0]] = item[1]
			}
		}
		if in.MaxKeys != nil {
			c.params["max-keys"] = strconv.Itoa(int(*in.MaxKeys))
		}
		conditions := map[string][]string{"s3:prefix": {prefix}, "s3:delimiter": {delimiter}, "s3:max-keys": {strconv.Itoa(limit)}}
		if w := s.authorize(tx.Context(), c, b, "ListBucketVersions", "", conditions); w != nil {
			return w
		}
		fetchRestoreStatus := slices.Contains(in.OptionalObjectAttributes, "RestoreStatus")
		if encoding != "" && encoding != "url" {
			return invalid("EncodingType must be url.")
		}
		if afterVersion != "" {
			if afterKey == "" {
				return invalid("A version-id marker cannot be specified without a key marker.")
			}
			if w := validateVersion(afterVersion); w != nil {
				return w
			}
		}
		out.Name = new(api.BucketName(b.Key.Name))
		out.Prefix = new(api.Prefix(versionListEncode(prefix, encoding)))
		out.KeyMarker = new(api.KeyMarker(versionListEncode(afterKey, encoding)))
		out.VersionIdMarker = new(api.VersionIdMarker(afterVersion))
		out.MaxKeys = new(api.MaxKeys(limit))
		out.IsTruncated = new(api.IsTruncated(false))
		out.EncodingType = in.EncodingType
		if in.Delimiter != nil {
			out.Delimiter = new(api.Delimiter(versionListEncode(delimiter, encoding)))
		}
		if limit == 0 {
			return nil
		}
		scanKey, scanVersion := afterKey, afterVersion
		lastKey, lastVersion, lastPrefix, latestKey, latestVersion := "", "", "", "", ""
		count := 0
		for {
			records, err := tx.ObjectVersions(VersionQuery{Bucket: b.Key, Prefix: prefix, AfterKey: scanKey, AfterVersion: scanVersion, Limit: 1000})
			if err != nil {
				return err
			}
			for _, record := range records {
				name := record.Key.Name
				scanKey, scanVersion = name, record.VersionID
				common := ""
				if delimiter != "" {
					if index := strings.Index(strings.TrimPrefix(name, prefix), delimiter); index >= 0 {
						common = name[:len(prefix)+index+len(delimiter)]
					}
				}
				if common != "" {
					if common <= afterKey || common == lastPrefix {
						continue
					}
					lastPrefix = common
				}
				if count == limit {
					out.IsTruncated = new(api.IsTruncated(true))
					out.NextKeyMarker = new(api.NextKeyMarker(versionListEncode(lastKey, encoding)))
					if lastVersion != "" {
						out.NextVersionIdMarker = new(api.NextVersionIdMarker(lastVersion))
					}
					return nil
				}
				if common != "" {
					out.CommonPrefixes = append(out.CommonPrefixes, api.CommonPrefix{Prefix: new(api.Prefix(versionListEncode(common, encoding)))})
					lastKey, lastVersion = common, ""
				} else {
					if latestKey != name {
						latestKey, latestVersion = name, record.VersionID
						// A continuation within the marker key starts below its current version.
						if name == afterKey {
							latestVersion = ""
						}
					}
					key := new(api.ObjectKey(versionListEncode(name, encoding)))
					version := new(api.ObjectVersionId(record.VersionID))
					latest := new(api.IsLatest(record.VersionID == latestVersion))
					if record.DeleteMarker {
						out.DeleteMarkers = append(out.DeleteMarkers, api.DeleteMarkerEntry{Key: key, VersionId: version, IsLatest: latest, LastModified: new(record.Modified), Owner: objectOwner(b, record)})
					} else {
						object := api.ObjectVersion{Key: key, VersionId: version, IsLatest: latest, LastModified: new(record.Modified), Owner: objectOwner(b, record), ETag: new(api.ETag(record.ETag)), Size: new(api.Size(record.Size)), StorageClass: new(api.ObjectVersionStorageClass(storageClassName(record.StorageClass)))}
						if record.ChecksumAlgorithm != "" {
							object.ChecksumAlgorithm = api.ChecksumAlgorithmList{api.ChecksumAlgorithm(record.ChecksumAlgorithm)}
							object.ChecksumType = new(api.ChecksumType(objectChecksumType(record)))
						}
						if fetchRestoreStatus {
							restore, err := objectRestoreForRead(tx, record)
							if err != nil {
								return err
							}
							object.RestoreStatus = restoreStatus(restore, s.clock.Now())
						}
						out.Versions = append(out.Versions, object)
					}
					lastKey, lastVersion = name, record.VersionID
				}
				count++
			}
			if len(records) < 1000 {
				return nil
			}
		}
	})
	return out, wire
}
