package integrations

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	api "stackd/internal/awsapi/glue"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// AthenaHiveDiscovery is supplied by the existing S3 owner. It executes current
// ListBucket policy checks rather than exposing a privileged object inventory.
type AthenaHiveDiscovery interface {
	ListObjectsV2(context.Context, *s3api.ListObjectsV2Input) (*s3api.ListObjectsV2Output, *awswire.Error)
}

func (a *AthenaEngine) repairHivePartitions(ctx context.Context, catalog AthenaGlue, id *api.CatalogIdString, db, name *api.NameString, table *api.Table) error {
	source, ok := a.S3.(AthenaHiveDiscovery)
	if !ok {
		return fmt.Errorf("S3 owner does not expose authorized Hive partition discovery")
	}
	location := hiveValue(table.StorageDescriptor.Location)
	if err := hiveLocation(location); err != nil {
		return err
	}
	if len(table.PartitionKeys) == 0 {
		return hiveInvalid("MSCK requires a partitioned Hive table")
	}
	// Native S3 locations retain literal key bytes, including Hive's percent
	// escapes. URL.Path would decode the root and point discovery elsewhere.
	bucket, prefix, _ := strings.Cut(strings.TrimPrefix(location, "s3://"), "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	input := &s3api.ListObjectsV2Input{Bucket: new(s3api.BucketName(bucket)), Prefix: new(s3api.Prefix(prefix))}
	found := map[string]api.PartitionInput{}
	for {
		page, rejected := source.ListObjectsV2(awsctx.WithViaService(ctx, "athena.amazonaws.com"), input)
		if rejected != nil {
			return rejected
		}
		if page == nil {
			return fmt.Errorf("S3 returned no object listing")
		}
		for _, object := range page.Contents {
			key := hiveValue(object.Key)
			values, path, valid := discoverHivePartition(prefix, key, table.PartitionKeys)
			if !valid {
				continue
			}
			storage := api.CloneStorageDescriptor(*table.StorageDescriptor)
			storage.Location = new(api.LocationString("s3://" + bucket + "/" + path))
			found[path] = api.PartitionInput{Values: values, StorageDescriptor: &storage}
		}
		if page.IsTruncated == nil || !bool(*page.IsTruncated) {
			break
		}
		if page.NextContinuationToken == nil || hiveValue(page.NextContinuationToken) == "" || hiveValue(page.NextContinuationToken) == hiveValue(input.ContinuationToken) {
			return fmt.Errorf("S3 returned no advancing continuation token")
		}
		input.ContinuationToken = new(s3api.Token(*page.NextContinuationToken))
	}
	paths := make([]string, 0, len(found))
	for path := range found {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for len(paths) > 0 {
		count := min(len(paths), 100)
		batch := make(api.PartitionInputList, 0, count)
		for _, path := range paths[:count] {
			batch = append(batch, found[path])
		}
		raw, rejected := catalog.command(ctx, "BatchCreatePartition", &api.BatchCreatePartitionInput{CatalogId: id, DatabaseName: db, TableName: name, PartitionInputList: batch})
		if rejected != nil {
			return rejected
		}
		output, ok := raw.(*api.BatchCreatePartitionOutput)
		if !ok {
			return fmt.Errorf("unexpected MSCK partition response from Glue")
		}
		for _, failure := range output.Errors {
			if failure.ErrorDetail != nil && hiveValue(failure.ErrorDetail.ErrorCode) != "AlreadyExistsException" {
				return hiveInvalid(hiveValue(failure.ErrorDetail.ErrorMessage))
			}
		}
		paths = paths[count:]
	}
	return nil
}

// AWS MSCK adds only Hive-compatible, lower-case partition names, ignoring
// leading underscore names and colon values. It discovers recursively and never
// removes stale Glue partitions. Explicit ALTER ADD has no such restrictions.
func discoverHivePartition(prefix, key string, keys api.ColumnList) (api.ValueStringList, string, bool) {
	if len(keys) == 0 || !strings.HasPrefix(key, prefix) {
		return nil, "", false
	}
	components := strings.Split(strings.TrimPrefix(key, prefix), "/")
	// The final component is an object, or the empty suffix of a directory marker.
	for start := 0; start+len(keys) < len(components); start++ {
		values := make(api.ValueStringList, len(keys))
		valid := true
		for i, column := range keys {
			expected := hiveValue(column.Name)
			name, value, ok := strings.Cut(components[start+i], "=")
			if !ok || expected == "" || strings.HasPrefix(expected, "_") || name != expected || name != strings.ToLower(name) {
				valid = false
				break
			}
			decoded, err := url.PathUnescape(value)
			if err != nil || strings.Contains(decoded, ":") {
				valid = false
				break
			}
			values[i] = api.ValueString(decoded)
		}
		if valid {
			return values, prefix + strings.Join(components[:start+len(keys)], "/") + "/", true
		}
	}
	return nil, "", false
}
