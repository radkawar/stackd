package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"strings"

	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/services/stepfunctions"
)

// runMapTask runs after the shared task adapter has assumed the execution role.
// Every object read, list page, and result write uses the same command boundary
// as an external caller; none of these operations bypass S3 authorization.
func (t *StepFunctionsTasks) runMapTask(ctx context.Context, task stepfunctions.TaskRecord, _ stepfunctions.RevisionRecord) (stepfunctions.TaskOutcome, error) {
	if task.Kind == "MAP_WRITER" {
		return t.runMapWriter(ctx, task), nil
	}
	var request stepfunctions.MapReaderRequest
	if err := json.Unmarshal([]byte(task.Parameters), &request); err != nil {
		return mapTaskOutcome(nil, "States.ItemReaderFailed", err), nil
	}
	output := stepfunctions.MapReaderOutput{Items: make([]any, 0)}
	var err error
	switch {
	case strings.HasSuffix(task.Resource, ":s3:listObjectsV2"):
		err = t.readMapListing(ctx, request, &output)
	case strings.HasSuffix(task.Resource, ":s3:getObject"):
		bucket, _ := request.Parameters["Bucket"].(string)
		key, _ := request.Parameters["Key"].(string)
		output.Source = mapObjectSource(bucket, key)
		err = t.readMapObject(ctx, request.Parameters, request.ReaderConfig, &output)
	default:
		err = fmt.Errorf("unsupported ItemReader resource %q", task.Resource)
	}
	return mapTaskOutcome(output, "States.ItemReaderFailed", err), nil
}

func mapTaskOutcome(output any, name string, err error) stepfunctions.TaskOutcome {
	outcome := stepfunctions.TaskOutcome{}
	if output != nil {
		encoded, encodeErr := json.Marshal(output)
		if encodeErr != nil {
			if err == nil {
				err = encodeErr
			}
		} else {
			outcome.Output = string(encoded)
		}
	}
	if err != nil {
		outcome.Error, outcome.Cause = name, err.Error()
	}
	return outcome
}

func mapObjectSource(bucket, key string) string {
	if key == "" {
		return "s3://" + bucket
	}
	return "s3://" + bucket + "/" + key
}

func (t *StepFunctionsTasks) mapS3Command(ctx context.Context, operation string, parameters map[string]any) (StepFunctionsCommandResult, error) {
	if err := ctx.Err(); err != nil {
		return StepFunctionsCommandResult{}, err
	}
	encoded, err := json.Marshal(parameters)
	if err != nil {
		return StepFunctionsCommandResult{}, err
	}
	result, failure := t.Commands.Call(ctx, "s3", operation, encoded)
	if failure != nil {
		return result, failure
	}
	return result, nil
}

func (t *StepFunctionsTasks) mapObjectBytes(ctx context.Context, parameters map[string]any) ([]byte, error) {
	result, err := t.mapS3Command(ctx, "GetObject", parameters)
	if err != nil {
		return nil, err
	}
	// Keep the typed streaming bytes: SDK JSON output would turn arbitrary
	// binary Parquet and compressed input into a lossy UTF-8 string.
	switch output := result.Output.(type) {
	case s3api.GetObjectOutput:
		return output.Body, nil
	case *s3api.GetObjectOutput:
		if output != nil {
			return output.Body, nil
		}
	}
	return nil, fmt.Errorf("GetObject returned %T instead of its modeled output", result.Output)
}

func (t *StepFunctionsTasks) readMapListing(ctx context.Context, request stepfunctions.MapReaderRequest, output *stepfunctions.MapReaderOutput) error {
	parameters := maps.Clone(request.Parameters)
	bucket, _ := parameters["Bucket"].(string)
	output.Source = mapObjectSource(bucket, "")
	seen := make(map[string]bool)
	for {
		result, err := t.mapS3Command(ctx, "ListObjectsV2", parameters)
		if err != nil {
			return err
		}
		var page *s3api.ListObjectsV2Output
		switch value := result.Output.(type) {
		case *s3api.ListObjectsV2Output:
			page = value
		case s3api.ListObjectsV2Output:
			page = &value
		}
		if page == nil {
			return fmt.Errorf("ListObjectsV2 returned %T instead of its modeled output", result.Output)
		}
		for _, entry := range page.Contents {
			if mapReaderFull(output, request.ReaderConfig) {
				return nil
			}
			if request.ReaderConfig.Transformation != "LOAD_AND_FLATTEN" {
				object := make(map[string]any, 8)
				if entry.ETag != nil {
					object["Etag"] = *entry.ETag
				}
				if entry.Key != nil {
					object["Key"] = *entry.Key
				}
				if entry.LastModified != nil {
					object["LastModified"] = float64(entry.LastModified.Unix()) + float64(entry.LastModified.Nanosecond())/1e9
				}
				if entry.Size != nil {
					object["Size"] = *entry.Size
				}
				if entry.StorageClass != nil {
					object["StorageClass"] = *entry.StorageClass
				}
				if entry.Owner != nil {
					object["Owner"] = entry.Owner
				}
				if entry.RestoreStatus != nil {
					object["RestoreStatus"] = entry.RestoreStatus
				}
				output.Items = append(output.Items, object)
				continue
			}
			if entry.Key == nil {
				return fmt.Errorf("ListObjectsV2 returned an object without Key")
			}
			key := string(*entry.Key)
			if page.EncodingType != nil && *page.EncodingType == "url" {
				key, err = url.PathUnescape(key)
				if err != nil {
					return err
				}
			}
			get := mapReferencedObjectParameters(parameters, bucket, key)
			if err := t.readMapObject(ctx, get, request.ReaderConfig, output); err != nil {
				return err
			}
		}
		if mapReaderFull(output, request.ReaderConfig) || page.IsTruncated == nil || !bool(*page.IsTruncated) {
			return nil
		}
		token := ""
		if page.NextContinuationToken != nil {
			token = string(*page.NextContinuationToken)
		}
		if token == "" || seen[token] {
			return fmt.Errorf("ListObjectsV2 returned an invalid continuation token")
		}
		seen[token] = true
		parameters["ContinuationToken"] = token
	}
}

func mapReaderFull(output *stepfunctions.MapReaderOutput, config stepfunctions.MapReaderConfig) bool {
	return config.MaxItems > 0 && int64(len(output.Items)) >= config.MaxItems
}

func mapReferencedObjectParameters(parent map[string]any, bucket, key string) map[string]any {
	parameters := map[string]any{"Bucket": bucket, "Key": key}
	for _, name := range []string{"ExpectedBucketOwner", "RequestPayer", "SSECustomerAlgorithm", "SSECustomerKey", "SSECustomerKeyMD5"} {
		if value, ok := parent[name]; ok {
			parameters[name] = value
		}
	}
	return parameters
}

func (t *StepFunctionsTasks) readMapObject(ctx context.Context, parameters map[string]any, config stepfunctions.MapReaderConfig, output *stepfunctions.MapReaderOutput) error {
	if mapReaderFull(output, config) {
		return nil
	}
	if config.InputType == "PARQUET" && parameters["VersionId"] != nil {
		return fmt.Errorf("parquet ItemReader does not support VersionId")
	}
	body, err := t.mapObjectBytes(ctx, parameters)
	if err != nil {
		return err
	}
	bucket, _ := parameters["Bucket"].(string)
	key, _ := parameters["Key"].(string)
	body, err = mapDecompress(body, key)
	if err != nil {
		return fmt.Errorf("read %s: %w", mapObjectSource(bucket, key), err)
	}
	if config.ManifestType == "ATHENA_DATA" {
		return t.readMapAthenaManifest(ctx, parameters, body, config, output)
	}
	if config.ManifestType == "S3_INVENTORY" || config.InputType == "MANIFEST" {
		return t.readMapInventory(ctx, parameters, body, config, output)
	}
	remaining := config.MaxItems
	if remaining > 0 {
		remaining -= int64(len(output.Items))
	}
	items, keys, err := parseMapData(ctx, body, config, remaining)
	if err != nil {
		return fmt.Errorf("parse %s: %w", mapObjectSource(bucket, key), err)
	}
	if keys != nil {
		if output.Keys == nil {
			output.Keys = make([]string, len(output.Items))
		}
		output.Keys = append(output.Keys, keys...)
	} else if output.Keys != nil {
		output.Keys = append(output.Keys, make([]string, len(items))...)
	}
	output.Items = append(output.Items, items...)
	for range items {
		output.Sources = append(output.Sources, mapObjectSource(bucket, key))
	}
	return nil
}

func (t *StepFunctionsTasks) readMapAthenaManifest(ctx context.Context, parameters map[string]any, body []byte, config stepfunctions.MapReaderConfig, output *stepfunctions.MapReaderOutput) error {
	config.ManifestType = ""
	reader := newMapCSVReader(body, ',')
	for !mapReaderFull(output, config) {
		row, err := reader.read()
		if err != nil {
			return mapCSVEnd(err)
		}
		if len(row) != 1 {
			return fmt.Errorf("athena manifest must contain one S3 URI per row")
		}
		location, err := url.Parse(row[0])
		if err != nil || !strings.EqualFold(location.Scheme, "s3") || location.Host == "" || location.Path == "" || location.RawQuery != "" || location.Fragment != "" {
			return fmt.Errorf("invalid Athena manifest S3 URI %q", row[0])
		}
		get := mapReferencedObjectParameters(parameters, location.Host, strings.TrimPrefix(location.Path, "/"))
		if err := t.readMapObject(ctx, get, config, output); err != nil {
			return err
		}
	}
	return nil
}

func (t *StepFunctionsTasks) readMapInventory(ctx context.Context, parameters map[string]any, body []byte, config stepfunctions.MapReaderConfig, output *stepfunctions.MapReaderOutput) error {
	var manifest struct {
		DestinationBucket string `json:"destinationBucket"`
		FileFormat        string `json:"fileFormat"`
		FileSchema        string `json:"fileSchema"`
		Files             []struct {
			Key string `json:"key"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return err
	}
	if manifest.FileFormat != "CSV" {
		return fmt.Errorf("S3 inventory ItemReader requires CSV, got %q", manifest.FileFormat)
	}
	if manifest.FileSchema == "" || manifest.Files == nil {
		return fmt.Errorf("invalid S3 inventory manifest")
	}
	bucket, _ := parameters["Bucket"].(string)
	if manifest.DestinationBucket != "" {
		_, suffix, ok := strings.Cut(manifest.DestinationBucket, ":s3:::")
		if !ok || suffix == "" {
			return fmt.Errorf("invalid S3 inventory destination bucket")
		}
		bucket = suffix
	}
	config.InputType, config.ManifestType, config.CSVHeaderLocation, config.CSVDelimiter = "CSV", "", "GIVEN", "COMMA"
	config.CSVHeaders = strings.Split(manifest.FileSchema, ",")
	for index := range config.CSVHeaders {
		config.CSVHeaders[index] = strings.TrimSpace(config.CSVHeaders[index])
	}
	for _, file := range manifest.Files {
		if mapReaderFull(output, config) {
			return nil
		}
		if file.Key == "" {
			return fmt.Errorf("S3 inventory manifest contains an empty file key")
		}
		get := mapReferencedObjectParameters(parameters, bucket, file.Key)
		if err := t.readMapObject(ctx, get, config, output); err != nil {
			return err
		}
	}
	return nil
}
