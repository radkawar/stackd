package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"stackd/internal/awsapi"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/services/stepfunctions"
)

const mapResultFileLimit int64 = 5 * 1024 * 1024 * 1024

type mapResultFile struct {
	Key  string `json:"Key"`
	Size int64  `json:"Size"`
}

func (t *StepFunctionsTasks) runMapWriter(ctx context.Context, task stepfunctions.TaskRecord) stepfunctions.TaskOutcome {
	output := stepfunctions.MapWriterOutput{}
	failed := func(err error) stepfunctions.TaskOutcome {
		return mapTaskOutcome(output, "States.ResultWriterFailed", err)
	}
	if !strings.HasSuffix(task.Resource, ":s3:putObject") {
		return failed(fmt.Errorf("unsupported ResultWriter resource %q", task.Resource))
	}
	var request stepfunctions.MapWriterRequest
	if err := json.Unmarshal([]byte(task.Parameters), &request); err != nil {
		return failed(err)
	}
	parameters := maps.Clone(request.Parameters)
	if parameters == nil {
		return failed(fmt.Errorf("ResultWriter parameters are required"))
	}
	prefix := ""
	if value, exists := parameters["Prefix"]; exists {
		var ok bool
		prefix, ok = value.(string)
		if !ok {
			return failed(fmt.Errorf("ResultWriter Prefix must be a string"))
		}
	}
	delete(parameters, "Prefix")
	id := request.MapRunARN[strings.LastIndex(request.MapRunARN, ":")+1:]
	if id == "" || !strings.Contains(request.MapRunARN, ":mapRun:") {
		return failed(fmt.Errorf("ResultWriter requires a Map Run ARN"))
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	prefix += id + "/"
	if request.Generation > 0 {
		prefix += fmt.Sprintf("Redrive-%d/", request.Generation)
	}
	parameters["Key"] = prefix + "manifest.json"
	delete(parameters, "Body")
	encoded, err := json.Marshal(parameters)
	if err != nil {
		return failed(err)
	}
	service, ok := awscatalog.LookupService("s3")
	if !ok {
		return failed(fmt.Errorf("S3 service is unavailable"))
	}
	operation, ok := service.Operation("PutObject")
	if !ok {
		return failed(fmt.Errorf("S3 PutObject is unavailable"))
	}
	var put s3api.PutObjectInput
	if err := awsapi.DecodeSDKInput(service, operation, encoded, &put); err != nil {
		return failed(err)
	}
	if put.Bucket == nil {
		return failed(fmt.Errorf("ResultWriter Bucket is required"))
	}
	bucket := string(*put.Bucket)
	files := map[string][]mapResultFile{"SUCCEEDED": {}, "FAILED": {}, "PENDING": {}}
	for _, file := range request.PriorFiles {
		if file.Status == "SUCCEEDED" && file.Generation < request.Generation {
			files["SUCCEEDED"] = append(files["SUCCEEDED"], mapResultFile{Key: file.Key, Size: file.Size})
		}
	}
	groups := make(map[string][]stepfunctions.MapResultExecution, 3)
executions:
	for _, execution := range request.Executions {
		status := "FAILED"
		switch execution.Status {
		case "SUCCEEDED":
			for _, file := range request.PriorFiles {
				// Results are ordered by execution name. Retain only ranges
				// whose actual S3 write was acknowledged, not every success
				// from a generation that may have failed partway through.
				if file.Status == "SUCCEEDED" && execution.Generation <= file.Generation && file.Generation < request.Generation && execution.Name >= file.FirstExecution && execution.Name <= file.LastExecution {
					output.ResultsWrittenItems += execution.ItemCount
					output.ResultsWrittenExecutions++
					continue executions
				}
			}
			status = "SUCCEEDED"
		case "PENDING", "RUNNING":
			status = "PENDING"
		case "FAILED", "TIMED_OUT", "ABORTED":
		default:
			return failed(fmt.Errorf("unrecognized child execution status %q", execution.Status))
		}
		groups[status] = append(groups[status], execution)
	}
	for _, status := range []string{"SUCCEEDED", "FAILED", "PENDING"} {
		var body bytes.Buffer
		var itemCount, executionCount int64
		var firstExecution, lastExecution string
		fileIndex := 0
		flush := func() error {
			if executionCount == 0 && !(status == "SUCCEEDED" && fileIndex == 0 && len(files[status]) > 0 && request.Generation > 0) {
				return nil
			}
			if request.WriterConfig.OutputType == "JSON" {
				if body.Len() == 0 {
					body.WriteByte('[')
				}
				body.WriteByte(']')
			}
			extension := "json"
			if request.WriterConfig.OutputType == "JSONL" {
				extension = "jsonl"
			}
			key := fmt.Sprintf("%s%s_%d.%s", prefix, status, fileIndex, extension)
			put.ContentType = new(s3api.ContentType("binary/octet-stream"))
			if err := t.writeMapObject(ctx, put, key, body.Bytes()); err != nil {
				return err
			}
			// Acknowledgement follows each successful object commit, rather than
			// the manifest commit. A later write failure must not erase counts.
			output.ResultsWrittenItems += itemCount
			output.ResultsWrittenExecutions += executionCount
			files[status] = append(files[status], mapResultFile{Key: key, Size: int64(body.Len())})
			output.Files = append(output.Files, stepfunctions.MapResultFile{Generation: request.Generation, Status: status, Index: int64(fileIndex), Key: key, Size: int64(body.Len()), FirstExecution: firstExecution, LastExecution: lastExecution})
			body.Reset()
			itemCount, executionCount = 0, 0
			firstExecution, lastExecution = "", ""
			fileIndex++
			return nil
		}
		for _, execution := range groups[status] {
			if err := ctx.Err(); err != nil {
				return failed(err)
			}
			part, err := stepfunctions.EncodeMapResults([]stepfunctions.MapResultExecution{execution}, request.WriterConfig)
			if err != nil {
				return failed(err)
			}
			if request.WriterConfig.OutputType == "JSON" {
				part = part[1 : len(part)-1]
			}
			overhead := int64(0)
			if request.WriterConfig.OutputType == "JSON" {
				overhead = 2
			}
			if int64(len(part))+overhead > mapResultFileLimit {
				return failed(fmt.Errorf("one execution result exceeds the 5 GiB result file limit"))
			}
			if int64(body.Len()+len(part))+overhead > mapResultFileLimit {
				if err := flush(); err != nil {
					return failed(err)
				}
			}
			if request.WriterConfig.OutputType == "JSON" {
				if body.Len() == 0 {
					body.WriteByte('[')
				} else if body.Len() > 1 && len(part) > 0 {
					body.WriteByte(',')
				}
			}
			body.Write(part)
			if executionCount == 0 {
				firstExecution = execution.Name
			}
			lastExecution = execution.Name
			itemCount += execution.ItemCount
			executionCount++
		}
		if err := flush(); err != nil {
			return failed(err)
		}
	}
	manifest := struct {
		DestinationBucket string                     `json:"DestinationBucket"`
		MapRunARN         string                     `json:"MapRunArn"`
		ResultFiles       map[string][]mapResultFile `json:"ResultFiles"`
	}{DestinationBucket: bucket, MapRunARN: request.MapRunARN, ResultFiles: files}
	body, err := json.Marshal(manifest)
	if err != nil {
		return failed(err)
	}
	key := prefix + "manifest.json"
	put.ContentType = new(s3api.ContentType("application/octet-stream"))
	if err := t.writeMapObject(ctx, put, key, body); err != nil {
		return failed(err)
	}
	output.Result = map[string]any{"MapRunArn": request.MapRunARN, "ResultWriterDetails": map[string]any{"Bucket": bucket, "Key": key}}
	return mapTaskOutcome(output, "States.ResultWriterFailed", nil)
}

func (t *StepFunctionsTasks) writeMapObject(ctx context.Context, input s3api.PutObjectInput, key string, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	input.Key = new(s3api.ObjectKey(key))
	input.Body = s3api.StreamingBlob(body)
	input.ContentLength = new(s3api.ContentLength(len(body)))
	_, failure := t.Commands.CallTyped(ctx, "s3", "PutObject", &input)
	if failure != nil {
		return failure
	}
	return nil
}
