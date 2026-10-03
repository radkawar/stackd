package integrations

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
	"stackd/internal/services/codepipeline"
)

// Match the bounded in-memory CodeBuild artifact reader. Deployment never
// materializes ZIP paths on the host or follows archive links.
const pipelineS3ArchiveBytes = 512 << 20
const pipelineS3ArchiveFiles = 100000

func (a *CodePipelineActions) deployS3(ctx context.Context, request codepipeline.ActionRequest) (codepipeline.ActionResult, error) {
	if len(request.InputArtifacts) != 1 || len(request.OutputArtifacts) != 0 {
		return pipelineS3DeployFailure("ConfigurationError", "S3 deployment requires one input artifact and no output artifacts"), nil
	}
	configuration := request.Action.Configuration
	bucket, key := string(configuration["BucketName"]), string(configuration["ObjectKey"])
	extract := string(configuration["Extract"])
	if extract != "true" && extract != "false" {
		return pipelineS3DeployFailure("ConfigurationError", fmt.Sprintf("Invalid value for configuration property '%s': 'Extract'. Edit your pipeline and set 'Extract' to either 'true' or 'false'.", extract)), nil
	}
	if extract == "false" && key == "" {
		return pipelineS3DeployFailure("ConfigurationError", "When the extract feature is disabled, you must provide an object. Edit your pipeline to fix the configuration."), nil
	}
	if bucket == "" {
		return pipelineS3DeployFailure("ConfigurationError", "S3 deployment requires BucketName"), nil
	}
	artifact := request.InputArtifacts[0]
	input := &s3api.GetObjectInput{Bucket: new(s3api.BucketName(artifact.Bucket)), Key: new(s3api.ObjectKey(artifact.Key))}
	if artifact.VersionID != "" {
		input.VersionId = new(s3api.ObjectVersionId(artifact.VersionID))
	}
	raw, err := pipelineCommand(ctx, a.S3, "s3", "GetObject", input)
	if err != nil {
		return pipelineS3DeployError(err, "")
	}
	body := raw.(*s3api.GetObjectOutput).Body
	put := &s3api.PutObjectInput{Bucket: new(s3api.BucketName(bucket))}
	if value := string(configuration["CacheControl"]); value != "" {
		put.CacheControl = new(s3api.CacheControl(value))
	}
	if value := string(configuration["CannedACL"]); value != "" {
		put.ACL = new(s3api.ObjectCannedACL(value))
	}
	if value := string(configuration["KMSEncryptionKeyARN"]); value != "" {
		put.ServerSideEncryption = new(s3api.ServerSideEncryption("aws:kms"))
		put.SSEKMSKeyId = new(s3api.SSEKMSKeyId(value))
	}
	if extract == "false" {
		put.Key, put.Body = new(s3api.ObjectKey(key)), body
		put.ContentType = new(s3api.ContentType("application/octet-stream"))
		if _, err := pipelineCommand(ctx, a.S3, "s3", "PutObject", put); err != nil {
			return pipelineS3DeployError(err, bucket)
		}
	} else {
		archive, err := pipelineS3DeployArchive(body)
		if err != nil {
			return pipelineS3ArchiveFailure(err), nil
		}
		prefix := key
		if prefix != "" {
			prefix += "/"
		}
		for _, file := range archive.File {
			if err := ctx.Err(); err != nil {
				return codepipeline.ActionResult{}, err
			}
			name := strings.ReplaceAll(file.Name, "\\", "/")
			if strings.Contains(name, "../") {
				return pipelineS3DeployFailure("ConfigurationError", "The file name "+name+" contains invalid sequence: dot-dot-slash."), nil
			}
			body, err := pipelineS3DeployMember(file)
			if err != nil {
				return pipelineS3ArchiveFailure(err), nil
			}
			if strings.HasSuffix(name, "/") {
				continue
			}
			put.Key, put.Body = new(s3api.ObjectKey(prefix+name)), body
			put.ContentType = new(s3api.ContentType(pipelineS3ContentType(name)))
			// A later rejected write leaves earlier real S3 writes intact. There is
			// no synthetic rollback; the execution owner fences completion/retry.
			if _, err := pipelineCommand(ctx, a.S3, "s3", "PutObject", put); err != nil {
				return pipelineS3DeployError(err, bucket)
			}
		}
	}
	handle := bucket
	if key != "" {
		handle += "/" + key
	}
	return codepipeline.ActionResult{Status: "Succeeded", Summary: "Deployment Succeeded", ExternalExecutionID: handle}, nil
}

func pipelineS3ArchiveFailure(err error) codepipeline.ActionResult {
	if errors.Is(err, zip.ErrFormat) || errors.Is(err, zip.ErrChecksum) || errors.Is(err, io.ErrUnexpectedEOF) {
		return pipelineS3DeployFailure("JobFailed", "The archive is malformed.")
	}
	return pipelineS3DeployFailure("JobFailed", "Unable to extract deployment ZIP: "+err.Error())
}

func pipelineS3DeployArchive(body []byte) (*zip.Reader, error) {
	if len(body) > pipelineS3ArchiveBytes {
		return nil, fmt.Errorf("archive exceeds 512 MiB")
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	// The provider accepts leading slashes and backslashes as S3 object keys.
	// Host ZIP-path policy must not override the per-member provider checks.
	if err != nil && (!errors.Is(err, zip.ErrInsecurePath) || archive == nil) {
		return nil, err
	}
	if len(archive.File) > pipelineS3ArchiveFiles {
		return nil, fmt.Errorf("ZIP has too many entries")
	}
	var total uint64
	for _, file := range archive.File {
		if file.UncompressedSize64 > pipelineS3ArchiveBytes-total {
			return nil, fmt.Errorf("expanded ZIP exceeds 512 MiB")
		}
		total += file.UncompressedSize64
	}
	return archive, nil
}

func pipelineS3DeployMember(file *zip.File) ([]byte, error) {
	if file.Flags&1 != 0 {
		// TODO: Comeback — calibrate native encrypted-archive failures.
		return nil, fmt.Errorf("encrypted ZIP member %q is not supported", file.Name)
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	// The extra byte makes the ZIP reader reach EOF and verify its CRC even
	// when the declared size is exact; malicious headers cannot expand freely.
	body, readErr := io.ReadAll(io.LimitReader(reader, int64(file.UncompressedSize64)+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if uint64(len(body)) != file.UncompressedSize64 {
		return nil, fmt.Errorf("ZIP member %q has inconsistent expanded size", file.Name)
	}
	return body, nil
}

func pipelineS3ContentType(name string) string {
	// Native S3 deployment infers these media types from the case-insensitive
	// extension, without charset parameters or content sniffing. In particular,
	// JavaScript differs from Go's MIME table; never consult the host registry.
	// TODO: Comeback — calibrate the remaining native extension mappings;
	// unmeasured extensions currently use application/octet-stream.
	switch strings.ToLower(path.Ext(name)) {
	case ".html":
		return "text/html"
	case ".json":
		return "application/json"
	case ".js":
		return "application/x-javascript"
	case ".css":
		return "text/css"
	case ".svg":
		return "image/svg+xml"
	case ".txt":
		return "text/plain"
	case ".xml":
		return "application/xml"
	case ".png":
		return "image/png"
	case ".jpg":
		return "image/jpeg"
	default:
		return "application/octet-stream"
	}
}

func pipelineS3DeployFailure(code, message string) codepipeline.ActionResult {
	return codepipeline.ActionResult{Status: "Failed", ErrorCode: code, ErrorMessage: message, Summary: message}
}

func pipelineS3DeployError(err error, deploymentBucket string) (codepipeline.ActionResult, error) {
	if rejected, ok := err.(*awswire.Error); ok {
		code := "ConfigurationError"
		message := rejected.Message
		if rejected.StatusCode == 403 || rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
			code = "PermissionError"
			if deploymentBucket != "" {
				message = "You do not have sufficient permissions to call s3.putObject for the deployment bucket, " + deploymentBucket + ". Verify that the policy on the resource allows you to perform this task. If you choose a canned ACL for your Amazon S3 deployment action, the policy must include the PutObjectAcl action. If the object already exists, the policy must also include the PutObjectVersionAcl action. " + rejected.Error()
			}
		} else if rejected.StatusCode >= 500 {
			return codepipeline.ActionResult{}, err
		}
		return pipelineS3DeployFailure(code, message), nil
	}
	return codepipeline.ActionResult{}, err
}
