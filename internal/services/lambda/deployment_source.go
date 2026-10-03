package lambda

import (
	"context"
	"errors"

	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// S3ObjectReference identifies the exact source retained by REFERENCE deployments.
// VersionID is empty only while resolving a current-object request.
type S3ObjectReference struct {
	Bucket, Key, VersionID string
}

// CodeSource reads deployment objects through S3's command and authorization
// boundary. ReadCode uses deploying-caller authority and resolves the source
// version; reference mode also requires Lambda service-principal access.
// ReadReference uses only Lambda's service authority for an existing source.
// The resource ARN supplies aws:SourceArn, never the execution role's identity.
type CodeSource interface {
	ReadCode(context.Context, Scope, string, S3ObjectReference, bool) ([]byte, S3ObjectReference, *awswire.Error)
	ReadReference(context.Context, Scope, string, S3ObjectReference) ([]byte, *awswire.Error)
}

func (s *Service) loadCode(ctx context.Context, scope Scope, resourceARN string, code []byte, bucket, key, version, mode string) (CodeArchive, *S3ObjectReference, *awswire.Error) {
	var reference *S3ObjectReference
	hasS3 := bucket != "" || key != "" || version != "" || mode != ""
	if code != nil {
		if hasS3 {
			return CodeArchive{}, nil, failure("InvalidParameterValueException", "Please do not provide other FunctionCode parameters when providing a ZipFile.", 400)
		}
		if len(code) > 50<<20 {
			return CodeArchive{}, nil, failure("RequestTooLargeException", "Direct ZIP uploads cannot exceed 50 MiB; use an S3 deployment source for larger packages.", 413)
		}
	} else {
		if !hasS3 {
			return CodeArchive{}, nil, failure("InvalidParameterValueException", "Please provide a source for function code.", 400)
		}
		if bucket == "" || key == "" {
			return CodeArchive{}, nil, failure("InvalidParameterValueException", "S3 Bucket and Key are required for uploading with S3 parameters.", 400)
		}
		if s.codeSource == nil {
			return CodeArchive{}, nil, unsupported("S3 deployment sources require configured S3 commands.")
		}
		var resolved S3ObjectReference
		var wire *awswire.Error
		code, resolved, wire = s.codeSource.ReadCode(ctx, scope, resourceARN, S3ObjectReference{Bucket: bucket, Key: key, VersionID: version}, mode == "REFERENCE")
		if wire != nil {
			return CodeArchive{}, nil, wire
		}
		if mode == "REFERENCE" {
			reference = &resolved
		}
	}
	if err := runtime.ValidateCode(code); err != nil {
		return CodeArchive{}, nil, deploymentArchiveError(err)
	}
	return deploymentArchive(scope, code, s.clock.Now()), reference, nil
}

func deploymentArchiveError(err error) *awswire.Error {
	message := "Could not unzip uploaded file. Please check your file, then try to upload again."
	if errors.Is(err, runtime.ErrDeploymentTooLarge) {
		message = "Unzipped size must be smaller than 262144000 bytes."
	}
	return failure("InvalidParameterValueException", message, 400)
}

func resolvedS3Object(reference *S3ObjectReference) *api.ResolvedS3Object {
	if reference == nil {
		return nil
	}
	return &api.ResolvedS3Object{S3Bucket: new(api.S3Bucket(reference.Bucket)), S3Key: new(api.S3Key(reference.Key)), S3ObjectVersion: new(api.S3ObjectVersion(reference.VersionID))}
}
