package ecr

import (
	"encoding/json"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecr"
	"stackd/journal"
)

var auditRequestDocument = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"layerPartBlob": {Mode: awsapi.OmitField}}}
var auditResponseDocument = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"repository.createdAt": {TimeLayout: time.RFC3339},
	"lastEvaluatedAt":      {TimeLayout: time.RFC3339},
}}
var auditDeletedRepositoryDocument = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"repository.createdAt":                  {TimeLayout: time.RFC3339},
	"repository.imageScanningConfiguration": {Mode: awsapi.OmitField},
	"repository.encryptionConfiguration":    {Mode: awsapi.OmitField},
}}

// These response/resource sets follow exact-request native captures, not Smithy
// resource traits: scanning and lifecycle writes do not all report resources.
func auditProjection(name string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "Describe") || strings.HasPrefix(name, "List") || strings.HasPrefix(name, "BatchGet") || name == "BatchCheckLayerAvailability", Request: auditRequestDocument}
	switch name {
	case "CreateRepository", "DeleteRepository", "InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload", "PutImage", "BatchDeleteImage", "PutImageTagMutability", "PutImageScanningConfiguration", "SetRepositoryPolicy", "DeleteRepositoryPolicy", "PutLifecyclePolicy", "DeleteLifecyclePolicy", "StartLifecyclePolicyPreview", "StartImageScan":
		p.Response = &auditResponseDocument
		if name == "DeleteRepository" {
			p.Response = &auditDeletedRepositoryDocument
		}
	}
	return p
}

func auditRepositoryResources(scope Scope, input any) []journal.APIEventResource {
	var registry *api.RegistryId
	var names api.RepositoryNameList
	var name *api.RepositoryName
	var arn *api.Arn
	switch in := input.(type) {
	case *api.CreateRepositoryInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.DeleteRepositoryInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.DescribeRepositoriesInput:
		registry, names = in.RegistryId, in.RepositoryNames
	case *api.BatchGetRepositoryScanningConfigurationInput:
		names = api.RepositoryNameList(in.RepositoryNames)
	case *api.BatchCheckLayerAvailabilityInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.InitiateLayerUploadInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.UploadLayerPartInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.CompleteLayerUploadInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.PutImageInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.BatchGetImageInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.BatchDeleteImageInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.DescribeImagesInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.ListImagesInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.PutImageTagMutabilityInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.PutImageScanningConfigurationInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.SetRepositoryPolicyInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.GetRepositoryPolicyInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.DeleteRepositoryPolicyInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.GetLifecyclePolicyPreviewInput:
		registry, name = in.RegistryId, in.RepositoryName
	case *api.TagResourceInput:
		arn = in.ResourceArn
	case *api.UntagResourceInput:
		arn = in.ResourceArn
	case *api.ListTagsForResourceInput:
		arn = in.ResourceArn
	}
	if registry != nil {
		scope.AccountID = value(registry)
	}
	if arn != nil {
		parts := strings.SplitN(value(arn), ":", 6)
		if len(parts) != 6 || !strings.HasPrefix(parts[5], "repository/") {
			return nil
		}
		return []journal.APIEventResource{{AccountID: parts[4], ARN: value(arn)}}
	}
	if name != nil {
		return []journal.APIEventResource{{AccountID: scope.AccountID, ARN: repositoryARN(RepositoryKey{scope, value(name)})}}
	}
	var resources []journal.APIEventResource
	for _, name := range names {
		resources = append(resources, journal.APIEventResource{AccountID: scope.AccountID, ARN: repositoryARN(RepositoryKey{scope, string(name)})})
	}
	return resources
}

func auditBatchGetImageRequest(call *journal.APICallCompleted) error {
	// ECR records these server-side defaults even though the public request model
	// has no matching members. Manifest contents remain in PutImage audit events.
	var request map[string]any
	if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
		return err
	}
	if request == nil {
		return nil
	}
	request["excludeManifestContent"] = false
	request["excludeTags"] = false
	request["disableLastRecordedPullTimeUpdate"] = false
	var err error
	call.RequestParameters, err = json.Marshal(request)
	return err
}
