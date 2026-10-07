package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/services/appsync"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-graphqlschema.html
// The schema is the owner's live executable SDL, never a CFN resource snapshot.
type cfnAppSyncSchema struct{ commands StepFunctionsCommands }

func (h cfnAppSyncSchema) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ApiId", "Definition", "DefinitionS3Location"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ApiId"); err != nil {
		return err
	}
	if (p["Definition"] == nil) == (p["DefinitionS3Location"] == nil) {
		return fmt.Errorf("exactly one Definition or DefinitionS3Location is required")
	}
	return cfnComputeStrings(p, "ApiId", "Definition", "DefinitionS3Location")
}
func (h cfnAppSyncSchema) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApiId"), h.Validate(b)
}
func cfnAppSyncSchemaID(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return strings.TrimSuffix(r.PhysicalID, "GraphQLSchema")
	}
	return cfnComputeString(r.Properties, "ApiId")
}
func cfnAppSyncSchemaResult(id string) cloudformation.ResourceResult {
	physical := id + "GraphQLSchema"
	return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical, Attributes: map[string]any{"Id": physical}}
}
func (h cfnAppSyncSchema) definition(ctx context.Context, id string) (string, error) {
	out, err := cfnComputeCall[api.GetIntrospectionSchemaOutput](appsync.WithCloudFormationSchemaRead(ctx), h.commands, "appsync", "GetIntrospectionSchema", map[string]any{"apiId": id, "format": "SDL"})
	if err != nil {
		return "", err
	}
	return string(out.Schema), nil
}
func (h cfnAppSyncSchema) apply(ctx context.Context, r cloudformation.ResourceRequest, id string) (cloudformation.ResourceResult, error) {
	definition := cfnComputeString(r.Properties, "Definition")
	if location := cfnComputeString(r.Properties, "DefinitionS3Location"); location != "" {
		var err error
		definition, err = cfnAppSyncS3Text(ctx, h.commands, location)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	out, err := cfnComputeCall[api.StartSchemaCreationResponse](ctx, h.commands, "appsync", "StartSchemaCreation", map[string]any{"apiId": id, "definition": []byte(definition)})
	result := cfnAppSyncSchemaResult(id)
	if err != nil {
		return result, err
	}
	if cfnComputeValue(out.Status) == "FAILED" {
		return result, fmt.Errorf("AppSync rejected schema definition")
	}
	return result, nil
}
func (h cfnAppSyncSchema) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnAppSyncSchemaID(r)
	claims := map[string]string{}
	ctx = cfnAppSyncOwnedContext(ctx, r, "GraphQLSchema", id, false, claims)
	definition, err := h.definition(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if claims[id] == cfnDeveloperClaim(r) {
		return cfnAppSyncSchemaResult(id), nil
	}
	if definition != "" || claims[id] != "" {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("schema belongs to another incarnation"))
	}
	return h.apply(ctx, r, id)
}
func (h cfnAppSyncSchema) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnAppSyncSchemaID(r)
	ctx = cfnAppSyncOwnedContext(ctx, r, "GraphQLSchema", id, true, nil)
	return h.apply(ctx, r, id)
}
func (h cfnAppSyncSchema) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	id := cfnAppSyncSchemaID(r)
	ctx = cfnAppSyncOwnedContext(ctx, r, "GraphQLSchema", id, true, nil)
	ctx = appsync.WithCloudFormationSchemaDeletion(ctx)
	err := cfnComputeRun(ctx, h.commands, "appsync", "StartSchemaCreation", map[string]any{"apiId": id, "definition": []byte{}})
	if cfnMessagingMissing(err, "NotFoundException") {
		return nil
	}
	return err
}
func (h cfnAppSyncSchema) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	id := cfnAppSyncSchemaID(r)
	definition, err := h.definition(ctx, id)
	if err != nil {
		return nil, err
	}
	if definition == "" {
		return nil, cfnDeveloperNotFound("schema", id)
	}
	return cloudformation.Properties{"Id": id + "GraphQLSchema", "ApiId": id, "Definition": definition}, nil
}
func (h cfnAppSyncSchema) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apis, err := (cfnAppSyncAPI(h)).apis(ctx)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, a := range apis {
		id := cfnComputeValue(a.ApiId)
		definition, err := h.definition(ctx, id)
		if err != nil {
			return nil, err
		}
		if definition == "" {
			continue
		}
		rows = append(rows, cloudformation.ResourceDescription{Identifier: id + "GraphQLSchema", Properties: cloudformation.Properties{"Id": id + "GraphQLSchema", "ApiId": id, "Definition": definition}})
	}
	return rows, nil
}
func (h cfnAppSyncSchema) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	out, err := cfnComputeCall[api.GetSchemaCreationStatusResponse](ctx, h.commands, "appsync", "GetSchemaCreationStatus", map[string]any{"apiId": cfnAppSyncSchemaID(r)})
	if err != nil {
		return false, err
	}
	switch cfnComputeValue(out.Status) {
	case "SUCCESS", "ACTIVE":
		return true, nil
	case "PROCESSING":
		return false, nil
	default:
		return false, fmt.Errorf("AppSync schema status %s", cfnComputeValue(out.Status))
	}
}
