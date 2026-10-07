package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html
var cfnAppSyncResolverProperties = []string{"ApiId", "TypeName", "FieldName", "Kind", "DataSourceName", "MaxBatchSize", "PipelineConfig", "Code", "CodeS3Location", "RequestMappingTemplate", "RequestMappingTemplateS3Location", "ResponseMappingTemplate", "ResponseMappingTemplateS3Location", "Runtime", "SyncConfig", "CachingConfig", "MetricsConfig"}

type cfnAppSyncResolver struct{ commands StepFunctionsCommands }

func (h cfnAppSyncResolver) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnAppSyncResolverProperties...); err != nil {
		return err
	}
	return cfnComputeRequired(p, "ApiId", "TypeName", "FieldName")
}
func (h cfnAppSyncResolver) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApiId", "TypeName", "FieldName"), h.Validate(b)
}
func cfnAppSyncResolverParts(arn string) (string, string, string, error) {
	id, tail, err := cfnAppSyncParts(arn, "types")
	if err != nil {
		return "", "", "", err
	}
	typ, field, ok := strings.Cut(tail, "/resolvers/")
	if !ok || typ == "" || field == "" {
		return "", "", "", fmt.Errorf("invalid resolver ARN")
	}
	return id, typ, field, nil
}
func (h cfnAppSyncResolver) get(ctx context.Context, id, typ, field string) (*api.Resolver, error) {
	out, err := cfnComputeCall[api.GetResolverResponse](ctx, h.commands, "appsync", "GetResolver", map[string]any{"apiId": id, "typeName": typ, "fieldName": field})
	if err != nil {
		return nil, err
	}
	return out.Resolver, nil
}
func cfnAppSyncResolverResult(p *api.Resolver) cloudformation.ResourceResult {
	arn := cfnComputeValue(p.ResolverArn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"ResolverArn": arn, "TypeName": cfnComputeValue(p.TypeName), "FieldName": cfnComputeValue(p.FieldName)}}
}
func (h cfnAppSyncResolver) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeString(r.Properties, "ApiId")
	typ := cfnComputeString(r.Properties, "TypeName")
	field := cfnComputeString(r.Properties, "FieldName")
	target := id + "/" + typ + "/" + field
	claims := map[string]string{}
	ctx = cfnAppSyncOwnedContext(ctx, r, "Resolver", target, false, claims)
	p, err := h.get(ctx, id, typ, field)
	if err == nil {
		if claims[target] != cfnDeveloperClaim(r) {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("resolver belongs to another incarnation"))
		}
		return cfnAppSyncResolverResult(p), nil
	}
	if !cfnMessagingMissing(err, "NotFoundException") {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "Resolver", target, true, nil)
	in, err := cfnAppSyncCodeInput(ctx, h.commands, r.Properties, cfnAppSyncResolverProperties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.CreateResolverResponse](ctx, h.commands, "appsync", "CreateResolver", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAppSyncResolverResult(out.Resolver), nil
}
func (h cfnAppSyncResolver) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, typ, field, err := cfnAppSyncResolverParts(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "Resolver", id+"/"+typ+"/"+field, true, nil)
	in, err := cfnAppSyncCodeInput(ctx, h.commands, r.Properties, cfnAppSyncResolverProperties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in["apiId"] = id
	in["typeName"] = typ
	in["fieldName"] = field
	in["kind"] = cfnComputeDefault(r.Properties, "Kind", "UNIT")
	in["maxBatchSize"] = cfnComputeDefault(r.Properties, "MaxBatchSize", 0)
	in["metricsConfig"] = cfnComputeDefault(r.Properties, "MetricsConfig", "DISABLED")
	out, err := cfnComputeCall[api.UpdateResolverResponse](ctx, h.commands, "appsync", "UpdateResolver", in)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID}, err
	}
	return cfnAppSyncResolverResult(out.Resolver), nil
}
func (h cfnAppSyncResolver) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnAppSyncScope(r); err != nil {
		return err
	}
	id, typ, field, err := cfnAppSyncResolverParts(r.PhysicalID)
	if err != nil {
		return err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "Resolver", id+"/"+typ+"/"+field, true, nil)
	err = cfnComputeRun(ctx, h.commands, "appsync", "DeleteResolver", map[string]any{"apiId": id, "typeName": typ, "fieldName": field})
	if cfnMessagingMissing(err, "NotFoundException") {
		return nil
	}
	return err
}
func (h cfnAppSyncResolver) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return nil, err
	}
	id, typ, field, err := cfnAppSyncResolverParts(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := h.get(ctx, id, typ, field)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p, cfnAppSyncResolverProperties...)
	if err != nil {
		return nil, err
	}
	out["ApiId"] = id
	out["ResolverArn"] = cfnComputeValue(p.ResolverArn)
	return out, nil
}
func (h cfnAppSyncResolver) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apis, err := (cfnAppSyncAPI(h)).apis(ctx)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, a := range apis {
		id := cfnComputeValue(a.ApiId)
		status, err := cfnComputeCall[api.GetSchemaCreationStatusResponse](ctx, h.commands, "appsync", "GetSchemaCreationStatus", map[string]any{"apiId": id})
		if err != nil {
			return nil, err
		}
		if cfnComputeValue(status.Status) == "NOT_APPLICABLE" {
			continue
		}
		schema, err := cfnComputeCall[api.GetIntrospectionSchemaOutput](ctx, h.commands, "appsync", "GetIntrospectionSchema", map[string]any{"apiId": id, "format": "JSON"})
		if err != nil {
			return nil, err
		}
		var document struct {
			Data struct {
				Schema struct {
					Types []struct{ Name, Kind string } `json:"types"`
				} `json:"__schema"`
			} `json:"data"`
		}
		if err = json.Unmarshal(schema.Schema, &document); err != nil {
			return nil, err
		}
		for _, typ := range document.Data.Schema.Types {
			if strings.HasPrefix(typ.Name, "__") || (typ.Kind != "OBJECT" && typ.Kind != "INTERFACE") {
				continue
			}
			token := ""
			for {
				out, err := cfnComputeCall[api.ListResolversResponse](ctx, h.commands, "appsync", "ListResolvers", cfnDeveloperPageInput(token, map[string]any{"apiId": id, "typeName": typ.Name}))
				if err != nil {
					return nil, err
				}
				for _, p := range out.Resolvers {
					r.PhysicalID = cfnComputeValue(p.ResolverArn)
					model, err := h.Read(ctx, r)
					if err != nil {
						return nil, err
					}
					rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: model})
				}
				next := cfnComputeValue(out.NextToken)
				if next == "" {
					break
				}
				if next == token {
					return nil, fmt.Errorf("AppSync resolver pagination did not advance")
				}
				token = next
			}
		}
	}
	return rows, nil
}
