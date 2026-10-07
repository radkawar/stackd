package integrations

import (
	"context"
	"fmt"
	"net/url"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/services/appsync"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-graphqlapi.html
var cfnAppSyncAPIProperties = []string{"Name", "AuthenticationType", "AdditionalAuthenticationProviders", "ApiType", "Visibility", "UserPoolConfig", "OpenIDConnectConfig", "LambdaAuthorizerConfig", "LogConfig", "XrayEnabled", "EnhancedMetricsConfig", "MergedApiExecutionRoleArn", "OwnerContact", "QueryDepthLimit", "ResolverCountLimit", "IntrospectionConfig", "Tags"}

type cfnAppSyncAPI struct{ commands StepFunctionsCommands }

func (h cfnAppSyncAPI) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnAppSyncAPIProperties...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name", "AuthenticationType"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnAppSyncAPI) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApiType", "Visibility"), h.Validate(b)
}
func cfnAppSyncAPIID(id string) string {
	if _, rest, ok := strings.Cut(id, ":apis/"); ok {
		return strings.Split(rest, "/")[0]
	}
	return id
}
func (h cfnAppSyncAPI) get(ctx context.Context, id string) (*api.GraphqlApi, error) {
	out, err := cfnComputeCall[api.GetGraphqlApiResponse](ctx, h.commands, "appsync", "GetGraphqlApi", map[string]any{"apiId": cfnAppSyncAPIID(id)})
	if err != nil {
		return nil, err
	}
	return out.GraphqlApi, nil
}
func cfnAppSyncTags(tags api.TagMap) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		out[string(k)] = string(v)
	}
	return out
}
func cfnAppSyncAPIResult(p *api.GraphqlApi) cloudformation.ResourceResult {
	id := cfnComputeValue(p.ApiId)
	arn := cfnComputeValue(p.Arn)
	graphql := string(p.Uris["GRAPHQL"])
	realtime := string(p.Uris["REALTIME"])
	g, _ := url.Parse(graphql)
	rt, _ := url.Parse(realtime)
	// Endpoint ARN differs from the management ARN; the owner endpoint uses ApiId.
	// https://aws.amazon.com/blogs/compute/build-real-time-applications-with-amazon-eventbridge-and-aws-appsync/
	endpointARN := strings.Replace(arn, ":apis/", ":endpoints/graphql-api/", 1)
	attrs := map[string]any{"ApiId": id, "Arn": arn, "GraphQLUrl": graphql, "RealtimeUrl": realtime, "GraphQLEndpointArn": endpointARN}
	if g != nil {
		attrs["GraphQLDns"] = g.Host
	}
	if rt != nil {
		attrs["RealtimeDns"] = rt.Host
	}
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: attrs}
}
func (h cfnAppSyncAPI) apis(ctx context.Context) ([]api.GraphqlApi, error) {
	var rows []api.GraphqlApi
	token := ""
	for {
		out, err := cfnComputeCall[api.ListGraphqlApisResponse](ctx, h.commands, "appsync", "ListGraphqlApis", cfnDeveloperPageInput(token, map[string]any{}))
		if err != nil {
			return nil, err
		}
		rows = append(rows, out.GraphqlApis...)
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
		if next == token {
			return nil, fmt.Errorf("AppSync pagination did not advance")
		}
		token = next
	}
}
func (h cfnAppSyncAPI) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if recovered, err := h.RecoverCreation(ctx, r); err == nil {
		return recovered, nil
	} else if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	ctx = appsync.WithCloudFormationOwnership(ctx, "GraphQLApi", cfnDeveloperClaim(r), "", false, nil)
	in := cfnDeveloperInput(r.Properties, cfnAppSyncAPIProperties...)
	in["tags"] = cfnResourceTags(r)
	out, err := cfnComputeCall[api.CreateGraphqlApiResponse](ctx, h.commands, "appsync", "CreateGraphqlApi", in)
	if err != nil {
		if admitted, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnAppSyncAPIResult(out.GraphqlApi), nil
}
func (h cfnAppSyncAPI) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	rows := map[string]string{}
	observed := appsync.WithCloudFormationOwnership(ctx, "GraphQLApi", cfnDeveloperClaim(r), "", false, rows)
	apis, err := h.apis(observed)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	for _, p := range apis {
		id := cfnComputeValue(p.ApiId)
		if rows[id] != cfnDeveloperClaim(r) {
			continue
		}
		owned := appsync.WithCloudFormationOwnership(ctx, "GraphQLApi", cfnDeveloperClaim(r), id, true, nil)
		exact, err := h.get(owned, id)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnAppSyncAPIResult(exact), nil
	}
	return cloudformation.ResourceResult{}, cfnDeveloperNotFound("AppSync API incarnation", r.Token)
}
func (h cfnAppSyncAPI) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAppSyncAPIUpdateContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags := cfnAppSyncTags(p.Tags)
	in := cfnDeveloperInput(r.Properties, cfnAppSyncAPIProperties...)
	delete(in, "tags")
	delete(in, "apiType")
	delete(in, "visibility")
	in["apiId"] = cfnComputeValue(p.ApiId)
	in["xrayEnabled"] = cfnComputeDefault(r.Properties, "XrayEnabled", false)
	in["queryDepthLimit"] = cfnComputeDefault(r.Properties, "QueryDepthLimit", 0)
	in["resolverCountLimit"] = cfnComputeDefault(r.Properties, "ResolverCountLimit", 0)
	in["introspectionConfig"] = cfnComputeDefault(r.Properties, "IntrospectionConfig", "ENABLED")
	in["additionalAuthenticationProviders"] = cfnComputeDefault(r.Properties, "AdditionalAuthenticationProviders", []any{})
	out, err := cfnComputeCall[api.UpdateGraphqlApiResponse](ctx, h.commands, "appsync", "UpdateGraphqlApi", in)
	result := cfnAppSyncAPIResult(p)
	if err != nil {
		return result, err
	}
	result = cfnAppSyncAPIResult(out.GraphqlApi)
	arn := cfnComputeValue(p.Arn)
	desired := cfnResourceTags(r)
	if removed := cfnComputeRemovedTags(tags, desired); len(removed) > 0 {
		if err = cfnComputeRun(ctx, h.commands, "appsync", "UntagResource", map[string]any{"resourceArn": arn, "tagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(desired) > 0 {
		err = cfnComputeRun(ctx, h.commands, "appsync", "TagResource", map[string]any{"resourceArn": arn, "tags": desired})
	}
	return result, err
}
func (h cfnAppSyncAPI) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnAppSyncScope(r); err != nil {
		return err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "GraphQLApi", cfnAppSyncAPIID(r.PhysicalID), true, nil)
	p, err := h.get(ctx, r.PhysicalID)
	if cfnComputeMissing(err) || cfnMessagingMissing(err, "NotFoundException") {
		return nil
	}
	if err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "appsync", "DeleteGraphqlApi", map[string]any{"apiId": cfnComputeValue(p.ApiId)})
}
func (h cfnAppSyncAPI) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return nil, err
	}
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p, cfnAppSyncAPIProperties...)
	if err != nil {
		return nil, err
	}
	out["Tags"] = cfnComputeTagList(cfnAppSyncTags(p.Tags))
	for k, v := range cfnAppSyncAPIResult(p).Attributes {
		out[k] = v
	}
	return out, nil
}
func (h cfnAppSyncAPI) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apis, err := h.apis(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]cloudformation.ResourceDescription, 0, len(apis))
	for _, p := range apis {
		r.PhysicalID = cfnComputeValue(p.Arn)
		model, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: model})
	}
	return rows, nil
}
