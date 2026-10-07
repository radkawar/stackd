package integrations

import (
	"context"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	glueowner "stackd/internal/services/glue"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-connection.html
type cfnGlueConnection struct{ commands StepFunctionsCommands }

func (h cfnGlueConnection) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ConnectionInput", "CatalogId", "Tags"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Connection", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueConnection) Replacement(a, b cloudformation.Properties) (bool, error) {
	av, _ := cfnComputeObject(a["ConnectionInput"])
	bv, _ := cfnComputeObject(b["ConnectionInput"])
	return cfnComputeChanged(a, b, "CatalogId") || cfnComputeChanged(av, bv, "Name"), h.Validate(b)
}
func (h cfnGlueConnection) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	catalog := cfnGlueCatalogID(r)
	name := ""
	if v, ok := cfnComputeObject(r.Properties["ConnectionInput"]); ok {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 2)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		catalog, name = parts[0], parts[1]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	id := catalog + "|" + name
	ctx = cfnGlueClaim(ctx, r, "connection", name)
	r.PhysicalID = id
	probe := map[string]any{"CatalogId": catalog, "Name": name, "HidePassword": true}
	_, err := cfnComputeCall[api.GetConnectionOutput](ctx, h.commands, "glue", "GetConnection", probe)
	if err == nil {
		return cfnAnalyticsResult(id, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	body := map[string]any{}
	if v, ok := cfnComputeObject(r.Properties["ConnectionInput"]); ok {
		for k, v := range v {
			body[k] = v
		}
	}
	body["Name"] = name
	input := map[string]any{"CatalogId": catalog, "ConnectionInput": body, "Tags": cfnAnalyticsCustomerTags(r)}
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateConnection", input); err != nil {
		// A failed response can follow native admission. Only this incarnation's
		// private native claim proves the controller may retain the ID for rollback.
		if _, probeErr := cfnComputeCall[api.GetConnectionOutput](ctx, h.commands, "glue", "GetConnection", probe); probeErr == nil {
			return cfnAnalyticsResult(id, name, nil), err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, name, nil), nil
}
func (h cfnGlueConnection) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	catalog := cfnGlueCatalogID(r)
	name := ""
	if v, ok := cfnComputeObject(r.Properties["ConnectionInput"]); ok {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 2)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		catalog, name = parts[0], parts[1]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	id := catalog + "|" + name
	arn := cfnGlueARN(r, "connection", name)
	ctx = cfnGlueClaim(ctx, r, "connection", name)
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	body := map[string]any{}
	if v, ok := cfnComputeObject(r.Properties["ConnectionInput"]); ok {
		for k, v := range v {
			body[k] = v
		}
	}
	// Omission in a redacted read model preserves the password. A template
	// that actually supplied it previously can explicitly remove it; the native
	// owner validates that the resulting authentication configuration is usable.
	previous, _ := cfnComputeObject(r.Previous["ConnectionInput"])
	oldProperties, _ := cfnComputeObject(previous["ConnectionProperties"])
	properties, _ := cfnComputeObject(body["ConnectionProperties"])
	if _, hadPassword := oldProperties["PASSWORD"]; hadPassword {
		if _, hasPassword := properties["PASSWORD"]; !hasPassword {
			ctx = glueowner.WithCloudFormationConnectionPasswordRemoval(ctx)
		}
	}
	body["Name"] = name
	input := map[string]any{"CatalogId": catalog, "Name": name, "ConnectionInput": body}
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateConnection", input); err != nil {
		return cfnAnalyticsResult(id, name, nil), err
	}
	return cfnAnalyticsResult(id, name, nil), cfnGlueUpdateTags(ctx, h.commands, r, arn)
}
func (h cfnGlueConnection) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	catalog := cfnGlueCatalogID(r)
	name := ""
	if v, ok := cfnComputeObject(r.Properties["ConnectionInput"]); ok {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 2)
		if err != nil {
			return err
		}
		catalog, name = parts[0], parts[1]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	id := catalog + "|" + name
	ctx = cfnGlueClaim(ctx, r, "connection", name)
	r.PhysicalID = id
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteConnection", map[string]any{"CatalogId": catalog, "ConnectionName": name}))
}
func (h cfnGlueConnection) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	catalog := cfnGlueCatalogID(r)
	name := ""
	if v, ok := cfnComputeObject(r.Properties["ConnectionInput"]); ok {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 2)
		if err != nil {
			return nil, err
		}
		catalog, name = parts[0], parts[1]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	arn := cfnGlueARN(r, "connection", name)
	ctx = cfnGlueClaim(ctx, r, "connection", name)
	out, err := cfnComputeCall[api.GetConnectionOutput](ctx, h.commands, "glue", "GetConnection", map[string]any{"CatalogId": catalog, "Name": name, "HidePassword": true})
	if err != nil {
		return nil, err
	}
	body, err := cfnAnalyticsProject(out.Connection, "AthenaProperties", "AuthenticationConfiguration", "ConnectionProperties", "ConnectionType", "Description", "MatchCriteria", "Name", "PhysicalConnectionRequirements", "PythonProperties", "SparkProperties", "ValidateCredentials", "ValidateForComputeEnvironments")
	if err != nil {
		return nil, err
	}
	if properties, ok := cfnComputeObject(body["ConnectionProperties"]); ok {
		delete(properties, "PASSWORD")
		delete(properties, "ENCRYPTED_PASSWORD")
	}
	p := cloudformation.Properties{"CatalogId": catalog, "Name": name, "ConnectionInput": body}
	tags, err := cfnGlueTags(ctx, h.commands, arn)
	if err != nil {
		return nil, err
	}
	p["Tags"] = tags
	return p, nil
}
func (h cfnGlueConnection) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{"HidePassword": true}
	for {
		out, err := cfnComputeCall[api.GetConnectionsOutput](ctx, h.commands, "glue", "GetConnections", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.ConnectionList {
			r.PhysicalID = r.Scope.Account + "|" + cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["NextToken"] = out.NextToken
	}
	return cfnAnalyticsSort(rows), nil
}
