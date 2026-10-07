package integrations

import (
	"context"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/awswire"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/cloudformation"
)

// cfnACfgDeployment starts an owner deployment and waits for the deployment
// job to complete. AWS AppConfig rolls back failed deployments; a rolled-back
// deployment fails the stack operation.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appconfig-deployment.html
type cfnACfgDeployment struct{ commands StepFunctionsCommands }

var cfnACfgDeploymentIdentity = []string{"ApplicationId", "EnvironmentId", "ConfigurationProfileId", "DeploymentStrategyId", "ConfigurationVersion", "Description", "KmsKeyIdentifier", "DynamicExtensionParameters", "Tags"}

func (h cfnACfgDeployment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnACfgDeploymentIdentity...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ApplicationId", "EnvironmentId", "ConfigurationProfileId", "DeploymentStrategyId", "ConfigurationVersion"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ApplicationId", "EnvironmentId", "ConfigurationProfileId", "DeploymentStrategyId", "ConfigurationVersion", "Description", "KmsKeyIdentifier"); err != nil {
		return err
	}
	if _, err := cfnACfgDynamicParameters(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}

// Every Deployment property, including Tags, is create-only.
func (h cfnACfgDeployment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, cfnACfgDeploymentIdentity...), h.Validate(b)
}

func cfnACfgDynamicParameters(p cloudformation.Properties) (map[string]string, error) {
	out := map[string]string{}
	v, ok := p["DynamicExtensionParameters"]
	if !ok {
		return out, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("DynamicExtensionParameters must be a list")
	}
	for _, item := range list {
		param, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("DynamicExtensionParameters entries must be objects")
		}
		if err := cfnComputeProperties(param, "ExtensionReference", "ParameterName", "ParameterValue"); err != nil {
			return nil, err
		}
		if err := cfnComputeStrings(param, "ExtensionReference", "ParameterName", "ParameterValue"); err != nil {
			return nil, err
		}
		name := cfnComputeString(param, "ParameterName")
		if name == "" {
			return nil, fmt.Errorf("DynamicExtensionParameters entries require ParameterName")
		}
		if _, duplicate := out[name]; duplicate {
			return nil, fmt.Errorf("duplicate dynamic extension parameter %s", name)
		}
		out[name] = cfnComputeString(param, "ParameterValue")
	}
	return out, nil
}

func cfnACfgDeploymentIdentityOf(id string) (string, string, int64, error) {
	parts, err := cfnAppParts(id, 3)
	if err != nil {
		return "", "", 0, err
	}
	n, err := strconv.ParseInt(parts[2], 10, 32)
	if err != nil || n < 1 {
		return "", "", 0, fmt.Errorf("invalid deployment identifier %q", id)
	}
	return parts[0], parts[1], n, nil
}

func cfnACfgDeploymentARN(r cloudformation.ResourceRequest, app, env string, n int64) string {
	return cfnACfgARN(r, "application/"+app+"/environment/"+env+"/deployment/"+strconv.FormatInt(n, 10))
}

func cfnACfgDeploymentResult(app, env string, d *api.Deployment) cloudformation.ResourceResult {
	n := strconv.FormatInt(cfnACfgInt(d.DeploymentNumber), 10)
	id := app + "|" + env + "|" + n
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"DeploymentNumber": n, "State": cfnComputeValue(d.State)}}
}

func (h cfnACfgDeployment) get(ctx context.Context, app, env string, n int64) (*api.Deployment, error) {
	return cfnComputeCall[api.GetDeploymentOutput](ctx, h.commands, "appconfig", "GetDeployment", map[string]any{"ApplicationId": app, "EnvironmentId": env, "DeploymentNumber": n})
}

func (h cfnACfgDeployment) deployments(ctx context.Context, app, env string) ([]api.DeploymentSummary, error) {
	return cfnACfgPages(ctx, h.commands, "ListDeployments", map[string]any{"ApplicationId": app, "EnvironmentId": env}, func(o *api.ListDeploymentsOutput) ([]api.DeploymentSummary, *api.NextToken) {
		return o.Items, o.NextToken
	})
}

// owned reads the deployment and verifies its incarnation claim.
func (h cfnACfgDeployment) owned(ctx context.Context, r cloudformation.ResourceRequest) (string, string, *api.Deployment, error) {
	app, env, n, err := cfnACfgDeploymentIdentityOf(r.PhysicalID)
	if err != nil {
		return "", "", nil, err
	}
	d, err := h.get(ctx, app, env, n)
	if err != nil {
		return app, env, nil, err
	}
	if _, err := cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgDeploymentARN(r, app, env, n)); err != nil {
		return app, env, nil, err
	}
	return app, env, d, nil
}

func (h cfnACfgDeployment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "deployment", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	app, env := cfnComputeString(r.Properties, "ApplicationId"), cfnComputeString(r.Properties, "EnvironmentId")
	rows, err := h.deployments(ctx, app, env)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgDeploymentARN(r, app, env, cfnACfgInt(row.DeploymentNumber))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		d, err := h.get(ctx, app, env, cfnACfgInt(rows[i].DeploymentNumber))
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgDeploymentResult(app, env, d), nil
	}
	in := cfnComputeCopy(r.Properties, "ApplicationId", "EnvironmentId", "ConfigurationProfileId", "DeploymentStrategyId", "ConfigurationVersion", "Description", "KmsKeyIdentifier")
	params, _ := cfnACfgDynamicParameters(r.Properties)
	if len(params) > 0 {
		in["DynamicExtensionParameters"] = params
	}
	in["Tags"] = cfnAppCustomerTags(r)
	d, err := cfnComputeCall[api.StartDeploymentOutput](ctx, h.commands, "appconfig", "StartDeployment", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgDeploymentResult(app, env, d), nil

}

func (h cfnACfgDeployment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "deployment", false)
	if changed, err := h.Replacement(r.Previous, r.Properties); err != nil || changed {
		if err == nil {
			err = fmt.Errorf("AppConfig deployments are immutable")
		}
		return cloudformation.ResourceResult{}, err
	}
	return h.Result(ctx, r)

}

func (h cfnACfgDeployment) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "deployment", false)
	_, _, d, err := h.owned(ctx, r)
	if err != nil {
		return false, err
	}
	switch state := cfnComputeValue(d.State); state {
	case "COMPLETE":
		return true, nil
	case "ROLLED_BACK", "REVERTED":
		return false, fmt.Errorf("AppConfig deployment %s ended in %s", r.PhysicalID, state)
	default:
		return false, nil
	}

}

func (h cfnACfgDeployment) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	app, env, d, err := h.owned(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgDeploymentResult(app, env, d), nil
}

// Delete stops an in-progress deployment; completed deployments remain in the
// environment's deployment history, which AppConfig never deletes.
func (h cfnACfgDeployment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "deployment", false)
	app, env, d, err := h.owned(ctx, r)
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	switch cfnComputeValue(d.State) {
	case "VALIDATING", "DEPLOYING", "BAKING":
		return cfnComputeRun(ctx, h.commands, "appconfig", "StopDeployment", map[string]any{"ApplicationId": app, "EnvironmentId": env, "DeploymentNumber": cfnACfgInt(d.DeploymentNumber)})
	}
	return nil

}

func (h cfnACfgDeployment) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "deployment", false)
	app, env, n, err := cfnACfgDeploymentIdentityOf(r.PhysicalID)
	if err != nil {
		return false, err
	}
	d, err := h.get(ctx, app, env, n)
	if cfnACfgMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	switch cfnComputeValue(d.State) {
	case "VALIDATING", "DEPLOYING", "BAKING", "ROLLING_BACK":
		return false, nil
	}
	return true, nil

}

func (h cfnACfgDeployment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	app, env, n, err := cfnACfgDeploymentIdentityOf(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	d, err := h.get(ctx, app, env, n)
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgDeploymentARN(r, app, env, n))
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"ApplicationId": app, "EnvironmentId": env, "DeploymentNumber": strconv.FormatInt(n, 10), "State": cfnComputeValue(d.State), "ConfigurationProfileId": cfnComputeValue(d.ConfigurationProfileId), "DeploymentStrategyId": cfnComputeValue(d.DeploymentStrategyId), "ConfigurationVersion": cfnComputeValue(d.ConfigurationVersion), "Tags": cfnAppUserTags(tags)}
	if d.Description != nil {
		p["Description"] = cfnComputeValue(d.Description)
	}
	if d.KmsKeyIdentifier != nil {
		p["KmsKeyIdentifier"] = cfnComputeValue(d.KmsKeyIdentifier)
	}
	return p, nil
}

func (h cfnACfgDeployment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apps, err := (cfnACfgApplication(h)).applications(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, app := range apps {
		appID := cfnComputeValue(app.Id)
		envs, err := (cfnACfgEnvironment(h)).environments(ctx, appID)
		if err != nil {
			return nil, err
		}
		for _, env := range envs {
			envID := cfnComputeValue(env.Id)
			rows, err := h.deployments(ctx, appID, envID)
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				n := strconv.FormatInt(cfnACfgInt(row.DeploymentNumber), 10)
				out = append(out, cloudformation.ResourceDescription{Identifier: appID + "|" + envID + "|" + n, Properties: cloudformation.Properties{"ApplicationId": appID, "EnvironmentId": envID, "DeploymentNumber": n, "State": cfnComputeValue(row.State)}})
			}
		}
	}
	return out, nil
}

// cfnACfgExtension owns one extension version. Creating a named extension that
// already exists requires LatestVersionNumber and creates a new owned version.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appconfig-extension.html
type cfnACfgExtension struct{ commands StepFunctionsCommands }

func (h cfnACfgExtension) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Actions", "Parameters", "LatestVersionNumber", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name", "Actions"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description"); err != nil {
		return err
	}
	if _, err := cfnACfgExtensionActions(p); err != nil {
		return err
	}
	if _, err := cfnACfgExtensionParameters(p); err != nil {
		return err
	}
	if _, _, err := cfnAppInteger(p, "LatestVersionNumber"); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgExtension) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}

func cfnACfgExtensionActions(p cloudformation.Properties) (map[string]any, error) {
	points, ok := cfnComputeObject(p["Actions"])
	if !ok || len(points) == 0 {
		return nil, fmt.Errorf("actions must be a nonempty map of action points")
	}
	for point, v := range points {
		list, ok := v.([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("actions.%s must be a nonempty list", point)
		}
		for _, item := range list {
			action, ok := cfnComputeObject(item)
			if !ok {
				return nil, fmt.Errorf("actions.%s entries must be objects", point)
			}
			if err := cfnComputeProperties(action, "Name", "Description", "Uri", "RoleArn"); err != nil {
				return nil, err
			}
			if err := cfnComputeRequired(action, "Name", "Uri"); err != nil {
				return nil, err
			}
			if err := cfnComputeStrings(action, "Name", "Description", "Uri", "RoleArn"); err != nil {
				return nil, err
			}
		}
	}
	return points, nil
}

// cfnACfgExtensionParameters coerces template booleans for the owner's decoder.
func cfnACfgExtensionParameters(p cloudformation.Properties) (map[string]any, error) {
	out := map[string]any{}
	v, ok := p["Parameters"]
	if !ok {
		return out, nil
	}
	params, ok := cfnComputeObject(v)
	if !ok {
		return nil, fmt.Errorf("parameters must be a map")
	}
	for name, raw := range params {
		param, ok := cfnComputeObject(raw)
		if !ok {
			return nil, fmt.Errorf("parameters.%s must be an object", name)
		}
		if err := cfnComputeProperties(param, "Description", "Dynamic", "Required"); err != nil {
			return nil, err
		}
		if err := cfnComputeRequired(param, "Required"); err != nil {
			return nil, fmt.Errorf("parameters.%s: %w", name, err)
		}
		item := cfnComputeCopy(param, "Description")
		for _, key := range []string{"Dynamic", "Required"} {
			if b, present, err := cfnAppBoolean(param, key); err != nil {
				return nil, fmt.Errorf("parameters.%s: %w", name, err)
			} else if present {
				item[key] = b
			}
		}
		out[name] = item
	}
	return out, nil
}

func cfnACfgExtensionResult(e *api.Extension) cloudformation.ResourceResult {
	id := cfnComputeValue(e.Id)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "Arn": cfnComputeValue(e.Arn), "VersionNumber": cfnACfgInt(e.VersionNumber)}}
}

func (h cfnACfgExtension) get(ctx context.Context, id string, version int64) (*api.Extension, error) {
	in := map[string]any{"ExtensionIdentifier": id}
	if version > 0 {
		in["VersionNumber"] = version
	}
	return cfnComputeCall[api.GetExtensionOutput](ctx, h.commands, "appconfig", "GetExtension", in)
}

func (h cfnACfgExtension) extensions(ctx context.Context, name string) ([]api.ExtensionSummary, error) {
	in := map[string]any{}
	if name != "" {
		in["Name"] = name
	}
	return cfnACfgPages(ctx, h.commands, "ListExtensions", in, func(o *api.ListExtensionsOutput) ([]api.ExtensionSummary, *api.NextToken) {
		return o.Items, o.NextToken
	})
}

// version resolves the extension version owned by this request, newest first.
// Cloud Control acts on the latest version.
func (h cfnACfgExtension) version(ctx context.Context, r cloudformation.ResourceRequest) (*api.Extension, map[string]string, error) {
	latest, err := h.get(appconfig.WithoutCloudFormationOwnership(ctx), r.PhysicalID, 0)
	if err != nil {
		return nil, nil, err
	}
	for n := cfnACfgInt(latest.VersionNumber); n >= 1; n-- {
		e := latest
		if n != cfnACfgInt(latest.VersionNumber) {
			if e, err = h.get(appconfig.WithoutCloudFormationOwnership(ctx), r.PhysicalID, n); cfnACfgMissing(err) {
				continue
			} else if err != nil {
				return nil, nil, err
			}
		}
		tags, err := cfnACfgTagsOf(ctx, h.commands, cfnComputeValue(e.Arn))
		if appconfig.IsCloudFormationOwnershipMismatch(err) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		return e, tags, nil
	}
	// Claims live on the owned version itself; without it, that version is gone.
	return nil, nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Extension " + r.PhysicalID + " has no version owned by this CloudFormation resource incarnation.", StatusCode: 404}
}

func (h cfnACfgExtension) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "extension", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "Name")
	rows, err := h.extensions(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	for _, row := range rows {
		if cfnComputeValue(row.Name) != name {
			continue
		}
		candidate := r
		candidate.PhysicalID = cfnComputeValue(row.Id)
		e, _, err := h.version(ctx, candidate)
		if cfnACfgMissing(err) {
			if cfnACfgRecoveryMissing(ctx) != nil {
				continue
			}
			if _, ok := r.Properties["LatestVersionNumber"]; !ok {
				return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("extension %s already exists without this private incarnation claim", name))
			}
			continue
		}
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgExtensionResult(e), nil
	}
	if err := cfnACfgRecoveryMissing(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	actions, _ := cfnACfgExtensionActions(r.Properties)
	params, _ := cfnACfgExtensionParameters(r.Properties)
	in := cfnComputeCopy(r.Properties, "Name", "Description")
	in["Actions"], in["Tags"] = actions, cfnAppCustomerTags(r)
	if len(params) != 0 {
		in["Parameters"] = params
	}
	if n, ok, _ := cfnAppInteger(r.Properties, "LatestVersionNumber"); ok {
		in["LatestVersionNumber"] = n
	}
	e, err := cfnComputeCall[api.CreateExtensionOutput](ctx, h.commands, "appconfig", "CreateExtension", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgExtensionResult(e), nil

}

func (h cfnACfgExtension) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "extension", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	e, tags, err := h.version(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	actions, _ := cfnACfgExtensionActions(r.Properties)
	params, _ := cfnACfgExtensionParameters(r.Properties)
	in := map[string]any{"ExtensionIdentifier": r.PhysicalID, "VersionNumber": cfnACfgInt(e.VersionNumber), "Description": cfnComputeDefault(r.Properties, "Description", ""), "Actions": actions, "Parameters": params}
	// An omitted optional map must stay absent: Smithy rejects an explicit
	// empty ParameterMap. Retain that rejection when clearing existing entries.
	if len(params) == 0 && len(e.Parameters) == 0 {
		delete(in, "Parameters")
	}
	updated, err := cfnComputeCall[api.UpdateExtensionOutput](ctx, h.commands, "appconfig", "UpdateExtension", in)
	if err != nil {
		return cfnACfgExtensionResult(e), err
	}
	return cfnACfgExtensionResult(updated), cfnACfgSyncTags(ctx, h.commands, r, cfnComputeValue(e.Arn), tags)

}

func (h cfnACfgExtension) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "extension", false)
	e, _, err := h.version(ctx, r)
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteExtension", map[string]any{"ExtensionIdentifier": r.PhysicalID, "VersionNumber": cfnACfgInt(e.VersionNumber)})
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}

func cfnACfgExtensionProperties(e *api.Extension, tags map[string]string) cloudformation.Properties {
	actions := map[string]any{}
	for point, list := range e.Actions {
		items := make([]any, 0, len(list))
		for _, a := range list {
			item := map[string]any{"Name": cfnComputeValue(a.Name), "Uri": cfnComputeValue(a.Uri)}
			if a.Description != nil {
				item["Description"] = cfnComputeValue(a.Description)
			}
			if a.RoleArn != nil {
				item["RoleArn"] = cfnComputeValue(a.RoleArn)
			}
			items = append(items, item)
		}
		actions[string(point)] = items
	}
	params := map[string]any{}
	for name, v := range e.Parameters {
		item := map[string]any{"Required": v.Required != nil && bool(*v.Required), "Dynamic": v.Dynamic != nil && bool(*v.Dynamic)}
		if v.Description != nil {
			item["Description"] = cfnComputeValue(v.Description)
		}
		params[string(name)] = item
	}
	p := cloudformation.Properties{"Id": cfnComputeValue(e.Id), "Arn": cfnComputeValue(e.Arn), "Name": cfnComputeValue(e.Name), "VersionNumber": cfnACfgInt(e.VersionNumber), "Actions": actions, "Parameters": params}
	if e.Description != nil {
		p["Description"] = cfnComputeValue(e.Description)
	}
	if tags != nil {
		p["Tags"] = cfnAppUserTags(tags)
	}
	return p
}

func (h cfnACfgExtension) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	e, tags, err := h.version(ctx, r)
	if err != nil {
		return nil, err
	}
	return cfnACfgExtensionProperties(e, tags), nil
}

func (h cfnACfgExtension) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.extensions(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(rows))
	for _, row := range rows {
		id := cfnComputeValue(row.Id)
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "Arn": cfnComputeValue(row.Arn), "Name": cfnComputeValue(row.Name), "VersionNumber": cfnACfgInt(row.VersionNumber)}})
	}
	return out, nil
}

// cfnACfgAssociation binds an extension version to an application,
// environment or configuration profile through the owner.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appconfig-extensionassociation.html
type cfnACfgAssociation struct{ commands StepFunctionsCommands }

func (h cfnACfgAssociation) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ExtensionIdentifier", "ResourceIdentifier", "ExtensionVersionNumber", "Parameters", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ExtensionIdentifier", "ResourceIdentifier"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ExtensionIdentifier", "ResourceIdentifier"); err != nil {
		return err
	}
	if _, _, err := cfnAppInteger(p, "ExtensionVersionNumber"); err != nil {
		return err
	}
	if _, err := cfnACfgAssociationParameters(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ExtensionIdentifier", "ResourceIdentifier", "ExtensionVersionNumber"), h.Validate(b)
}

func cfnACfgAssociationParameters(p cloudformation.Properties) (map[string]any, error) {
	v, ok := p["Parameters"]
	if !ok {
		return map[string]any{}, nil
	}
	params, ok := cfnComputeObject(v)
	if !ok {
		return nil, fmt.Errorf("parameters must be a string map")
	}
	for name, value := range params {
		if _, ok := value.(string); !ok {
			return nil, fmt.Errorf("parameters.%s must be a string", name)
		}
	}
	return params, nil
}

func cfnACfgAssociationResult(a *api.ExtensionAssociation) cloudformation.ResourceResult {
	id := cfnComputeValue(a.Id)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "Arn": cfnComputeValue(a.Arn), "ExtensionArn": cfnComputeValue(a.ExtensionArn), "ResourceArn": cfnComputeValue(a.ResourceArn)}}
}

func (h cfnACfgAssociation) get(ctx context.Context, id string) (*api.ExtensionAssociation, error) {
	return cfnComputeCall[api.GetExtensionAssociationOutput](ctx, h.commands, "appconfig", "GetExtensionAssociation", map[string]any{"ExtensionAssociationId": id})
}

func (h cfnACfgAssociation) associations(ctx context.Context) ([]api.ExtensionAssociationSummary, error) {
	return cfnACfgPages(ctx, h.commands, "ListExtensionAssociations", map[string]any{}, func(o *api.ListExtensionAssociationsOutput) ([]api.ExtensionAssociationSummary, *api.NextToken) {
		return o.Items, o.NextToken
	})
}

func (h cfnACfgAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "extensionassociation", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rows, err := h.associations(ctx)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgARN(r, "extensionassociation/"+cfnComputeValue(row.Id))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		a, err := h.get(ctx, cfnComputeValue(rows[i].Id))
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgAssociationResult(a), nil
	}
	params, _ := cfnACfgAssociationParameters(r.Properties)
	in := cfnComputeCopy(r.Properties, "ExtensionIdentifier", "ResourceIdentifier")
	in["Parameters"], in["Tags"] = params, cfnAppCustomerTags(r)
	if n, ok, _ := cfnAppInteger(r.Properties, "ExtensionVersionNumber"); ok {
		in["ExtensionVersionNumber"] = n
	}
	a, err := cfnComputeCall[api.CreateExtensionAssociationOutput](ctx, h.commands, "appconfig", "CreateExtensionAssociation", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgAssociationResult(a), nil

}

func (h cfnACfgAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "extensionassociation", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnACfgARN(r, "extensionassociation/"+r.PhysicalID)
	tags, err := cfnACfgOwnedTags(ctx, h.commands, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	params, _ := cfnACfgAssociationParameters(r.Properties)
	a, err := cfnComputeCall[api.UpdateExtensionAssociationOutput](ctx, h.commands, "appconfig", "UpdateExtensionAssociation", map[string]any{"ExtensionAssociationId": r.PhysicalID, "Parameters": params})
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}, err
	}
	return cfnACfgAssociationResult(a), cfnACfgSyncTags(ctx, h.commands, r, arn, tags)

}

func (h cfnACfgAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "extensionassociation", false)
	_, err := cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgARN(r, "extensionassociation/"+r.PhysicalID))
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteExtensionAssociation", map[string]any{"ExtensionAssociationId": r.PhysicalID})
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}

func (h cfnACfgAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	a, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgARN(r, "extensionassociation/"+r.PhysicalID))
	if err != nil {
		return nil, err
	}
	params := map[string]any{}
	for k, v := range a.Parameters {
		params[string(k)] = string(v)
	}
	return cloudformation.Properties{"Id": cfnComputeValue(a.Id), "Arn": cfnComputeValue(a.Arn), "ExtensionArn": cfnComputeValue(a.ExtensionArn), "ResourceArn": cfnComputeValue(a.ResourceArn), "ExtensionVersionNumber": cfnACfgInt(a.ExtensionVersionNumber), "Parameters": params, "Tags": cfnAppUserTags(tags)}, nil
}

func (h cfnACfgAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.associations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(rows))
	for _, row := range rows {
		id := cfnComputeValue(row.Id)
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "ExtensionArn": cfnComputeValue(row.ExtensionArn), "ResourceArn": cfnComputeValue(row.ResourceArn)}})
	}
	return out, nil
}
