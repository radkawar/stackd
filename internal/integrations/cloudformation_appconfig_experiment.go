package integrations

import (
	"context"
	"fmt"
	"strconv"
	"time"

	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/services/cloudformation"
)

// cfnACfgExperiment manages feature-flag experiment definitions.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appconfig-experimentdefinition.html
type cfnACfgExperiment struct{ commands StepFunctionsCommands }

var cfnACfgExperimentProperties = []string{"ApplicationIdentifier", "Name", "ConfigurationProfileIdentifier", "EnvironmentIdentifier", "FlagKey", "Treatments", "Control", "AudienceRule", "AudienceDescription", "Hypothesis", "LaunchCriteria", "Tags"}

func (h cfnACfgExperiment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnACfgExperimentProperties...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ApplicationIdentifier", "Name", "ConfigurationProfileIdentifier", "EnvironmentIdentifier", "FlagKey", "Treatments", "Control", "AudienceRule"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ApplicationIdentifier", "Name", "ConfigurationProfileIdentifier", "EnvironmentIdentifier", "FlagKey", "AudienceRule", "AudienceDescription", "Hypothesis", "LaunchCriteria"); err != nil {
		return err
	}
	if _, _, err := cfnACfgTreatments(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgExperiment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApplicationIdentifier", "Name", "ConfigurationProfileIdentifier", "EnvironmentIdentifier", "FlagKey"), h.Validate(b)
}

// cfnACfgTreatment maps the template treatment to the owner's TreatmentInput;
// treatment keys are assigned by the owner.
func cfnACfgTreatment(v any, path string) (map[string]any, error) {
	t, ok := cfnComputeObject(v)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	if err := cfnComputeProperties(t, "Description", "AttributeValues", "Enabled", "Weight"); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfnComputeRequired(t, "Weight", "Enabled"); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfnComputeStrings(t, "Description"); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	enabled, _, err := cfnAppBoolean(t, "Enabled")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	weight, _, err := cfnAppFloat(t, "Weight")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	flag := map[string]any{"Enabled": enabled}
	if values, ok := t["AttributeValues"]; ok {
		attributes, ok := cfnComputeObject(values)
		if !ok {
			return nil, fmt.Errorf("%s.AttributeValues must be a map", path)
		}
		for name, raw := range attributes {
			value, ok := cfnComputeObject(raw)
			if !ok {
				return nil, fmt.Errorf("%s.AttributeValues.%s must be an object", path, name)
			}
			if err := cfnComputeProperties(value, "StringValue", "NumberValue", "BooleanValue", "StringArray", "NumberArray"); err != nil {
				return nil, fmt.Errorf("%s.AttributeValues.%s: %w", path, name, err)
			}
		}
		flag["AttributeValues"] = attributes
	}
	out := map[string]any{"Weight": weight, "FlagValue": flag}
	if d, ok := t["Description"]; ok {
		out["Description"] = d
	}
	return out, nil
}

func cfnACfgTreatments(p cloudformation.Properties) (map[string]any, []any, error) {
	control, err := cfnACfgTreatment(p["Control"], "Control")
	if err != nil {
		return nil, nil, err
	}
	list, ok := p["Treatments"].([]any)
	if !ok || len(list) == 0 || len(list) > 5 {
		return nil, nil, fmt.Errorf("treatments must contain between 1 and 5 treatments")
	}
	treatments := make([]any, 0, len(list))
	for i, item := range list {
		t, err := cfnACfgTreatment(item, "Treatments["+strconv.Itoa(i)+"]")
		if err != nil {
			return nil, nil, err
		}
		treatments = append(treatments, t)
	}
	return control, treatments, nil
}

func cfnACfgTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func cfnACfgExperimentARN(r cloudformation.ResourceRequest, app, id string) string {
	return cfnACfgARN(r, "application/"+app+"/experimentdefinition/"+id)
}

func cfnACfgExperimentResult(d *api.ExperimentDefinition) cloudformation.ResourceResult {
	app, id := cfnComputeValue(d.ApplicationId), cfnComputeValue(d.Id)
	physical := app + "|" + id
	attributes := map[string]any{"ApplicationId": app, "Id": id, "Status": cfnComputeValue(d.Status), "CreatedAt": cfnACfgTime(d.CreatedAt), "UpdatedAt": cfnACfgTime(d.UpdatedAt)}
	if d.Control != nil {
		attributes["Control.Key"] = cfnComputeValue(d.Control.Key)
	}
	return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical, Attributes: attributes}
}

func (h cfnACfgExperiment) get(ctx context.Context, app, id string) (*api.ExperimentDefinition, error) {
	return cfnComputeCall[api.GetExperimentDefinitionOutput](ctx, h.commands, "appconfig", "GetExperimentDefinition", map[string]any{"ApplicationIdentifier": app, "ExperimentDefinitionIdentifier": id})
}

func (h cfnACfgExperiment) definitions(ctx context.Context, app string) ([]api.ExperimentDefinitionSummary, error) {
	return cfnACfgPages(ctx, h.commands, "ListExperimentDefinitions", map[string]any{"ApplicationIdentifier": app}, func(o *api.ListExperimentDefinitionsOutput) ([]api.ExperimentDefinitionSummary, *api.NextToken) {
		return o.Items, o.NextToken
	})
}

func (h cfnACfgExperiment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentdefinition", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rows, err := h.definitions(ctx, cfnComputeString(r.Properties, "ApplicationIdentifier"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgExperimentARN(r, cfnComputeValue(row.ApplicationId), cfnComputeValue(row.Id))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		d, err := h.get(ctx, cfnComputeValue(rows[i].ApplicationId), cfnComputeValue(rows[i].Id))
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgExperimentResult(d), nil
	}
	control, treatments, _ := cfnACfgTreatments(r.Properties)
	in := cfnComputeCopy(r.Properties, "ApplicationIdentifier", "Name", "ConfigurationProfileIdentifier", "EnvironmentIdentifier", "FlagKey", "AudienceRule", "AudienceDescription", "Hypothesis", "LaunchCriteria")
	in["Control"], in["Treatments"], in["Tags"] = control, treatments, cfnAppCustomerTags(r)
	d, err := cfnComputeCall[api.CreateExperimentDefinitionOutput](ctx, h.commands, "appconfig", "CreateExperimentDefinition", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgExperimentResult(d), nil

}

func (h cfnACfgExperiment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentdefinition", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnACfgExperimentARN(r, parts[0], parts[1])
	tags, err := cfnACfgOwnedTags(ctx, h.commands, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	control, treatments, _ := cfnACfgTreatments(r.Properties)
	in := map[string]any{"ApplicationIdentifier": parts[0], "ExperimentDefinitionIdentifier": parts[1], "AudienceRule": r.Properties["AudienceRule"], "Control": control, "Treatments": treatments}
	for _, key := range []string{"AudienceDescription", "Hypothesis", "LaunchCriteria"} {
		in[key] = cfnComputeDefault(r.Properties, key, "")
	}
	d, err := cfnComputeCall[api.UpdateExperimentDefinitionOutput](ctx, h.commands, "appconfig", "UpdateExperimentDefinition", in)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}, err
	}
	return cfnACfgExperimentResult(d), cfnACfgSyncTags(ctx, h.commands, r, arn, tags)

}

// Delete destroys the definition so the owner no longer reports it; archiving
// would leave a readable resource behind a deleted stack resource.
func (h cfnACfgExperiment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentdefinition", false)
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return err
	}
	_, err = cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgExperimentARN(r, parts[0], parts[1]))
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteExperimentDefinition", map[string]any{"ApplicationIdentifier": parts[0], "ExperimentDefinitionIdentifier": parts[1], "DeleteType": "DESTROY"})
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}

func cfnACfgTreatmentProperties(t *api.Treatment) map[string]any {
	out := map[string]any{"Key": cfnComputeValue(t.Key), "Weight": cfnACfgFloat(t.Weight)}
	if t.Description != nil {
		out["Description"] = cfnComputeValue(t.Description)
	}
	if t.FlagValue != nil {
		out["Enabled"] = t.FlagValue.Enabled != nil && bool(*t.FlagValue.Enabled)
		if len(t.FlagValue.AttributeValues) > 0 {
			values := map[string]any{}
			for name, v := range t.FlagValue.AttributeValues {
				item := map[string]any{}
				if v.StringValue != nil {
					item["StringValue"] = cfnComputeValue(v.StringValue)
				}
				if v.NumberValue != nil {
					item["NumberValue"] = float64(*v.NumberValue)
				}
				if v.BooleanValue != nil {
					item["BooleanValue"] = bool(*v.BooleanValue)
				}
				if v.StringArray != nil {
					list := make([]any, 0, len(v.StringArray))
					for _, s := range v.StringArray {
						list = append(list, string(s))
					}
					item["StringArray"] = list
				}
				if v.NumberArray != nil {
					list := make([]any, 0, len(v.NumberArray))
					for _, n := range v.NumberArray {
						list = append(list, float64(n))
					}
					item["NumberArray"] = list
				}
				values[string(name)] = item
			}
			out["AttributeValues"] = values
		}
	}
	return out
}

func (h cfnACfgExperiment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return nil, err
	}
	d, err := h.get(ctx, parts[0], parts[1])
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgExperimentARN(r, parts[0], parts[1]))
	if err != nil {
		return nil, err
	}
	treatments := make([]any, 0, len(d.Treatments))
	for i := range d.Treatments {
		treatments = append(treatments, cfnACfgTreatmentProperties(&d.Treatments[i]))
	}
	p := cloudformation.Properties{"ApplicationId": parts[0], "Id": parts[1], "ApplicationIdentifier": parts[0], "Name": cfnComputeValue(d.Name), "ConfigurationProfileIdentifier": cfnComputeValue(d.ConfigurationProfileId), "EnvironmentIdentifier": cfnComputeValue(d.EnvironmentId), "FlagKey": cfnComputeValue(d.FlagKey), "AudienceRule": cfnComputeValue(d.AudienceRule), "Status": cfnComputeValue(d.Status), "CreatedAt": cfnACfgTime(d.CreatedAt), "UpdatedAt": cfnACfgTime(d.UpdatedAt), "Treatments": treatments, "Tags": cfnAppUserTags(tags)}
	if d.Control != nil {
		p["Control"] = cfnACfgTreatmentProperties(d.Control)
	}
	for key, value := range map[string]*api.Description{"AudienceDescription": d.AudienceDescription, "Hypothesis": d.Hypothesis, "LaunchCriteria": d.LaunchCriteria} {
		if value != nil {
			p[key] = string(*value)
		}
	}
	return p, nil
}

func (h cfnACfgExperiment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apps, err := (cfnACfgApplication(h)).applications(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, app := range apps {
		rows, err := h.definitions(ctx, cfnComputeValue(app.Id))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			appID, id := cfnComputeValue(row.ApplicationId), cfnComputeValue(row.Id)
			out = append(out, cloudformation.ResourceDescription{Identifier: appID + "|" + id, Properties: cloudformation.Properties{"ApplicationId": appID, "Id": id, "Name": cfnComputeValue(row.Name), "Status": cfnComputeValue(row.Status)}})
		}
	}
	return out, nil
}

// cfnACfgExperimentRun starts, adjusts and stops experiment runs. Each change
// publishes a managed AppConfig deployment, which stabilization observes.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appconfig-experimentrun.html
type cfnACfgExperimentRun struct{ commands StepFunctionsCommands }

func (h cfnACfgExperimentRun) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ApplicationIdentifier", "ExperimentDefinitionIdentifier", "ExposurePercentage", "Description", "TreatmentOverrides", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ApplicationIdentifier", "ExperimentDefinitionIdentifier", "ExposurePercentage"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ApplicationIdentifier", "ExperimentDefinitionIdentifier", "Description"); err != nil {
		return err
	}
	if n, _, err := cfnAppFloat(p, "ExposurePercentage"); err != nil || n < 0 || n > 100 {
		return fmt.Errorf("ExposurePercentage must be a number between 0 and 100")
	}
	if _, err := cfnACfgOverrides(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgExperimentRun) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApplicationIdentifier", "ExperimentDefinitionIdentifier"), h.Validate(b)
}

func cfnACfgOverrides(p cloudformation.Properties) (map[string]any, error) {
	v, ok := p["TreatmentOverrides"]
	if !ok {
		return nil, nil
	}
	overrides, ok := cfnComputeObject(v)
	if !ok {
		return nil, fmt.Errorf("TreatmentOverrides must be an object")
	}
	if err := cfnComputeProperties(overrides, "Inline"); err != nil {
		return nil, err
	}
	if inline, ok := overrides["Inline"]; ok {
		entries, ok := cfnComputeObject(inline)
		if !ok {
			return nil, fmt.Errorf("TreatmentOverrides.Inline must be a string map")
		}
		for entity, key := range entries {
			if _, ok := key.(string); !ok {
				return nil, fmt.Errorf("TreatmentOverrides.Inline.%s must be a treatment key", entity)
			}
		}
	}
	return overrides, nil
}

func cfnACfgRunIdentity(id string) (string, string, int64, error) {
	parts, err := cfnAppParts(id, 3)
	if err != nil {
		return "", "", 0, err
	}
	n, err := strconv.ParseInt(parts[2], 10, 32)
	if err != nil || n < 1 {
		return "", "", 0, fmt.Errorf("invalid experiment run identifier %q", id)
	}
	return parts[0], parts[1], n, nil
}

func cfnACfgRunARN(r cloudformation.ResourceRequest, app, definition string, n int64) string {
	return cfnACfgExperimentARN(r, app, definition) + "/experimentrun/" + strconv.FormatInt(n, 10)
}

func cfnACfgRunResult(v *api.ExperimentRun) cloudformation.ResourceResult {
	app, definition, run := cfnComputeValue(v.ApplicationId), cfnComputeValue(v.ExperimentDefinitionId), strconv.FormatInt(cfnACfgInt(v.Run), 10)
	physical := app + "|" + definition + "|" + run
	return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical, Attributes: map[string]any{"ApplicationId": app, "ExperimentDefinitionId": definition, "Run": run, "Status": cfnComputeValue(v.Status), "StartedAt": cfnACfgTime(v.StartedAt), "UpdatedAt": cfnACfgTime(v.UpdatedAt)}}
}

func (h cfnACfgExperimentRun) get(ctx context.Context, app, definition string, n int64) (*api.ExperimentRun, error) {
	return cfnComputeCall[api.GetExperimentRunOutput](ctx, h.commands, "appconfig", "GetExperimentRun", map[string]any{"ApplicationIdentifier": app, "ExperimentDefinitionIdentifier": definition, "Run": n})
}

func (h cfnACfgExperimentRun) owned(ctx context.Context, r cloudformation.ResourceRequest) (*api.ExperimentRun, map[string]string, error) {
	app, definition, n, err := cfnACfgRunIdentity(r.PhysicalID)
	if err != nil {
		return nil, nil, err
	}
	v, err := h.get(ctx, app, definition, n)
	if err != nil {
		return nil, nil, err
	}
	tags, err := cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgRunARN(r, app, definition, n))
	return v, tags, err
}

func (h cfnACfgExperimentRun) runs(ctx context.Context, app, definition string) ([]api.ExperimentRunSummary, error) {
	return cfnACfgPages(ctx, h.commands, "ListExperimentRuns", map[string]any{"ApplicationIdentifier": app, "ExperimentDefinitionIdentifier": definition}, func(o *api.ListExperimentRunsOutput) ([]api.ExperimentRunSummary, *api.NextToken) {
		return o.Items, o.NextToken
	})
}

func (h cfnACfgExperimentRun) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentrun", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	d, err := (cfnACfgExperiment(h)).get(ctx, cfnComputeString(r.Properties, "ApplicationIdentifier"), cfnComputeString(r.Properties, "ExperimentDefinitionIdentifier"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	app, definition := cfnComputeValue(d.ApplicationId), cfnComputeValue(d.Id)
	rows, err := h.runs(ctx, app, definition)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgRunARN(r, app, definition, cfnACfgInt(row.Run))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		v, err := h.get(ctx, app, definition, cfnACfgInt(rows[i].Run))
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgRunResult(v), nil
	}
	in := map[string]any{"ApplicationIdentifier": app, "ExperimentDefinitionIdentifier": definition, "Tags": cfnAppCustomerTags(r)}
	if v, ok := r.Properties["Description"]; ok {
		in["Description"] = v
	}
	exposure, _, _ := cfnAppFloat(r.Properties, "ExposurePercentage")
	in["ExposurePercentage"] = exposure
	if overrides, _ := cfnACfgOverrides(r.Properties); overrides != nil {
		in["TreatmentOverrides"] = overrides
	}
	v, err := cfnComputeCall[api.StartExperimentRunOutput](ctx, h.commands, "appconfig", "StartExperimentRun", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgRunResult(v), nil

}

// Update issues one owner change per deployment attribute, as the owner
// accepts either an exposure or an override change per request.
func (h cfnACfgExperimentRun) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentrun", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, tags, err := h.owned(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	base := map[string]any{"ApplicationIdentifier": cfnComputeValue(v.ApplicationId), "ExperimentDefinitionIdentifier": cfnComputeValue(v.ExperimentDefinitionId), "Run": cfnACfgInt(v.Run)}
	var changes []map[string]any
	// The owner stores exposure as float32; compare at that precision.
	if exposure, _, _ := cfnAppFloat(r.Properties, "ExposurePercentage"); v.ExposurePercentage == nil || float32(*v.ExposurePercentage) != float32(exposure) {
		changes = append(changes, map[string]any{"ExposurePercentage": exposure})
	}
	if cfnComputeChanged(r.Previous, r.Properties, "TreatmentOverrides") {
		overrides, _ := cfnACfgOverrides(r.Properties)
		if overrides == nil {
			overrides = map[string]any{"Inline": map[string]any{}}
		}
		changes = append(changes, map[string]any{"TreatmentOverrides": overrides})
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Description") {
		if len(changes) == 0 {
			changes = append(changes, map[string]any{})
		}
		changes[0]["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	}
	result := cfnACfgRunResult(v)
	for _, change := range changes {
		for k, value := range base {
			change[k] = value
		}
		updated, err := cfnComputeCall[api.UpdateExperimentRunOutput](ctx, h.commands, "appconfig", "UpdateExperimentRun", change)
		if err != nil {
			return result, err
		}
		result = cfnACfgRunResult(updated)
	}
	app, definition, n, _ := cfnACfgRunIdentity(r.PhysicalID)
	return result, cfnACfgSyncTags(ctx, h.commands, r, cfnACfgRunARN(r, app, definition, n), tags)

}

// runDeployment is the newest managed deployment published for the run.
func (h cfnACfgExperimentRun) runDeployment(ctx context.Context, r cloudformation.ResourceRequest) (*api.Deployment, error) {
	app, definition, n, err := cfnACfgRunIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	d, err := (cfnACfgExperiment(h)).get(ctx, app, definition)
	if err != nil {
		return nil, err
	}
	env := cfnComputeValue(d.EnvironmentId)
	deployments := cfnACfgDeployment(h)
	rows, err := deployments.deployments(ctx, app, env)
	if err != nil {
		return nil, err
	}
	marker := "For " + cfnACfgRunARN(r, app, definition, n)
	var newest *api.Deployment
	for _, row := range rows {
		if cfnComputeValue(row.Type) != "MANAGED" || newest != nil && cfnACfgInt(row.DeploymentNumber) <= cfnACfgInt(newest.DeploymentNumber) {
			continue
		}
		v, err := deployments.get(ctx, app, env, cfnACfgInt(row.DeploymentNumber))
		if err != nil {
			return nil, err
		}
		if cfnComputeValue(v.Description) == marker {
			newest = v
		}
	}
	return newest, nil
}

func (h cfnACfgExperimentRun) deploymentSettled(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	d, err := h.runDeployment(ctx, r)
	if err != nil || d == nil {
		return d == nil && err == nil, err
	}
	switch state := cfnComputeValue(d.State); state {
	case "COMPLETE":
		return true, nil
	case "ROLLED_BACK", "REVERTED":
		return false, fmt.Errorf("experiment run deployment %d ended in %s", cfnACfgInt(d.DeploymentNumber), state)
	default:
		return false, nil
	}
}

func (h cfnACfgExperimentRun) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentrun", false)
	if _, _, err := h.owned(ctx, r); err != nil {
		return false, err
	}
	return h.deploymentSettled(ctx, r)

}

func (h cfnACfgExperimentRun) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, _, err := h.owned(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgRunResult(v), nil
}

// Delete stops a running experiment; completed runs remain in the
// definition's run history, which AppConfig keeps until the definition goes.
func (h cfnACfgExperimentRun) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentrun", false)
	v, _, err := h.owned(ctx, r)
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(v.Status) != "RUNNING" {
		return nil
	}
	return cfnComputeRun(ctx, h.commands, "appconfig", "StopExperimentRun", map[string]any{"ApplicationIdentifier": cfnComputeValue(v.ApplicationId), "ExperimentDefinitionIdentifier": cfnComputeValue(v.ExperimentDefinitionId), "Run": cfnACfgInt(v.Run)})

}

func (h cfnACfgExperimentRun) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "experimentrun", false)
	ready, err := h.deploymentSettled(ctx, r)
	if cfnACfgMissing(err) {
		return true, nil
	}
	return ready, err

}

func (h cfnACfgExperimentRun) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	app, definition, n, err := cfnACfgRunIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	v, err := h.get(ctx, app, definition, n)
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgRunARN(r, app, definition, n))
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"ApplicationId": app, "ApplicationIdentifier": app, "ExperimentDefinitionId": definition, "ExperimentDefinitionIdentifier": definition, "Run": strconv.FormatInt(n, 10), "Status": cfnComputeValue(v.Status), "StartedAt": cfnACfgTime(v.StartedAt), "UpdatedAt": cfnACfgTime(v.UpdatedAt), "ExposurePercentage": cfnACfgFloat(v.ExposurePercentage), "Tags": cfnAppUserTags(tags)}
	if v.Description != nil {
		p["Description"] = cfnComputeValue(v.Description)
	}
	if v.TreatmentOverrides != nil {
		inline := map[string]any{}
		for entity, key := range v.TreatmentOverrides.Inline {
			inline[string(entity)] = string(key)
		}
		p["TreatmentOverrides"] = map[string]any{"Inline": inline}
	}
	return p, nil
}

func (h cfnACfgExperimentRun) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	definitions, err := (cfnACfgExperiment(h)).List(ctx, r)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, d := range definitions {
		parts, err := cfnAppParts(d.Identifier, 2)
		if err != nil {
			return nil, err
		}
		rows, err := h.runs(ctx, parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			run := strconv.FormatInt(cfnACfgInt(row.Run), 10)
			out = append(out, cloudformation.ResourceDescription{Identifier: parts[0] + "|" + parts[1] + "|" + run, Properties: cloudformation.Properties{"ApplicationId": parts[0], "ExperimentDefinitionId": parts[1], "Run": run, "Status": cfnComputeValue(row.Status)}})
		}
	}
	return out, nil
}
