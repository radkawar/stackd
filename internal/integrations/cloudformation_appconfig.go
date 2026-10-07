package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/cloudformation"
)

// CloudFormationApplicationHandlers registers AppConfig, Resource Groups,
// Service Catalog AppRegistry and Secrets Manager resources. Every effect is an
// owner command under the caller's or stack role's authority; owner resources
// carry stack incarnation claims, and no resource state lives in this adapter.
func CloudFormationApplicationHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::AppConfig::Application":                               cfnACfgApplication{commands},
		"AWS::AppConfig::Environment":                               cfnACfgEnvironment{commands},
		"AWS::AppConfig::ConfigurationProfile":                      cfnACfgProfile{commands},
		"AWS::AppConfig::DeploymentStrategy":                        cfnACfgStrategy{commands},
		"AWS::AppConfig::HostedConfigurationVersion":                cfnACfgHosted{commands},
		"AWS::AppConfig::Deployment":                                cfnACfgDeployment{commands},
		"AWS::AppConfig::Extension":                                 cfnACfgExtension{commands},
		"AWS::AppConfig::ExtensionAssociation":                      cfnACfgAssociation{commands},
		"AWS::AppConfig::ExperimentDefinition":                      cfnACfgExperiment{commands},
		"AWS::AppConfig::ExperimentRun":                             cfnACfgExperimentRun{commands},
		"AWS::ResourceGroups::Group":                                cfnRGroup{commands},
		"AWS::ResourceGroups::TagSyncTask":                          cfnRGroupTagSync{commands},
		"AWS::ServiceCatalogAppRegistry::Application":               cfnAppRegApplication{commands},
		"AWS::ServiceCatalogAppRegistry::AttributeGroup":            cfnAppRegAttributeGroup{commands},
		"AWS::ServiceCatalogAppRegistry::AttributeGroupAssociation": cfnAppRegAttributeAssociation{commands},
		"AWS::ServiceCatalogAppRegistry::ResourceAssociation":       cfnAppRegResourceAssociation{commands},
		"AWS::SecretsManager::Secret":                               cfnSecret{commands},
		"AWS::SecretsManager::ResourcePolicy":                       cfnSecretPolicy{commands},
		"AWS::SecretsManager::RotationSchedule":                     cfnSecretRotation{commands},
		"AWS::SecretsManager::SecretTargetAttachment":               cfnSecretAttachment{commands},
	}
}

// cfnAppTagTarget reconciles customer tags while retaining native AWS-managed
// tags. All resource and edge authority lives in private native row fields.
func cfnAppTagTarget(current, owned map[string]string) map[string]string {
	desired := owned
	for key, value := range current {
		lower := strings.ToLower(key)
		if _, ok := desired[key]; !ok && strings.HasPrefix(lower, "aws:") {
			desired[key] = value
		}
	}
	return desired
}

// cfnAppTagSync applies customer configuration through the owner's tag API.
func cfnAppTagSync(ctx context.Context, current, owned map[string]string, tag func(context.Context, map[string]string) error, untag func(context.Context, []string) error) error {
	desired := cfnAppTagTarget(current, owned)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := untag(ctx, removed); err != nil {
			return err
		}
	}
	changed := map[string]string{}
	for key, value := range desired {
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			continue
		}
		if old, ok := current[key]; !ok || old != value {
			changed[key] = value
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return tag(ctx, changed)
}

// cfnAppUserTags projects customer tags, never AWS-managed tags.
func cfnAppUserTags(tags map[string]string) []any {
	out := []any{}
	for _, key := range cfnMessagingKeys(tags) {
		lower := strings.ToLower(key)
		if !strings.HasPrefix(lower, "aws:") {
			out = append(out, map[string]any{"Key": key, "Value": tags[key]})
		}
	}
	return out
}

func cfnAppNumber(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case json.Number:
		return n.Float64()
	case string:
		// Ref and Fn::GetAtt values are strings at the template boundary.
		return strconv.ParseFloat(strings.TrimSpace(n), 64)
	}
	return 0, fmt.Errorf("expected a number, got %T", v)
}

func cfnAppFloat(p map[string]any, key string) (float64, bool, error) {
	v, ok := p[key]
	if !ok {
		return 0, false, nil
	}
	n, err := cfnAppNumber(v)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, false, fmt.Errorf("%s must be a number", key)
	}
	return n, true, nil
}

func cfnAppInteger(p map[string]any, key string) (int64, bool, error) {
	n, ok, err := cfnAppFloat(p, key)
	if err != nil || !ok {
		return 0, ok, err
	}
	if n != math.Trunc(n) || n < math.MinInt32 || n > math.MaxInt32 {
		return 0, false, fmt.Errorf("%s must be an integer", key)
	}
	return int64(n), true, nil
}

func cfnAppBoolean(p map[string]any, key string) (bool, bool, error) {
	switch v := p[key].(type) {
	case nil:
		if _, ok := p[key]; ok {
			return false, false, fmt.Errorf("%s must be a boolean", key)
		}
		return false, false, nil
	case bool:
		return v, true, nil
	case string:
		if v == "true" || v == "false" {
			return v == "true", true, nil
		}
	}
	return false, false, fmt.Errorf("%s must be a boolean", key)
}

// cfnAppNumbers coerces template scalars before the owner's typed decoder.
func cfnAppNumbers(in map[string]any, p map[string]any, integers []string, floats []string) error {
	for _, key := range integers {
		if n, ok, err := cfnAppInteger(p, key); err != nil {
			return err
		} else if ok {
			in[key] = n
		}
	}
	for _, key := range floats {
		if n, ok, err := cfnAppFloat(p, key); err != nil {
			return err
		} else if ok {
			in[key] = n
		}
	}
	return nil
}

func cfnAppParts(id string, n int) ([]string, error) {
	parts := strings.Split(id, "|")
	if len(parts) != n || slices.Contains(parts, "") {
		return nil, fmt.Errorf("invalid resource identifier %q", id)
	}
	return parts, nil
}

// cfnAppTagged is the native customer-tag boundary. It carries no ownership.
type cfnAppTagged struct {
	list  func(context.Context) (map[string]string, error)
	tag   func(context.Context, map[string]string) error
	untag func(context.Context, []string) error
}

// AppConfig: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_AppConfig.html

func cfnACfgARN(r cloudformation.ResourceRequest, resource string) string {
	return "arn:" + r.Scope.Partition + ":appconfig:" + r.Scope.Region + ":" + r.Scope.Account + ":" + resource
}

func cfnACfgMissing(err error) bool {
	return cfnMessagingMissing(err, "ResourceNotFoundException")
}

func cfnACfgTagsOf(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "appconfig", "ListTagsForResource", map[string]any{"ResourceArn": arn})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.Tags))
	for k, v := range out.Tags {
		tags[string(k)] = string(v)
	}
	return tags, nil
}

func cfnACfgTagger(c StepFunctionsCommands, arn string) cfnAppTagged {
	return cfnAppTagged{
		list: func(ctx context.Context) (map[string]string, error) { return cfnACfgTagsOf(ctx, c, arn) },
		tag: func(ctx context.Context, tags map[string]string) error {
			return cfnComputeRun(ctx, c, "appconfig", "TagResource", map[string]any{"ResourceArn": arn, "Tags": tags})
		},
		untag: func(ctx context.Context, keys []string) error {
			return cfnComputeRun(ctx, c, "appconfig", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": keys})
		},
	}
}

func cfnACfgSyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	t := cfnACfgTagger(c, arn)
	return cfnAppTagSync(ctx, current, cfnAppCustomerTags(r), t.tag, t.untag)
}

// cfnACfgOwnedTags observes the native private claim; every subsequent owner
// mutation independently fences that same claim inside its transaction.
func cfnACfgOwnedTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) (map[string]string, error) {
	return cfnACfgTagsOf(ctx, c, arn)
}

// cfnACfgRecover uses authorized native private-claim observations, never tags.
func cfnACfgRecover(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arns []string) (int, error) {
	for i, arn := range arns {
		_, err := cfnACfgTagsOf(ctx, c, arn)
		if cfnACfgMissing(err) || appconfig.IsCloudFormationOwnershipMismatch(err) {
			continue
		}
		if err != nil {
			return -1, err
		}
		return i, nil
	}
	return -1, cfnACfgRecoveryMissing(ctx)
}

// cfnACfgPages drains an owner list operation.
func cfnACfgPages[O any, I any](ctx context.Context, c StepFunctionsCommands, operation string, in map[string]any, page func(*O) ([]I, *api.NextToken)) ([]I, error) {
	var rows []I
	for {
		out, err := cfnComputeCall[O](ctx, c, "appconfig", operation, in)
		if err != nil {
			return nil, err
		}
		items, next := page(out)
		rows = append(rows, items...)
		token := cfnComputeValue(next)
		if token == "" {
			return rows, nil
		}
		if token == in["NextToken"] {
			return nil, fmt.Errorf("AppConfig %s pagination did not advance", operation)
		}
		in["NextToken"] = token
	}
}

func cfnACfgTagProperties(p cloudformation.Properties) error {
	_, err := cfnComputeTags(p)
	return err
}

func cfnACfgInt[T ~int32](p *T) int64 {
	if p == nil {
		return 0
	}
	return int64(*p)
}

func cfnACfgFloat[T ~float32 | ~float64](p *T) float64 {
	if p == nil {
		return 0
	}
	return float64(*p)
}

func cfnACfgDeletionCheck(p cloudformation.Properties) error {
	switch v := p["DeletionProtectionCheck"]; v {
	case nil, "ACCOUNT_DEFAULT", "APPLY", "BYPASS":
		return nil
	default:
		return fmt.Errorf("DeletionProtectionCheck must be ACCOUNT_DEFAULT, APPLY or BYPASS")
	}
}

type cfnACfgApplication struct{ commands StepFunctionsCommands }

func (h cfnACfgApplication) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description"); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgApplication) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func cfnACfgApplicationResult(id string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"ApplicationId": id}}
}
func (h cfnACfgApplication) applications(ctx context.Context) ([]api.Application, error) {
	return cfnACfgPages(ctx, h.commands, "ListApplications", map[string]any{}, func(o *api.ListApplicationsOutput) ([]api.Application, *api.NextToken) {
		return o.Items, o.NextToken
	})
}
func (h cfnACfgApplication) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "application", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rows, err := h.applications(ctx)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgARN(r, "application/"+cfnComputeValue(row.Id))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgApplicationResult(cfnComputeValue(rows[i].Id)), nil
	}
	in := cfnComputeCopy(r.Properties, "Name", "Description")
	in["Tags"] = cfnAppCustomerTags(r)
	out, err := cfnComputeCall[api.CreateApplicationOutput](ctx, h.commands, "appconfig", "CreateApplication", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgApplicationResult(cfnComputeValue(out.Id)), nil

}
func (h cfnACfgApplication) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "application", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnACfgARN(r, "application/"+r.PhysicalID)
	tags, err := cfnACfgOwnedTags(ctx, h.commands, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnACfgApplicationResult(r.PhysicalID)
	in := map[string]any{"ApplicationId": r.PhysicalID, "Name": r.Properties["Name"], "Description": cfnComputeDefault(r.Properties, "Description", "")}
	if err := cfnComputeRun(ctx, h.commands, "appconfig", "UpdateApplication", in); err != nil {
		return result, err
	}
	return result, cfnACfgSyncTags(ctx, h.commands, r, arn, tags)

}
func (h cfnACfgApplication) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "application", false)
	_, err := cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgARN(r, "application/"+r.PhysicalID))
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteApplication", map[string]any{"ApplicationId": r.PhysicalID})
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}
func (h cfnACfgApplication) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.GetApplicationOutput](ctx, h.commands, "appconfig", "GetApplication", map[string]any{"ApplicationId": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgARN(r, "application/"+r.PhysicalID))
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"ApplicationId": cfnComputeValue(out.Id), "Name": cfnComputeValue(out.Name), "Tags": cfnAppUserTags(tags)}
	if out.Description != nil {
		p["Description"] = cfnComputeValue(out.Description)
	}
	return p, nil
}
func (h cfnACfgApplication) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.applications(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(rows))
	for _, row := range rows {
		id := cfnComputeValue(row.Id)
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"ApplicationId": id, "Name": cfnComputeValue(row.Name)}})
	}
	return out, nil
}

type cfnACfgEnvironment struct{ commands StepFunctionsCommands }

func (h cfnACfgEnvironment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ApplicationId", "Name", "Description", "Monitors", "DeletionProtectionCheck", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ApplicationId", "Name"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ApplicationId", "Name", "Description", "DeletionProtectionCheck"); err != nil {
		return err
	}
	if v, ok := p["Monitors"]; ok {
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("monitors must be a list")
		}
		for _, item := range list {
			monitor, ok := cfnComputeObject(item)
			if !ok {
				return fmt.Errorf("monitors entries must be objects")
			}
			if err := cfnComputeProperties(monitor, "AlarmArn", "AlarmRoleArn"); err != nil {
				return err
			}
			if err := cfnComputeRequired(monitor, "AlarmArn"); err != nil {
				return err
			}
		}
	}
	if err := cfnACfgDeletionCheck(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgEnvironment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApplicationId"), h.Validate(b)
}
func cfnACfgEnvironmentResult(app, env string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: app + "|" + env, Ref: env, Attributes: map[string]any{"EnvironmentId": env}}
}
func (h cfnACfgEnvironment) environments(ctx context.Context, app string) ([]api.Environment, error) {
	return cfnACfgPages(ctx, h.commands, "ListEnvironments", map[string]any{"ApplicationId": app}, func(o *api.ListEnvironmentsOutput) ([]api.Environment, *api.NextToken) {
		return o.Items, o.NextToken
	})
}
func (h cfnACfgEnvironment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "environment", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	app := cfnComputeString(r.Properties, "ApplicationId")
	rows, err := h.environments(ctx, app)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgARN(r, "application/"+app+"/environment/"+cfnComputeValue(row.Id))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgEnvironmentResult(app, cfnComputeValue(rows[i].Id)), nil
	}
	in := cfnComputeCopy(r.Properties, "ApplicationId", "Name", "Description", "Monitors")
	in["Tags"] = cfnAppCustomerTags(r)
	out, err := cfnComputeCall[api.CreateEnvironmentOutput](ctx, h.commands, "appconfig", "CreateEnvironment", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgEnvironmentResult(app, cfnComputeValue(out.Id)), nil

}
func (h cfnACfgEnvironment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "environment", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnACfgARN(r, "application/"+parts[0]+"/environment/"+parts[1])
	tags, err := cfnACfgOwnedTags(ctx, h.commands, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnACfgEnvironmentResult(parts[0], parts[1])
	in := map[string]any{"ApplicationId": parts[0], "EnvironmentId": parts[1], "Name": r.Properties["Name"], "Description": cfnComputeDefault(r.Properties, "Description", ""), "Monitors": cfnComputeDefault(r.Properties, "Monitors", []any{})}
	if err := cfnComputeRun(ctx, h.commands, "appconfig", "UpdateEnvironment", in); err != nil {
		return result, err
	}
	return result, cfnACfgSyncTags(ctx, h.commands, r, arn, tags)

}
func (h cfnACfgEnvironment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "environment", false)
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return err
	}
	_, err = cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgARN(r, "application/"+parts[0]+"/environment/"+parts[1]))
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	in := map[string]any{"ApplicationId": parts[0], "EnvironmentId": parts[1]}
	if v, ok := r.Properties["DeletionProtectionCheck"]; ok {
		in["DeletionProtectionCheck"] = v
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteEnvironment", in)
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}
func cfnACfgMonitors(rows []api.Monitor) []any {
	out := make([]any, 0, len(rows))
	for _, m := range rows {
		item := map[string]any{"AlarmArn": cfnComputeValue(m.AlarmArn)}
		if m.AlarmRoleArn != nil {
			item["AlarmRoleArn"] = cfnComputeValue(m.AlarmRoleArn)
		}
		out = append(out, item)
	}
	return out
}
func (h cfnACfgEnvironment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetEnvironmentOutput](ctx, h.commands, "appconfig", "GetEnvironment", map[string]any{"ApplicationId": parts[0], "EnvironmentId": parts[1]})
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgARN(r, "application/"+parts[0]+"/environment/"+parts[1]))
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"ApplicationId": parts[0], "EnvironmentId": parts[1], "Name": cfnComputeValue(out.Name), "Monitors": cfnACfgMonitors(out.Monitors), "Tags": cfnAppUserTags(tags)}
	if out.Description != nil {
		p["Description"] = cfnComputeValue(out.Description)
	}
	return p, nil
}
func (h cfnACfgEnvironment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apps, err := (cfnACfgApplication(h)).applications(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, app := range apps {
		id := cfnComputeValue(app.Id)
		rows, err := h.environments(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			env := cfnComputeValue(row.Id)
			out = append(out, cloudformation.ResourceDescription{Identifier: id + "|" + env, Properties: cloudformation.Properties{"ApplicationId": id, "EnvironmentId": env, "Name": cfnComputeValue(row.Name)}})
		}
	}
	return out, nil
}

type cfnACfgProfile struct{ commands StepFunctionsCommands }

var cfnACfgProfileProperties = []string{"ApplicationId", "Name", "Description", "LocationUri", "RetrievalRoleArn", "Validators", "Type", "KmsKeyIdentifier", "DeletionProtectionCheck", "Tags"}

func (h cfnACfgProfile) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnACfgProfileProperties...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ApplicationId", "Name", "LocationUri"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ApplicationId", "Name", "Description", "LocationUri", "RetrievalRoleArn", "Type", "KmsKeyIdentifier", "DeletionProtectionCheck"); err != nil {
		return err
	}
	if v, ok := p["Validators"]; ok {
		list, ok := v.([]any)
		if !ok || len(list) > 2 {
			return fmt.Errorf("validators must be a list of at most two validators")
		}
		for _, item := range list {
			validator, ok := cfnComputeObject(item)
			if !ok {
				return fmt.Errorf("validators entries must be objects")
			}
			if err := cfnComputeProperties(validator, "Type", "Content"); err != nil {
				return err
			}
			if err := cfnComputeStrings(validator, "Type", "Content"); err != nil {
				return err
			}
		}
	}
	if err := cfnACfgDeletionCheck(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgProfile) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApplicationId", "LocationUri", "Type"), h.Validate(b)
}
func cfnACfgProfileResult(app string, out *api.ConfigurationProfile) cloudformation.ResourceResult {
	id := cfnComputeValue(out.Id)
	attributes := map[string]any{"ConfigurationProfileId": id}
	if out.KmsKeyArn != nil {
		attributes["KmsKeyArn"] = cfnComputeValue(out.KmsKeyArn)
	}
	return cloudformation.ResourceResult{PhysicalID: app + "|" + id, Ref: id, Attributes: attributes}
}
func (h cfnACfgProfile) get(ctx context.Context, app, id string) (*api.ConfigurationProfile, error) {
	return cfnComputeCall[api.GetConfigurationProfileOutput](ctx, h.commands, "appconfig", "GetConfigurationProfile", map[string]any{"ApplicationId": app, "ConfigurationProfileId": id})
}
func (h cfnACfgProfile) profiles(ctx context.Context, app string) ([]api.ConfigurationProfileSummary, error) {
	return cfnACfgPages(ctx, h.commands, "ListConfigurationProfiles", map[string]any{"ApplicationId": app}, func(o *api.ListConfigurationProfilesOutput) ([]api.ConfigurationProfileSummary, *api.NextToken) {
		return o.Items, o.NextToken
	})
}
func (h cfnACfgProfile) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "configurationprofile", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	app := cfnComputeString(r.Properties, "ApplicationId")
	rows, err := h.profiles(ctx, app)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgARN(r, "application/"+app+"/configurationprofile/"+cfnComputeValue(row.Id))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		out, err := h.get(ctx, app, cfnComputeValue(rows[i].Id))
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgProfileResult(app, out), nil
	}
	in := cfnComputeCopy(r.Properties, "ApplicationId", "Name", "Description", "LocationUri", "RetrievalRoleArn", "Validators", "Type", "KmsKeyIdentifier")
	in["Tags"] = cfnAppCustomerTags(r)
	out, err := cfnComputeCall[api.CreateConfigurationProfileOutput](ctx, h.commands, "appconfig", "CreateConfigurationProfile", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgProfileResult(app, out), nil

}
func (h cfnACfgProfile) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "configurationprofile", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnACfgARN(r, "application/"+parts[0]+"/configurationprofile/"+parts[1])
	tags, err := cfnACfgOwnedTags(ctx, h.commands, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := map[string]any{"ApplicationId": parts[0], "ConfigurationProfileId": parts[1], "Name": r.Properties["Name"], "Description": cfnComputeDefault(r.Properties, "Description", ""), "Validators": cfnComputeDefault(r.Properties, "Validators", []any{}), "KmsKeyIdentifier": cfnComputeDefault(r.Properties, "KmsKeyIdentifier", "")}
	if v, ok := r.Properties["RetrievalRoleArn"]; ok {
		in["RetrievalRoleArn"] = v
	} else if r.Previous["RetrievalRoleArn"] != nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("RetrievalRoleArn cannot be removed from an existing configuration profile")
	}
	out, err := cfnComputeCall[api.UpdateConfigurationProfileOutput](ctx, h.commands, "appconfig", "UpdateConfigurationProfile", in)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: parts[1]}, err
	}
	result := cfnACfgProfileResult(parts[0], out)
	return result, cfnACfgSyncTags(ctx, h.commands, r, arn, tags)

}
func (h cfnACfgProfile) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "configurationprofile", false)
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return err
	}
	_, err = cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgARN(r, "application/"+parts[0]+"/configurationprofile/"+parts[1]))
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	in := map[string]any{"ApplicationId": parts[0], "ConfigurationProfileId": parts[1]}
	if v, ok := r.Properties["DeletionProtectionCheck"]; ok {
		in["DeletionProtectionCheck"] = v
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteConfigurationProfile", in)
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}
func (h cfnACfgProfile) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return nil, err
	}
	out, err := h.get(ctx, parts[0], parts[1])
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgARN(r, "application/"+parts[0]+"/configurationprofile/"+parts[1]))
	if err != nil {
		return nil, err
	}
	validators := make([]any, 0, len(out.Validators))
	for _, v := range out.Validators {
		validators = append(validators, map[string]any{"Type": cfnComputeValue(v.Type), "Content": cfnComputeValue(v.Content)})
	}
	p := cloudformation.Properties{"ApplicationId": parts[0], "ConfigurationProfileId": parts[1], "Name": cfnComputeValue(out.Name), "LocationUri": cfnComputeValue(out.LocationUri), "Validators": validators, "Tags": cfnAppUserTags(tags)}
	for key, value := range map[string]*string{"Description": (*string)(out.Description), "RetrievalRoleArn": (*string)(out.RetrievalRoleArn), "Type": (*string)(out.Type), "KmsKeyIdentifier": (*string)(out.KmsKeyIdentifier), "KmsKeyArn": (*string)(out.KmsKeyArn)} {
		if value != nil {
			p[key] = *value
		}
	}
	return p, nil
}
func (h cfnACfgProfile) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apps, err := (cfnACfgApplication(h)).applications(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, app := range apps {
		id := cfnComputeValue(app.Id)
		rows, err := h.profiles(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			profile := cfnComputeValue(row.Id)
			out = append(out, cloudformation.ResourceDescription{Identifier: id + "|" + profile, Properties: cloudformation.Properties{"ApplicationId": id, "ConfigurationProfileId": profile, "Name": cfnComputeValue(row.Name), "LocationUri": cfnComputeValue(row.LocationUri)}})
		}
	}
	return out, nil
}

type cfnACfgStrategy struct{ commands StepFunctionsCommands }

func (h cfnACfgStrategy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "DeploymentDurationInMinutes", "FinalBakeTimeInMinutes", "GrowthFactor", "GrowthType", "ReplicateTo", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name", "DeploymentDurationInMinutes", "GrowthFactor", "ReplicateTo"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description", "GrowthType", "ReplicateTo"); err != nil {
		return err
	}
	if err := cfnAppNumbers(map[string]any{}, p, []string{"DeploymentDurationInMinutes", "FinalBakeTimeInMinutes"}, []string{"GrowthFactor"}); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnACfgStrategy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "ReplicateTo"), h.Validate(b)
}
func cfnACfgStrategyResult(id string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id}}
}
func (h cfnACfgStrategy) strategies(ctx context.Context) ([]api.DeploymentStrategy, error) {
	return cfnACfgPages(ctx, h.commands, "ListDeploymentStrategies", map[string]any{}, func(o *api.ListDeploymentStrategiesOutput) ([]api.DeploymentStrategy, *api.NextToken) {
		return o.Items, o.NextToken
	})
}
func (h cfnACfgStrategy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "deploymentstrategy", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rows, err := h.strategies(ctx)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	// AWS predefined strategies are untaggable and never stack incarnations.
	rows = slices.DeleteFunc(rows, func(v api.DeploymentStrategy) bool { return strings.HasPrefix(cfnComputeValue(v.Id), "AppConfig.") })
	arns := make([]string, len(rows))
	for i, row := range rows {
		arns[i] = cfnACfgARN(r, "deploymentstrategy/"+cfnComputeValue(row.Id))
	}
	if i, err := cfnACfgRecover(ctx, h.commands, r, arns); err != nil || i >= 0 {
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnACfgStrategyResult(cfnComputeValue(rows[i].Id)), nil
	}
	in := cfnComputeCopy(r.Properties, "Name", "Description", "GrowthType", "ReplicateTo")
	if err := cfnAppNumbers(in, r.Properties, []string{"DeploymentDurationInMinutes", "FinalBakeTimeInMinutes"}, []string{"GrowthFactor"}); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in["Tags"] = cfnAppCustomerTags(r)
	out, err := cfnComputeCall[api.CreateDeploymentStrategyOutput](ctx, h.commands, "appconfig", "CreateDeploymentStrategy", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgStrategyResult(cfnComputeValue(out.Id)), nil

}
func (h cfnACfgStrategy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "deploymentstrategy", false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnACfgARN(r, "deploymentstrategy/"+r.PhysicalID)
	tags, err := cfnACfgOwnedTags(ctx, h.commands, r, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnACfgStrategyResult(r.PhysicalID)
	in := map[string]any{"DeploymentStrategyId": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", ""), "FinalBakeTimeInMinutes": 0}
	if v, ok := r.Properties["GrowthType"]; ok {
		in["GrowthType"] = v
	} else {
		in["GrowthType"] = "LINEAR"
	}
	if err := cfnAppNumbers(in, r.Properties, []string{"DeploymentDurationInMinutes", "FinalBakeTimeInMinutes"}, []string{"GrowthFactor"}); err != nil {
		return result, err
	}
	if err := cfnComputeRun(ctx, h.commands, "appconfig", "UpdateDeploymentStrategy", in); err != nil {
		return result, err
	}
	return result, cfnACfgSyncTags(ctx, h.commands, r, arn, tags)

}
func (h cfnACfgStrategy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "deploymentstrategy", false)
	_, err := cfnACfgOwnedTags(ctx, h.commands, r, cfnACfgARN(r, "deploymentstrategy/"+r.PhysicalID))
	if cfnACfgMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteDeploymentStrategy", map[string]any{"DeploymentStrategyId": r.PhysicalID})
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}
func cfnACfgStrategyProperties(v api.DeploymentStrategy) cloudformation.Properties {
	p := cloudformation.Properties{"Id": cfnComputeValue(v.Id), "Name": cfnComputeValue(v.Name), "DeploymentDurationInMinutes": cfnACfgInt(v.DeploymentDurationInMinutes), "FinalBakeTimeInMinutes": cfnACfgInt(v.FinalBakeTimeInMinutes), "GrowthFactor": cfnACfgFloat(v.GrowthFactor), "GrowthType": cfnComputeValue(v.GrowthType), "ReplicateTo": cfnComputeValue(v.ReplicateTo)}
	if v.Description != nil {
		p["Description"] = cfnComputeValue(v.Description)
	}
	return p
}
func (h cfnACfgStrategy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.GetDeploymentStrategyOutput](ctx, h.commands, "appconfig", "GetDeploymentStrategy", map[string]any{"DeploymentStrategyId": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	tags, err := cfnACfgTagsOf(ctx, h.commands, cfnACfgARN(r, "deploymentstrategy/"+r.PhysicalID))
	if err != nil {
		return nil, err
	}
	p := cfnACfgStrategyProperties(*out)
	p["Tags"] = cfnAppUserTags(tags)
	return p, nil
}
func (h cfnACfgStrategy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.strategies(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, row := range rows {
		if id := cfnComputeValue(row.Id); !strings.HasPrefix(id, "AppConfig.") {
			out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cfnACfgStrategyProperties(row)})
		}
	}
	return out, nil
}

// cfnACfgHosted publishes immutable hosted versions. The owner binds a version
// to the incarnation so recovery never publishes a second version.
type cfnACfgHosted struct{ commands StepFunctionsCommands }

func (h cfnACfgHosted) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ApplicationId", "ConfigurationProfileId", "Content", "ContentType", "Description", "LatestVersionNumber", "VersionLabel"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ApplicationId", "ConfigurationProfileId", "Content", "ContentType"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ApplicationId", "ConfigurationProfileId", "Content", "ContentType", "Description", "VersionLabel"); err != nil {
		return err
	}
	_, _, err := cfnAppInteger(p, "LatestVersionNumber")
	return err
}
func (h cfnACfgHosted) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApplicationId", "ConfigurationProfileId", "Content", "ContentType", "Description", "LatestVersionNumber", "VersionLabel"), h.Validate(b)
}
func cfnACfgHostedResult(app, profile string, n int64) cloudformation.ResourceResult {
	version := strconv.FormatInt(n, 10)
	return cloudformation.ResourceResult{PhysicalID: app + "|" + profile + "|" + version, Ref: version, Attributes: map[string]any{"VersionNumber": version}}
}
func (h cfnACfgHosted) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "hostedconfigurationversion", true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	app, profile := cfnComputeString(r.Properties, "ApplicationId"), cfnComputeString(r.Properties, "ConfigurationProfileId")
	in := &api.CreateHostedConfigurationVersionInput{
		ApplicationId:          new(api.Name(app)),
		ConfigurationProfileId: new(api.LongName(profile)),
		Content:                api.Blob(cfnComputeString(r.Properties, "Content")),
		ContentType:            new(api.StringWithLengthBetween1And255(cfnComputeString(r.Properties, "ContentType"))),
	}
	if v, ok := r.Properties["Description"].(string); ok {
		in.Description = new(api.Description(v))
	}
	if v, ok := r.Properties["VersionLabel"].(string); ok {
		in.VersionLabel = new(api.VersionLabel(v))
	}
	if n, ok, _ := cfnAppInteger(r.Properties, "LatestVersionNumber"); ok {
		in.LatestVersionNumber = new(api.Integer(n))
	}
	out, err := cfnMessagingCall[api.CreateHostedConfigurationVersionOutput](ctx, h.commands, "appconfig", "CreateHostedConfigurationVersion", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgHostedResult(app, profile, cfnACfgInt(out.VersionNumber)), nil

}
func (h cfnACfgHosted) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnACfgOwnerContext(ctx, r, "hostedconfigurationversion", false)
	if changed, err := h.Replacement(r.Previous, r.Properties); err != nil || changed {
		if err == nil {
			err = fmt.Errorf("hosted configuration versions are immutable")
		}
		return cloudformation.ResourceResult{}, err
	}
	app, profile, n, err := cfnACfgHostedIdentity(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnACfgHostedResult(app, profile, n), nil

}
func cfnACfgHostedIdentity(id string) (string, string, int64, error) {
	parts, err := cfnAppParts(id, 3)
	if err != nil {
		return "", "", 0, err
	}
	n, err := strconv.ParseInt(parts[2], 10, 32)
	if err != nil || n < 1 {
		return "", "", 0, fmt.Errorf("invalid hosted configuration version identifier %q", id)
	}
	return parts[0], parts[1], n, nil
}
func (h cfnACfgHosted) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnACfgOwnerContext(ctx, r, "hostedconfigurationversion", false)
	app, profile, n, err := cfnACfgHostedIdentity(r.PhysicalID)
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "appconfig", "DeleteHostedConfigurationVersion", map[string]any{"ApplicationId": app, "ConfigurationProfileId": profile, "VersionNumber": n})
	if cfnACfgMissing(err) {
		return nil
	}
	return err

}
func (h cfnACfgHosted) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	app, profile, n, err := cfnACfgHostedIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetHostedConfigurationVersionOutput](ctx, h.commands, "appconfig", "GetHostedConfigurationVersion", map[string]any{"ApplicationId": app, "ConfigurationProfileId": profile, "VersionNumber": n})
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"ApplicationId": app, "ConfigurationProfileId": profile, "VersionNumber": strconv.FormatInt(n, 10), "Content": string(out.Content), "ContentType": cfnComputeValue(out.ContentType)}
	if out.Description != nil {
		p["Description"] = cfnComputeValue(out.Description)
	}
	if out.VersionLabel != nil {
		p["VersionLabel"] = cfnComputeValue(out.VersionLabel)
	}
	return p, nil
}
func (h cfnACfgHosted) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apps, err := (cfnACfgApplication(h)).applications(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, app := range apps {
		appID := cfnComputeValue(app.Id)
		profiles, err := (cfnACfgProfile(h)).profiles(ctx, appID)
		if err != nil {
			return nil, err
		}
		for _, profile := range profiles {
			profileID := cfnComputeValue(profile.Id)
			if cfnComputeValue(profile.LocationUri) != "hosted" {
				continue
			}
			rows, err := cfnACfgPages(ctx, h.commands, "ListHostedConfigurationVersions", map[string]any{"ApplicationId": appID, "ConfigurationProfileId": profileID}, func(o *api.ListHostedConfigurationVersionsOutput) ([]api.HostedConfigurationVersionSummary, *api.NextToken) {
				return o.Items, o.NextToken
			})
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				version := strconv.FormatInt(cfnACfgInt(row.VersionNumber), 10)
				out = append(out, cloudformation.ResourceDescription{Identifier: appID + "|" + profileID + "|" + version, Properties: cloudformation.Properties{"ApplicationId": appID, "ConfigurationProfileId": profileID, "VersionNumber": version, "ContentType": cfnComputeValue(row.ContentType)}})
			}
		}
	}
	return out, nil
}
