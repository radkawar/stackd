package integrations

import (
	"context"
	"fmt"
	"time"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/services/cloudformation"
)

// cfnSSMServiceSetting manages an account/Region SSM service setting through
// the SSM owner. Settings are singletons without tags: like the native
// resource, create overwrites the current value and delete resets it.
type cfnSSMServiceSetting struct{ commands StepFunctionsCommands }
type cfnSSMServiceSettingProperties struct {
	SettingId    string
	SettingValue string
}

func (h cfnSSMServiceSetting) decode(raw cloudformation.Properties) (cfnSSMServiceSettingProperties, error) {
	var p cfnSSMServiceSettingProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	if len(p.SettingId) < 1 || len(p.SettingId) > 1000 {
		return p, fmt.Errorf("SettingId must be 1 through 1000 characters")
	}
	if len(p.SettingValue) < 1 || len(p.SettingValue) > 4096 {
		return p, fmt.Errorf("SettingValue must be 1 through 4096 characters")
	}
	return p, nil
}
func (h cfnSSMServiceSetting) Validate(raw cloudformation.Properties) error {
	_, err := h.decode(raw)
	return err
}
func (h cfnSSMServiceSetting) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingChanged(a, b, "SettingId"), nil
}
func (h cfnSSMServiceSetting) get(ctx context.Context, id string) (*api.ServiceSetting, error) {
	out, err := cfnComputeCall[api.GetServiceSettingResult](ctx, h.commands, "ssm", "GetServiceSetting", map[string]any{"SettingId": id})
	if err != nil {
		return nil, cfnStorageMissing(err, "ServiceSettingNotFound")
	}
	if out.ServiceSetting == nil {
		return nil, fmt.Errorf("SSM returned no service setting")
	}
	return out.ServiceSetting, nil
}
func cfnSSMServiceSettingProjection(setting *api.ServiceSetting) cloudformation.Properties {
	p := cloudformation.Properties{"Arn": cfnComputeValue(setting.ARN), "SettingId": cfnComputeValue(setting.SettingId), "SettingValue": cfnComputeValue(setting.SettingValue), "Status": cfnComputeValue(setting.Status), "LastModifiedUser": cfnComputeValue(setting.LastModifiedUser)}
	if setting.LastModifiedDate != nil {
		p["LastModifiedDate"] = time.Time(*setting.LastModifiedDate).UTC().Format(time.RFC3339)
	}
	return p
}
func (h cfnSSMServiceSetting) apply(ctx context.Context, p cfnSSMServiceSettingProperties) (cloudformation.ResourceResult, error) {
	if err := cfnComputeRun(ctx, h.commands, "ssm", "UpdateServiceSetting", map[string]any{"SettingId": p.SettingId, "SettingValue": p.SettingValue}); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	setting, err := h.get(ctx, p.SettingId)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	projection := cfnSSMServiceSettingProjection(setting)
	arn, _ := projection["Arn"].(string)
	result := cfnMessagingResult(arn)
	result.Attributes = map[string]any{"Arn": arn, "Status": projection["Status"], "LastModifiedUser": projection["LastModifiedUser"], "LastModifiedDate": projection["LastModifiedDate"]}
	return result, nil
}
func (h cfnSSMServiceSetting) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.apply(ctx, p)
}
func (h cfnSSMServiceSetting) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SSM::ServiceSetting", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cfnMessagingResult(r.PhysicalID), err
	}
	if replace {
		return cfnMessagingResult(r.PhysicalID), fmt.Errorf("service setting update requires replacement")
	}
	p, err := h.decode(r.Properties)
	if err != nil {
		return cfnMessagingResult(r.PhysicalID), err
	}
	return h.apply(ctx, p)
}

// settingID accepts the setting ARN physical identifier, which the SSM owner
// resolves in the caller's account and Region.
func (h cfnSSMServiceSetting) settingID(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	id, _ := r.Properties["SettingId"].(string)
	return id
}
func (h cfnSSMServiceSetting) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	id := h.settingID(r)
	if id == "" {
		return nil
	}
	err := cfnComputeRun(ctx, h.commands, "ssm", "ResetServiceSetting", map[string]any{"SettingId": id})
	if cfnMessagingMissing(err, "ServiceSettingNotFound") && !r.CloudControl {
		return nil
	}
	return cfnStorageMissing(err, "ServiceSettingNotFound")
}
func (h cfnSSMServiceSetting) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	setting, err := h.get(ctx, h.settingID(r))
	if err != nil {
		return nil, err
	}
	return cfnSSMServiceSettingProjection(setting), nil
}

// List reports the settings the SSM owner admits. The registry's list handler
// also uses GetServiceSetting; unsupported setting IDs are not enumerated.
func (h cfnSSMServiceSetting) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	for _, id := range []string{"/ssm/documents/console/public-sharing-permission", "/ssm/parameter-store/default-parameter-tier"} {
		setting, err := h.get(ctx, id)
		if err != nil {
			return nil, err
		}
		p := cfnSSMServiceSettingProjection(setting)
		arn, _ := p["Arn"].(string)
		out = append(out, cloudformation.ResourceDescription{Identifier: arn, Properties: p})
	}
	return out, nil
}

var _ cloudformation.ResourceReader = cfnSSMServiceSetting{}
