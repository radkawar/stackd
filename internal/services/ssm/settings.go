package ssm

import (
	"context"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
)

const defaultTierSetting = "/ssm/parameter-store/default-parameter-tier"
const throughputSetting = "/ssm/parameter-store/high-throughput-enabled"
const documentPublicSharingSetting = "/ssm/documents/console/public-sharing-permission"

func settingDefault(id string) (string, error) {
	switch id {
	case documentPublicSharingSetting:
		// Native GetServiceSetting reports Enable / Default; see document_sharing.json.
		return "Enable", nil
	case defaultTierSetting:
		return "Standard", nil
	case throughputSetting:
		// TODO: Comeback implement Parameter Store request quota admission before exposing throughput settings.
		return "", failure("UnsupportedOperation", "Parameter Store throughput settings require request quota admission.")
	default:
		return "", failure("ServiceSettingNotFound", "The specified service setting is not supported.")
	}
}

func settingARN(scope Scope, id string) string {
	return "arn:" + scope.Partition + ":ssm:" + scope.Region + ":" + scope.AccountID + ":servicesetting" + id
}

func (s *Service) serviceSetting(tx Transaction, action, id string) (SettingRecord, error) {
	scope := scopeFor(tx.Context())
	if strings.HasPrefix(id, "arn:") {
		prefix := settingARN(scope, "")
		if !strings.HasPrefix(id, prefix+"/") {
			return SettingRecord{}, failure("ServiceSettingNotFound", "The service setting ARN does not belong to this account and Region.")
		}
		id = strings.TrimPrefix(id, prefix)
	}
	initial, err := settingDefault(id)
	if err != nil {
		return SettingRecord{}, err
	}
	if s.authorizer != nil {
		if err := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: "ssm:" + action, ResourceARN: settingARN(scope, id)}); err != nil {
			return SettingRecord{}, err
		}
	}
	settings, err := tx.Settings(scope)
	if err != nil {
		return SettingRecord{}, err
	}
	for _, setting := range settings {
		if setting.ID == id {
			return setting, nil
		}
	}
	setting := SettingRecord{Scope: scope, ID: id, Value: initial, ModifiedUser: "System", Modified: s.clock.Now().UTC()}
	return setting, tx.PutSetting(setting)
}

func settingOutput(setting SettingRecord) *api.ServiceSetting {
	initial, _ := settingDefault(setting.ID)
	status := "Customized"
	if setting.Value == initial {
		status = "Default"
	}
	return &api.ServiceSetting{ARN: new(api.String(settingARN(setting.Scope, setting.ID))), LastModifiedDate: &setting.Modified, LastModifiedUser: new(api.String(setting.ModifiedUser)), SettingId: new(api.ServiceSettingId(setting.ID)), SettingValue: new(api.ServiceSettingValue(setting.Value)), Status: new(api.String(status))}
}

func defaultTier(r Reader, scope Scope) (string, error) {
	settings, err := r.Settings(scope)
	if err != nil {
		return "", err
	}
	for _, setting := range settings {
		if setting.ID == defaultTierSetting {
			return setting.Value, nil
		}
	}
	return "Standard", nil
}

func (s *Service) getServiceSetting(tx Transaction, in *api.GetServiceSettingRequest) (*api.GetServiceSettingResult, error) {
	setting, err := s.serviceSetting(tx, "GetServiceSetting", value(in.SettingId))
	if err != nil {
		return nil, err
	}
	return &api.GetServiceSettingResult{ServiceSetting: settingOutput(setting)}, nil
}

func (s *Service) updateServiceSetting(tx Transaction, in *api.UpdateServiceSettingRequest) (*api.UpdateServiceSettingResult, error) {
	setting, err := s.serviceSetting(tx, "UpdateServiceSetting", value(in.SettingId))
	if err != nil {
		return nil, err
	}
	v := value(in.SettingValue)
	valid := v == "Standard" || v == "Advanced" || v == "Intelligent-Tiering"
	if setting.ID == documentPublicSharingSetting {
		valid = v == "Enable" || v == "Disable"
	}
	if !valid {
		return nil, failure("ValidationException", "The supplied value is not valid for this service setting.")
	}
	setting.Value, setting.Modified, setting.ModifiedUser = v, s.clock.Now().UTC(), awsctx.FromContext(tx.Context()).PrincipalARN
	return &api.UpdateServiceSettingResult{}, tx.PutSetting(setting)
}

func (s *Service) resetServiceSetting(tx Transaction, in *api.ResetServiceSettingRequest) (*api.ResetServiceSettingResult, error) {
	setting, err := s.serviceSetting(tx, "ResetServiceSetting", value(in.SettingId))
	if err != nil {
		return nil, err
	}
	setting.Value, _ = settingDefault(setting.ID)
	setting.Modified, setting.ModifiedUser = s.clock.Now().UTC(), awsctx.FromContext(tx.Context()).PrincipalARN
	if err := tx.PutSetting(setting); err != nil {
		return nil, err
	}
	return &api.ResetServiceSettingResult{ServiceSetting: settingOutput(setting)}, nil
}

// DocumentPublicSharingAllowed is an internal admission read, not a caller
// GetServiceSetting request. It shares the current journal transaction.
func (s *Service) DocumentPublicSharingAllowed(ctx context.Context) (bool, error) {
	allowed := true
	err := s.repository.View(ctx, func(r Reader) error {
		settings, err := r.Settings(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, setting := range settings {
			if setting.ID == documentPublicSharingSetting {
				allowed = setting.Value == "Enable"
				break
			}
		}
		return nil
	})
	return allowed, err
}
