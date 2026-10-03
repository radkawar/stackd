package appconfig

import (
	"time"

	api "stackd/internal/awsapi/appconfig"
)

func registerSettings(s *Service) {
	register(s, "GetAccountSettings", func(tx Transaction, in *api.GetAccountSettingsInput) (*api.GetAccountSettingsOutput, error) {
		if err := s.authorize(tx.Context(), "GetAccountSettings", "*", nil); err != nil {
			return nil, err
		}
		v, err := accountSettings(tx, scopeFor(tx.Context()))
		if err != nil {
			return nil, err
		}
		return settingsOutput(v), nil
	})
	register(s, "UpdateAccountSettings", func(tx Transaction, in *api.UpdateAccountSettingsInput) (*api.UpdateAccountSettingsOutput, error) {
		if err := s.authorize(tx.Context(), "UpdateAccountSettings", "*", nil); err != nil {
			return nil, err
		}
		v, err := accountSettings(tx, scopeFor(tx.Context()))
		if err != nil {
			return nil, err
		}
		if p := in.DeletionProtection; p != nil {
			if p.Enabled != nil {
				v.DeletionProtectionEnabled = bool(*p.Enabled)
			}
			if p.ProtectionPeriodInMinutes != nil {
				n := int32(*p.ProtectionPeriodInMinutes)
				if n < 15 || n > 1440 {
					return nil, failure("BadRequestException", "ProtectionPeriodInMinutes must be between 15 and 1440.")
				}
				v.ProtectionMinutes = n
			}
		}
		if p := in.VendedMetrics; p != nil && p.Enabled != nil {
			if bool(*p.Enabled) {
				// TODO: Comeback: calibrate the Agent's compressed Uplink-Payload
				// transport and publish actual treatment counts through CloudWatch
				// before accepting the account-wide VendedMetrics opt-in.
				return nil, failure("NotImplementedException", "Vended metrics require AppConfig Agent treatment-count ingestion, which is not yet available.")
			}
			v.VendedMetricsEnabled = bool(*p.Enabled)
			v.VendedMetricsSet = true
		}
		if err := tx.PutSettings(v); err != nil {
			return nil, err
		}
		return settingsOutput(v), nil
	})
}
func accountSettings(r Reader, sc Scope) (Settings, error) {
	v, ok, err := r.Settings(sc)
	if err != nil {
		return Settings{}, err
	}
	if !ok {
		v = Settings{Scope: sc, DeletionProtectionEnabled: true, ProtectionMinutes: 60}
	}
	return v, nil
}
func settingsOutput(v Settings) *api.AccountSettings {
	out := &api.AccountSettings{DeletionProtection: &api.DeletionProtectionSettings{Enabled: new(api.Boolean(v.DeletionProtectionEnabled)), ProtectionPeriodInMinutes: new(api.DeletionProtectionDuration(v.ProtectionMinutes))}, VendedMetrics: &api.VendedMetricsSettings{}}
	if v.VendedMetricsSet {
		out.VendedMetrics.Enabled = new(api.Boolean(v.VendedMetricsEnabled))
	}
	return out
}
func (s *Service) checkDeletionProtection(r Reader, sc Scope, createdAt, lastPoll time.Time, check string) error {
	if check == "BYPASS" {
		return nil
	}
	if check != "" && check != "ACCOUNT_DEFAULT" && check != "APPLY" {
		return failure("BadRequestException", "Invalid DeletionProtectionCheck.")
	}
	v, err := accountSettings(r, sc)
	if err != nil {
		return err
	}
	if check != "APPLY" && !v.DeletionProtectionEnabled {
		return nil
	}
	now := s.clock.Now()
	if !createdAt.IsZero() && now.Sub(createdAt) < time.Hour {
		return nil
	}
	if !lastPoll.IsZero() && now.Sub(lastPoll) < time.Duration(v.ProtectionMinutes)*time.Minute {
		return failure("BadRequestException", "Deletion protection is enabled and the resource has been recently accessed. Use DeletionProtectionCheck BYPASS to delete this resource.")
	}
	return nil
}
