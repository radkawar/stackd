package glue

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/glue"
)

func registerSecurity(s *Service) {
	registerControl(s, "CreateSecurityConfiguration", s.createSecurityConfiguration)
	registerControl(s, "GetSecurityConfiguration", s.getSecurityConfiguration)
	registerControl(s, "GetSecurityConfigurations", s.getSecurityConfigurations)
	registerControl(s, "DeleteSecurityConfiguration", s.deleteSecurityConfiguration)
}

// TODO: Comeback implement the data-quality execution owner before admitting
// DataQualityEncryption configurations; retention alone is not encryption.
func validateSecurity(c *api.EncryptionConfiguration) error {
	if c == nil {
		return failure("InvalidInputException", "EncryptionConfiguration is required.")
	}
	if len(c.S3Encryption) > 1 {
		return failure("InvalidInputException", "At most one S3 encryption configuration is supported.")
	}
	for _, v := range c.S3Encryption {
		switch value(v.S3EncryptionMode) {
		case "DISABLED", "SSE-S3":
		case "SSE-KMS":
			if value(v.KmsKeyArn) == "" {
				return failure("InvalidInputException", "SSE-KMS requires a KMS key ARN.")
			}
		default:
			return failure("InvalidInputException", "Invalid S3 encryption mode.")
		}
	}
	if v := c.CloudWatchEncryption; v != nil {
		switch value(v.CloudWatchEncryptionMode) {
		case "DISABLED":
		case "SSE-KMS":
			if value(v.KmsKeyArn) == "" {
				return failure("InvalidInputException", "CloudWatch SSE-KMS requires a KMS key ARN.")
			}
		default:
			return failure("InvalidInputException", "Invalid CloudWatch encryption mode.")
		}
	}
	if v := c.JobBookmarksEncryption; v != nil {
		switch value(v.JobBookmarksEncryptionMode) {
		case "DISABLED":
		case "CSE-KMS":
			if value(v.KmsKeyArn) == "" {
				return failure("InvalidInputException", "Bookmark encryption requires a KMS key ARN.")
			}
		default:
			return failure("InvalidInputException", "Invalid job bookmark encryption mode.")
		}
	}
	if c.DataQualityEncryption != nil {
		return unsupported("Data quality encryption is not implemented.")
	}
	return nil
}
func (s *Service) createSecurityConfiguration(ctx context.Context, tx Transaction, in *api.CreateSecurityConfigurationInput) (*api.CreateSecurityConfigurationOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if err := workflowName(key.Name); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "CreateSecurityConfiguration", key.Scope, "*", nil); err != nil {
		return nil, err
	}
	if err := validateSecurity(in.EncryptionConfiguration); err != nil {
		return nil, err
	}
	if _, err := tx.SecurityConfiguration(key); err == nil {
		return nil, failure("AlreadyExistsException", "Security configuration already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := workflowTime(s.clock.Now())
	if err := tx.PutSecurityConfiguration(SecurityConfigurationRecord{Key: key, Configuration: api.SecurityConfiguration{Name: in.Name, CreatedTimeStamp: now, EncryptionConfiguration: in.EncryptionConfiguration}}); err != nil {
		return nil, err
	}
	return &api.CreateSecurityConfigurationOutput{Name: in.Name, CreatedTimestamp: now}, nil
}
func (s *Service) getSecurityConfiguration(ctx context.Context, tx Transaction, in *api.GetSecurityConfigurationInput) (*api.GetSecurityConfigurationOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "GetSecurityConfiguration", scope, "*", nil); err != nil {
		return nil, err
	}
	v, err := tx.SecurityConfiguration(ResourceKey{scope, value(in.Name)})
	if err != nil {
		return nil, err
	}
	return &api.GetSecurityConfigurationOutput{SecurityConfiguration: &v.Configuration}, nil
}
func (s *Service) getSecurityConfigurations(ctx context.Context, tx Transaction, in *api.GetSecurityConfigurationsInput) (*api.GetSecurityConfigurationsOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "GetSecurityConfigurations", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.SecurityConfigurations(scope)
	if err != nil {
		return nil, err
	}
	rows, token, err := workflowPage(rows, func(v SecurityConfigurationRecord) string { return v.Key.Name }, "security/"+workflowScope(scope), in.MaxResults, in.NextToken, 1000)
	if err != nil {
		return nil, err
	}
	out := &api.GetSecurityConfigurationsOutput{NextToken: token, SecurityConfigurations: api.SecurityConfigurationList{}}
	for _, v := range rows {
		out.SecurityConfigurations = append(out.SecurityConfigurations, v.Configuration)
	}
	return out, nil
}
func (s *Service) deleteSecurityConfiguration(ctx context.Context, tx Transaction, in *api.DeleteSecurityConfigurationInput) (*api.DeleteSecurityConfigurationOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "DeleteSecurityConfiguration", scope, "*", nil); err != nil {
		return nil, err
	}
	key := ResourceKey{scope, value(in.Name)}
	if _, err := tx.SecurityConfiguration(key); err != nil {
		return nil, err
	}
	if err := tx.DeleteSecurityConfiguration(key); err != nil {
		return nil, err
	}
	return &api.DeleteSecurityConfigurationOutput{}, nil
}

// ResolveSecurityConfiguration supplies the current named configuration to job
// execution. The job owner applies S3/Logs encryption through those owners, and
// rejects modes its runtime cannot implement before launching customer code.
func (s *Service) ResolveSecurityConfiguration(ctx context.Context, scope Scope, name string) (api.EncryptionConfiguration, error) {
	var out api.EncryptionConfiguration
	err := s.repository.View(ctx, func(tx Reader) error {
		v, err := tx.SecurityConfiguration(ResourceKey{scope, name})
		if err != nil {
			return err
		}
		if v.Configuration.EncryptionConfiguration != nil {
			out = *v.Configuration.EncryptionConfiguration
		}
		return nil
	})
	return out, err
}
