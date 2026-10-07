package eventbridge

import (
	"bytes"
	"context"
	"crypto/cipher"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

func (s *Service) prepareBusKey(ctx context.Context, key BusKey, identifier string, initialize bool) (string, *awswire.Error) {
	if identifier == "" {
		return "", nil
	}
	if s.busKeys == nil {
		return "", unsupported("No event bus KMS provider is configured.")
	}
	return s.busKeys.PrepareBusKey(ctx, key, identifier, initialize)
}

func busKeyIdentifier(identifier string) *api.KmsKeyIdentifier {
	if identifier == "" {
		return nil
	}
	return str[api.KmsKeyIdentifier](identifier)
}

func busDLQ(arn string) *api.DeadLetterConfig {
	if arn == "" {
		return nil
	}
	return &api.DeadLetterConfig{Arn: str[api.ResourceArn](arn)}
}

func validDeadLetterARN(key BusKey, arn string) bool {
	parts := strings.SplitN(arn, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[1] == key.Partition && parts[2] == "sqs" && parts[3] == key.Region && len(parts[4]) == 12 && strings.Trim(parts[4], "0123456789") == "" && parts[5] != "" && !strings.HasSuffix(parts[5], ".fifo")
}

func validateBusDLQ(key BusKey, config *api.DeadLetterConfig) *awswire.Error {
	if config == nil {
		return nil
	}
	if config.Arn == nil {
		return failure("ValidationException", "Parameter DeadLetterConfig.Arn is not valid. Reason: Provide a valid SQS queue ARN, or an empty string to remove the dead-letter queue configuration.")
	}
	if value(config.Arn) == "" {
		return nil
	}
	if !validDeadLetterARN(key, value(config.Arn)) {
		return failure("AccessDeniedException", "Access to the resource "+value(config.Arn)+" is denied. Reason: You must specify a standard dead letter queue in the same region.")
	}
	return nil
}

func (s *Service) updateBus(ctx context.Context, in *api.UpdateEventBusInput) (out *api.UpdateEventBusOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "UpdateEventBus", in, &out, &rejected, false)
	if in.LogConfig != nil {
		return nil, unsupported("Event-bus logging is not implemented.")
	}
	key, rejected := busKey(ctx, value(in.Name))
	if rejected != nil {
		return nil, rejected
	}
	if rejected := validateBusDLQ(key, in.DeadLetterConfig); rejected != nil {
		return nil, rejected
	}
	var selected BusRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		selected, err = s.bus(tx, key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "UpdateEventBus", key.ARN(), selected.Tags, nil, selected.Policy); err != nil {
			return err
		}
		if err := cloudFormationBusCheck(tx.Context(), selected); err != nil {
			return err
		}
		return s.cloudFormationBusPolicyUpdateCheck(tx, selected)
	})
	if err != nil {
		return nil, wireError(err)
	}
	identifier := selected.KmsKeyIdentifier
	if in.KmsKeyIdentifier != nil {
		requested := value(in.KmsKeyIdentifier)
		if selected.KmsKeyIdentifier != "" && requested != selected.KmsKeyIdentifier {
			if _, rejected := s.prepareBusKey(ctx, key, selected.KmsKeyIdentifier, false); rejected != nil {
				return nil, rejected
			}
		}
		identifier, rejected = s.prepareBusKey(ctx, key, requested, requested != selected.KmsKeyIdentifier)
		if rejected != nil {
			return nil, rejected
		}
	}
	var previous, replacement cipher.AEAD
	configured := selected
	if in.KmsKeyIdentifier != nil {
		previous, rejected = s.configurationCipher(ctx, selected, false)
		if rejected != nil {
			return nil, rejected
		}
		configured.KmsKeyIdentifier = identifier
		replacement, rejected = s.newConfigurationKey(ctx, &configured)
		if rejected != nil {
			return nil, rejected
		}
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := s.bus(tx, key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "UpdateEventBus", key.ARN(), current.Tags, nil, current.Policy); err != nil {
			return err
		}
		if err := cloudFormationBusCheck(tx.Context(), current); err != nil {
			return err
		}
		if err := s.cloudFormationBusPolicyUpdateCheck(tx, current); err != nil {
			return err
		}
		if current.KmsKeyIdentifier != selected.KmsKeyIdentifier || !bytes.Equal(current.ConfigurationDataKey, selected.ConfigurationDataKey) || current.DeadLetterARN != selected.DeadLetterARN || current.Description != selected.Description {
			return failure("ConcurrentModificationException", "Event bus configuration changed during the update.")
		}
		current.KmsKeyIdentifier = identifier
		if in.KmsKeyIdentifier != nil {
			reader := configurationReader{Reader: tx, cipher: previous}
			rules, err := reader.Rules(key)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				targets, err := reader.Targets(rule.Key)
				if err != nil {
					return err
				}
				if err := tx.PutRule(sealRuleConfiguration(rule, replacement)); err != nil {
					return err
				}
				for _, target := range targets {
					sealed, err := sealTargetConfiguration(target, replacement)
					if err != nil {
						return err
					}
					if err := tx.PutTarget(sealed); err != nil {
						return err
					}
				}
			}
			current.ConfigurationDataKey, current.ConfigurationKeyARN = configured.ConfigurationDataKey, configured.ConfigurationKeyARN
		}
		if in.DeadLetterConfig != nil {
			current.DeadLetterARN = value(in.DeadLetterConfig.Arn)
		}
		if in.Description != nil {
			current.Description = value(in.Description)
		}
		current.Modified = s.clock.Now()
		if err := tx.PutBus(current); err != nil {
			return err
		}
		out = &api.UpdateEventBusOutput{Arn: str[api.String](key.ARN()), Name: str[api.EventBusName](key.Name), KmsKeyIdentifier: busKeyIdentifier(identifier), DeadLetterConfig: busDLQ(current.DeadLetterARN)}
		if current.Description != "" {
			out.Description = str[api.EventBusDescription](current.Description)
		}
		return s.recordCall(tx.Context(), "UpdateEventBus", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	if in.KmsKeyIdentifier != nil {
		s.busCache.drop(key)
	}
	return out, nil
}
