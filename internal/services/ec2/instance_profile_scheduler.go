package ec2

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
)

// Association transitions have no host effects. They share the instance resource
// transaction, and reread current rows rather than committing a pre-lock snapshot.
// Initial/retiring transitions use one service second; failed credential delivery
// retries after five. These are local scheduling choices, not AWS latency claims.
func (s *Service) AdvanceInstanceProfileAssociations(ctx context.Context) (int, error) {
	count := 0
	err := s.repository.Update(ctx, func(tx Transaction) error {
		records, err := tx.PendingInstanceProfileAssociations(s.clock.Now())
		if err != nil {
			return err
		}
		for _, record := range records {
			instance, err := tx.Instance(ResourceKey{Scope: record.Key.Scope, ID: record.InstanceID})
			if err != nil {
				return err
			}
			switch record.State {
			case api.IamInstanceProfileAssociationStateASSOCIATING:
				if s.instanceProfiles == nil {
					return unsupported("IAM instance-profile credentials are not configured.")
				}
				// Prepare the v2 variant; v1 is issued only if requested. Both
				// variants retain IAM validity independently of HttpTokens.
				delivered, err := s.instanceProfiles.InstanceProfileCredentials(instanceServiceContext(tx.Context(), instance.Key), instance.credentialOrigin(), *record.profile(), record.Credentials.V2, true)
				record.Timestamp = s.clock.Now()
				if err != nil {
					var rejected *awswire.Error
					if !errors.As(err, &rejected) || rejected.Code != "AccessDenied" && rejected.Code != "InstanceProfileNotFound" {
						return err
					}
					record.NextActionAt = s.clock.Now().Add(5 * time.Second)
					if err := tx.PutInstanceProfileAssociation(record); err != nil {
						return err
					}
					count++
					continue
				}
				if delivered.Credentials != nil {
					record.Credentials.V2 = str(delivered.Credentials.AccessKeyId)
				}
				record.State = api.IamInstanceProfileAssociationStateASSOCIATED
				record.NextActionAt = time.Time{}
				instance.Data.IamInstanceProfile = record.profile()
				if err := tx.PutInstance(instance); err != nil {
					return err
				}
			case api.IamInstanceProfileAssociationStateDISASSOCIATING:
				rows, err := tx.InstanceProfileAssociations(instance.Key.Scope)
				if err != nil {
					return err
				}
				pendingReplacement := false
				for _, other := range rows {
					if other.InstanceID == instance.Key.ID && other.Key != record.Key && other.State == api.IamInstanceProfileAssociationStateASSOCIATING {
						pendingReplacement = true
						break
					}
				}
				if pendingReplacement {
					record.NextActionAt = s.clock.Now().Add(time.Second)
					if err := tx.PutInstanceProfileAssociation(record); err != nil {
						return err
					}
					count++
					continue
				}
				if err := tx.DeleteInstanceProfileAssociation(record.Key); err != nil {
					return err
				}
				if profile := instance.Data.IamInstanceProfile; profile != nil && str(profile.Id) == record.ProfileID && str(profile.Arn) == record.ProfileARN {
					instance.Data.IamInstanceProfile = nil
					if err := tx.PutInstance(instance); err != nil {
						return err
					}
				}
				count++
				continue
			case api.IamInstanceProfileAssociationStateDISASSOCIATED:
				if err := tx.DeleteInstanceProfileAssociation(record.Key); err != nil {
					return err
				}
				count++
				continue
			}
			if err := tx.PutInstanceProfileAssociation(record); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

func (s *Service) terminateInstanceProfileAssociations(tx Transaction, instance *InstanceRecord) error {
	records, err := tx.InstanceProfileAssociations(instance.Key.Scope)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.InstanceID != instance.Key.ID {
			continue
		}
		if err := tx.DeleteInstanceProfileAssociation(record.Key); err != nil {
			return err
		}
	}
	instance.Data.IamInstanceProfile = nil
	return nil
}

func (s *Service) refreshInstanceProfileDelivery(tx Transaction, instance ResourceKey) error {
	records, err := tx.InstanceProfileAssociations(instance.Scope)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.InstanceID != instance.ID || record.State == api.IamInstanceProfileAssociationStateDISASSOCIATED {
			continue
		}
		record.Credentials = InstanceCredentialReferences{}
		record.Timestamp = s.clock.Now()
		if err := tx.PutInstanceProfileAssociation(record); err != nil {
			return err
		}
	}
	return nil
}
