package organizations

import (
	"context"
	"errors"
	"time"
)

// AccountProvisioning requests initial account settings and IAM roles when creating an
// organization or member account, or accepting an invitation. An empty
// AccessRoleName provisions only the Organizations service-linked role; it does
// not replace account metadata or copy contacts.
// Organizations owns account allocation, validation and creation time; IAM
// owns the roles, trust, attachments and protected service ownership.
type AccountProvisioning struct {
	Partition, AccountID, AccountName, ManagementAccountID, AccessRoleName string
	CreatedAt                                                              time.Time
}

// AccountProvisioner commits initial contacts, roles and the Organizations callback
// in one transaction. The callback must use its supplied context to join that
// transaction. Errors and cancellation roll back all participating services. Implementations
// must not perform external effects or retain the callback context.
type AccountProvisioner interface {
	WithAccountProvisioning(context.Context, AccountProvisioning, func(context.Context) error) error
}

// SetAccountProvisioner connects account initialization before serving requests.
func (s *Service) SetAccountProvisioner(provisioner AccountProvisioner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accountProvisioner = provisioner
}

var errProvisioningConflict = errors.New("organization changed during account provisioning")

func (s *Service) commit(ctx context.Context, partition string, revision uint64, worker *operationState) (bool, error) {
	record := worker.record()
	var effects func(context.Context) error
	if len(worker.events) > 0 && s.events != nil || worker.auditCall != nil {
		effects = func(ctx context.Context) error {
			for _, event := range worker.events {
				if s.events == nil {
					break
				}
				var err error
				switch {
				case event.EffectivePolicyChanged.PolicyType != "":
					err = s.events.AppendEffectivePolicyChanged(ctx, event.Envelope, event.EffectivePolicyChanged)
				case event.AccountCreationChanged.CreationRequestID != "":
					err = s.events.AppendAccountCreationChanged(ctx, event.Envelope, event.AccountCreationChanged)
				default:
					err = s.events.AppendHandshakeChanged(ctx, event.Envelope, event.HandshakeChanged)
				}
				if err != nil {
					return err
				}
			}
			if worker.auditCall != nil {
				return s.recordCall(ctx, *worker.auditCall)
			}
			return nil
		}
	}
	if worker.accountProvisioning == nil {
		return s.storage.CompareAndSwap(ctx, partition, revision, record, effects)
	}
	s.mu.RLock()
	provisioner := s.accountProvisioner
	s.mu.RUnlock()
	if provisioner == nil {
		return false, errors.New("IAM account provisioning is not configured")
	}
	err := provisioner.WithAccountProvisioning(ctx, *worker.accountProvisioning, func(ctx context.Context) error {
		committed, err := s.storage.CompareAndSwap(ctx, partition, revision, record, effects)
		if err != nil {
			return err
		}
		if !committed {
			return errProvisioningConflict
		}
		return nil
	})
	if errors.Is(err, errProvisioningConflict) {
		// Aborting the authority leaves no role before the operation reloads
		// Organizations state and repeats authorization.
		return false, nil
	}
	return err == nil, err
}
