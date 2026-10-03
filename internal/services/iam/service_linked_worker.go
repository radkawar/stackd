package iam

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"stackd/internal/identity"
)

type serviceLinkedRuntime struct {
	mu              sync.Mutex
	templates       map[string]serviceLinkedRegistration
	started, closed bool
	ctx             context.Context
	cancel          context.CancelFunc
	checks          sync.WaitGroup
	inflight        map[string]struct{}
	retryAt         map[string]time.Time
}

func (s *Service) initServiceLinkedRoles() {
	ctx, cancel := context.WithCancel(context.Background())
	s.serviceLinked = &serviceLinkedRuntime{
		templates: make(map[string]serviceLinkedRegistration), ctx: ctx, cancel: cancel,
		inflight: make(map[string]struct{}), retryAt: make(map[string]time.Time),
	}
	for _, template := range builtinServiceLinkedTemplates() {
		s.serviceLinked.templates[serviceLinkedTemplateKey(template.Partition, template.ServiceName)] = serviceLinkedRegistration{template: template, usage: absentServiceLinkedProvider{}, absent: true}
	}
	template := roleManagerRoleTemplate()
	s.serviceLinked.templates[serviceLinkedTemplateKey(template.Partition, template.ServiceName)] = serviceLinkedRegistration{template: template, usage: roleManagerRoleUsage{repository: s.repository}}
}

func (s *Service) processServiceLinkedRoleDeletion(ctx context.Context, scope Scope, id string) error {
	var job ServiceLinkedRoleDeletion
	eligible := false
	err := s.repository.Update(ctx, func(tx WriteTx) error {
		now := s.clock.Now().UTC()
		var err error
		job, err = tx.ServiceLinkedRoleDeletion(scope, id)
		if err != nil {
			return err
		}
		if !serviceLinkedPending(job.Status) || job.CreatedAt.After(now) {
			return nil
		}
		eligible = true
		job.Status = serviceLinkedInProgress
		job.UpdatedAt = now
		return tx.PutServiceLinkedRoleDeletion(scope, job)
	})
	if err != nil || !eligible {
		return err
	}
	s.serviceLinked.mu.Lock()
	registration, ok := s.serviceLinked.templates[serviceLinkedTemplateKey(scope.Partition, job.ServiceName)]
	s.serviceLinked.mu.Unlock()
	if !ok {
		return s.finishServiceLinkedDeletion(ctx, scope, id, nil, "The linked service's deletion checker is not installed.")
	}
	ref := ServiceLinkedRoleReference{Scope: scope, ID: job.RoleID, ARN: job.RoleARN, Name: job.RoleName, ServiceName: job.ServiceName}
	called := false
	var transactionErr error
	err = registration.usage.WithServiceLinkedRoleUsage(ctx, ref, func(ctx context.Context, usage []ServiceLinkedRoleUsage) error {
		if called {
			return errors.New("service-linked usage provider called completion more than once")
		}
		called = true
		reason := ""
		if len(usage) > 0 {
			reason = registration.template.UsageFailureReason
		}
		transactionErr = s.finishServiceLinkedDeletion(ctx, scope, id, usage, reason)
		return transactionErr
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if transactionErr != nil {
		return transactionErr
	}
	var inUse *ServiceLinkedRoleInUseError
	if errors.As(err, &inUse) {
		return s.finishServiceLinkedDeletion(ctx, scope, id, nil, inUse.Error())
	}
	if err != nil || !called {
		// Provider errors fail closed; no resource mutation happens on an
		// unavailable usage check. Terminal FAILED allows an explicit retry.
		return s.finishServiceLinkedDeletion(ctx, scope, id, nil, "The linked service could not verify whether this role is still in use.")
	}
	return nil
}

func (s *Service) finishServiceLinkedDeletion(ctx context.Context, scope Scope, id string, usage []ServiceLinkedRoleUsage, failure string) error {
	return s.repository.Update(ctx, func(tx WriteTx) error {
		now := s.clock.Now().UTC()
		job, err := tx.ServiceLinkedRoleDeletion(scope, id)
		if err != nil {
			return err
		}
		if !serviceLinkedPending(job.Status) {
			return nil
		}
		job.UpdatedAt = now
		job.Usage = normalizedServiceLinkedUsage(usage)
		if failure == "" && len(job.Usage) > 0 {
			failure = "The service-linked role is still being used by dependent resources."
		}
		r, err := tx.Role(scope, job.RoleName)
		if err != nil && !errors.Is(err, ErrRecordNotFound) {
			return err
		}
		if err == nil && (r.RoleId != job.RoleID || r.ServiceLinkedService != job.ServiceName) {
			failure = "The role identity no longer matches this deletion request."
		}
		if failure == "" && err == nil {
			sessions, err := tx.PrincipalCredentials(scope.AccountID, job.RoleID)
			if err != nil {
				return err
			}
			for _, session := range sessions {
				c := session.Credential
				if c.IssuerARN == job.RoleARN && c.IssuerID == job.RoleID && session.Status == identity.Active && c.SessionToken != "" && c.Expiration.After(job.UpdatedAt) {
					failure = "The service-linked role has active sessions. Wait for those sessions to expire before deleting it."
					break
				}
			}
			profiles, err := tx.InstanceProfiles(scope)
			if err != nil {
				return err
			}
			for _, profile := range profiles {
				if profile.RoleId == job.RoleID {
					failure = "The service-linked role is still associated with an instance profile."
				}
			}
		}
		if failure != "" {
			job.Status = serviceLinkedFailed
			job.FailureReason = failure
		} else {
			if err == nil {
				if err := tx.DeleteRole(scope, job.RoleName); err != nil {
					return err
				}
			}
			job.Status = serviceLinkedSucceeded
			job.FailureReason = ""
			job.Usage = nil
		}
		return tx.PutServiceLinkedRoleDeletion(scope, job)
	})
}

func normalizedServiceLinkedUsage(usage []ServiceLinkedRoleUsage) []ServiceLinkedRoleUsage {
	byRegion := make(map[string][]string)
	for _, u := range usage {
		byRegion[u.Region] = append(byRegion[u.Region], u.ResourceARNs...)
	}
	result := make([]ServiceLinkedRoleUsage, 0, len(byRegion))
	for region, resources := range byRegion {
		slices.Sort(resources)
		result = append(result, ServiceLinkedRoleUsage{Region: region, ResourceARNs: slices.Compact(resources)})
	}
	slices.SortFunc(result, func(a, b ServiceLinkedRoleUsage) int { return strings.Compare(a.Region, b.Region) })
	return result
}
