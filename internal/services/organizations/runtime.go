package organizations

import (
	"context"
	"errors"
	"net/http"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) execute(r *http.Request, action string, input any, fn func(*operationState, *http.Request) (any, *awswire.Error)) (result any, outcome *awswire.Error) {
	var output any
	var auditedCommit bool
	// Read and rejected outcomes run only after any role-inspection authority
	// closes. A CAS retry never publishes an attempt, and committed modeled
	// failures have already been recorded by the successful effects callback.
	defer func() {
		if !auditedCommit {
			if err := s.recordOutcome(r.Context(), action, input, output, outcome); err != nil {
				result, outcome = nil, storageFailure()
			}
		}
	}()
	m := awsctx.FromContext(r.Context())
	if m.Partition == "" || m.AccountID == "" {
		return nil, failure("AccessDeniedException", "An authenticated account and partition are required.")
	}
	s.mu.RLock()
	authorizer := s.authorizer
	provisioner := s.accountProvisioner
	roles := s.roleInspector
	s.mu.RUnlock()
	if action == "CreateAccount" && provisioner == nil {
		return nil, storageFailure()
	}
	for attempt := 0; attempt < 16; attempt++ {
		record, revision, err := s.storage.Load(r.Context(), m.Partition)
		if err != nil {
			return nil, storageFailure()
		}
		worker := &operationState{serviceState: decodeState(record, m.Partition, m.AccountID), tokenKey: s.tokenKey, instant: s.clock.Now(), accountQuota: s.accountQuotas.maximum(m.Partition, m.AccountID)}
		if action == "AcceptHandshake" {
			id := inputString(input.(interface{ ResourceHandshakeID() *string }).ResourceHandshakeID())
			worker.accountQuota = s.accountQuotas.maximum(m.Partition, worker.handshakes[id].ManagementAccountID)
		}

		var result any
		var committed bool
		attempt := func(ctx context.Context) error {
			worker.instant = s.clock.Now()
			var apiErr *awswire.Error
			result, committed, apiErr = s.executeAttempt(r.WithContext(ctx), action, input, worker, revision, authorizer, fn)
			if apiErr != nil {
				return apiErr
			}
			return nil
		}
		if accounts := worker.roleCheckAccounts(action, input); len(accounts) > 0 {
			if roles == nil {
				return nil, storageFailure()
			}
			err = roles.WithOrganizationServiceRoles(r.Context(), m.Partition, accounts, func(ctx context.Context, present map[string]bool) error {
				worker.serviceRoles = present
				return attempt(ctx)
			})
		} else {
			err = attempt(r.Context())
		}
		if err != nil {
			var apiErr *awswire.Error
			if errors.As(err, &apiErr) {
				return nil, apiErr
			}
			return nil, storageFailure()
		}
		if committed {
			output = worker.auditOutput
			auditedCommit = !readOnlyOperation(action)
			if action == "CreateAccount" || len(worker.events) > 0 {
				s.jobs.Wake()
			}
			return result, worker.afterCommitError
		}
	}
	return nil, failure("ConcurrentModificationException", "Organization state changed while authorizing this request; retry the operation.")
}

func (s *Service) executeAttempt(r *http.Request, action string, input any, worker *operationState, revision uint64, authorizer authorization.Authorizer, fn func(*operationState, *http.Request) (any, *awswire.Error)) (any, bool, *awswire.Error) {
	plan, apiErr := worker.authorizationPlan(r, action, input)
	if apiErr != nil {
		return nil, false, apiErr
	}
	ctx := context.WithValue(r.Context(), policySnapshotKey{}, worker.callerPolicySnapshot(s))
	for _, permission := range plan {
		permission.EvaluationTime = &worker.instant
		if err := authorizer.Authorize(ctx, permission); err != nil {
			return nil, false, failure("AccessDeniedException", err.Message)
		}
	}
	result, apiErr := fn(worker, r.WithContext(ctx))
	if apiErr != nil {
		return nil, false, apiErr
	}
	if readOnlyOperation(action) {
		return result, true, nil
	}
	if s.apiEvents != nil {
		call, err := auditOutcome(action, input, worker.auditOutput, worker.afterCommitError)
		if err != nil {
			return nil, false, storageFailure()
		}
		worker.auditCall = &call
	}
	committed, err := s.commit(r.Context(), worker.partition, revision, worker)
	if err != nil {
		if errors.As(err, &apiErr) {
			return nil, false, apiErr
		}
		return nil, false, storageFailure()
	}
	return result, committed, nil
}

func storageFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceException", Message: "Organizations storage transaction failed.", StatusCode: http.StatusInternalServerError}
}

type policySnapshotKey struct{}
type policySnapshot struct {
	source             *Service
	partition, account string
	levels             []iampolicy.PolicyLevel
	organization, path string
}

type organizationControlSource struct{ service *Service }

func (s organizationControlSource) PrincipalOrganization(ctx context.Context) (string, string, error) {
	return s.service.PrincipalOrganization(ctx)
}

func (s organizationControlSource) ServiceControlPolicies(ctx context.Context) ([]iampolicy.PolicyLevel, error) {
	return s.service.ServiceControlPolicies(ctx, awsctx.FromContext(ctx).AccountID)
}
