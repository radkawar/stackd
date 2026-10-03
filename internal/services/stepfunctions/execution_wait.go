package stepfunctions

import (
	"context"

	api "stackd/internal/awsapi/stepfunctions"
)

// WaitExecution is the trusted same-account service-completion observation used
// by nested .sync tasks. Public DescribeExecution retains its independent IAM
// boundary; cross-account adapters must poll that authorized public command.
func (s *Service) WaitExecution(ctx context.Context, arn string) (*api.DescribeExecutionOutput, error) {
	for {
		s.mu.Lock()
		changed := s.changed
		s.mu.Unlock()
		var result *api.DescribeExecutionOutput
		if err := s.repository.Update(ctx, func(r Transaction) error {
			key, err := executionKeyFor(r, arn)
			if err != nil {
				return err
			}
			execution, _, err := s.retainedExecution(r, key)
			if err != nil {
				return err
			}
			if execution.Status == "RUNNING" || execution.Status == "PENDING" || execution.Status == "PENDING_REDRIVE" {
				return nil
			}
			if execution.Encrypted != nil {
				revision, readErr := r.Revision(RevisionKey{Scope: key.Scope, ID: execution.RevisionID})
				if readErr != nil {
					return readErr
				}
				execution, err = s.workflowReader(r, revision, revision.RoleARN).execution(execution)
				if err != nil {
					return err
				}
			}
			result = s.executionDescription(execution)
			return nil
		}); err != nil || result != nil {
			return result, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-changed:
		}
	}
}
