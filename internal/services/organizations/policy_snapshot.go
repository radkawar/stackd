package organizations

import (
	"context"
	"errors"

	"stackd/internal/awsctx"
)

// WithPolicySnapshot pins one detached caller-account SCP hierarchy while fn
// runs. Calls made through
// this service and the same account/partition reuse the snapshot; other scopes
// resolve independently. The callback context expires when fn returns and must
// not be retained for later authorization.
//
// The snapshot reuses decoded policies; its caller's storage transaction owns
// atomicity. A context borrowed from IAM keeps the shared domain locked through
// fn and credential publication. Without a borrowed transaction this is an
// independent read and subsequent Organizations writes may commit during fn.
func (s *Service) WithPolicySnapshot(ctx context.Context, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("organizations policy snapshot callback is required")
	}
	m := awsctx.FromContext(ctx)
	if m.Partition == "" || m.AccountID == "" {
		return errors.New("organizations policy snapshot requires a caller account and partition")
	}
	record, _, err := s.storage.Load(ctx, m.Partition)
	if err != nil {
		return err
	}
	worker := &operationState{serviceState: decodeState(record, m.Partition, m.AccountID)}
	snapshot := worker.callerPolicySnapshot(s)
	callbackCtx, cancel := context.WithCancel(context.WithValue(ctx, policySnapshotKey{}, snapshot))
	defer cancel()
	if err := callbackCtx.Err(); err != nil {
		return err
	}
	if err := fn(callbackCtx); err != nil {
		return err
	}
	return callbackCtx.Err()
}
