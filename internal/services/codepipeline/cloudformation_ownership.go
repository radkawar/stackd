package codepipeline

import "context"

type cfnOwnershipKey struct{}
type cfnUpdateKey struct{}

// WithCloudFormationUpdate atomically records an internal revision replay fence.
func WithCloudFormationUpdate(ctx context.Context, hash string) context.Context {
	return context.WithValue(ctx, cfnUpdateKey{}, hash)
}

type cfnOwnership struct {
	Claim, Name string
	Enforce     bool
	Rows        map[string]string
}

func WithCloudFormationOwnership(ctx context.Context, claim, name string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, cfnOwnership{claim, name, enforce, rows})
}

type cfnOwnershipTransaction struct {
	Transaction
	b cfnOwnership
}

func bindCloudFormationOwnership(tx Transaction) Transaction {
	b, ok := tx.Context().Value(cfnOwnershipKey{}).(cfnOwnership)
	if !ok {
		return tx
	}
	return &cfnOwnershipTransaction{tx, b}
}

func (t *cfnOwnershipTransaction) observe(v Pipeline) error {
	if v.Name != t.b.Name {
		return nil
	}
	if t.b.Rows != nil {
		t.b.Rows[v.Name] = v.Ownership
	}
	if t.b.Enforce && v.Ownership != t.b.Claim {
		return failure("ConflictException", "Pipeline belongs to another CloudFormation incarnation")
	}
	return nil
}

func (t *cfnOwnershipTransaction) Pipelines(scope Scope) ([]Pipeline, error) {
	rows, err := t.Transaction.Pipelines(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if err := t.observe(v); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func (t *cfnOwnershipTransaction) PutPipeline(v Pipeline) error {
	rows, err := t.Transaction.Pipelines(v.Scope)
	if err != nil {
		return err
	}
	exists := false
	for _, old := range rows {
		if old.Name != v.Name {
			continue
		}
		exists = true
		if err := t.observe(old); err != nil {
			return err
		}
		if v.Name == t.b.Name && !t.b.Enforce && old.Ownership != t.b.Claim {
			return failure("ConflictException", "Pipeline already exists outside this incarnation")
		}
		v.Ownership = old.Ownership
	}
	if v.Name == t.b.Name {
		if t.b.Enforce && !exists {
			return failure("ConflictException", "Pipeline incarnation no longer exists")
		}
		v.Ownership = t.b.Claim
	}
	return t.Transaction.PutPipeline(v)
}

func (t *cfnOwnershipTransaction) DeletePipeline(scope Scope, name string) error {
	if _, err := t.Pipelines(scope); err != nil {
		return err
	}
	return t.Transaction.DeletePipeline(scope, name)
}
