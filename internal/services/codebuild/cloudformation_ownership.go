package codebuild

import (
	"context"
	"errors"
)

type cfnOwnershipKey struct{}
type cfnOwnership struct {
	Kind, Claim, Target string
	Enforce             bool
	Rows                map[string]string
}

// WithCloudFormationOwnership supplies private source-credential ownership.
func WithCloudFormationOwnership(ctx context.Context, claim, target string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{Claim: claim, Target: target, Enforce: enforce, Rows: rows})
}

// WithCloudFormationResourceOwnership binds project/fleet admission and mutation
// to service-row claims. Public API tags never constitute ownership evidence.
func WithCloudFormationResourceOwnership(ctx context.Context, kind, claim, target string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{Kind: kind, Claim: claim, Target: target, Enforce: enforce, Rows: rows})
}

type cfnOwnershipTransaction struct {
	Transaction
	b *cfnOwnership
}

func bindCloudFormationOwnership(tx Transaction) Transaction {
	b, _ := tx.Context().Value(cfnOwnershipKey{}).(*cfnOwnership)
	return &cfnOwnershipTransaction{tx, b}
}
func (t *cfnOwnershipTransaction) observe(v CredentialRecord) error {
	if t.b == nil || t.b.Kind != "" {
		return nil
	}
	if t.b.Rows != nil {
		t.b.Rows[v.ARN] = v.Ownership
	}
	if t.b.Enforce && (t.b.Target == "" || t.b.Target == v.ARN) && v.Ownership != t.b.Claim {
		return failure("ResourceAlreadyExistsException", "Credential belongs to another CloudFormation incarnation")
	}
	return nil
}
func (t *cfnOwnershipTransaction) Credential(k CredentialKey) (CredentialRecord, error) {
	v, err := t.Transaction.Credential(k)
	if err == nil {
		err = t.observe(v)
	}
	return v, err
}
func (t *cfnOwnershipTransaction) Credentials(k Scope) ([]CredentialRecord, error) {
	rows, err := t.Transaction.Credentials(k)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if err = t.observe(v); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (t *cfnOwnershipTransaction) PutCredential(v CredentialRecord) error {
	old, err := t.Transaction.Credential(v.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		if err = t.observe(old); err != nil {
			return err
		}
		v.Ownership = old.Ownership
	}
	if t.b != nil && t.b.Kind == "" {
		v.Ownership = t.b.Claim
	}
	return t.Transaction.PutCredential(v)
}
func (t *cfnOwnershipTransaction) DeleteCredential(k CredentialKey) error {
	if v, err := t.Transaction.Credential(k); err == nil {
		if err = t.observe(v); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return t.Transaction.DeleteCredential(k)
}
func (t *cfnOwnershipTransaction) resource(kind, id, claim string) error {
	if t.b == nil || t.b.Kind != kind || !t.b.Enforce || (t.b.Target != "" && t.b.Target != id) {
		return nil
	}
	if claim != t.b.Claim {
		return failure("ResourceAlreadyExistsException", "Resource belongs to another CloudFormation incarnation")
	}
	return nil
}

// Only authorized batch reads publish claims to adapters.
func observeCloudFormationResource(ctx context.Context, kind, id, claim string) {
	b, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership)
	if b != nil && b.Kind == kind && b.Rows != nil {
		b.Rows[id] = claim
	}
}
func (t *cfnOwnershipTransaction) Project(k ProjectKey) (ProjectRecord, error) {
	v, err := t.Transaction.Project(k)
	if err == nil {
		err = t.resource("Project", k.Name, v.Ownership)
	}
	return v, err
}
func (t *cfnOwnershipTransaction) Fleet(k FleetKey) (FleetRecord, error) {
	v, err := t.Transaction.Fleet(k)
	if err == nil {
		err = t.resource("Fleet", value(v.Data.Arn), v.Ownership)
	}
	return v, err
}
func (t *cfnOwnershipTransaction) PutProject(v ProjectRecord) error {
	old, err := t.Transaction.Project(v.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		if err = t.resource("Project", old.Key.Name, old.Ownership); err != nil {
			return err
		}
		v.Ownership = old.Ownership
	} else if t.b != nil && t.b.Kind == "Project" {
		v.Ownership = t.b.Claim
	}
	return t.Transaction.PutProject(v)
}
func (t *cfnOwnershipTransaction) PutFleet(v FleetRecord) error {
	old, err := t.Transaction.Fleet(v.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		if err = t.resource("Fleet", value(old.Data.Arn), old.Ownership); err != nil {
			return err
		}
		v.Ownership = old.Ownership
	} else if t.b != nil && t.b.Kind == "Fleet" {
		v.Ownership = t.b.Claim
	}
	return t.Transaction.PutFleet(v)
}
func (t *cfnOwnershipTransaction) DeleteProject(k ProjectKey) error {
	if _, err := t.Project(k); err != nil {
		return err
	}
	return t.Transaction.DeleteProject(k)
}
func (t *cfnOwnershipTransaction) DeleteFleet(k FleetKey) error {
	if _, err := t.Fleet(k); err != nil {
		return err
	}
	return t.Transaction.DeleteFleet(k)
}
