package sesv2

import (
	"context"
	"errors"
)

type cfnOwnershipKey struct{}
type cfnOwnership struct {
	claim   string
	enforce bool
	rows    map[string]string
}

// WithCloudFormationOwnership binds SES admission and mutations to one private
// CloudFormation incarnation. Identities and configuration sets stamp claims
// only at creation and check them after IAM authorizes the native target.
// rows receives authorized identity/configuration-set claims keyed by ARN,
// and retained template claims keyed by template name. Direct writes retain claims.
func WithCloudFormationOwnership(ctx context.Context, claim string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{claim, enforce, rows})
}

type cfnOwnershipTransaction struct {
	Transaction
	b *cfnOwnership
}

func bindCloudFormationOwnership(tx Transaction) Transaction {
	b, _ := tx.Context().Value(cfnOwnershipKey{}).(*cfnOwnership)
	return &cfnOwnershipTransaction{tx, b}
}
func (t *cfnOwnershipTransaction) observe(v Template) error {
	if t.b == nil {
		return nil
	}
	if t.b.rows != nil {
		t.b.rows[v.Key.Name] = v.Owner
	}
	if t.b.enforce && v.Owner != t.b.claim {
		return failure("ConflictException", "The template belongs to another CloudFormation resource.", 409)
	}
	return nil
}
func (t *cfnOwnershipTransaction) Template(k ResourceKey) (Template, error) {
	v, e := t.Transaction.Template(k)
	if e == nil {
		e = t.observe(v)
	}
	return v, e
}
func (t *cfnOwnershipTransaction) PutTemplate(v Template) error {
	old, e := t.Transaction.Template(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if e == nil {
		if e = t.observe(old); e != nil {
			return e
		}
		v.Owner = old.Owner
	}
	if t.b != nil && t.b.claim != "" {
		v.Owner = t.b.claim
	}
	return t.Transaction.PutTemplate(v)
}
func (t *cfnOwnershipTransaction) DeleteTemplate(k ResourceKey) error {
	if v, e := t.Transaction.Template(k); e == nil {
		if e = t.observe(v); e != nil {
			return e
		}
	} else if !errors.Is(e, ErrNotFound) {
		return e
	}
	return t.Transaction.DeleteTemplate(k)
}

func cloudFormationOwner(ctx context.Context) string {
	if b, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership); b != nil {
		return b.claim
	}
	return ""
}

// observeCloudFormationResource is called after current IAM authorizes the
// target row, in the same native transaction as its mutation.
func observeCloudFormationResource(ctx context.Context, arn, owner string) error {
	b, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership)
	if b == nil {
		return nil
	}
	if b.enforce && (b.claim == "" || owner != b.claim) {
		return failure("ConflictException", "The resource belongs to another CloudFormation incarnation.", 409)
	}
	if b.rows != nil {
		b.rows[arn] = owner
	}
	return nil
}
