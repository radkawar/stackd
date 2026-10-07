package athena

import (
	"context"
	"errors"
)

// CloudFormationOwner is trusted controller context, never customer API input.
// Ownership is committed on the native resource record in the creation transaction.
type cloudFormationOwner struct{ Kind, Incarnation string }
type cloudFormationOwnerKey struct{}

func WithCloudFormationOwner(ctx context.Context, kind, incarnation string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{kind, incarnation})
}

type cloudFormationTx struct {
	Transaction
	owner cloudFormationOwner
}

func cloudFormationTransaction(tx Transaction, ctx context.Context) Transaction {
	owner, _ := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if owner.Kind == "" {
		return tx
	}
	return cloudFormationTx{tx, owner}
}
func (t cloudFormationTx) check(kind, owner string) error {
	if t.owner.Kind == kind && (t.owner.Incarnation == "" || owner != t.owner.Incarnation) {
		return failure("AlreadyExistsException", "Resource is not owned by this CloudFormation incarnation.")
	}
	return nil
}
func (t cloudFormationTx) NamedQuery(key ResourceKey) (NamedQueryRecord, error) {
	v, err := t.Transaction.NamedQuery(key)
	if err == nil {
		err = t.check("NamedQuery", v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutNamedQuery(v NamedQueryRecord) error {
	old, err := t.Transaction.NamedQuery(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == "NamedQuery" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutNamedQuery(v)
}
func (t cloudFormationTx) PreparedStatement(key StatementKey) (PreparedStatementRecord, error) {
	v, err := t.Transaction.PreparedStatement(key)
	if err == nil {
		err = t.check("PreparedStatement", v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutPreparedStatement(v PreparedStatementRecord) error {
	old, err := t.Transaction.PreparedStatement(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == "PreparedStatement" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutPreparedStatement(v)
}
func (t cloudFormationTx) NamedQueryByToken(scope Scope, token string) (NamedQueryRecord, error) {
	v, err := t.Transaction.NamedQueryByToken(scope, token)
	if err == nil {
		err = t.check("NamedQuery", v.CFNOwner)
	}
	return v, err
}

// Tagged parents claim one exact native ARN, so other same-kind rows read by
// the command stay ordinary IAM-authorized reads. Service defaults are never claimed.
func CloudFormationWorkGroupClaim(key ResourceKey) string   { return key.ARN("workgroup") }
func CloudFormationDataCatalogClaim(key ResourceKey) string { return key.ARN("datacatalog") }
func (t cloudFormationTx) WorkGroup(key ResourceKey) (WorkGroupRecord, error) {
	v, err := t.Transaction.WorkGroup(key)
	if err == nil {
		err = t.check(CloudFormationWorkGroupClaim(key), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutWorkGroup(v WorkGroupRecord) error {
	old, err := t.Transaction.WorkGroup(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == CloudFormationWorkGroupClaim(v.Key) && v.Key.Name != "primary" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutWorkGroup(v)
}
func (t cloudFormationTx) DeleteWorkGroup(key ResourceKey) error {
	if _, err := t.WorkGroup(key); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return t.Transaction.DeleteWorkGroup(key)
}
func (t cloudFormationTx) Catalog(key ResourceKey) (CatalogRecord, error) {
	v, err := t.Transaction.Catalog(key)
	if err == nil {
		err = t.check(CloudFormationDataCatalogClaim(key), v.CFNOwner)
	}
	return v, err
}
func (t cloudFormationTx) PutCatalog(v CatalogRecord) error {
	old, err := t.Transaction.Catalog(v.Key)
	if err == nil {
		v.CFNOwner = old.CFNOwner
	} else if !errors.Is(err, ErrNotFound) {
		return err
	} else if t.owner.Kind == CloudFormationDataCatalogClaim(v.Key) && v.Key.Name != "AwsDataCatalog" {
		v.CFNOwner = t.owner.Incarnation
	}
	return t.Transaction.PutCatalog(v)
}
func (t cloudFormationTx) DeleteCatalog(key ResourceKey) error {
	if _, err := t.Catalog(key); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return t.Transaction.DeleteCatalog(key)
}
