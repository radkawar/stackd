package ecr

import (
	"context"
	"errors"
)

type cfnOwnershipKey struct{}
type cfnOwnership struct {
	Kind, Claim      string
	Enforce, Release bool
	Rows             map[string]string
}

func WithCloudFormationOwnership(ctx context.Context, kind, claim string, enforce, release bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{kind, claim, enforce, release, rows})
}

type cfnOwnershipTransaction struct {
	Transaction
	b *cfnOwnership
}

func bindCloudFormationOwnership(tx Transaction) Transaction {
	b, _ := tx.Context().Value(cfnOwnershipKey{}).(*cfnOwnership)
	if b == nil {
		return tx
	}
	return &cfnOwnershipTransaction{tx, b}
}
func (t *cfnOwnershipTransaction) claim(v *RegistryRecord) *string {
	switch t.b.Kind {
	case "RegistryPolicy":
		return &v.PolicyOwnership
	case "ReplicationConfiguration":
		return &v.ReplicationOwnership
	case "RegistryScanningConfiguration":
		return &v.ScanningOwnership
	}
	return nil
}
func (t *cfnOwnershipTransaction) observe(v RegistryRecord) error {
	claim := t.claim(&v)
	if claim == nil {
		return nil
	}
	if t.b.Rows != nil {
		t.b.Rows[v.Scope.AccountID] = *claim
	}
	if t.b.Enforce && *claim != t.b.Claim {
		absent := false
		if t.b.Release && *claim == "" {
			switch t.b.Kind {
			case "RegistryPolicy":
				absent = v.Policy.Document == ""
			case "ReplicationConfiguration":
				absent = len(v.Replication.Rules) == 0
			case "RegistryScanningConfiguration":
				absent = value(v.Scanning.ScanType) == "BASIC" && len(v.Scanning.Rules) == 0
			}
		}
		if !absent {
			return failure("InvalidParameterException", "Registry resource belongs to another CloudFormation incarnation")
		}
	}
	return nil
}
func (t *cfnOwnershipTransaction) Registry(k Scope) (RegistryRecord, error) {
	v, e := t.Transaction.Registry(k)
	if e == nil {
		e = t.observe(v)
	}
	return v, e
}
func (t *cfnOwnershipTransaction) PutRegistry(v RegistryRecord) error {
	old, e := t.Transaction.Registry(v.Scope)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if errors.Is(e, ErrNotFound) && t.b.Enforce && !t.b.Release {
		return failure("InvalidParameterException", "Registry incarnation no longer exists")
	}
	if e == nil {
		if e = t.observe(old); e != nil {
			return e
		}
		claim := t.claim(&old)
		if claim != nil && !t.b.Enforce && *claim != t.b.Claim {
			occupied := *claim != ""
			switch t.b.Kind {
			case "RegistryPolicy":
				occupied = occupied || old.Policy.Document != ""
			case "ReplicationConfiguration":
				occupied = occupied || len(old.Replication.Rules) > 0
			case "RegistryScanningConfiguration":
				occupied = occupied || value(old.Scanning.ScanType) != "BASIC" || len(old.Scanning.Rules) > 0
			}
			if occupied {
				return failure("InvalidParameterException", "Registry resource is already configured outside this incarnation")
			}
		}
	}
	if claim := t.claim(&v); claim != nil {
		if t.b.Release {
			*claim = ""
		} else {
			*claim = t.b.Claim
		}
	}
	return t.Transaction.PutRegistry(v)
}

// RepositoryOwnershipKind binds a private repository incarnation claim. Bound
// CreateRepository stamps it in the admitting transaction; ordinary writes
// preserve the stored claim, so public tags can neither forge nor transfer it.
const RepositoryOwnershipKind = "Repository"

func repositoryOwnershipConflict() error {
	return failure("InvalidParameterException", "Repository belongs to another CloudFormation incarnation")
}

// fenceRepository runs after current IAM authorized the exact repository. It
// records the observed private claim and, for enforcing owners, rejects any
// other incarnation, including native same-name recreations.
func fenceRepository(tx Transaction, repo RepositoryRecord) error {
	t, ok := tx.(*cfnOwnershipTransaction)
	if !ok || t.b.Kind != RepositoryOwnershipKind {
		return nil
	}
	if t.b.Rows != nil {
		t.b.Rows[repo.ARN] = repo.Ownership
	}
	if t.b.Enforce && repo.Ownership != t.b.Claim {
		return repositoryOwnershipConflict()
	}
	return nil
}
func (t *cfnOwnershipTransaction) PutRepository(v RepositoryRecord) error {
	if t.b.Kind != RepositoryOwnershipKind {
		return t.Transaction.PutRepository(v)
	}
	old, err := t.Transaction.Repository(v.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil && old.Ownership != t.b.Claim {
		return repositoryOwnershipConflict()
	}
	if err != nil && t.b.Enforce {
		return failure("RepositoryNotFoundException", "Repository incarnation no longer exists")
	}
	v.Ownership = t.b.Claim
	return t.Transaction.PutRepository(v)
}
func (t *cfnOwnershipTransaction) DeleteRepository(k RepositoryKey) error {
	if t.b.Kind == RepositoryOwnershipKind {
		old, err := t.Transaction.Repository(k)
		if err != nil {
			return err
		}
		if old.Ownership != t.b.Claim {
			return repositoryOwnershipConflict()
		}
	}
	return t.Transaction.DeleteRepository(k)
}
