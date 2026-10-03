package lambda

import (
	"database/sql"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) FunctionPolicy(key domain.FunctionReference) (domain.FunctionPolicy, error) {
	row, err := r.q.GetFunctionPolicy(r.ctx, sqlcgen.GetFunctionPolicyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FunctionPolicy{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.FunctionPolicy{}, err
	}
	principals, err := r.q.GetFunctionPolicyPrincipals(r.ctx, sqlcgen.GetFunctionPolicyPrincipalsParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier})
	if err != nil {
		return domain.FunctionPolicy{}, err
	}
	result := domain.FunctionPolicy{Key: key, Document: row.Document, Revision: row.Revision, PrincipalIDs: make(map[string]string, len(principals)), Owner: domain.FunctionPolicyOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}}
	for _, principal := range principals {
		result.PrincipalIDs[principal.Principal] = principal.PrincipalID
	}
	return result, nil
}

func (w writer) PutFunctionPolicy(value domain.FunctionPolicy) error {
	key := value.Key
	if err := w.q.PutFunctionPolicy(w.ctx, sqlcgen.PutFunctionPolicyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier, Document: value.Document, Revision: value.Revision, OwnerStackID: value.Owner.StackID, OwnerLogicalID: value.Owner.LogicalID, OwnerToken: value.Owner.Token}); err != nil {
		return err
	}
	if err := w.q.DeleteFunctionPolicyPrincipals(w.ctx, sqlcgen.DeleteFunctionPolicyPrincipalsParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier}); err != nil {
		return err
	}
	for principal, id := range value.PrincipalIDs {
		if err := w.q.PutFunctionPolicyPrincipal(w.ctx, sqlcgen.PutFunctionPolicyPrincipalParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier, Principal: principal, PrincipalID: id}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteFunctionPolicy(key domain.FunctionReference) error {
	return w.q.DeleteFunctionPolicy(w.ctx, sqlcgen.DeleteFunctionPolicyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier})
}
