package dynamodb

import (
	engine "stackd/engine/dynamodb"
	"stackd/internal/authorization"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func databaseRecord(row sqlcgen.DynamodbDatabase) domain.DatabaseRecord {
	return domain.DatabaseRecord{Spec: engine.Specification{ID: row.ID, Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Retiring: row.Retiring}
}

func (r reader) Database(k domain.Scope) (domain.DatabaseRecord, error) {
	row, err := r.q.GetDatabase(r.ctx, sqlcgen.GetDatabaseParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return domain.DatabaseRecord{}, missing(err)
	}
	return databaseRecord(row), nil
}

func (r reader) Databases() ([]domain.DatabaseRecord, error) {
	rows, err := r.q.ListDatabases(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DatabaseRecord, len(rows))
	for i, row := range rows {
		out[i] = databaseRecord(row)
	}
	return out, nil
}

func (w writer) PutDatabase(v domain.DatabaseRecord) error {
	s := v.Spec
	return w.q.PutDatabase(w.ctx, sqlcgen.PutDatabaseParams{ID: s.ID, Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Retiring: v.Retiring})
}

func (w writer) DeleteDatabase(id string) error { return w.q.DeleteDatabase(w.ctx, id) }

func (r reader) Policy(k domain.PolicyKey) (domain.PolicyRecord, error) {
	row, err := r.q.GetPolicy(r.ctx, sqlcgen.GetPolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN})
	if err != nil {
		return domain.PolicyRecord{}, missing(err)
	}
	out := domain.PolicyRecord{Key: k, Policy: authorization.BoundPolicy{Document: row.Document}, Revision: row.Revision}
	if row.PrincipalsPresent {
		principals, err := r.q.ListPolicyPrincipals(r.ctx, sqlcgen.ListPolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN})
		if err != nil {
			return out, err
		}
		out.Policy.PrincipalIDs = make(map[string]string, len(principals))
		for _, principal := range principals {
			out.Policy.PrincipalIDs[principal.PrincipalArn] = principal.PrincipalID
		}
	}
	return out, nil
}

func (w writer) PutPolicy(v domain.PolicyRecord) error {
	k := v.Key
	if err := w.q.PutPolicy(w.ctx, sqlcgen.PutPolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN, Document: v.Policy.Document, Revision: v.Revision, PrincipalsPresent: v.Policy.PrincipalIDs != nil}); err != nil {
		return err
	}
	if err := w.q.DeletePolicyPrincipals(w.ctx, sqlcgen.DeletePolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN}); err != nil {
		return err
	}
	for arn, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutPolicyPrincipal(w.ctx, sqlcgen.PutPolicyPrincipalParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN, PrincipalArn: arn, PrincipalID: id}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeletePolicy(k domain.PolicyKey) error {
	return w.q.DeletePolicy(w.ctx, sqlcgen.DeletePolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceArn: k.ResourceARN})
}
