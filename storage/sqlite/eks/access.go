package eks

import (
	"encoding/json"

	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func (r reader) AccessEntry(k domain.Key, principal string) (domain.AccessEntry, error) {
	row, err := r.q.GetAccessEntry(r.ctx, sqlcgen.GetAccessEntryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PrincipalArn: principal})
	if err != nil {
		return domain.AccessEntry{}, missing(err)
	}
	return accessEntry(row)
}
func (r reader) AccessEntries(k domain.Key) ([]domain.AccessEntry, error) {
	rows, err := r.q.ListAccessEntries(r.ctx, sqlcgen.ListAccessEntriesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AccessEntry, 0, len(rows))
	for _, row := range rows {
		v, err := accessEntry(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func accessEntry(row sqlcgen.EksAccessEntry) (domain.AccessEntry, error) {
	v := domain.AccessEntry{
		Key:          domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		PrincipalARN: row.PrincipalArn, PrincipalID: row.PrincipalID, Username: row.Username, Type: row.Type,
		ID: row.ID, ClientToken: row.ClientToken, RequestHash: row.RequestHash,
		Created: readTime(row.Created), Modified: readTime(row.Modified),
	}
	if err := json.Unmarshal([]byte(row.Groups), &v.Groups); err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(row.Tags), &v.Tags); err != nil {
		return v, err
	}
	return v, nil
}
func (w writer) PutAccessEntry(v domain.AccessEntry) error {
	groups, err := encodeStrings(v.Groups)
	if err != nil {
		return err
	}
	tags, err := encodeTags(v.Tags)
	if err != nil {
		return err
	}
	k := v.Key
	return w.q.PutAccessEntry(w.ctx, sqlcgen.PutAccessEntryParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		PrincipalArn: v.PrincipalARN, PrincipalID: v.PrincipalID, Username: v.Username, Type: v.Type,
		ID: v.ID, ClientToken: v.ClientToken, RequestHash: v.RequestHash,
		Groups: groups, Tags: tags, Created: timeValue(v.Created), Modified: timeValue(v.Modified),
	})
}
func (w writer) DeleteAccessEntry(k domain.Key, principal string) error {
	if err := w.q.DeletePrincipalMutations(w.ctx, sqlcgen.DeletePrincipalMutationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PrincipalArn: principal}); err != nil {
		return err
	}
	if err := w.q.DeletePrincipalPolicies(w.ctx, sqlcgen.DeletePrincipalPoliciesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PrincipalArn: principal}); err != nil {
		return err
	}
	return w.q.DeleteAccessEntry(w.ctx, sqlcgen.DeleteAccessEntryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PrincipalArn: principal})
}
func (r reader) AccessPolicies(k domain.Key, principal string) ([]domain.AccessPolicy, error) {
	rows, err := r.q.ListAccessPolicies(r.ctx, sqlcgen.ListAccessPoliciesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PrincipalArn: principal})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AccessPolicy, 0, len(rows))
	for _, row := range rows {
		v := domain.AccessPolicy{
			Key:          domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
			PrincipalARN: row.PrincipalArn, PolicyARN: row.PolicyArn, ScopeType: row.ScopeType,
			Associated: readTime(row.Associated), Modified: readTime(row.Modified),
		}
		if err := json.Unmarshal([]byte(row.Namespaces), &v.Namespaces); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutAccessPolicy(v domain.AccessPolicy) error {
	namespaces, err := encodeStrings(v.Namespaces)
	if err != nil {
		return err
	}
	k := v.Key
	return w.q.PutAccessPolicy(w.ctx, sqlcgen.PutAccessPolicyParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		PrincipalArn: v.PrincipalARN, PolicyArn: v.PolicyARN, ScopeType: v.ScopeType,
		Namespaces: namespaces, Associated: timeValue(v.Associated), Modified: timeValue(v.Modified),
	})
}
func (w writer) DeleteAccessPolicy(k domain.Key, principal, policy string) error {
	return w.q.DeleteAccessPolicy(w.ctx, sqlcgen.DeleteAccessPolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PrincipalArn: principal, PolicyArn: policy})
}

func (r reader) AccessMutation(k domain.Key, principal, token string) (domain.AccessMutation, error) {
	row, err := r.q.GetAccessMutation(r.ctx, sqlcgen.GetAccessMutationParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		PrincipalArn: principal, Token: token,
	})
	if err != nil {
		return domain.AccessMutation{}, missing(err)
	}
	return domain.AccessMutation{
		Key:          domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		PrincipalARN: row.PrincipalArn, Token: row.Token, RequestHash: row.RequestHash,
	}, nil
}

func (w writer) PutAccessMutation(v domain.AccessMutation) error {
	k := v.Key
	return w.q.PutAccessMutation(w.ctx, sqlcgen.PutAccessMutationParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		PrincipalArn: v.PrincipalARN, Token: v.Token, RequestHash: v.RequestHash,
	})
}
