package opensearch

import (
	domain "stackd/storage/opensearch"
	"stackd/storage/sqlite/opensearch/internal/sqlcgen"
)

func (r reader) Domain(k domain.Key) (domain.Domain, error) {
	row, err := r.q.GetDomain(r.ctx, sqlcgen.GetDomainParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.Domain{}, missing(err)
	}
	return r.domain(row)
}

func (r reader) Domains(scope domain.Scope) ([]domain.Domain, error) {
	rows, err := r.q.ListDomains(r.ctx, sqlcgen.ListDomainsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.domains(rows)
}

func (r reader) AllDomains() ([]domain.Domain, error) {
	rows, err := r.q.AllDomains(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.domains(rows)
}

func (r reader) domains(rows []sqlcgen.OpensearchDomain) ([]domain.Domain, error) {
	out := make([]domain.Domain, 0, len(rows))
	for _, row := range rows {
		v, err := r.domain(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) domain(row sqlcgen.OpensearchDomain) (domain.Domain, error) {
	v := domain.Domain{
		Key:            domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		Incarnation:    row.Incarnation,
		EngineVersion:  row.EngineVersion,
		Status:         row.Status,
		NativeEndpoint: row.NativeEndpoint,
		LastError:      row.LastError,
		AccessPolicy:   row.AccessPolicy,
		InstanceType:   row.InstanceType,
		InstanceCount:  int32(row.InstanceCount),
		Created:        readTime(row.Created),
		Updated:        readTime(row.Updated),
		Due:            readTime(row.Due),
		Version:        row.Version,
		ConfigVersion:  row.ConfigVersion,
	}
	var err error
	v.AdvancedOptions, err = r.advancedOptions(v.Key)
	if err != nil {
		return domain.Domain{}, err
	}
	v.PolicyPrincipals, err = r.policyPrincipals(v.Key)
	if err != nil {
		return domain.Domain{}, err
	}
	v.Tags, err = r.tags(v.Key)
	return v, err
}

func (w writer) PutDomain(v domain.Domain) error {
	k := v.Key
	if err := w.q.PutDomain(w.ctx, sqlcgen.PutDomainParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		Incarnation:    v.Incarnation,
		EngineVersion:  v.EngineVersion,
		Status:         v.Status,
		NativeEndpoint: v.NativeEndpoint,
		LastError:      v.LastError,
		AccessPolicy:   v.AccessPolicy,
		InstanceType:   v.InstanceType,
		InstanceCount:  int64(v.InstanceCount),
		Created:        timeValue(v.Created),
		Updated:        timeValue(v.Updated),
		Due:            timeValue(v.Due),
		Version:        v.Version,
		ConfigVersion:  v.ConfigVersion,
	}); err != nil {
		return err
	}
	if err := w.putAdvancedOptions(k, v.AdvancedOptions); err != nil {
		return err
	}
	if err := w.putPolicyPrincipals(k, v.PolicyPrincipals); err != nil {
		return err
	}
	return w.putTags(k, v.Tags)
}

func (w writer) DeleteDomain(k domain.Key) error {
	return w.q.DeleteDomain(w.ctx, sqlcgen.DeleteDomainParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
