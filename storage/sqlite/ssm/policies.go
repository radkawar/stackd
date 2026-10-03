package ssm

import (
	"stackd/storage/sqlite/ssm/internal/sqlcgen"
	domain "stackd/storage/ssm"
)

func (r reader) parameterPolicies(id int64) ([]domain.ParameterPolicy, error) {
	rows, err := r.q.ListParameterPolicies(r.ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ParameterPolicy, 0, len(rows))
	for _, row := range rows {
		p := domain.ParameterPolicy{Type: row.Type, Version: row.Version, Fired: row.Fired}
		if row.Due.Valid {
			p.Due = row.Due.Time.UTC()
		}
		if row.AttributesPresent {
			attributes, err := r.q.ListParameterPoliciesAttributes(r.ctx, row.ID)
			if err != nil {
				return nil, err
			}
			p.Attributes = make(map[string]string, len(attributes))
			for _, a := range attributes {
				p.Attributes[a.MapKey] = a.Value
			}
		}
		out = append(out, p)
	}
	return out, nil
}
func (w writer) putParameterPolicies(id int64, policies []domain.ParameterPolicy) error {
	if err := w.q.DeleteParameterPolicies(w.ctx, id); err != nil {
		return err
	}
	for i, p := range policies {
		policyID, err := w.q.PutParameterPolicies(w.ctx, sqlcgen.PutParameterPoliciesParams{ParentID: id, Position: int64(i), Type: p.Type, Version: p.Version, AttributesPresent: p.Attributes != nil, Due: policyTime(p.Due), Fired: p.Fired})
		if err != nil {
			return err
		}
		for key, value := range p.Attributes {
			if err := w.q.PutParameterPoliciesAttributes(w.ctx, sqlcgen.PutParameterPoliciesAttributesParams{ParentID: policyID, MapKey: key, Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r reader) versionPolicies(id int64) ([]domain.ParameterPolicy, error) {
	rows, err := r.q.ListVersionPolicies(r.ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ParameterPolicy, 0, len(rows))
	for _, row := range rows {
		p := domain.ParameterPolicy{Type: row.Type, Version: row.Version, Fired: row.Fired}
		if row.Due.Valid {
			p.Due = row.Due.Time.UTC()
		}
		if row.AttributesPresent {
			attributes, err := r.q.ListVersionPoliciesAttributes(r.ctx, row.ID)
			if err != nil {
				return nil, err
			}
			p.Attributes = make(map[string]string, len(attributes))
			for _, a := range attributes {
				p.Attributes[a.MapKey] = a.Value
			}
		}
		out = append(out, p)
	}
	return out, nil
}
func (w writer) putVersionPolicies(id int64, policies []domain.ParameterPolicy) error {
	if err := w.q.DeleteVersionPolicies(w.ctx, id); err != nil {
		return err
	}
	for i, p := range policies {
		policyID, err := w.q.PutVersionPolicies(w.ctx, sqlcgen.PutVersionPoliciesParams{ParentID: id, Position: int64(i), Type: p.Type, Version: p.Version, AttributesPresent: p.Attributes != nil, Due: policyTime(p.Due), Fired: p.Fired})
		if err != nil {
			return err
		}
		for key, value := range p.Attributes {
			if err := w.q.PutVersionPoliciesAttributes(w.ctx, sqlcgen.PutVersionPoliciesAttributesParams{ParentID: policyID, MapKey: key, Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}
