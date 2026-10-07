package ssm

import (
	"stackd/internal/authorization"
	"stackd/storage/sqlite/ssm/internal/sqlcgen"
	domain "stackd/storage/ssm"
)

func (r reader) Parameter(k domain.ParameterKey) (domain.ParameterRecord, error) {
	v, err := r.q.GetParameter(r.ctx, sqlcgen.GetParameterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.ParameterRecord{}, missing(err)
	}
	return r.parameter(v)
}
func (r reader) Parameters(scope domain.Scope) ([]domain.ParameterRecord, error) {
	rows, err := r.q.ListParameters(r.ctx, sqlcgen.ListParametersParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ParameterRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.parameter(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) NextPolicy() (domain.ParameterRecord, error) {
	row, err := r.q.NextPolicy(r.ctx)
	if err != nil {
		return domain.ParameterRecord{}, missing(err)
	}
	return r.parameter(row)
}
func (r reader) parameter(row sqlcgen.SsmParameter) (domain.ParameterRecord, error) {
	out := domain.ParameterRecord{Key: domain.ParameterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}, ARN: row.Arn, Type: row.Type, Tier: row.Tier, DataType: row.DataType, Description: row.Description, AllowedPattern: row.AllowedPattern, CurrentVersion: row.CurrentVersion}
	out.Incarnation, out.CloudFormationOwner = row.Incarnation, row.CloudformationOwner
	if row.TagsPresent {
		tags, err := r.q.ListTags(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Tags = make(map[string]string, len(tags))
		for _, tag := range tags {
			out.Tags[tag.MapKey] = tag.Value
		}
	}
	if row.PoliciesPresent {
		policies, err := r.parameterPolicies(row.ID)
		if err != nil {
			return out, err
		}
		out.Policies = policies
	}
	if row.ResourcePoliciesPresent {
		policies, err := r.q.ListResourcePolicies(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.ResourcePolicies = make([]domain.ResourcePolicy, 0, len(policies))
		for _, policy := range policies {
			p := domain.ResourcePolicy{ID: policy.PolicyID, Hash: policy.Hash, Policy: authorization.BoundPolicy{Document: policy.Document, TrustPolicy: policy.TrustPolicy}, CloudFormationOwner: policy.CloudformationOwner}
			if policy.PrincipalsPresent {
				bindings, err := r.q.ListResourcePolicyBindings(r.ctx, policy.ID)
				if err != nil {
					return out, err
				}
				p.Policy.PrincipalIDs = make(map[string]string, len(bindings))
				for _, b := range bindings {
					p.Policy.PrincipalIDs[b.Arn] = b.PrincipalID
				}
			}
			out.ResourcePolicies = append(out.ResourcePolicies, p)
		}
	}
	return out, nil
}
func (w writer) PutParameter(v domain.ParameterRecord) error {
	k := v.Key
	id, err := w.q.PutParameter(w.ctx, sqlcgen.PutParameterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Arn: v.ARN, Incarnation: v.Incarnation, CloudformationOwner: v.CloudFormationOwner, Type: v.Type, Tier: v.Tier, DataType: v.DataType, Description: v.Description, AllowedPattern: v.AllowedPattern, CurrentVersion: v.CurrentVersion, TagsPresent: v.Tags != nil, PoliciesPresent: v.Policies != nil, ResourcePoliciesPresent: v.ResourcePolicies != nil})
	if err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, id); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutTags(w.ctx, sqlcgen.PutTagsParams{ParentID: id, MapKey: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.putParameterPolicies(id, v.Policies); err != nil {
		return err
	}
	if err := w.q.DeleteResourcePolicies(w.ctx, id); err != nil {
		return err
	}
	for i, p := range v.ResourcePolicies {
		policyID, err := w.q.PutResourcePolicies(w.ctx, sqlcgen.PutResourcePoliciesParams{ParentID: id, Position: int64(i), PolicyID: p.ID, Hash: p.Hash, Document: p.Policy.Document, TrustPolicy: p.Policy.TrustPolicy, PrincipalsPresent: p.Policy.PrincipalIDs != nil, CloudformationOwner: p.CloudFormationOwner})
		if err != nil {
			return err
		}
		for arn, principal := range p.Policy.PrincipalIDs {
			if err := w.q.PutResourcePolicyBindings(w.ctx, sqlcgen.PutResourcePolicyBindingsParams{ParentID: policyID, Arn: arn, PrincipalID: principal}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteParameter(k domain.ParameterKey) error {
	return w.q.DeleteParameter(w.ctx, sqlcgen.DeleteParameterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
