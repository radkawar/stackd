package identitycenter

import (
	"maps"
	"slices"
	"time"

	domain "stackd/storage/identitycenter"
	"stackd/storage/sqlite/identitycenter/internal/sqlcgen"
)

func (r reader) Instance(arn string) (domain.Instance, error) {
	row, err := r.q.GetInstance(r.ctx, arn)
	if err != nil {
		return domain.Instance{}, missing(err)
	}
	return r.instance(row)
}

func (r reader) Instances(scope domain.Scope) ([]domain.Instance, error) {
	rows, err := r.q.ListInstances(r.ctx, sqlcgen.ListInstancesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Instance, len(rows))
	for i, row := range rows {
		out[i], err = r.instance(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) instance(row sqlcgen.IdentitycenterInstance) (domain.Instance, error) {
	v := domain.Instance{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, StoreID: row.StoreID, Name: row.Name, ClientToken: row.ClientToken, Created: row.Created.UTC()}
	tags, err := r.q.ListInstanceTags(r.ctx, row.Arn)
	if err != nil {
		return domain.Instance{}, err
	}
	v.Tags = make(map[string]string, len(tags))
	for _, tag := range tags {
		v.Tags[tag.Key] = tag.Value
	}
	return v, nil
}

func (w writer) PutInstance(v domain.Instance) error {
	if err := w.q.PutInstance(w.ctx, sqlcgen.PutInstanceParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, StoreID: v.StoreID, Name: v.Name, ClientToken: v.ClientToken, Created: v.Created.UTC()}); err != nil {
		return err
	}
	if err := w.q.DeleteInstanceTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for _, key := range slices.Sorted(maps.Keys(v.Tags)) {
		if err := w.q.PutInstanceTag(w.ctx, sqlcgen.PutInstanceTagParams{InstanceArn: v.ARN, Key: key, Value: v.Tags[key]}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteInstance(arn string) error { return w.q.DeleteInstance(w.ctx, arn) }

func (r reader) PermissionSet(arn string) (domain.PermissionSet, error) {
	row, err := r.q.GetPermissionSet(r.ctx, arn)
	if err != nil {
		return domain.PermissionSet{}, missing(err)
	}
	return r.permissionSet(row)
}

func (r reader) PermissionSets(instance string) ([]domain.PermissionSet, error) {
	rows, err := r.q.ListPermissionSets(r.ctx, instance)
	if err != nil {
		return nil, err
	}
	out := make([]domain.PermissionSet, len(rows))
	for i, row := range rows {
		out[i], err = r.permissionSet(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) permissionSet(row sqlcgen.IdentitycenterPermissionSet) (domain.PermissionSet, error) {
	v := domain.PermissionSet{InstanceARN: row.InstanceArn, ARN: row.Arn, Name: row.Name, Description: row.Description, RelayState: row.RelayState, InlinePolicy: row.InlinePolicy, Duration: time.Duration(row.DurationNs), Created: row.Created.UTC(), BoundaryARN: row.BoundaryArn, Boundary: domain.PolicyReference{Name: row.BoundaryName, Path: row.BoundaryPath}}
	tags, err := r.q.ListPermissionSetTags(r.ctx, row.Arn)
	if err != nil {
		return domain.PermissionSet{}, err
	}
	v.Tags = make(map[string]string, len(tags))
	for _, tag := range tags {
		v.Tags[tag.Key] = tag.Value
	}
	managed, err := r.q.ListManagedPolicies(r.ctx, row.Arn)
	if err != nil {
		return domain.PermissionSet{}, err
	}
	v.ManagedPolicies = make([]string, len(managed))
	for i, policy := range managed {
		v.ManagedPolicies[i] = policy.Arn
	}
	customer, err := r.q.ListCustomerManagedPolicies(r.ctx, row.Arn)
	if err != nil {
		return domain.PermissionSet{}, err
	}
	v.CustomerManagedPolicies = make([]domain.PolicyReference, len(customer))
	for i, policy := range customer {
		v.CustomerManagedPolicies[i] = domain.PolicyReference{Name: policy.Name, Path: policy.Path}
	}
	return v, nil
}

func (w writer) PutPermissionSet(v domain.PermissionSet) error {
	if err := w.q.PutPermissionSet(w.ctx, sqlcgen.PutPermissionSetParams{Arn: v.ARN, InstanceArn: v.InstanceARN, Name: v.Name, Description: v.Description, RelayState: v.RelayState, InlinePolicy: v.InlinePolicy, DurationNs: int64(v.Duration), Created: v.Created.UTC(), BoundaryArn: v.BoundaryARN, BoundaryName: v.Boundary.Name, BoundaryPath: v.Boundary.Path}); err != nil {
		return err
	}
	if err := w.q.DeletePermissionSetTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for _, key := range slices.Sorted(maps.Keys(v.Tags)) {
		if err := w.q.PutPermissionSetTag(w.ctx, sqlcgen.PutPermissionSetTagParams{PermissionSetArn: v.ARN, Key: key, Value: v.Tags[key]}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteManagedPolicies(w.ctx, v.ARN); err != nil {
		return err
	}
	for i, arn := range v.ManagedPolicies {
		if err := w.q.PutManagedPolicy(w.ctx, sqlcgen.PutManagedPolicyParams{PermissionSetArn: v.ARN, Position: int64(i), Arn: arn}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCustomerManagedPolicies(w.ctx, v.ARN); err != nil {
		return err
	}
	for i, policy := range v.CustomerManagedPolicies {
		if err := w.q.PutCustomerManagedPolicy(w.ctx, sqlcgen.PutCustomerManagedPolicyParams{PermissionSetArn: v.ARN, Position: int64(i), Name: policy.Name, Path: policy.Path}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeletePermissionSet(arn string) error { return w.q.DeletePermissionSet(w.ctx, arn) }
