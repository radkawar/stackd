package eks

import (
	"encoding/json"

	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func (r reader) Cluster(k domain.Key) (domain.Cluster, error) {
	row, err := r.q.GetCluster(r.ctx, sqlcgen.GetClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.Cluster{}, missing(err)
	}
	return cluster(row)
}
func (r reader) Clusters(scope domain.Scope) ([]domain.Cluster, error) {
	rows, err := r.q.ListClusters(r.ctx, sqlcgen.ListClustersParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return clusters(rows)
}
func (r reader) AllClusters() ([]domain.Cluster, error) {
	rows, err := r.q.AllClusters(r.ctx)
	if err != nil {
		return nil, err
	}
	return clusters(rows)
}
func clusters(rows []sqlcgen.EksCluster) ([]domain.Cluster, error) {
	out := make([]domain.Cluster, 0, len(rows))
	for _, row := range rows {
		v, err := cluster(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func cluster(row sqlcgen.EksCluster) (domain.Cluster, error) {
	v := domain.Cluster{
		Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		ID:  row.ID, RoleARN: row.RoleArn, KubernetesVersion: row.KubernetesVersion,
		Status: row.Status, Operation: row.Operation, Error: row.Error,
		Endpoint: row.Endpoint, CertificateAuthority: row.CertificateAuthority, VPCID: row.VpcID,
		Created: readTime(row.Created), Due: readTime(row.Due), Generation: row.Generation,
		ClientToken: row.ClientToken, RequestHash: row.RequestHash, CreatorARN: row.CreatorArn, CreatorID: row.CreatorID,
		AuthenticationMode: row.AuthenticationMode, BootstrapAdmin: row.BootstrapAdmin != 0, DeletionProtection: row.DeletionProtection != 0,
	}
	if err := json.Unmarshal([]byte(row.Subnets), &v.Subnets); err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(row.SecurityGroups), &v.SecurityGroups); err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(row.Tags), &v.Tags); err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(row.EnabledLogTypes), &v.EnabledLogTypes); err != nil {
		return v, err
	}
	return v, nil
}
func (w writer) PutCluster(v domain.Cluster) error {
	subnets, err := encodeStrings(v.Subnets)
	if err != nil {
		return err
	}
	groups, err := encodeStrings(v.SecurityGroups)
	if err != nil {
		return err
	}
	tags, err := encodeTags(v.Tags)
	if err != nil {
		return err
	}
	logging, err := encodeStrings(v.EnabledLogTypes)
	if err != nil {
		return err
	}
	k := v.Key
	return w.q.PutCluster(w.ctx, sqlcgen.PutClusterParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		ID: v.ID, RoleArn: v.RoleARN, KubernetesVersion: v.KubernetesVersion,
		Status: v.Status, Operation: v.Operation, Error: v.Error,
		Endpoint: v.Endpoint, CertificateAuthority: v.CertificateAuthority, VpcID: v.VPCID,
		Subnets: subnets, SecurityGroups: groups, Tags: tags,
		Created: timeValue(v.Created), Due: timeValue(v.Due), Generation: v.Generation,
		ClientToken: v.ClientToken, RequestHash: v.RequestHash, CreatorArn: v.CreatorARN, CreatorID: v.CreatorID,
		AuthenticationMode: v.AuthenticationMode, BootstrapAdmin: bit(v.BootstrapAdmin), DeletionProtection: bit(v.DeletionProtection),
		EnabledLogTypes: logging,
	})
}
func (w writer) DeleteCluster(k domain.Key) error {
	if err := w.deleteClusterPodIdentities(k); err != nil {
		return err
	}
	if err := w.deleteClusterNodegroups(k); err != nil {
		return err
	}
	if err := w.q.DeleteClusterAccessMutations(w.ctx, sqlcgen.DeleteClusterAccessMutationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteClusterAccessPolicies(w.ctx, sqlcgen.DeleteClusterAccessPoliciesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteClusterAccessEntries(w.ctx, sqlcgen.DeleteClusterAccessEntriesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteClusterUpdates(w.ctx, sqlcgen.DeleteClusterUpdatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	return w.q.DeleteCluster(w.ctx, sqlcgen.DeleteClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
