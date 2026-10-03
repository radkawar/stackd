package eks

import (
	"encoding/json"
	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func (r reader) PodIdentityAssociation(k domain.Key, id string) (domain.PodIdentityAssociation, error) {
	row, err := r.q.GetPodIdentityAssociation(r.ctx, sqlcgen.GetPodIdentityAssociationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ID: id})
	if err != nil {
		return domain.PodIdentityAssociation{}, missing(err)
	}
	return podIdentity(row)
}
func (r reader) PodIdentityAssociations(k domain.Key) ([]domain.PodIdentityAssociation, error) {
	rows, err := r.q.ListPodIdentityAssociations(r.ctx, sqlcgen.ListPodIdentityAssociationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PodIdentityAssociation, 0, len(rows))
	for _, row := range rows {
		a, err := podIdentity(row)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}
func podIdentity(row sqlcgen.EksPodIdentityAssociation) (domain.PodIdentityAssociation, error) {
	a := domain.PodIdentityAssociation{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}, ID: row.ID, ClusterID: row.ClusterID, Namespace: row.Namespace, ServiceAccount: row.ServiceAccount, RoleARN: row.RoleArn, RoleID: row.RoleID, TargetRoleARN: row.TargetRoleArn, TargetRoleID: row.TargetRoleID, ExternalID: row.ExternalID, OwnerARN: row.OwnerArn, Policy: row.Policy, DisableSessionTags: row.DisableSessionTags != 0, Created: readTime(row.Created), Modified: readTime(row.Modified), ClientToken: row.ClientToken}
	err := json.Unmarshal([]byte(row.Tags), &a.Tags)
	return a, err
}
func (w writer) PutPodIdentityAssociation(a domain.PodIdentityAssociation) error {
	tags, err := encodeTags(a.Tags)
	if err != nil {
		return err
	}
	k := a.Key
	return w.q.PutPodIdentityAssociation(w.ctx, sqlcgen.PutPodIdentityAssociationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ID: a.ID, ClusterID: a.ClusterID, Namespace: a.Namespace, ServiceAccount: a.ServiceAccount, RoleArn: a.RoleARN, RoleID: a.RoleID, TargetRoleArn: a.TargetRoleARN, TargetRoleID: a.TargetRoleID, ExternalID: a.ExternalID, OwnerArn: a.OwnerARN, Policy: a.Policy, DisableSessionTags: bit(a.DisableSessionTags), Tags: tags, Created: timeValue(a.Created), Modified: timeValue(a.Modified), ClientToken: a.ClientToken})
}
func (w writer) DeletePodIdentityAssociation(k domain.Key, id string) error {
	return w.q.DeletePodIdentityAssociation(w.ctx, sqlcgen.DeletePodIdentityAssociationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ID: id})
}
func (w writer) deleteClusterPodIdentities(k domain.Key) error {
	return w.q.DeleteClusterPodIdentityAssociations(w.ctx, sqlcgen.DeleteClusterPodIdentityAssociationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}

var _ domain.PodIdentityTransaction = writer{}
