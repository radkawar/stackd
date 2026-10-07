package kafka

import (
	"stackd/internal/authorization"
	domain "stackd/storage/kafka"
	"stackd/storage/sqlite/kafka/internal/sqlcgen"
)

func (r reader) Cluster(arn string) (domain.ClusterRecord, error) {
	row, e := r.q.GetCluster(r.ctx, arn)
	if e != nil {
		return domain.ClusterRecord{}, missing(e)
	}
	return r.cluster(row)
}
func (r reader) Clusters(sc domain.Scope) ([]domain.ClusterRecord, error) {
	rows, e := r.q.ListClusters(r.ctx, sqlcgen.ListClustersParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	return r.clusters(rows)
}
func (r reader) AllClusters() ([]domain.ClusterRecord, error) {
	rows, e := r.q.AllClusters(r.ctx)
	if e != nil {
		return nil, e
	}
	return r.clusters(rows)
}
func (r reader) clusters(rows []sqlcgen.MskCluster) ([]domain.ClusterRecord, error) {
	out := make([]domain.ClusterRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.cluster(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) cluster(row sqlcgen.MskCluster) (domain.ClusterRecord, error) {
	v := domain.ClusterRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, Name: row.Name, Incarnation: row.Incarnation, KafkaVersion: row.KafkaVersion, SecurityMode: row.SecurityMode, State: row.State, Failure: row.Failure, Operation: row.Operation, OperationARN: row.OperationArn, ConfigurationARN: row.ConfigurationArn, PendingConfigurationARN: row.PendingConfigurationArn, ConfigurationRevision: row.ConfigurationRevision, PendingConfigurationRevision: row.PendingConfigurationRevision, ServerProperties: row.ServerProperties, PendingServerProperties: row.PendingServerProperties, Brokers: int32(row.Brokers), RebootBrokerID: int32(row.RebootBrokerID), Version: row.Version, Created: readTime(row.Created), Due: readTime(row.Due), Endpoint: domain.Endpoint{CAPEM: row.Capem, SecurityMode: row.SecurityMode}, Tags: map[string]string{}, Policy: authorization.BoundPolicy{Document: row.PolicyDocument, PrincipalIDs: map[string]string{}}, PolicyVersion: row.PolicyVersion}
	v.OwnerStackID, v.OwnerLogicalID, v.OwnerToken = row.OwnerStackID, row.OwnerLogicalID, row.OwnerToken
	tags, e := r.q.ListClusterTags(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, x := range tags {
		v.Tags[x.TagKey] = x.TagValue
	}
	brokers, e := r.q.ListClusterBrokers(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, x := range brokers {
		v.Endpoint.Brokers = append(v.Endpoint.Brokers, domain.Broker{ID: int32(x.BrokerID), Address: x.Address})
	}
	secrets, e := r.q.ListClusterSecrets(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, x := range secrets {
		v.Secrets = append(v.Secrets, x.SecretArn)
	}
	principals, e := r.q.ListPolicyPrincipals(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, x := range principals {
		v.Policy.PrincipalIDs[x.PrincipalArn] = x.PrincipalID
	}
	return v, nil
}
func (w writer) PutCluster(v domain.ClusterRecord) error {
	e := w.q.PutCluster(w.ctx, sqlcgen.PutClusterParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: v.Name, Incarnation: v.Incarnation, KafkaVersion: v.KafkaVersion, SecurityMode: v.SecurityMode, State: v.State, Failure: v.Failure, Operation: v.Operation, OperationArn: v.OperationARN, ConfigurationArn: v.ConfigurationARN, PendingConfigurationArn: v.PendingConfigurationARN, ConfigurationRevision: v.ConfigurationRevision, PendingConfigurationRevision: v.PendingConfigurationRevision, ServerProperties: v.ServerProperties, PendingServerProperties: v.PendingServerProperties, Brokers: int64(v.Brokers), RebootBrokerID: int64(v.RebootBrokerID), Version: v.Version, Created: timeValue(v.Created), Due: timeValue(v.Due), Capem: blob(v.Endpoint.CAPEM), PolicyDocument: v.Policy.Document, PolicyVersion: v.PolicyVersion, OwnerStackID: v.OwnerStackID, OwnerLogicalID: v.OwnerLogicalID, OwnerToken: v.OwnerToken})
	if e != nil {
		return e
	}
	if e = w.q.DeleteClusterTags(w.ctx, v.ARN); e != nil {
		return e
	}
	for k, x := range v.Tags {
		if e = w.q.PutClusterTag(w.ctx, sqlcgen.PutClusterTagParams{Arn: v.ARN, TagKey: k, TagValue: x}); e != nil {
			return e
		}
	}
	if e = w.q.DeleteClusterBrokers(w.ctx, v.ARN); e != nil {
		return e
	}
	for _, x := range v.Endpoint.Brokers {
		if e = w.q.PutClusterBroker(w.ctx, sqlcgen.PutClusterBrokerParams{Arn: v.ARN, BrokerID: int64(x.ID), Address: x.Address}); e != nil {
			return e
		}
	}
	if e = w.q.DeleteClusterSecrets(w.ctx, v.ARN); e != nil {
		return e
	}
	for _, x := range v.Secrets {
		if e = w.q.PutClusterSecret(w.ctx, sqlcgen.PutClusterSecretParams{Arn: v.ARN, SecretArn: x}); e != nil {
			return e
		}
	}
	if e = w.q.DeletePolicyPrincipals(w.ctx, v.ARN); e != nil {
		return e
	}
	for arn, id := range v.Policy.PrincipalIDs {
		if e = w.q.PutPolicyPrincipal(w.ctx, sqlcgen.PutPolicyPrincipalParams{Arn: v.ARN, PrincipalArn: arn, PrincipalID: id}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteCluster(arn string) error { return w.q.DeleteCluster(w.ctx, arn) }
