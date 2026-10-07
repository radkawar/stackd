package kafka

import (
	domain "stackd/storage/kafka"
	"stackd/storage/sqlite/kafka/internal/sqlcgen"
)

func (r reader) Configuration(arn string) (domain.ConfigurationRecord, error) {
	row, e := r.q.GetConfiguration(r.ctx, arn)
	if e != nil {
		return domain.ConfigurationRecord{}, missing(e)
	}
	return r.configuration(row)
}
func (r reader) Configurations(sc domain.Scope) ([]domain.ConfigurationRecord, error) {
	rows, e := r.q.ListConfigurations(r.ctx, sqlcgen.ListConfigurationsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ConfigurationRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.configuration(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) configuration(row sqlcgen.MskConfiguration) (domain.ConfigurationRecord, error) {
	v := domain.ConfigurationRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, Name: row.Name, Description: row.Description, Created: readTime(row.Created), LatestRevision: row.LatestRevision}
	v.OwnerStackID, v.OwnerLogicalID, v.OwnerToken = row.OwnerStackID, row.OwnerLogicalID, row.OwnerToken
	versions, e := r.q.ListConfigurationVersions(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, x := range versions {
		v.KafkaVersions = append(v.KafkaVersions, x.KafkaVersion)
	}
	return v, nil
}
func (w writer) PutConfiguration(v domain.ConfigurationRecord) error {
	e := w.q.PutConfiguration(w.ctx, sqlcgen.PutConfigurationParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: v.Name, Description: v.Description, Created: timeValue(v.Created), LatestRevision: v.LatestRevision, OwnerStackID: v.OwnerStackID, OwnerLogicalID: v.OwnerLogicalID, OwnerToken: v.OwnerToken})
	if e != nil {
		return e
	}
	if e = w.q.DeleteConfigurationVersions(w.ctx, v.ARN); e != nil {
		return e
	}
	for _, x := range v.KafkaVersions {
		if e = w.q.PutConfigurationVersion(w.ctx, sqlcgen.PutConfigurationVersionParams{Arn: v.ARN, KafkaVersion: x}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteConfiguration(arn string) error {
	if e := w.q.DeleteRevision(w.ctx, arn); e != nil {
		return e
	}
	return w.q.DeleteConfiguration(w.ctx, arn)
}
func revision(row sqlcgen.MskRevision) domain.RevisionRecord {
	return domain.RevisionRecord{ARN: row.Arn, Revision: row.Revision, Description: row.Description, ServerProperties: row.ServerProperties, Created: readTime(row.Created)}
}
func (r reader) Revision(arn string, n int64) (domain.RevisionRecord, error) {
	row, e := r.q.GetRevision(r.ctx, sqlcgen.GetRevisionParams{Arn: arn, Revision: n})
	return revision(row), missing(e)
}
func (r reader) Revisions(arn string) ([]domain.RevisionRecord, error) {
	rows, e := r.q.ListRevisions(r.ctx, arn)
	if e != nil {
		return nil, e
	}
	out := make([]domain.RevisionRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, revision(row))
	}
	return out, nil
}
func (w writer) PutRevision(v domain.RevisionRecord) error {
	return w.q.PutRevision(w.ctx, sqlcgen.PutRevisionParams{Arn: v.ARN, Revision: v.Revision, Description: v.Description, ServerProperties: v.ServerProperties, Created: timeValue(v.Created)})
}
func operation(row sqlcgen.MskOperation) domain.OperationRecord {
	return domain.OperationRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, ClusterARN: row.ClusterArn, Type: row.Type, State: row.State, Failure: row.Failure, SourceConfigurationARN: row.SourceConfigurationArn, TargetConfigurationARN: row.TargetConfigurationArn, SourceRevision: row.SourceRevision, TargetRevision: row.TargetRevision, Created: readTime(row.Created), Ended: readTime(row.Ended)}
}
func (r reader) Operation(arn string) (domain.OperationRecord, error) {
	row, e := r.q.GetOperation(r.ctx, arn)
	return operation(row), missing(e)
}
func (r reader) Operations(arn string) ([]domain.OperationRecord, error) {
	rows, e := r.q.ListOperations(r.ctx, arn)
	if e != nil {
		return nil, e
	}
	out := make([]domain.OperationRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, operation(row))
	}
	return out, nil
}
func (w writer) PutOperation(v domain.OperationRecord) error {
	return w.q.PutOperation(w.ctx, sqlcgen.PutOperationParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ClusterArn: v.ClusterARN, Type: v.Type, State: v.State, Failure: v.Failure, SourceConfigurationArn: v.SourceConfigurationARN, TargetConfigurationArn: v.TargetConfigurationARN, SourceRevision: v.SourceRevision, TargetRevision: v.TargetRevision, Created: timeValue(v.Created), Ended: timeValue(v.Ended)})
}
