package journal

import (
	"context"
	"database/sql"
	"errors"

	"stackd/journal"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/journal/internal/sqlcgen"
)

const kubernetesAuditType = "eks.kubernetes.audit_observed.v1"

func (s *storage) AppendKubernetesAuditObserved(ctx context.Context, e journal.Envelope, v journal.KubernetesAuditObserved) (bool, error) {
	if err := journal.ValidateKubernetesAudit(e, v); err != nil {
		return false, err
	}
	inserted := false
	err := sqlite.Transact(ctx, s.db, false, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		_, err := q.FindKubernetesAudit(ctx, sqlcgen.FindKubernetesAuditParams{Partition: e.Partition, AccountID: e.AccountID, Region: e.Region, ClusterID: v.ClusterID, AuditID: v.AuditID, Stage: v.Stage})
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = s.append(ctx, e, kubernetesAuditType, func(ctx context.Context, q *sqlcgen.Queries, sequence int64) error {
			if err := q.AppendKubernetesAudit(ctx, sqlcgen.AppendKubernetesAuditParams{Sequence: sequence, Partition: e.Partition, AccountID: e.AccountID, Region: e.Region, ClusterArn: v.ClusterARN, ClusterID: v.ClusterID, ClusterName: v.ClusterName, AuditID: v.AuditID, Stage: v.Stage, Verb: v.Verb, RequestUri: v.RequestURI, UserName: v.UserName, UserUid: v.UserUID, ActorUserName: v.ActorUserName, SourceIp: v.SourceIP, Namespace: v.Namespace, Resource: v.Resource, Subresource: v.Subresource, Name: v.Name, UserAgent: v.UserAgent, ApiVersion: v.APIVersion, ResponseCode: int64(v.ResponseCode), NativeAt: v.NativeAt, RoleRefApiGroup: v.RoleRefAPIGroup, RoleRefKind: v.RoleRefKind, RoleRefName: v.RoleRefName, DeleteOptionsObserved: v.DeleteOptionsObserved, DryRun: v.DryRun}); err != nil {
				return err
			}
			for pos, name := range v.Groups {
				if err := q.AppendKubernetesAuditGroup(ctx, sqlcgen.AppendKubernetesAuditGroupParams{Sequence: sequence, Position: int64(pos), Name: name}); err != nil {
					return err
				}
			}
			for pos, subject := range v.Subjects {
				if err := q.AppendKubernetesAuditSubject(ctx, sqlcgen.AppendKubernetesAuditSubjectParams{Sequence: sequence, Position: int64(pos), ApiGroup: subject.APIGroup, Kind: subject.Kind, Name: subject.Name, Namespace: subject.Namespace}); err != nil {
					return err
				}
			}
			return nil
		})
		inserted = err == nil
		return err
	})
	return inserted && err == nil, err
}

func readKubernetesAudit(ctx context.Context, q *sqlcgen.Queries, sequence int64) (*journal.KubernetesAuditObserved, error) {
	v, err := q.ReadKubernetesAudit(ctx, sequence)
	if err != nil {
		return nil, err
	}
	groups, err := q.ReadKubernetesAuditGroups(ctx, sequence)
	if err != nil {
		return nil, err
	}
	subjects, err := q.ReadKubernetesAuditSubjects(ctx, sequence)
	if err != nil {
		return nil, err
	}
	event := &journal.KubernetesAuditObserved{ClusterARN: v.ClusterArn, ClusterID: v.ClusterID, ClusterName: v.ClusterName, AuditID: v.AuditID, Stage: v.Stage, Verb: v.Verb, RequestURI: v.RequestUri, UserName: v.UserName, UserUID: v.UserUid, ActorUserName: v.ActorUserName, SourceIP: v.SourceIp, Namespace: v.Namespace, Resource: v.Resource, Subresource: v.Subresource, Name: v.Name, UserAgent: v.UserAgent, APIVersion: v.ApiVersion, ResponseCode: int32(v.ResponseCode), NativeAt: v.NativeAt, Groups: groups, RoleRefAPIGroup: v.RoleRefApiGroup, RoleRefKind: v.RoleRefKind, RoleRefName: v.RoleRefName, DeleteOptionsObserved: v.DeleteOptionsObserved, DryRun: v.DryRun}
	if len(subjects) > 0 {
		event.Subjects = make([]journal.KubernetesSubject, len(subjects))
		for i, subject := range subjects {
			event.Subjects[i] = journal.KubernetesSubject{APIGroup: subject.ApiGroup, Kind: subject.Kind, Name: subject.Name, Namespace: subject.Namespace}
		}
	}
	return event, nil
}
