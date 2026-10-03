package guardduty

import (
	"database/sql"
	"errors"

	domain "stackd/internal/services/guardduty"
	"stackd/journal"
	"stackd/storage/sqlite/guardduty/internal/sqlcgen"
)

func kubernetesObservation(v sqlcgen.KubernetesAuditEvent) *journal.KubernetesAuditObserved {
	return &journal.KubernetesAuditObserved{ClusterARN: v.ClusterArn, ClusterID: v.ClusterID, ClusterName: v.ClusterName, AuditID: v.AuditID, Stage: v.Stage, Verb: v.Verb, RequestURI: v.RequestUri, UserName: v.UserName, UserUID: v.UserUid, ActorUserName: v.ActorUserName, SourceIP: v.SourceIp, Namespace: v.Namespace, Resource: v.Resource, Subresource: v.Subresource, Name: v.Name, UserAgent: v.UserAgent, APIVersion: v.ApiVersion, ResponseCode: int32(v.ResponseCode), NativeAt: v.NativeAt, RoleRefAPIGroup: v.RoleRefApiGroup, RoleRefKind: v.RoleRefKind, RoleRefName: v.RoleRefName, DeleteOptionsObserved: v.DeleteOptionsObserved, DryRun: v.DryRun}
}
func (r reader) readKubernetesObservation(v *domain.Finding) error {
	row, err := r.q.GetKubernetesObservation(r.ctx, sqlcgen.GetKubernetesObservationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	event := kubernetesObservation(row)
	event.Groups, err = r.q.GetKubernetesObservationGroups(r.ctx, row.Sequence)
	if err != nil {
		return err
	}
	subjects, err := r.q.GetKubernetesObservationSubjects(r.ctx, row.Sequence)
	if err != nil {
		return err
	}
	if len(subjects) > 0 {
		event.Subjects = make([]journal.KubernetesSubject, len(subjects))
		for i, subject := range subjects {
			event.Subjects[i] = journal.KubernetesSubject{APIGroup: subject.ApiGroup, Kind: subject.Kind, Name: subject.Name, Namespace: subject.Namespace}
		}
	}
	v.Observation.Kubernetes = event
	return nil
}
func (r reader) readKubernetesObservations(scope domain.Scope, detector string, findings []domain.Finding) error {
	rows, err := r.q.ListKubernetesObservations(r.ctx, sqlcgen.ListKubernetesObservationsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, DetectorID: detector})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	groups, err := r.q.ListKubernetesObservationGroups(r.ctx, sqlcgen.ListKubernetesObservationGroupsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, DetectorID: detector})
	if err != nil {
		return err
	}
	subjects, err := r.q.ListKubernetesObservationSubjects(r.ctx, sqlcgen.ListKubernetesObservationSubjectsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, DetectorID: detector})
	if err != nil {
		return err
	}
	next, group, subject := 0, 0, 0
	for i := range findings {
		v := &findings[i]
		for next < len(rows) && rows[next].FindingID < v.ID {
			next++
		}
		if next == len(rows) || rows[next].FindingID != v.ID {
			continue
		}
		event := kubernetesObservation(rows[next].KubernetesAuditEvent)
		for group < len(groups) && groups[group].ID < v.ID {
			group++
		}
		start := group
		for group < len(groups) && groups[group].ID == v.ID {
			group++
		}
		if group > start {
			event.Groups = make([]string, group-start)
			for j := start; j < group; j++ {
				event.Groups[j-start] = groups[j].Name
			}
		}
		for subject < len(subjects) && subjects[subject].ID < v.ID {
			subject++
		}
		first := subject
		for subject < len(subjects) && subjects[subject].ID == v.ID {
			subject++
		}
		if subject > first {
			event.Subjects = make([]journal.KubernetesSubject, subject-first)
			for j := first; j < subject; j++ {
				row := subjects[j]
				event.Subjects[j-first] = journal.KubernetesSubject{APIGroup: row.ApiGroup, Kind: row.Kind, Name: row.Name, Namespace: row.Namespace}
			}
		}
		v.Observation.Kubernetes = event
	}
	return nil
}
func (w writer) putKubernetesObservation(v domain.Finding) error {
	event := v.Observation.Kubernetes
	if event == nil {
		return w.q.DeleteKubernetesObservation(w.ctx, sqlcgen.DeleteKubernetesObservationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID})
	}
	count, err := w.q.PutKubernetesObservation(w.ctx, sqlcgen.PutKubernetesObservationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID, ClusterID: event.ClusterID, AuditID: event.AuditID, Stage: event.Stage})
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("GuardDuty Kubernetes observation has no committed source admission")
	}
	return nil
}
