package iam

import (
	"cmp"
	"slices"
)

func (t *memoryTx) AccessReport(scope Scope, id string) (AccessReport, error) {
	if err := t.check(false); err != nil {
		return AccessReport{}, err
	}
	report, ok := t.state.accessReports[scope][id]
	if !ok {
		return AccessReport{}, ErrRecordNotFound
	}
	return cloneAccessReport(report), nil
}

func (t *memoryTx) PendingAccessReports(scope Scope) ([]AccessReport, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	reports := make([]AccessReport, 0, len(t.state.accessReports[scope]))
	for _, report := range t.state.accessReports[scope] {
		if report.CompletedAt == nil {
			reports = append(reports, cloneAccessReport(report))
		}
	}
	slices.SortFunc(reports, func(a, b AccessReport) int { return cmp.Compare(a.ID, b.ID) })
	return reports, nil
}

func (t *memoryTx) LatestOrganizationAccessReport(scope Scope, owner, entityPath, policyID string) (AccessReport, error) {
	if err := t.check(false); err != nil {
		return AccessReport{}, err
	}
	var latest AccessReport
	found := false
	for _, report := range t.state.accessReports[scope] {
		organization := report.Organization
		if organization == nil || report.Owner != owner || organization.EntityPath != entityPath || organization.PolicyID != policyID {
			continue
		}
		if !found || report.RequestedAt.After(latest.RequestedAt) || (report.RequestedAt.Equal(latest.RequestedAt) && report.ID > latest.ID) {
			latest, found = report, true
		}
	}
	if !found {
		return AccessReport{}, ErrRecordNotFound
	}
	return cloneAccessReport(latest), nil
}

func (t *memoryTx) AccessReportScopes() ([]Scope, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	scopes := make([]Scope, 0, len(t.state.accessReports))
	for scope := range t.state.accessReports {
		scopes = append(scopes, scope)
	}
	slices.SortFunc(scopes, func(a, b Scope) int {
		return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID))
	})
	return scopes, nil
}

func (t *memoryTx) PutAccessReport(scope Scope, report AccessReport) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.accessReports[scope] == nil {
		t.state.accessReports[scope] = make(map[string]AccessReport)
	}
	t.state.accessReports[scope][report.ID] = cloneAccessReport(report)
	return nil
}

func cloneAccessReport(report AccessReport) AccessReport {
	if report.CompletedAt != nil {
		instant := *report.CompletedAt
		report.CompletedAt = &instant
	}
	if report.Organization != nil {
		organization := *report.Organization
		if organization.Error != nil {
			copy := *organization.Error
			organization.Error = &copy
		}
		organization.Services = slices.Clone(organization.Services)
		for i := range organization.Services {
			if activity := organization.Services[i].LastActivity; activity != nil {
				copy := *activity
				organization.Services[i].LastActivity = &copy
			}
		}
		report.Organization = &organization
	}
	report.Services = slices.Clone(report.Services)
	for i := range report.Services {
		service := &report.Services[i]
		service.LastActivity = cloneLastActivity(service.LastActivity)
		service.Actions = slices.Clone(service.Actions)
		for j := range service.Actions {
			service.Actions[j].LastActivity = cloneLastActivity(service.Actions[j].LastActivity)
		}
		service.Entities = slices.Clone(service.Entities)
		for j := range service.Entities {
			service.Entities[j].LastActivity = cloneLastActivity(service.Entities[j].LastActivity)
		}
	}
	return report
}

func cloneLastActivity(activity *PrincipalActivity) *PrincipalActivity {
	if activity == nil {
		return nil
	}
	copy := *activity
	return &copy
}
