package iam

import (
	"cmp"
	"context"
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
	"stackd/internal/services/organizations"
)

func buildOrganizationAccessReport(ctx context.Context, partition string, snapshot organizations.AccessReportSnapshot) ([]OrganizationServiceAccess, *awswire.Error) {
	levels := make([][]string, len(snapshot.PolicyLevels))
	for i, level := range snapshot.PolicyLevels {
		for _, p := range level.Documents {
			levels[i] = append(levels[i], p.Document)
		}
	}
	permissions, apiErr := reportPermissionActions(ctx, levels)
	if apiErr != nil {
		return nil, apiErr
	}
	services := make([]OrganizationServiceAccess, 0, len(permissions))
	indexes := make(map[string]int, len(permissions))
	for _, namespace := range sortedMapKeys(permissions) {
		name, ok := catalog.LastAccessServiceName(namespace)
		if !ok {
			return nil, accessReportFailure()
		}
		indexes[namespace] = len(services)
		services = append(services, OrganizationServiceAccess{Namespace: namespace, Name: name})
	}
	transaction := ctx.Value(transactionKey{}).(serviceTransaction)
	serviceCutoff := transaction.currentTime.Add(-serviceAccessTrackingPeriod)
	for _, account := range snapshot.Accounts {
		activities, err := transaction.tx.PrincipalActivities(Scope{Partition: partition, AccountID: account.AccountID})
		if err != nil {
			return nil, accessReportFailure()
		}
		seen := make(map[string]bool)
		for _, activity := range activities {
			index, included := indexes[activity.ServiceNamespace]
			if !included || !activity.LastAuthenticated.After(serviceCutoff) || activity.LastAuthenticated.After(transaction.currentTime) {
				continue
			}
			service := &services[index]
			if !seen[service.Namespace] {
				service.AuthenticatedAccounts++
				seen[service.Namespace] = true
			}
			current := service.LastActivity
			if current == nil || activity.LastAuthenticated.After(current.LastAuthenticated) || activity.LastAuthenticated.Equal(current.LastAuthenticated) && cmp.Or(strings.Compare(account.EntityPath, current.EntityPath), strings.Compare(activity.Region, current.Region)) < 0 {
				service.LastActivity = &AccountActivity{EntityPath: account.EntityPath, Region: activity.Region, LastAuthenticated: activity.LastAuthenticated}
			}
		}
	}
	return services, nil
}
