package iam

import (
	"cmp"
	"context"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

// The account-report guide specifies the last 400 days for service information;
// the general guide/API describe at least 400 days. Use the documented duration
// with the same exclusive lower bound as RoleLastUsed. Sub-day AWS cutoff
// precision has not been observed. Action history has separate tracking start
// dates, not this rolling duration.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started-reduce-permissions-last-accessed.html
const serviceAccessTrackingPeriod = 400 * 24 * time.Hour

func accessReportSource(a *account, m awsctx.Metadata, arn string) ([]permissionPolicySource, map[string]string, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && strings.HasPrefix(parts[5], "policy/") {
		if parts[0] != "arn" || parts[2] != "iam" || parts[3] != "" || len(parts[5]) == len("policy/") {
			return nil, nil, invalidInput("Invalid IAM policy ARN.")
		}
		if err := lastAccessScope(m, parts[1], parts[4]); err != nil {
			return nil, nil, err
		}
		if a.policies[arn] == nil {
			if _, ok := lookupAWSManagedPolicy(m.Partition, arn); !ok {
				return nil, nil, missing("policy", arn)
			}
		}
		source, apiErr := managedPermissionPolicySource(a, arn)
		if apiErr != nil {
			return nil, nil, apiErr
		}
		entities := map[string]string{}
		for _, u := range a.users {
			if _, attached := u.IdentityPolicies.Attached[arn]; attached {
				entities[u.UserId] = u.Arn
			}
		}
		for _, r := range a.roles {
			if _, attached := r.IdentityPolicies.Attached[arn]; attached {
				entities[r.RoleId] = r.Arn
			}
		}
		for _, g := range a.groups {
			if _, attached := g.IdentityPolicies.Attached[arn]; !attached {
				continue
			}
			for key := range g.Members {
				if u := a.users[key]; u != nil {
					entities[u.UserId] = u.Arn
				}
			}
		}
		return []permissionPolicySource{source}, entities, nil
	}
	identity, apiErr := lastAccessIdentity(a, m, arn)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	sources, apiErr := permissionPolicySources(a, identity.owners)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	entities := make(map[string]string)
	switch identity.kind {
	case "user", "role":
		entities[identity.id] = identity.arn
	case "group":
		group := a.groups[strings.ToLower(identity.name)]
		for _, key := range sortedMapKeys(group.Members) {
			if u := a.users[key]; u != nil {
				entities[u.UserId] = u.Arn
			}
		}
	}
	return sources, entities, nil
}

func buildAccessReport(ctx context.Context, a *account, m awsctx.Metadata, sourceARN, granularity string, activities []PrincipalActivity) ([]ServiceAccess, *awswire.Error) {
	sources, entities, apiErr := accessReportSource(a, m, sourceARN)
	if apiErr != nil {
		return nil, apiErr
	}
	documents := make([]string, 0, len(sources))
	for _, source := range sources {
		documents = append(documents, source.document)
	}
	permissions, apiErr := reportPermissionActions(ctx, [][]string{documents})
	if apiErr != nil {
		return nil, apiErr
	}
	result := make([]ServiceAccess, 0, len(permissions))
	serviceCutoff := a.currentTime.Add(-serviceAccessTrackingPeriod)
	for _, namespace := range sortedMapKeys(permissions) {
		name, ok := catalog.LastAccessServiceName(namespace)
		if !ok {
			return nil, accessReportFailure()
		}
		service := ServiceAccess{Namespace: namespace, Name: name, Entities: make([]EntityAccess, 0, len(entities))}
		entityIndexes := make(map[string]int, len(service.Entities))
		for _, id := range sortedMapKeys(entities) {
			entityIndexes[id] = len(service.Entities)
			service.Entities = append(service.Entities, EntityAccess{ID: id})
		}
		actions := make(map[string]int)
		if granularity == "ACTION_LEVEL" {
			for _, action := range permissions[namespace] {
				if catalog.TracksActionLastAccess(action) {
					name := strings.TrimPrefix(action, namespace+":")
					actions[strings.ToLower(name)] = len(service.Actions)
					service.Actions = append(service.Actions, ActionAccess{Name: name})
				}
			}
		}
		for _, activity := range activities {
			if activity.ServiceNamespace != namespace || activity.LastAuthenticated.After(a.currentTime) {
				continue
			}
			i, found := entityIndexes[activity.PrincipalID]
			if !found {
				continue
			}
			// Service activity includes authenticated denials, even when the specific
			// operation was not granted. Group/policy sources restrict the service set.
			// Principal IDs join current entities; a rename does not lose prior use.
			activity.PrincipalARN = entities[activity.PrincipalID]
			if activity.LastAuthenticated.After(serviceCutoff) {
				retainLatestActivity(&service.Entities[i].LastActivity, activity)
				retainLatestActivity(&service.LastActivity, activity)
			}
			// Retain tracked action history independently of the service window.
			// AWS's historical rollout dates do not suppress activity recorded by
			// this emulator at an earlier modeled epoch.
			if index, tracked := actions[strings.ToLower(activity.ActionName)]; tracked {
				retainLatestActivity(&service.Actions[index].LastActivity, activity)
			}
		}
		result = append(result, service)
	}
	return result, nil
}

func retainLatestActivity(current **PrincipalActivity, activity PrincipalActivity) {
	previous := *current
	if previous == nil || activity.LastAuthenticated.After(previous.LastAuthenticated) || activity.LastAuthenticated.Equal(previous.LastAuthenticated) && cmp.Or(strings.Compare(activity.PrincipalID, previous.PrincipalID), strings.Compare(activity.ActionName, previous.ActionName), strings.Compare(activity.Region, previous.Region)) < 0 {
		*current = &activity
	}
}
