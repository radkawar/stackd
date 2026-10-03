package iam

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

func isLastAccessAction(action string) bool {
	switch action {
	case "GenerateServiceLastAccessedDetails", "GetServiceLastAccessedDetails", "GetServiceLastAccessedDetailsWithEntities", "ListPoliciesGrantingServiceAccess", "GenerateOrganizationsAccessReport", "GetOrganizationsAccessReport":
		return true
	}
	return false
}

func lastAccessIdentity(a *account, m awsctx.Metadata, arn string) (permissionPolicyIdentity, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[2] != "iam" {
		return permissionPolicyIdentity{}, invalid("Invalid service in ARN")
	}
	kind, name, err := contextKeySourceARN(arn)
	if err != nil {
		return permissionPolicyIdentity{}, err
	}
	if err := lastAccessScope(m, parts[1], parts[4]); err != nil {
		return permissionPolicyIdentity{}, err
	}
	return permissionPolicyIdentityByName(a, kind, name)
}

func lastAccessScope(m awsctx.Metadata, partition, account string) *awswire.Error {
	if partition != m.Partition {
		return invalid("Invalid ARN partition")
	}
	if account != m.AccountID && account != "aws" {
		return &awswire.Error{Code: "AccessDenied", Message: "The resource must belong to this account.", StatusCode: 403}
	}
	return nil
}

func accessReportOwner(m awsctx.Metadata) string {
	if m.SessionType != "" {
		return m.AccessKeyID
	}
	return m.PrincipalID
}

func (s *Service) generateServiceLastAccessedDetails(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.GenerateServiceLastAccessedDetailsInput](ctx)
	if err != nil {
		return nil, err
	}
	source := inputString(input.Arn)
	granularity := inputString(input.Granularity)
	if input.Granularity == nil {
		granularity = "SERVICE_LEVEL"
	}
	jobID, randomErr := randomUUID()
	if randomErr != nil {
		return nil, accessReportFailure()
	}
	transaction := ctx.Value(transactionKey{}).(serviceTransaction)
	activities, activityErr := transaction.tx.PrincipalActivities(Scope{m.Partition, m.AccountID})
	if activityErr != nil {
		return nil, accessReportFailure()
	}
	services, apiErr := buildAccessReport(ctx, a, m, source, granularity, activities)
	if apiErr != nil {
		return nil, apiErr
	}
	report := AccessReport{ID: jobID, Owner: accessReportOwner(m), Granularity: granularity, RequestedAt: a.currentTime, Services: services}
	if err := transaction.tx.(WriteTx).PutAccessReport(Scope{m.Partition, m.AccountID}, report); err != nil {
		return nil, accessReportFailure()
	}
	return &iamapi.GenerateServiceLastAccessedDetailsOutput{JobId: wirePointer(iamapi.JobIDType(jobID))}, nil
}

func (s *Service) loadAccessReport(ctx context.Context, m awsctx.Metadata, id string) (AccessReport, *awswire.Error) {
	var report AccessReport
	err := s.view(ctx, func(tx ReadTx) error {
		var err error
		report, err = tx.AccessReport(Scope{m.Partition, m.AccountID}, id)
		return err
	})
	if errors.Is(err, ErrRecordNotFound) || (err == nil && report.Owner != accessReportOwner(m)) {
		return AccessReport{}, missing("job", id)
	}
	if err != nil {
		return AccessReport{}, accessReportFailure()
	}
	return report, nil
}

func (s *Service) ownedAccessReport(ctx context.Context, m awsctx.Metadata, id string) (AccessReport, *awswire.Error) {
	report, err := s.loadAccessReport(ctx, m, id)
	if err != nil {
		return AccessReport{}, err
	}
	if report.Organization != nil {
		return AccessReport{}, missing("job", id)
	}
	return report, nil
}

func (s *Service) getServiceLastAccessedDetails(ctx context.Context, _ *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, apiErr := generatedIAMInput[iamapi.GetServiceLastAccessedDetailsInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	report, apiErr := s.ownedAccessReport(ctx, m, inputString(input.JobId))
	if apiErr != nil {
		return nil, apiErr
	}
	out := &iamapi.GetServiceLastAccessedDetailsOutput{JobStatus: wirePointer(accessReportStatus(report)), JobCreationDate: wirePointer(iamapi.DateType(report.RequestedAt)), IsTruncated: wirePointer(iamapi.BooleanType(false))}
	if report.CompletedAt == nil {
		return out, nil
	}
	out.JobCompletionDate = wirePointer(iamapi.DateType(*report.CompletedAt))
	out.JobType = wirePointer(iamapi.AccessAdvisorUsageGranularityType(report.Granularity))
	services, pagination, apiErr := page(ctx, report.Services, func(service ServiceAccess) string { return service.Namespace }, m, input)
	if apiErr != nil {
		return nil, apiErr
	}
	out.IsTruncated = wirePointer(iamapi.BooleanType(pagination.IsTruncated))
	if pagination.Marker != "" {
		out.Marker = wirePointer(iamapi.ResponseMarkerType(pagination.Marker))
	}
	out.ServicesLastAccessed = make(iamapi.ServicesLastAccessed, 0, len(services))
	for _, service := range services {
		out.ServicesLastAccessed = append(out.ServicesLastAccessed, wireServiceAccess(service))
	}
	return out, nil
}

func (s *Service) getServiceLastAccessedDetailsWithEntities(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, apiErr := generatedIAMInput[iamapi.GetServiceLastAccessedDetailsWithEntitiesInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	metadata, err := catalog.Load()
	if err != nil {
		return nil, accessReportFailure()
	}
	namespace := inputString(input.ServiceNamespace)
	if service, ok := metadata.LookupService(namespace); !ok || service.Prefix != namespace {
		return nil, invalidInput("Invalid service namespace.")
	}
	report, apiErr := s.ownedAccessReport(ctx, m, inputString(input.JobId))
	if apiErr != nil {
		return nil, apiErr
	}
	out := &iamapi.GetServiceLastAccessedDetailsWithEntitiesOutput{JobStatus: wirePointer(accessReportStatus(report)), JobCreationDate: wirePointer(iamapi.DateType(report.RequestedAt)), IsTruncated: wirePointer(iamapi.BooleanType(false))}
	if report.CompletedAt == nil {
		return out, nil
	}
	out.JobCompletionDate = wirePointer(iamapi.DateType(*report.CompletedAt))
	var entities []EntityAccess
	for _, service := range report.Services {
		if service.Namespace == namespace {
			entities = service.Entities
			break
		}
	}
	// Membership and usage are frozen, but AWS resolves current identity
	// metadata and drops deleted principals when the report is read.
	members := make(map[string]*PrincipalActivity, len(entities))
	for _, entity := range entities {
		members[entity.ID] = entity.LastActivity
	}
	details := make(iamapi.EntityDetailsListType, 0, len(entities))
	for _, user := range a.users {
		activity, present := members[user.UserId]
		if !present {
			continue
		}
		info := &iamapi.EntityInfo{Arn: wirePointer(iamapi.ArnType(user.Arn)), Id: wirePointer(iamapi.IdType(user.UserId)), Name: wirePointer(iamapi.UserNameType(user.UserName)), Path: wirePointer(iamapi.PathType(user.Path)), Type: wirePointer(iamapi.PolicyOwnerEntityTypeUSER)}
		details = append(details, wireAccessEntity(info, activity))
	}
	for _, role := range a.roles {
		activity, present := members[role.RoleId]
		if !present {
			continue
		}
		info := &iamapi.EntityInfo{Arn: wirePointer(iamapi.ArnType(role.Arn)), Id: wirePointer(iamapi.IdType(role.RoleId)), Name: wirePointer(iamapi.UserNameType(role.RoleName)), Path: wirePointer(iamapi.PathType(role.Path)), Type: wirePointer(iamapi.PolicyOwnerEntityTypeROLE)}
		details = append(details, wireAccessEntity(info, activity))
	}
	slices.SortFunc(details, func(a, b iamapi.EntityDetails) int {
		if a.LastAuthenticated == nil && b.LastAuthenticated != nil {
			return 1
		}
		if a.LastAuthenticated != nil && b.LastAuthenticated == nil {
			return -1
		}
		if a.LastAuthenticated != nil && b.LastAuthenticated != nil {
			if order := time.Time(*b.LastAuthenticated).Compare(time.Time(*a.LastAuthenticated)); order != 0 {
				return order
			}
		}
		return strings.Compare(string(*a.EntityInfo.Arn), string(*b.EntityInfo.Arn))
	})
	// Entity markers bind the job and API, but can continue another namespace.
	positions := make(map[string]string, len(details))
	for i, entity := range details {
		positions[string(*entity.EntityInfo.Id)] = fmt.Sprintf("%020d", i+1)
	}
	selection := *input
	selection.ServiceNamespace = nil
	details, pagination, apiErr := page(ctx, details, func(entity iamapi.EntityDetails) string { return positions[string(*entity.EntityInfo.Id)] }, m, &selection)
	if apiErr != nil {
		return nil, apiErr
	}
	out.IsTruncated = wirePointer(iamapi.BooleanType(pagination.IsTruncated))
	if pagination.Marker != "" {
		out.Marker = wirePointer(iamapi.ResponseMarkerType(pagination.Marker))
	}
	out.EntityDetailsList = details
	return out, nil
}

func wireServiceAccess(service ServiceAccess) iamapi.ServiceLastAccessed {
	count := 0
	for _, entity := range service.Entities {
		if entity.LastActivity != nil {
			count++
		}
	}
	out := iamapi.ServiceLastAccessed{ServiceName: wirePointer(iamapi.ServiceNameType(service.Name)), ServiceNamespace: wirePointer(iamapi.ServiceNamespaceType(service.Namespace)), TotalAuthenticatedEntities: wirePointer(iamapi.IntegerType(count))}
	if activity := service.LastActivity; activity != nil {
		out.LastAuthenticated = wirePointer(iamapi.DateType(activity.LastAuthenticated))
		out.LastAuthenticatedEntity = wirePointer(iamapi.ArnType(activity.PrincipalARN))
		out.LastAuthenticatedRegion = wirePointer(iamapi.StringType(activity.Region))
	}
	for _, action := range service.Actions {
		tracked := iamapi.TrackedActionLastAccessed{ActionName: wirePointer(iamapi.StringType(action.Name))}
		if activity := action.LastActivity; activity != nil {
			tracked.LastAccessedTime = wirePointer(iamapi.DateType(activity.LastAuthenticated))
			tracked.LastAccessedEntity = wirePointer(iamapi.ArnType(activity.PrincipalARN))
			tracked.LastAccessedRegion = wirePointer(iamapi.StringType(activity.Region))
		}
		out.TrackedActionsLastAccessed = append(out.TrackedActionsLastAccessed, tracked)
	}
	return out
}

func accessReportStatus(report AccessReport) iamapi.JobStatusType {
	if report.CompletedAt == nil {
		return iamapi.JobStatusTypeIN_PROGRESS
	}
	if report.Organization != nil && report.Organization.Error != nil {
		return iamapi.JobStatusTypeFAILED
	}
	return iamapi.JobStatusTypeCOMPLETED
}

func accessReportFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceFailure", Message: "Unable to generate or read the access report.", StatusCode: 500}
}

func wireAccessEntity(info *iamapi.EntityInfo, activity *PrincipalActivity) iamapi.EntityDetails {
	result := iamapi.EntityDetails{EntityInfo: info}
	if activity != nil {
		result.LastAuthenticated = wirePointer(iamapi.DateType(activity.LastAuthenticated))
	}
	return result
}
