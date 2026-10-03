package iam

import (
	"cmp"
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
	"stackd/internal/services/organizations"
)

// OrganizationAccessSource owns organization membership, SCP eligibility and
// the account hierarchy. IAM consumes its detached snapshot in a separate
// transaction to aggregate authenticated activity.
type OrganizationAccessSource interface {
	AccessReportSnapshot(context.Context, string, string) (organizations.AccessReportSnapshot, error)
	CheckAccessReportAccess(context.Context) error
}

// AWS reuses a caller's recent report for the same selection, including failed
// reports. This interval is measured from job creation, not completion.
const organizationReportReuse = time.Minute

func (s *Service) generateOrganizationsAccessReport(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, apiErr := generatedIAMInput[iamapi.GenerateOrganizationsAccessReportInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if s.organizationReports == nil {
		return nil, organizationReportAccessError(organizations.ErrAccessReportManagementRequired)
	}
	path, policyID := inputString(input.EntityPath), inputString(input.OrganizationsPolicyId)
	transaction := ctx.Value(transactionKey{}).(serviceTransaction)
	scope := Scope{m.Partition, m.AccountID}
	previous, err := transaction.tx.LatestOrganizationAccessReport(scope, accessReportOwner(m), path, policyID)
	if err != nil && !errors.Is(err, ErrRecordNotFound) {
		return nil, accessReportFailure()
	}
	if err == nil && a.currentTime.Before(previous.RequestedAt.Add(organizationReportReuse)) {
		if err := s.organizationReports.CheckAccessReportAccess(ctx); err != nil {
			return nil, organizationReportAccessError(err)
		}
		return &iamapi.GenerateOrganizationsAccessReportOutput{JobId: wirePointer(iamapi.JobIDType(previous.ID))}, nil
	}
	// AWS admits one active Organizations report per account, across callers.
	// Reusing an existing report does not consume another generation slot.
	pending, err := transaction.tx.PendingAccessReports(scope)
	if err != nil {
		return nil, accessReportFailure()
	}
	for _, report := range pending {
		if report.Organization != nil {
			return nil, &awswire.Error{Code: "ReportGenerationLimitExceeded", Message: "Maximum number of concurrent jobs exceeded", StatusCode: 409}
		}
	}
	snapshot, err := s.organizationReports.AccessReportSnapshot(ctx, path, policyID)
	payload := &OrganizationAccessReport{EntityPath: path, PolicyID: policyID}
	switch {
	case errors.Is(err, organizations.ErrAccessReportEntityNotFound):
		payload.Error = &AccessReportError{Code: "INVALID_ORGANIZATIONS_ENTITY_PATH", Message: "The entity with the specified path does not exist in your organization."}
	case errors.Is(err, organizations.ErrAccessReportPolicyNotFound):
		payload.Error = &AccessReportError{Code: "INVALID_ORGANIZATIONS_POLICY", Message: "The policy with the specified ID does not exist in your organization."}
	case errors.Is(err, organizations.ErrAccessReportReadDenied):
		payload.Error = &AccessReportError{Code: "ORGANIZATIONS_REPORT_ACCESS_DENIED", Message: "Requester is not authorized to perform the required AWS Organizations Describe* and List* actions."}
	case err != nil:
		return nil, organizationReportAccessError(err)
	default:
		payload.Services, apiErr = buildOrganizationAccessReport(ctx, m.Partition, snapshot)
		if apiErr != nil {
			return nil, apiErr
		}
	}
	jobID, err := randomUUID()
	if err != nil {
		return nil, accessReportFailure()
	}
	report := AccessReport{ID: jobID, Owner: accessReportOwner(m), RequestedAt: a.currentTime, Organization: payload}
	if err := transaction.tx.(WriteTx).PutAccessReport(scope, report); err != nil {
		return nil, accessReportFailure()
	}
	return &iamapi.GenerateOrganizationsAccessReportOutput{JobId: wirePointer(iamapi.JobIDType(jobID))}, nil
}

func (s *Service) getOrganizationsAccessReport(ctx context.Context, _ *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, apiErr := generatedIAMInput[iamapi.GetOrganizationsAccessReportInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if s.organizationReports == nil {
		return nil, organizationReportAccessError(organizations.ErrAccessReportManagementRequired)
	}
	if err := s.organizationReports.CheckAccessReportAccess(ctx); err != nil {
		return nil, organizationReportAccessError(err)
	}
	id := inputString(input.JobId)
	report, apiErr := s.loadAccessReport(ctx, m, id)
	if apiErr != nil {
		return nil, apiErr
	}
	if report.Organization == nil {
		return nil, missing("job", id)
	}
	out := &iamapi.GetOrganizationsAccessReportOutput{JobStatus: wirePointer(accessReportStatus(report)), JobCreationDate: wirePointer(iamapi.DateType(report.RequestedAt)), IsTruncated: wirePointer(iamapi.BooleanType(false))}
	if report.CompletedAt == nil {
		return out, nil
	}
	out.JobCompletionDate = wirePointer(iamapi.DateType(*report.CompletedAt))
	if failure := report.Organization.Error; failure != nil {
		out.ErrorDetails = &iamapi.ErrorDetails{Code: wirePointer(iamapi.StringType(failure.Code)), Message: wirePointer(iamapi.StringType(failure.Message))}
		return out, nil
	}
	services := report.Organization.Services
	unused := 0
	for _, service := range services {
		if service.AuthenticatedAccounts == 0 {
			unused++
		}
	}
	out.NumberOfServicesAccessible = wirePointer(iamapi.IntegerType(len(services)))
	out.NumberOfServicesNotAccessed = wirePointer(iamapi.IntegerType(unused))
	sortKey := inputString(input.SortKey)
	if input.SortKey == nil {
		sortKey = "SERVICE_NAMESPACE_ASCENDING"
	}
	sortOrganizationAccess(services, sortKey)
	positions := make(map[string]string, len(services))
	for i, service := range services {
		positions[service.Namespace] = fmt.Sprintf("%020d", i+1)
	}
	selection := *input
	selection.SortKey = wirePointer(iamapi.SortKeyType(sortKey))
	services, pagination, apiErr := page(ctx, services, func(service OrganizationServiceAccess) string { return positions[service.Namespace] }, m, &selection)
	if apiErr != nil {
		return nil, apiErr
	}
	out.IsTruncated = wirePointer(iamapi.BooleanType(pagination.IsTruncated))
	if pagination.Marker != "" {
		out.Marker = wirePointer(iamapi.MarkerType(pagination.Marker))
	}
	out.AccessDetails = make(iamapi.AccessDetails, 0, len(services))
	for _, service := range services {
		row := iamapi.AccessDetail{ServiceName: wirePointer(iamapi.ServiceNameType(service.Name)), ServiceNamespace: wirePointer(iamapi.ServiceNamespaceType(service.Namespace)), TotalAuthenticatedEntities: wirePointer(iamapi.IntegerType(service.AuthenticatedAccounts))}
		if region, present := catalog.OrganizationsAccessDefaultRegion(service.Namespace); present {
			row.Region = wirePointer(iamapi.StringType(region))
		}
		if activity := service.LastActivity; activity != nil {
			row.EntityPath = wirePointer(iamapi.OrganizationsEntityPathType(activity.EntityPath))
			row.Region = wirePointer(iamapi.StringType(activity.Region))
			row.LastAuthenticatedTime = wirePointer(iamapi.DateType(activity.LastAuthenticated))
		}
		out.AccessDetails = append(out.AccessDetails, row)
	}
	return out, nil
}

func sortOrganizationAccess(services []OrganizationServiceAccess, key string) {
	slices.SortFunc(services, func(a, b OrganizationServiceAccess) int {
		order := 0
		if strings.HasPrefix(key, "LAST_AUTHENTICATED_TIME_") {
			switch {
			case a.LastActivity == nil && b.LastActivity != nil:
				order = -1
			case a.LastActivity != nil && b.LastActivity == nil:
				order = 1
			case a.LastActivity != nil && b.LastActivity != nil:
				order = a.LastActivity.LastAuthenticated.Compare(b.LastActivity.LastAuthenticated)
			}
			if order == 0 {
				order = cmp.Compare(catalog.OrganizationsAccessTimeSortRank(a.Namespace), catalog.OrganizationsAccessTimeSortRank(b.Namespace))
			}
		}
		if order == 0 {
			order = strings.Compare(a.Namespace, b.Namespace)
		}
		if strings.HasSuffix(key, "_DESCENDING") {
			return -order
		}
		return order
	})
}

func organizationReportAccessError(err error) *awswire.Error {
	switch {
	case errors.Is(err, organizations.ErrAccessReportWrongOrganization):
		return &awswire.Error{Code: "AccessDenied", Message: "The organization ID in the specified entity path is different than your organization ID.", StatusCode: 403}
	case errors.Is(err, organizations.ErrAccessReportManagementRequired):
		return &awswire.Error{Code: "AccessDenied", Message: "Organizations access reports require the management account.", StatusCode: 403}
	case errors.Is(err, organizations.ErrAccessReportSCPDisabled):
		return &awswire.Error{Code: "AccessDenied", Message: "Service control policies must be enabled for the organization root.", StatusCode: 403}
	default:
		return accessReportFailure()
	}
}
