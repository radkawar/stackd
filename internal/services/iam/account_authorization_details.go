package iam

import (
	"context"
	"slices"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// An authorization report pages account entities together. Relationships and
// policy versions belong to their parent entity and never consume page slots.
type authorizationReportEntity struct {
	kind iamapi.EntityType
	key  string
}

func (entity authorizationReportEntity) pageKey() string {
	// Entity families share the limit; filter order must not move policies or
	// groups ahead of users. Policy ownership does not create another family.
	var family string
	switch entity.kind {
	case iamapi.EntityTypeUser:
		family = "0"
	case iamapi.EntityTypeRole:
		family = "1"
	case iamapi.EntityTypeGroup:
		family = "2"
	default:
		family = "3"
	}
	return family + "\x00" + entity.key
}

func (s *Service) getAccountAuthorizationDetails(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.GetAccountAuthorizationDetailsInput](ctx)
	if err != nil {
		return nil, err
	}
	filters, err := authorizationReportFilters(input.Filter)
	if err != nil {
		return nil, err
	}
	// Bind the marker to the effective filter set, independent of order and duplicates.
	selection := *input
	selection.Filter = filters
	var entities []authorizationReportEntity
	for _, filter := range filters {
		switch filter {
		case iamapi.EntityTypeUser:
			for key := range a.users {
				entities = append(entities, authorizationReportEntity{filter, key})
			}
		case iamapi.EntityTypeGroup:
			for key := range a.groups {
				entities = append(entities, authorizationReportEntity{filter, key})
			}
		case iamapi.EntityTypeRole:
			for key := range a.roles {
				entities = append(entities, authorizationReportEntity{filter, key})
			}
		case iamapi.EntityTypeLocalManagedPolicy, iamapi.EntityTypeAWSManagedPolicy:
			// Customer policies include unused policies. loadAccount installs
			// only AWS policies referenced by attachments or boundaries, which
			// is exactly the AWS-owned subset included in this report.
			for arn := range a.policies {
				if isAWSManagedPolicyARN(arn) == (filter == iamapi.EntityTypeAWSManagedPolicy) {
					entities = append(entities, authorizationReportEntity{filter, arn})
				}
			}
		}
	}
	entities, paging, err := page(ctx, entities, authorizationReportEntity.pageKey, m, &selection)
	if err != nil {
		return nil, invalid(err.Message)
	}
	out := &iamapi.GetAccountAuthorizationDetailsOutput{
		IsTruncated: wirePointer(iamapi.BooleanType(paging.IsTruncated)), Marker: wireMarker(paging),
		UserDetailList: make(iamapi.UserDetailListType, 0), GroupDetailList: make(iamapi.GroupDetailListType, 0),
		RoleDetailList: make(iamapi.RoleDetailListType, 0), Policies: make(iamapi.ManagedPolicyDetailListType, 0),
	}
	for _, entity := range entities {
		if ctx.Err() != nil {
			return nil, authorizationReportFailure()
		}
		switch entity.kind {
		case iamapi.EntityTypeUser:
			detail, err := authorizationUserDetail(a, a.users[entity.key])
			if err != nil {
				return nil, err
			}
			out.UserDetailList = append(out.UserDetailList, detail)
		case iamapi.EntityTypeGroup:
			detail, err := authorizationGroupDetail(a, a.groups[entity.key])
			if err != nil {
				return nil, err
			}
			out.GroupDetailList = append(out.GroupDetailList, detail)
		case iamapi.EntityTypeRole:
			detail, err := s.authorizationRoleDetail(ctx, a, m, a.roles[entity.key])
			if err != nil {
				return nil, err
			}
			out.RoleDetailList = append(out.RoleDetailList, detail)
		case iamapi.EntityTypeLocalManagedPolicy, iamapi.EntityTypeAWSManagedPolicy:
			out.Policies = append(out.Policies, authorizationPolicyDetail(a.policies[entity.key]))
		}
	}
	return out, nil
}

func authorizationReportFilters(input iamapi.EntityListType) ([]iamapi.EntityType, *awswire.Error) {
	filters := slices.Clone(input)
	if len(filters) == 0 {
		filters = []iamapi.EntityType{iamapi.EntityTypeUser, iamapi.EntityTypeGroup, iamapi.EntityTypeRole, iamapi.EntityTypeLocalManagedPolicy, iamapi.EntityTypeAWSManagedPolicy}
	}
	for _, filter := range filters {
		switch filter {
		case iamapi.EntityTypeUser, iamapi.EntityTypeGroup, iamapi.EntityTypeRole, iamapi.EntityTypeLocalManagedPolicy, iamapi.EntityTypeAWSManagedPolicy:
		default:
			return nil, invalid("Filter must contain User, Group, Role, LocalManagedPolicy, or AWSManagedPolicy.")
		}
	}
	slices.Sort(filters)
	return slices.Compact(filters), nil
}

func authorizationReportFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceFailure", StatusCode: 500, Message: "Unable to load account authorization details."}
}
