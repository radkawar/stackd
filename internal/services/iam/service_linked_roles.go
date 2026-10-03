package iam

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) serviceLinkedHandlers() map[string]handler {
	return map[string]handler{"CreateServiceLinkedRole": s.createServiceLinkedRole, "DeleteServiceLinkedRole": s.deleteServiceLinkedRole, "GetServiceLinkedRoleDeletionStatus": getServiceLinkedRoleDeletionStatus}
}

func (s *Service) createServiceLinkedRole(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.CreateServiceLinkedRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	service := inputString(input.AWSServiceName)
	if len(service) < 1 || len(service) > 128 || !namePattern.MatchString(service) {
		return nil, invalid("Invalid AWSServiceName.")
	}
	template, err := s.serviceLinkedTemplate(m.Partition, service)
	if err != nil {
		return nil, err
	}
	name, err := serviceLinkedRoleName(template, inputString(input.CustomSuffix), input.CustomSuffix != nil)
	if err != nil {
		return nil, err
	}
	if a.roles[strings.ToLower(name)] != nil {
		return nil, &awswire.Error{Code: "InvalidInput", StatusCode: 400, Message: "Service role name " + name + " has been taken in this account, please try a different suffix."}
	}
	description := template.DefaultDescription
	if input.Description != nil {
		description = inputString(input.Description)
	}
	r := newServiceLinkedRole(template, m, name, description, a.currentTime)
	// AWS includes these roles in Roles summary usage, but creation of a
	// service-linked role may exceed the ordinary IAM role quota.
	a.roles[strings.ToLower(name)] = r
	return serviceLinkedRoleOutput(r), nil
}

func serviceLinkedRoleOutput(r *Role) *iamapi.CreateServiceLinkedRoleOutput {
	wire := &iamapi.Role{Path: wirePointer(iamapi.PathType(r.Path)), RoleName: wirePointer(iamapi.RoleNameType(r.RoleName)), RoleId: wirePointer(iamapi.IdType(r.RoleId)), Arn: wirePointer(iamapi.ArnType(r.Arn)), CreateDate: wirePointer(iamapi.DateType(r.CreateDate)), AssumeRolePolicyDocument: wirePointer(iamapi.PolicyDocumentType(encodedDocument(r.AssumeRolePolicyDocument)))}
	return &iamapi.CreateServiceLinkedRoleOutput{Role: wire}
}

// newServiceLinkedRole shares the sourced definition between explicit IAM
// requests and trusted automatic provisioning. Registration owns validation.
func newServiceLinkedRole(template ServiceLinkedRoleTemplate, m awsctx.Metadata, name, description string, now time.Time) *Role {
	path := "/aws-service-role/" + template.ServiceName + "/"
	r := &Role{Path: path, RoleName: name, RoleId: newID("AROA"), Arn: resourceARN(m, "role", path, name), CreateDate: now, AssumeRolePolicyDocument: template.TrustPolicy, Description: description, MaxSessionDuration: 3600, ServiceLinkedService: template.ServiceName, IdentityPolicies: newIdentityPolicies()}
	r.Inline = maps.Clone(template.InlinePolicies)
	if r.Inline == nil {
		r.Inline = make(map[string]string)
	}
	for _, arn := range template.ManagedPolicyARNs {
		r.Attached[arn] = struct{}{}
	}
	return r
}

func serviceLinkedRoleName(template ServiceLinkedRoleTemplate, suffix string, present bool) (string, *awswire.Error) {
	name := template.RoleName
	if present {
		if !template.AllowCustomSuffix {
			return "", &awswire.Error{Code: "InvalidInput", StatusCode: 400, Message: "Custom suffix is not allowed for " + template.ServiceName}
		}
		if len(suffix) < 1 || len(suffix) > 64 || !namePattern.MatchString(suffix) {
			return "", invalid("Invalid CustomSuffix.")
		}
		name += "_" + suffix
	}
	if len(name) > 64 {
		return "", &awswire.Error{Code: "InvalidInput", StatusCode: 400, Message: "Service-linked role name exceeds 64 characters."}
	}
	return name, nil
}

func (s *Service) deleteServiceLinkedRole(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.DeleteServiceLinkedRoleInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(input.RoleName))
	if err != nil {
		return nil, err
	}
	if r.ServiceLinkedService == "" {
		return nil, missing("service-linked role", r.RoleName)
	}
	for _, job := range a.serviceLinkedDeletions {
		if job.RoleID == r.RoleId && serviceLinkedPending(job.Status) {
			return &iamapi.DeleteServiceLinkedRoleOutput{DeletionTaskId: wirePointer(iamapi.DeletionTaskIdType(job.ID))}, nil
		}
	}
	uuid, uuidErr := randomUUID()
	if uuidErr != nil {
		return nil, &awswire.Error{Code: "ServiceFailure", StatusCode: 500, Message: "Unable to create role deletion task identifier."}
	}
	id := fmt.Sprintf("task/aws-service-role/%s/%s/%s", r.ServiceLinkedService, r.RoleName, uuid)
	now := a.currentTime
	a.serviceLinkedDeletions[id] = &ServiceLinkedRoleDeletion{ID: id, RoleID: r.RoleId, RoleARN: r.Arn, RoleName: r.RoleName, ServiceName: r.ServiceLinkedService, Status: serviceLinkedNotStarted, CreatedAt: now, UpdatedAt: now}
	return &iamapi.DeleteServiceLinkedRoleOutput{DeletionTaskId: wirePointer(iamapi.DeletionTaskIdType(id))}, nil
}

var serviceLinkedTaskPattern = regexp.MustCompile(`^task/aws-service-role/[A-Za-z0-9_+=,.@-]+/[A-Za-z0-9_+=,.@-]+/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func getServiceLinkedRoleDeletionStatus(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.GetServiceLinkedRoleDeletionStatusInput](ctx)
	if err != nil {
		return nil, err
	}
	id := inputString(input.DeletionTaskId)
	if !serviceLinkedTaskPattern.MatchString(id) {
		return nil, &awswire.Error{Code: "InvalidInput", StatusCode: 400, Message: "Invalid task id"}
	}
	job := a.serviceLinkedDeletions[id]
	if job == nil {
		return nil, missing("deletion task", id)
	}
	output := &iamapi.GetServiceLinkedRoleDeletionStatusOutput{Status: wirePointer(iamapi.DeletionTaskStatusType(job.Status))}
	if job.FailureReason != "" || len(job.Usage) > 0 {
		output.Reason = &iamapi.DeletionTaskFailureReasonType{Reason: wirePointer(iamapi.ReasonType(job.FailureReason))}
		for _, usage := range job.Usage {
			row := iamapi.RoleUsageType{Region: wirePointer(iamapi.RegionNameType(usage.Region))}
			for _, arn := range usage.ResourceARNs {
				row.Resources = append(row.Resources, iamapi.ArnType(arn))
			}
			output.Reason.RoleUsageList = append(output.Reason.RoleUsageList, row)
		}
	}
	return output, nil
}
