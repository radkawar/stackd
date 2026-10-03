package iam

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// PutServiceLinkedRolePolicy is a trusted service-owner command, not a public
// IAM permission bypass. The adapter authorizes the originating caller before
// invoking it with the linked service principal. IAM still owns role identity,
// policy validation, limits, and the transactional IAM API event.
func (s *Service) PutServiceLinkedRolePolicy(ctx context.Context, scope Scope, service, roleName, policyName, document string) error {
	return s.mutateServiceLinkedRolePolicy(ctx, scope, service, roleName, policyName, document, false)
}

// DeleteServiceLinkedRolePolicy is idempotent for an absent owned policy so a
// linked service can clean up inactive resources and resume lifecycle work.
func (s *Service) DeleteServiceLinkedRolePolicy(ctx context.Context, scope Scope, service, roleName, policyName string) error {
	return s.mutateServiceLinkedRolePolicy(ctx, scope, service, roleName, policyName, "", true)
}

func (s *Service) mutateServiceLinkedRolePolicy(ctx context.Context, scope Scope, service, roleName, policyName, document string, remove bool) error {
	if awsctx.FromContext(ctx).ServicePrincipal.Name != service || service == "" || !strings.HasPrefix(policyName, "AWSServiceOwned-"+service+"-") {
		return &awswire.Error{Code: "AccessDenied", Message: "The policy does not belong to the invoking linked service.", StatusCode: 403}
	}
	if err := validateName(policyName, "PolicyName", 128); err != nil {
		return err
	}
	return s.updateAt(ctx, func(tx WriteTx, now time.Time) error {
		template, wire := s.serviceLinkedTemplate(scope.Partition, service)
		if wire != nil {
			return wire
		}
		role, err := tx.Role(scope, roleName)
		if errors.Is(err, ErrRecordNotFound) {
			return missing("role", roleName)
		}
		if err != nil {
			return err
		}
		path := "/aws-service-role/" + service + "/"
		if role.ServiceLinkedService != service || role.RoleName != template.RoleName || role.Path != path || role.Arn != "arn:"+scope.Partition+":iam::"+scope.AccountID+":role"+path+template.RoleName {
			return &awswire.Error{Code: "AccessDenied", Message: "The role does not belong to the invoking linked service template.", StatusCode: 403}
		}
		for name := range template.InlinePolicies {
			if strings.EqualFold(name, policyName) {
				return conflict("A resource policy cannot replace a service-linked template policy.")
			}
		}
		operation := "PutRolePolicy"
		var input any = &iamapi.PutRolePolicyInput{RoleName: new(iamapi.RoleNameType(roleName)), PolicyName: new(iamapi.PolicyNameType(policyName)), PolicyDocument: new(iamapi.PolicyDocumentType(document))}
		if remove {
			stored, exists := inlinePolicyName(&role.IdentityPolicies, policyName)
			if !exists {
				return nil
			}
			delete(role.Inline, stored)
			operation = "DeleteRolePolicy"
			input = &iamapi.DeleteRolePolicyInput{RoleName: new(iamapi.RoleNameType(roleName)), PolicyName: new(iamapi.PolicyNameType(policyName))}
		} else {
			if role.Inline == nil {
				role.Inline = make(map[string]string)
			}
			if wire := putIdentityPolicy(&role.IdentityPolicies, "Role", policyName, document); wire != nil {
				return wire
			}
		}
		if err := tx.PutRole(scope, role); err != nil {
			return err
		}
		if s.apiCallEvents == nil {
			return nil
		}
		metadata := awsctx.FromContext(ctx)
		metadata.Partition, metadata.AccountID = scope.Partition, scope.AccountID
		metadata.InvokedBy = service
		metadata.RequestID = uuid.NewString()
		if parent := apievents.EventID(ctx); parent != "" {
			metadata.ParentEventID = parent
		}
		model, _ := awscatalog.LookupService("iam")
		op, _ := model.Operation(operation)
		audit := awsapi.WithDecodedRequest(awsctx.WithMetadata(tx.Context(), metadata), awsapi.DecodedRequest{Operation: op, Input: input})
		return s.appendAPICall(serviceLinkedRoleAuditContext(audit), now, &iamapi.Unit{}, nil)
	})
}
