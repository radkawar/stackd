package iam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/organizations"
)

// WithAccountRoles provisions initial account roles and commits Organizations
// through the callback in the same authority. Creating the management account's
// missing service-linked role, or accepting an all-features invitation, requires
// the caller's IAM permission. Provisioning
// a new member adds no IAM permission requirement to its Organizations checks.
func (s *Service) WithAccountRoles(ctx context.Context, in organizations.AccountProvisioning, commit func(context.Context) error) error {
	return s.withAuthorityTransaction(ctx, func(ctx context.Context, tx WriteTx, _ identity.Repository, now time.Time) error {
		scope := Scope{Partition: in.Partition, AccountID: in.AccountID}
		m := awsctx.Metadata{Partition: in.Partition, AccountID: in.AccountID}
		template, apiErr := s.serviceLinkedTemplate(in.Partition, organizations.ServicePrincipal)
		if apiErr != nil {
			return apiErr
		}
		linked, err := tx.Role(scope, template.RoleName)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrRecordNotFound) {
			return err
		}
		if !exists && in.AccessRoleName == "" {
			s.mu.Lock()
			authorizer := s.authorizer
			s.mu.Unlock()
			permission := authorization.Request{Action: "iam:CreateServiceLinkedRole", ResourceARN: resourceARN(m, "role", "/aws-service-role/"+template.ServiceName+"/", template.RoleName), Context: map[string][]string{"iam:AWSServiceName": {template.ServiceName}}, EvaluationTime: &now}
			if err := authorizer.Authorize(ctx, permission); err != nil {
				return &awswire.Error{Code: "AccessDeniedForDependencyException", Message: "Creating the Organizations service-linked role requires iam:CreateServiceLinkedRole for organizations.amazonaws.com.", StatusCode: http.StatusBadRequest}
			}
		}
		// Validate the Organizations revision before using its allocated account
		// ID. A stale attempt must retry rather than collide with the role that
		// a winning account creation has already installed. This write remains
		// staged and rolls back if role provisioning fails below.
		if err := commit(ctx); err != nil {
			return err
		}
		if exists {
			if linked.ServiceLinkedService != template.ServiceName {
				return duplicate("Role", template.RoleName)
			}
		} else if err := tx.PutRole(scope, *newServiceLinkedRole(template, m, template.RoleName, template.DefaultDescription, in.CreatedAt)); err != nil {
			return err
		}
		if in.AccessRoleName == "" {
			return nil
		}
		policyARN := "arn:" + in.Partition + ":iam::aws:policy/AdministratorAccess"
		if _, ok := lookupAWSManagedPolicy(in.Partition, policyARN); !ok {
			return unavailableManagedCatalogue(in.Partition)
		}
		if _, err := tx.Role(scope, in.AccessRoleName); err == nil {
			return duplicate("Role", in.AccessRoleName)
		} else if !errors.Is(err, ErrRecordNotFound) {
			return err
		}
		policies := newIdentityPolicies()
		policies.Attached[policyARN] = struct{}{}
		role := Role{
			Path: "/", RoleName: in.AccessRoleName, RoleId: newID("AROA"),
			Arn: resourceARN(m, "role", "/", in.AccessRoleName), CreateDate: in.CreatedAt,
			AssumeRolePolicyDocument: fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:%s:iam::%s:root"},"Action":"sts:AssumeRole"}]}`, in.Partition, in.ManagementAccountID),
			MaxSessionDuration:       3600, IdentityPolicies: policies,
		}
		if err := tx.PutRole(scope, role); err != nil {
			return err
		}
		return tx.PutAccountMetadata(scope, AccountMetadata{CreatedAt: in.CreatedAt})
	})
}
