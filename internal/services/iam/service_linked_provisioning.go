package iam

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// EnsureServiceLinkedRole is used by a linked service when its first resource
// requires an IAM role. Existing roles require no creation permission. Role
// protection, trust and policies come from the registered service template.
// Permission denial leaves a borrowed transaction usable. The caller must invoke
// the returned error's RecordRejection(context.Context) using that transaction
// when continuing, or its original request context after rolling it back.
func (s *Service) EnsureServiceLinkedRole(ctx context.Context, service string) error {
	m := awsctx.FromContext(ctx)
	return s.ensureServiceLinkedRole(ctx, Scope{Partition: m.Partition, AccountID: m.AccountID}, service, true)
}

// ProvisionServiceLinkedRole installs a role for an authorized service-owned
// lifecycle, including organization member accounts. The service adapter owns
// membership and administration checks; this is not a public IAM permission bypass.
// It shares the registered template, protected identity and audit path with
// caller-authorized provisioning.
func (s *Service) ProvisionServiceLinkedRole(ctx context.Context, scope Scope, service string) error {
	ctx = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: service, Type: "AWSService"})
	metadata := awsctx.FromContext(ctx)
	metadata.InvokedBy = service
	return s.ensureServiceLinkedRole(awsctx.WithMetadata(ctx, metadata), scope, service, false)
}

func (s *Service) ensureServiceLinkedRole(ctx context.Context, scope Scope, service string, callerOwned bool) error {
	model, _ := awscatalog.LookupService("iam")
	op, _ := model.Operation("CreateServiceLinkedRole")
	input := &iamapi.CreateServiceLinkedRoleInput{AWSServiceName: wirePointer(iamapi.GroupNameType(service))}
	decoded := awsapi.DecodedRequest{Operation: op, Input: input}
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	metadata := awsctx.FromContext(ctx)
	attempted := false
	var denied *awswire.Error
	err := s.updateAt(ctx, func(tx WriteTx, now time.Time) error {
		m := awsctx.FromContext(ctx)
		m.Partition, m.AccountID = scope.Partition, scope.AccountID
		template, apiErr := s.serviceLinkedTemplate(m.Partition, service)
		if apiErr != nil {
			return apiErr
		}
		role, err := tx.Role(scope, template.RoleName)
		if err == nil {
			if role.ServiceLinkedService != service {
				return duplicate("Role", template.RoleName)
			}
			return nil
		}
		if !errors.Is(err, ErrRecordNotFound) {
			return err
		}
		attempted = true
		m.RequestID = uuid.NewString()
		if parent := apievents.EventID(ctx); parent != "" {
			m.ParentEventID = parent
		}
		metadata = m
		ctx = awsapi.WithDecodedRequest(awsctx.WithMetadata(tx.Context(), m), decoded)
		if template.DefaultDescription != "" {
			input.Description = wirePointer(iamapi.RoleDescriptionType(template.DefaultDescription))
		}
		if callerOwned {
			s.mu.Lock()
			authorizer := s.authorizer
			s.mu.Unlock()
			request := authorization.Request{Action: "iam:CreateServiceLinkedRole", ResourceARN: resourceARN(m, "role", "/aws-service-role/"+service+"/", template.RoleName), Context: map[string][]string{"iam:AWSServiceName": {service}}, EvaluationTime: &now}
			if rejected := authorizer.Authorize(ctx, request); rejected != nil {
				denied = rejected
				return nil
			}
		}
		r := newServiceLinkedRole(template, m, template.RoleName, template.DefaultDescription, now)
		if err := tx.PutRole(scope, *r); err != nil {
			return err
		}
		if s.apiCallEvents == nil {
			return nil
		}
		return s.appendAPICall(serviceLinkedRoleAuditContext(ctx), now, serviceLinkedRoleOutput(r), nil)
	})
	if err == nil && denied != nil {
		err = denied
	}
	if err != nil && attempted && s.apiCallEvents != nil {
		var apiErr *awswire.Error
		if !errors.As(err, &apiErr) {
			apiErr = &awswire.Error{Code: "ServiceFailure", Message: "Unable to create service-linked role.", StatusCode: 500}
		}
		return &serviceLinkedRoleFailure{service: s, cause: err, failure: *apiErr, request: decoded, metadata: metadata, at: s.clock.Now()}
	}
	return err
}

// RemoveProvisionedServiceLinkedRole applies an authorized service lifecycle
// transition, such as an account leaving an organization. The service owns that
// transition; IAM protects unrelated roles with a colliding name.
func (s *Service) RemoveProvisionedServiceLinkedRole(ctx context.Context, scope Scope, service string) error {
	return s.updateAt(ctx, func(tx WriteTx, _ time.Time) error {
		template, wire := s.serviceLinkedTemplate(scope.Partition, service)
		if wire != nil {
			return wire
		}
		role, err := tx.Role(scope, template.RoleName)
		if errors.Is(err, ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if role.ServiceLinkedService != service {
			return duplicate("Role", template.RoleName)
		}
		return tx.DeleteRole(scope, template.RoleName)
	})
}

// This completion retains only public command values, never the borrowed
// transaction context. The calling service owns its enclosing resource command.
type serviceLinkedRoleFailure struct {
	service  *Service
	cause    error
	failure  awswire.Error
	request  awsapi.DecodedRequest
	metadata awsctx.Metadata
	at       time.Time
}

func (e *serviceLinkedRoleFailure) Error() string { return e.cause.Error() }
func (e *serviceLinkedRoleFailure) Unwrap() error { return e.cause }

func (e *serviceLinkedRoleFailure) RecordRejection(ctx context.Context) error {
	request := e.request
	if e.failure.Code == "AccessDenied" {
		request.Input = nil
	}
	ctx = awsapi.WithDecodedRequest(awsctx.WithMetadata(ctx, e.metadata), request)
	return e.service.appendAPICall(serviceLinkedRoleAuditContext(ctx), e.at, nil, &e.failure)
}

// Forwarded IAM audit calls identify the invoking service, but authorization
// still evaluates the original caller's transport context.
func serviceLinkedRoleAuditContext(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	if metadata.InvokedBy != "" {
		metadata.SourceIP, metadata.UserAgent = metadata.InvokedBy, metadata.InvokedBy
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	return ctx
}
