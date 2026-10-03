package iam

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

// ResolveGrantPrincipal binds a KMS grant to an IAM identity or a named STS
// session. Session names need not have been issued: the role's immutable ID,
// rather than a particular set of temporary credentials, owns the binding.
func (s *Service) ResolveGrantPrincipal(ctx context.Context, reference string) (authorization.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Principal{}, err
	}
	m := awsctx.FromContext(ctx)
	if principal, ok := ec2InfrastructureReference(m.Partition, reference); ok {
		account, _, _ := strings.Cut(principal.ID, ":")
		found, err := s.AccountExists(ctx, m.Partition, account)
		if err != nil {
			return authorization.Principal{}, err
		}
		if !found {
			return authorization.Principal{}, authorization.ErrInvalidPrincipal
		}
		return principal, nil
	}
	if strings.HasPrefix(reference, "arn:") {
		parts := strings.SplitN(reference, ":", 6)
		if len(parts) != 6 || parts[1] != m.Partition || parts[3] != "" {
			return authorization.Principal{}, authorization.ErrInvalidPrincipal
		}
		if parts[2] != "sts" {
			return s.ResolvePrincipal(ctx, reference)
		}
		resource := strings.Split(parts[5], "/")
		switch {
		case len(resource) == 3 && resource[0] == "assumed-role" && namePattern.MatchString(resource[2]):
			var role Role
			err := s.view(ctx, func(tx ReadTx) error {
				var err error
				role, err = tx.Role(Scope{Partition: m.Partition, AccountID: parts[4]}, resource[1])
				return err
			})
			if errors.Is(err, ErrRecordNotFound) {
				return authorization.Principal{}, authorization.ErrInvalidPrincipal
			}
			if err != nil {
				return authorization.Principal{}, err
			}
			return roleSessionPrincipal(role.Arn, role.RoleId, resource[2]), nil
		case len(resource) == 2 && resource[0] == "federated-user":
			return s.grantFederatedPrincipal(ctx, parts[4], resource[1])
		default:
			return authorization.Principal{}, authorization.ErrInvalidPrincipal
		}
	}
	if id, session, ok := strings.Cut(reference, ":"); ok {
		if strings.HasPrefix(id, "AROA") && namePattern.MatchString(session) {
			role, err := s.ResolvePrincipal(ctx, id)
			if err != nil {
				return authorization.Principal{}, err
			}
			return roleSessionPrincipal(role.ARN, role.ID, session), nil
		}
		return s.grantFederatedPrincipal(ctx, id, session)
	}
	return s.ResolvePrincipal(ctx, reference)
}

func roleSessionPrincipal(arn, id, name string) authorization.Principal {
	parts := strings.SplitN(arn, ":", 6)
	_, roleName, _ := strings.Cut(parts[5], "role/")
	roleName = roleName[strings.LastIndex(roleName, "/")+1:]
	return authorization.Principal{ARN: "arn:" + parts[1] + ":sts::" + parts[4] + ":assumed-role/" + roleName + "/" + name, ID: id + ":" + name}
}

func (s *Service) grantFederatedPrincipal(ctx context.Context, account, name string) (authorization.Principal, error) {
	if !namePattern.MatchString(name) {
		return authorization.Principal{}, authorization.ErrInvalidPrincipal
	}
	m := awsctx.FromContext(ctx)
	found, err := s.AccountExists(ctx, m.Partition, account)
	if err != nil {
		return authorization.Principal{}, err
	}
	if !found {
		return authorization.Principal{}, authorization.ErrInvalidPrincipal
	}
	return authorization.Principal{ARN: "arn:" + m.Partition + ":sts::" + account + ":federated-user/" + name, ID: account + ":" + name}, nil
}
