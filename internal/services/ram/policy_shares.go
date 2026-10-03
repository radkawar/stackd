package ram

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ram"
	"strings"
)

// SyncResourcePolicy joins the owner's transaction. The original owner policy is
// the sole authority until promotion; an empty template retains an unpromotable
// origin instead of flattening Deny statements or principal-specific conditions.
func (s *Service) SyncResourcePolicy(ctx context.Context, resource ResourceIdentity, policyID string, principals []string, template string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		sc := Scope{resource.Partition, resource.AccountID, resource.Region}
		digest := sha256.Sum256([]byte(resource.ARN + "\x00" + policyID))
		key := hex.EncodeToString(digest[:16])
		arn := arnFor(sc, "resource-share", key)
		sh, e := tx.Share(arn)
		exists := e == nil
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		now := s.clock.Now()
		if len(principals) == 0 {
			if exists {
				sh.Status = "DELETED"
				sh.Updated = now
				return tx.PutShare(sh)
			}
			return nil
		}
		if exists && sh.FeatureSet == "STANDARD" {
			return failure("OperationNotPermittedException", "The policy has already been promoted to a RAM-managed share.")
		}
		if !exists {
			sh = Share{Scope: sc, ARN: arn, Name: "Resource policy " + policyID, Status: "ACTIVE", FeatureSet: "CREATED_FROM_POLICY", PolicyID: policyID, AllowExternal: true, Created: now, Tags: map[string]string{}}
		}
		sh.Updated = now
		sh.Status = "ACTIVE"
		sh.Resources = []ResourceAssociation{{ResourceIdentity: resource, Status: "ASSOCIATED", Created: now, Updated: now}}
		sh.Principals = nil
		for _, principal := range principals {
			parts := strings.SplitN(principal, ":", 6)
			if len(parts) == 6 && parts[2] == "iam" && parts[5] == "root" && accountPattern.MatchString(parts[4]) {
				principal = parts[4]
			}
			p := PrincipalAssociation{Principal: principal, Status: "ASSOCIATED", Created: now, Updated: now}
			if principalAccount(principal) == "" {
				p.Organization = true
			} else if len(principal) > 12 && s.binder != nil {
				document, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]string{"AWS": principal}, "Action": "ram:GetResourceShares", "Resource": "*"}}})
				bound, e := s.binder.BindResourcePolicy(tx.Context(), string(document), authorization.ResourcePolicyOptions{})
				if e != nil {
					return e
				}
				p.PrincipalID = bound.PrincipalIDs[principal]
			}
			sh.Principals = append(sh.Principals, p)
		}
		sh.Permissions = nil
		if template != "" {
			doc, actions, e := s.customerTemplate(resource.ResourceType, template)
			if e == nil {
				p := Permission{Scope: sc, ARN: arnFor(sc, "permission", "policy-"+key), Name: "policy-" + key, ResourceType: resource.ResourceType, Type: "CUSTOMER_MANAGED", FeatureSet: "CREATED_FROM_POLICY", Status: "ATTACHABLE", DefaultVersion: 1, Created: now, Updated: now, Versions: []PermissionVersion{{Version: 1, Document: doc, Actions: actions, Created: now, Updated: now}}}
				if e = tx.PutPermission(p); e != nil {
					return e
				}
				sh.Permissions = []PermissionAssociation{{p.ARN, p.ResourceType, 1}}
			}
		}
		return tx.PutShare(sh)
	})
}
func (s *Service) promotePermissionCreatedFromPolicy(tx Transaction, in *api.PromotePermissionCreatedFromPolicyRequest) (*api.PromotePermissionCreatedFromPolicyResponse, error) {
	p, e := s.permission(tx, value(in.PermissionArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "PromotePermissionCreatedFromPolicy", p.ARN, p.Tags); e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "PromotePermissionCreatedFromPolicy", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if replay {
		p, e = tx.Permission(rec.ARN)
		if e != nil {
			return nil, e
		}
		return &api.PromotePermissionCreatedFromPolicyResponse{ClientToken: in.ClientToken, Permission: permissionSummary(p, p.DefaultVersion, "PromotePermissionCreatedFromPolicy")}, nil
	}
	if p.FeatureSet != "CREATED_FROM_POLICY" {
		return nil, failure("OperationNotPermittedException", "Only policy-created permissions can be promoted.")
	}
	name := value(in.Name)
	if !permissionNamePattern.MatchString(name) {
		return nil, failure("InvalidParameterException", "Invalid permission name.")
	}
	arn := arnFor(p.Scope, "permission", name)
	old, e := tx.Permission(arn)
	if e == nil && old.Status != "DELETED" {
		return nil, failure("PermissionAlreadyExistsException", "The permission name already exists.")
	}
	if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	p.ARN = arn
	p.Name = name
	p.FeatureSet = "STANDARD"
	p.Updated = s.clock.Now()
	if e = tx.PutPermission(p); e != nil {
		return nil, e
	}
	rec.ARN = p.ARN
	if e = saveReceipt(tx, rec); e != nil {
		return nil, e
	}
	return &api.PromotePermissionCreatedFromPolicyResponse{ClientToken: in.ClientToken, Permission: permissionSummary(p, p.DefaultVersion, "PromotePermissionCreatedFromPolicy")}, nil
}
func (s *Service) promoteResourceShareCreatedFromPolicy(tx Transaction, in *api.PromoteResourceShareCreatedFromPolicyRequest) (*api.PromoteResourceShareCreatedFromPolicyResponse, error) {
	sh, e := s.ownedShare(tx, value(in.ResourceShareArn), "PromoteResourceShareCreatedFromPolicy", false)
	if e != nil {
		return nil, e
	}
	if sh.FeatureSet != "CREATED_FROM_POLICY" || sh.Status != "ACTIVE" {
		return nil, failure("InvalidStateTransitionException", "Only active policy-created shares can be promoted.")
	}
	if len(sh.Permissions) == 0 {
		return nil, failure("UnmatchedPolicyPermissionException", "The original policy has no equivalent RAM permission.")
	}
	owner, ok := s.resources.(PolicyResourceOwner)
	if !ok {
		return nil, failure("OperationNotPermittedException", "The resource owner does not support policy promotion.")
	}
	permissions, e := tx.Permissions()
	if e != nil {
		return nil, e
	}
	replacement := []PermissionAssociation{}
	for _, a := range sh.Permissions {
		original, e := s.sharePermission(tx, sh, a)
		if e != nil {
			return nil, e
		}
		v, e := versionOf(original, a.Version)
		if e != nil {
			return nil, e
		}
		idx := slices.IndexFunc(permissions, func(p Permission) bool {
			if p.Scope != sh.Scope || p.FeatureSet != "STANDARD" || p.Status == "DELETED" || p.ResourceType != a.ResourceType {
				return false
			}
			candidate, e := versionOf(p, p.DefaultVersion)
			return e == nil && equalTemplate(candidate.Document, v.Document)
		})
		if idx < 0 {
			return nil, failure("UnmatchedPolicyPermissionException", "Promote an exactly matching managed permission first.")
		}
		p := permissions[idx]
		replacement = append(replacement, PermissionAssociation{p.ARN, p.ResourceType, p.DefaultVersion})
	}
	for _, a := range sh.Resources {
		if _, active, e := s.currentResource(tx, a); e != nil {
			return nil, e
		} else if !active {
			return nil, ErrNotFound
		}
		if e = s.authorizeResource(tx, a.ARN); e != nil {
			return nil, e
		}
		if e = owner.RemoveResourcePolicy(tx.Context(), a.ARN, sh.PolicyID, ""); e != nil {
			return nil, e
		}
	}
	sh.Permissions = replacement
	sh.FeatureSet = "STANDARD"
	sh.PolicyID = ""
	sh.Updated = s.clock.Now()
	if e = tx.PutShare(sh); e != nil {
		return nil, e
	}
	return &api.PromoteResourceShareCreatedFromPolicyResponse{ReturnValue: new(api.Boolean(true))}, nil
}
