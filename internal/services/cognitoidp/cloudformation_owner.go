package cognitoidp

import (
	"context"
	"errors"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awswire"
)

// ResourceOwner identifies one CloudFormation logical resource incarnation.
// Ownership is a typed owner claim beside the authoritative row, never a
// customer-visible marker: public pool tags are mutable by TagResource.
type ResourceOwner struct{ StackID, LogicalID, Token string }

type resourceOwnerKey struct{}

type creationRecoveryKey struct{}

// WithResourceOwner fences mutations of user pools and their children and
// recovers a create for this incarnation from the persisted claim. Reads need
// no owner.
func WithResourceOwner(ctx context.Context, owner ResourceOwner) context.Context {
	return context.WithValue(ctx, resourceOwnerKey{}, owner)
}

// WithCreationRecovery observes a create of this exact incarnation without
// performing it: the create command replays the claimed resource under the
// caller's current create authority, or fails ResourceNotFoundException when
// the incarnation was never admitted.
func WithCreationRecovery(ctx context.Context, owner ResourceOwner) context.Context {
	return context.WithValue(WithResourceOwner(ctx, owner), creationRecoveryKey{}, true)
}

// ProviderName is a pool's documented regional issuer name,
// cognito-idp.<region>.<partition suffix>/<pool ID>. Identity pools name the
// pool by it; CloudFormation exposes it and its https URL as attributes.
func ProviderName(partition, region, poolID string) string {
	return strings.TrimPrefix(poolIssuerURL(PoolKey{Scope: Scope{Partition: partition, Region: region}, ID: poolID}, ""), "https://")
}

// Ownership kinds. "pool" claims a user pool by its own ID and is found by
// incarnation to recover a generated pool ID. "client-token" recovers a
// client created with a generated ID; every other claim names the canonical
// physical resource in its pool.
const (
	OwnerKindPool        = "pool"
	OwnerKindClient      = "client"
	OwnerKindClientToken = "client-token"
	OwnerKindUser        = "user"
	OwnerKindGroup       = "group"
	OwnerKindMembership  = "membership"
	OwnerKindDomain      = "domain"
	OwnerKindProvider    = "provider"
)

type OwnershipKey struct {
	PoolKey
	Kind, Name string
}

// OwnershipRecord is removed with its resource. Membership claims name their
// canonical user and group so deleting either removes the claim.
type OwnershipRecord struct {
	Key                                 OwnershipKey
	PhysicalID, MemberUser, MemberGroup string
	Owner                               ResourceOwner
}

func membershipName(user, group string) string {
	return strconv.Quote(user) + "/" + strconv.Quote(group)
}

func tokenName(owner ResourceOwner) string {
	return strconv.Quote(owner.StackID) + "/" + strconv.Quote(owner.LogicalID) + "/" + strconv.Quote(owner.Token)
}

// ownedCommand runs inside the command transaction before the operation. A
// non-nil replay is the persisted create result for this incarnation; finish
// records the claim after a successful create. Deletion releases claims with
// their resource in the repository.
func (s *Service) ownedCommand(tx Transaction, action string, in any) (any, func(any) error, error) {
	owner, bound := tx.Context().Value(resourceOwnerKey{}).(ResourceOwner)
	if !bound {
		return nil, nil, nil
	}
	if owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return nil, nil, failure("InvalidParameterException", "Incomplete CloudFormation resource owner.")
	}
	recovering, _ := tx.Context().Value(creationRecoveryKey{}).(bool)
	notAdmitted := func() error {
		return failure("ResourceNotFoundException", "This exact CloudFormation resource incarnation was not admitted.")
	}
	claim := func(pool PoolRecord, kind, name string) (OwnershipRecord, bool, error) {
		v, err := tx.Ownership(OwnershipKey{PoolKey: pool.Key, Kind: kind, Name: name})
		if errors.Is(err, ErrNotFound) {
			return v, false, nil
		}
		return v, err == nil, err
	}
	// Mutation of an existing child requires this incarnation's claim.
	require := func(poolID, kind, name string) (PoolRecord, error) {
		pool, err := s.adminPool(tx, action, poolID)
		if err != nil {
			return pool, err
		}
		v, found, err := claim(pool, kind, name)
		if err != nil {
			return pool, err
		}
		if !found {
			return pool, failure("ResourceNotFoundException", "The resource is not owned by this CloudFormation resource.")
		}
		if v.Owner != owner {
			return pool, failure("InvalidParameterException", "The resource belongs to another CloudFormation resource incarnation.")
		}
		return pool, nil
	}
	record := func(v OwnershipRecord) func(any) error {
		v.Owner = owner
		return func(any) error { return tx.PutOwnership(v) }
	}
	// A create finding this incarnation's claim on a live row replays it. A
	// live row claimed by another incarnation conflicts; the owner then
	// reports its native duplicate error. Claims never outlive their row.
	existing := func(pool PoolRecord, kind, name string) (bool, error) {
		v, found, err := claim(pool, kind, name)
		if err != nil || !found {
			return false, err
		}
		if v.Owner != owner {
			return false, failure("InvalidParameterException", "The resource belongs to another CloudFormation resource incarnation.")
		}
		return true, nil
	}
	switch in := in.(type) {
	case *api.CreateUserPoolInput:
		// Replay and recovery need the same authority as the create itself.
		if err := s.authorize(tx, "cognito-idp:CreateUserPool", "*", requestTagConditions(in.UserPoolTags)); err != nil {
			return nil, nil, err
		}
		scope := scopeFor(tx.Context())
		v, err := tx.PoolOwnership(scope, owner)
		if err == nil {
			pool, err := tx.Pool(v.Key.PoolKey)
			if err != nil {
				return nil, nil, err
			}
			notePool(tx.Context(), pool.Key)
			return &api.CreateUserPoolOutput{UserPool: &pool.Data}, nil, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, nil, err
		}
		if recovering {
			return nil, nil, notAdmitted()
		}
		return nil, func(out any) error {
			id := value(out.(*api.CreateUserPoolOutput).UserPool.Id)
			return tx.PutOwnership(OwnershipRecord{Key: OwnershipKey{PoolKey: PoolKey{Scope: scope, ID: id}, Kind: OwnerKindPool, Name: id}, PhysicalID: id, Owner: owner})
		}, nil
	case *api.SetUserPoolMfaConfigInput:
		_, err := require(value(in.UserPoolId), OwnerKindPool, value(in.UserPoolId))
		return nil, nil, err
	case *api.UpdateUserPoolInput:
		_, err := require(value(in.UserPoolId), OwnerKindPool, value(in.UserPoolId))
		return nil, nil, err
	case *api.AddCustomAttributesInput:
		_, err := require(value(in.UserPoolId), OwnerKindPool, value(in.UserPoolId))
		return nil, nil, err
	case *api.DeleteUserPoolInput:
		// Pool deletion cascades every claim in the pool.
		_, err := require(value(in.UserPoolId), OwnerKindPool, value(in.UserPoolId))
		return nil, nil, err
	case *api.CreateUserPoolClientInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			// A missing pool is not proof that this client was never admitted.
			var wire *awswire.Error
			if recovering && errors.As(err, &wire) && wire.Code == "ResourceNotFoundException" {
				return nil, nil, failure("InvalidParameterException", "User pool "+value(in.UserPoolId)+" is unavailable for creation recovery.")
			}
			return nil, nil, err
		}
		v, found, err := claim(pool, OwnerKindClientToken, tokenName(owner))
		if err != nil {
			return nil, nil, err
		}
		if found {
			client, err := tx.Client(ClientKey{PoolKey: pool.Key, ID: v.PhysicalID})
			if err != nil {
				return nil, nil, err
			}
			return &api.CreateUserPoolClientOutput{UserPoolClient: &client.Data}, nil, nil
		}
		if recovering {
			return nil, nil, notAdmitted()
		}
		return nil, func(out any) error {
			id := value(out.(*api.CreateUserPoolClientOutput).UserPoolClient.ClientId)
			for _, v := range []OwnershipRecord{
				{Key: OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindClientToken, Name: tokenName(owner)}, PhysicalID: id, Owner: owner},
				{Key: OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindClient, Name: id}, PhysicalID: id, Owner: owner},
			} {
				if err := tx.PutOwnership(v); err != nil {
					return err
				}
			}
			return nil
		}, nil
	case *api.UpdateUserPoolClientInput:
		_, err := require(value(in.UserPoolId), OwnerKindClient, value(in.ClientId))
		return nil, nil, err
	case *api.DeleteUserPoolClientInput:
		// Repository client deletion removes both client claims.
		_, err := require(value(in.UserPoolId), OwnerKindClient, value(in.ClientId))
		return nil, nil, err
	case *api.AdminCreateUserInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			return nil, nil, err
		}
		if user, err := resolveUser(tx, pool, value(in.Username)); err == nil {
			replay, err := existing(pool, OwnerKindUser, user.Key.Username)
			if err != nil || !replay {
				return nil, nil, err
			}
			noteUser(tx.Context(), user)
			return &api.AdminCreateUserOutput{User: &user.Data}, nil, nil
		}
		return nil, func(out any) error {
			name := value(out.(*api.AdminCreateUserOutput).User.Username)
			return tx.PutOwnership(OwnershipRecord{Key: OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindUser, Name: name}, PhysicalID: name, Owner: owner})
		}, nil
	case *api.AdminDeleteUserInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			return nil, nil, err
		}
		user, err := resolveUser(tx, pool, value(in.Username))
		if err != nil {
			return nil, nil, err
		}
		_, err = require(value(in.UserPoolId), OwnerKindUser, user.Key.Username)
		return nil, nil, err
	case *api.CreateGroupInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			return nil, nil, err
		}
		name := value(in.GroupName)
		if group, err := tx.Group(GroupKey{PoolKey: pool.Key, Name: name}); err == nil {
			replay, err := existing(pool, OwnerKindGroup, name)
			if err != nil || !replay {
				return nil, nil, err
			}
			return &api.CreateGroupOutput{Group: &group.Data}, nil, nil
		}
		return nil, record(OwnershipRecord{Key: OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindGroup, Name: name}, PhysicalID: name}), nil
	case *api.UpdateGroupInput:
		_, err := require(value(in.UserPoolId), OwnerKindGroup, value(in.GroupName))
		return nil, nil, err
	case *api.DeleteGroupInput:
		_, err := require(value(in.UserPoolId), OwnerKindGroup, value(in.GroupName))
		return nil, nil, err
	case *api.AdminAddUserToGroupInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			return nil, nil, err
		}
		user, err := resolveUser(tx, pool, value(in.Username))
		if err != nil {
			return nil, nil, err
		}
		group := value(in.GroupName)
		name := membershipName(user.Key.Username, group)
		if _, err := existing(pool, OwnerKindMembership, name); err != nil {
			return nil, nil, err
		}
		// Native membership addition is idempotent; claim it for this incarnation.
		return nil, record(OwnershipRecord{Key: OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindMembership, Name: name}, PhysicalID: name, MemberUser: user.Key.Username, MemberGroup: group}), nil
	case *api.AdminRemoveUserFromGroupInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			return nil, nil, err
		}
		user, err := resolveUser(tx, pool, value(in.Username))
		if err != nil {
			return nil, nil, err
		}
		_, err = require(value(in.UserPoolId), OwnerKindMembership, membershipName(user.Key.Username, value(in.GroupName)))
		return nil, nil, err
	case *api.CreateUserPoolDomainInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			var wire *awswire.Error
			if recovering && errors.As(err, &wire) && wire.Code == "ResourceNotFoundException" {
				return nil, nil, failure("InvalidParameterException", "User pool "+value(in.UserPoolId)+" is unavailable for creation recovery.")
			}
			return nil, nil, err
		}
		name := value(in.Domain)
		if recovering {
			v, found, err := claim(pool, OwnerKindDomain, name)
			if err != nil {
				return nil, nil, err
			}
			if !found || v.Owner != owner {
				return nil, nil, notAdmitted()
			}
			if value(pool.Data.Domain) != name {
				return nil, nil, failure("InvalidParameterException", "The claimed domain is unavailable for creation recovery.")
			}
			return &api.CreateUserPoolDomainOutput{ManagedLoginVersion: ptr(api.WrappedIntegerType(1))}, nil, nil
		}
		if value(pool.Data.Domain) == name {
			replay, err := existing(pool, OwnerKindDomain, name)
			if err != nil || !replay {
				return nil, nil, err
			}
			return &api.CreateUserPoolDomainOutput{ManagedLoginVersion: ptr(api.WrappedIntegerType(1))}, nil, nil
		}
		return nil, record(OwnershipRecord{Key: OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindDomain, Name: name}, PhysicalID: name}), nil
	case *api.UpdateUserPoolDomainInput:
		_, err := require(value(in.UserPoolId), OwnerKindDomain, value(in.Domain))
		return nil, nil, err
	case *api.DeleteUserPoolDomainInput:
		// The domain owner releases the claim with the domain.
		_, err := require(value(in.UserPoolId), OwnerKindDomain, value(in.Domain))
		return nil, nil, err
	case *api.CreateIdentityProviderInput:
		pool, err := s.adminPool(tx, action, value(in.UserPoolId))
		if err != nil {
			return nil, nil, err
		}
		name := value(in.ProviderName)
		if provider, err := tx.Provider(ProviderKey{PoolKey: pool.Key, Name: name}); err == nil {
			replay, err := existing(pool, OwnerKindProvider, name)
			if err != nil || !replay {
				return nil, nil, err
			}
			out := providerOutput(provider)
			return &api.CreateIdentityProviderOutput{IdentityProvider: &out}, nil, nil
		}
		return nil, record(OwnershipRecord{Key: OwnershipKey{PoolKey: pool.Key, Kind: OwnerKindProvider, Name: name}, PhysicalID: name}), nil
	case *api.UpdateIdentityProviderInput:
		_, err := require(value(in.UserPoolId), OwnerKindProvider, value(in.ProviderName))
		return nil, nil, err
	case *api.DeleteIdentityProviderInput:
		_, err := require(value(in.UserPoolId), OwnerKindProvider, value(in.ProviderName))
		return nil, nil, err
	}
	return nil, nil, nil
}
