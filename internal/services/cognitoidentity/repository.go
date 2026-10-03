// Package cognitoidentity owns regional identity pools and their login bindings.
package cognitoidentity

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/cognitoidentity"
)

var ErrNotFound = errors.New("cognito identity resource not found")

type Scope struct{ Partition, AccountID, Region string }
type PoolKey struct {
	Scope
	ID string
}

func (k PoolKey) ARN() string {
	return "arn:" + k.Partition + ":cognito-identity:" + k.Region + ":" + k.AccountID + ":identitypool/" + k.ID
}

type PoolRecord struct {
	Key                                PoolKey
	Name                               string
	AllowUnauthenticated, AllowClassic bool
	Providers                          api.CognitoIdentityProviderList
	Tags                               api.IdentityPoolTagsType
	Roles                              api.RolesMap
	Mappings                           api.RoleMappingMap
	PrincipalTagMaps                   map[string]PrincipalTagMap
}

// PrincipalTagMap binds principal tag keys to verified ID-token claim names.
type PrincipalTagMap struct {
	UseDefaults bool
	Tags        api.PrincipalTags
}
type Login struct{ Provider, Subject string }
type IdentityRecord struct {
	Pool              PoolKey
	ID                string
	Created, Modified time.Time
	Logins            []Login
}

// All callbacks borrow one shared transaction context. Records are detached.
type Reader interface {
	Context() context.Context
	Pool(PoolKey) (PoolRecord, error)
	PoolByID(partition, region, id string) (PoolRecord, error)
	Pools(Scope) ([]PoolRecord, error)
	Identity(partition, region, id string) (IdentityRecord, error)
	IdentityByLogin(PoolKey, Login) (IdentityRecord, error)
	Identities(PoolKey) ([]IdentityRecord, error)
}
type Transaction interface {
	Reader
	PutPool(PoolRecord) error
	DeletePool(PoolKey) error
	PutIdentity(IdentityRecord) error
	DeleteIdentity(partition, region, id string) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
