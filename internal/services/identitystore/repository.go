// Package identitystore owns Identity Center directory users, groups and memberships.
package identitystore

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("identity store resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Store struct {
	ID    string
	Scope Scope
}
type Key struct{ StoreID, ID string }
type Name struct{ Formatted, FamilyName, GivenName, MiddleName, HonorificPrefix, HonorificSuffix string }
type Email struct {
	Value, Type string
	Primary     bool
}
type User struct {
	StoreID, ID, UserName, DisplayName                                                             string
	Name                                                                                           Name
	Emails                                                                                         []Email
	NickName, ProfileURL, Title, UserType, PreferredLanguage, Locale, Timezone, Birthdate, Website string
}
type Group struct{ StoreID, ID, DisplayName, Description, CloudFormationOwner string }
type Membership struct{ StoreID, ID, UserID, GroupID, CloudFormationOwner string }

type Reader interface {
	Context() context.Context
	Store(string) (Store, error)
	User(Key) (User, error)
	UserByName(string, string) (User, error)
	Users(string) ([]User, error)
	Group(Key) (Group, error)
	GroupByName(string, string) (Group, error)
	Groups(string) ([]Group, error)
	Membership(Key) (Membership, error)
	MembershipFor(string, string, string) (Membership, error)
	Memberships(string, string, string) ([]Membership, error)
}
type Transaction interface {
	Reader
	PutStore(Store) error
	DeleteStore(string) error
	PutUser(User) error
	DeleteUser(Key) error
	PutGroup(Group) error
	DeleteGroup(Key) error
	PutMembership(Membership) error
	DeleteMembership(Key) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
