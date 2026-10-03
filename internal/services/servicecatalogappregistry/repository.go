// Package servicecatalogappregistry owns applications, attribute groups and resource associations.
package servicecatalogappregistry

import (
	"context"
	"time"
)

type Scope struct{ Partition, AccountID, Region string }

type Application struct {
	Scope
	ID, ARN, Name, Description, ClientToken, CreateFingerprint string
	GroupARN, TagGroupARN                                      string
	Created, Modified                                          time.Time
	Tags                                                       map[string]string
}

type AttributeGroup struct {
	Scope
	ID, ARN, Name, Description, Attributes, ClientToken, CreateFingerprint string
	Created, Modified                                                      time.Time
	Tags                                                                   map[string]string
}

// Association retains association intent, not resource tags or an ARN catalog.
// Resource existence, tags and incarnation remain authoritative at their owner.
type Association struct {
	ApplicationARN, ResourceARN, ResourceName, ResourceType, Incarnation string
	ApplyTag                                                             bool
	Created                                                              time.Time
}

type Configuration struct {
	Scope
	TagKey string
}

type Reader interface {
	Context() context.Context
	Application(Scope, string) (Application, bool, error)
	Applications(Scope) ([]Application, error)
	AccountApplications(partition, accountID string) ([]Application, error)
	AttributeGroup(Scope, string) (AttributeGroup, bool, error)
	AttributeGroups(Scope) ([]AttributeGroup, error)
	AttributeGroupAssociations(string) ([]string, error)
	Associations(string) ([]Association, error)
	Configuration(Scope) (Configuration, error)
}

type Transaction interface {
	Reader
	PutApplication(Application) error
	DeleteApplication(Scope, string) error
	PutAttributeGroup(AttributeGroup) error
	DeleteAttributeGroup(Scope, string) error
	AssociateAttributeGroup(string, string) error
	DisassociateAttributeGroup(string, string) error
	PutAssociation(Association) error
	DeleteAssociation(string, string) error
	PutConfiguration(Configuration) error
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
