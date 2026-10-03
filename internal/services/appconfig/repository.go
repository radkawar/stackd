// Package appconfig owns configuration content, deployments and polling sessions.
package appconfig

import (
	"context"
	"time"
)

type Scope struct{ Partition, AccountID, Region string }
type Application struct {
	Scope
	ID, Name, Description string
}
type Monitor struct{ AlarmARN, RoleARN string }
type Environment struct {
	Scope
	ApplicationID, ID, Name, Description, State string
	Monitors                                    []Monitor
	CreatedAt, LastPoll                         time.Time
}
type Validator struct{ Type, Content string }
type Profile struct {
	Scope
	ApplicationID, ID, Name, Description, LocationURI, RetrievalRoleARN, Type, KMSKeyIdentifier, KMSKeyARN string
	Validators                                                                                             []Validator
	CreatedAt, LastPoll                                                                                    time.Time
	NextVersion                                                                                            int32
}
type HostedVersion struct {
	Scope
	ApplicationID, ProfileID                          string
	Number                                            int32
	Description, ContentType, VersionLabel, KMSKeyARN string
	Content                                           []byte
}
type Strategy struct {
	Scope
	ID, Name, Description, GrowthType, ReplicateTo string
	DurationMinutes, FinalBakeMinutes              int32
	GrowthFactor                                   float64
}
type DeploymentEvent struct {
	Type, Description, TriggeredBy string
	At                             time.Time
	Invocations                    []ActionInvocation
}
type ActionInvocation struct{ ID, ExtensionID, ActionName, URI, RoleARN, ErrorCode, ErrorMessage string }
type AppliedExtension struct {
	AssociationID, ExtensionID string
	Version                    int32
	Parameters                 map[string]string
	Actions                    []ExtensionAction
}
type Deployment struct {
	Scope
	ApplicationID, EnvironmentID, ProfileID, StrategyID                                                                                                string
	Number, PreviousDeployment                                                                                                                         int32
	ConfigurationName, ConfigurationVersion, VersionLabel, LocationURI, Description, ContentType, State, Type, GrowthType, KMSKeyIdentifier, KMSKeyARN string
	ExperimentFlags                                                                                                                                    string
	// PipelineActionID binds an accepted deployment to its actual producer.
	// Public StartDeployment calls leave it empty and can redeploy a version.
	PipelineActionID                  string
	Content                           []byte
	DurationMinutes, FinalBakeMinutes int32
	GrowthFactor, Percentage          float64
	StartedAt, CompletedAt, Due       time.Time
	Generation                        int64
	Events                            []DeploymentEvent
	Extensions                        []AppliedExtension
	DynamicParameters                 map[string][]string
}
type Session struct {
	Scope
	Token, ClientID, ApplicationID, EnvironmentID, ProfileID string
	LastDeployment                                           int32
	PollSeconds                                              int32
	CreatedAt, ExpiresAt, NextPoll                           time.Time
}
type ExtensionAction struct{ Point, Name, Description, URI, RoleARN string }
type ExtensionParameter struct {
	Name, Description string
	Required, Dynamic bool
}
type Extension struct {
	Scope
	ID, Name, Description, ARN string
	Version                    int32
	Actions                    []ExtensionAction
	Parameters                 []ExtensionParameter
}
type Association struct {
	Scope
	ID, ARN, ExtensionID, ExtensionARN, ResourceARN string
	ExtensionVersion                                int32
	Parameters                                      map[string]string
}
type Settings struct {
	Scope
	DeletionProtectionEnabled              bool
	ProtectionMinutes                      int32
	VendedMetricsEnabled, VendedMetricsSet bool
}

// Readers and writers borrow the shared transaction context. Content is immutable
// after publication; repositories clone mutable byte and collection values.
type Reader interface {
	ExperimentReader
	Context() context.Context
	Applications(Scope) ([]Application, error)
	Environments(Scope, string) ([]Environment, error)
	Profiles(Scope, string) ([]Profile, error)
	HostedVersions(Scope, string, string) ([]HostedVersion, error)
	Strategies(Scope) ([]Strategy, error)
	Deployments(Scope, string, string) ([]Deployment, error)
	PendingDeployments() ([]Deployment, error)
	Sessions(Scope) ([]Session, error)
	Session(Scope, string) (Session, bool, error)
	Extensions(Scope) ([]Extension, error)
	Associations(Scope) ([]Association, error)
	Tags(Scope, string) (map[string]string, error)
	Settings(Scope) (Settings, bool, error)
}
type Transaction interface {
	Reader
	ExperimentWriter
	PutApplication(Application) error
	DeleteApplication(Scope, string) error
	PutEnvironment(Environment) error
	DeleteEnvironment(Scope, string, string) error
	PutProfile(Profile) error
	DeleteProfile(Scope, string, string) error
	PutHostedVersion(HostedVersion) error
	DeleteHostedVersion(Scope, string, string, int32) error
	PutStrategy(Strategy) error
	DeleteStrategy(Scope, string) error
	PutDeployment(Deployment) error
	DeleteDeployment(Scope, string, string, int32) error
	PutSession(Session) error
	DeleteSession(Scope, string) error
	PutExtension(Extension) error
	DeleteExtension(Scope, string, int32) error
	PutAssociation(Association) error
	DeleteAssociation(Scope, string) error
	PutTags(Scope, string, map[string]string) error
	PutSettings(Settings) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

type ConfigurationContent struct {
	Content                                                    []byte
	ContentType, Version, VersionLabel, KMSKeyARN, Description string
}

// Effects delegates current authority and real effects to the existing owners.
// These methods must not execute while an AppConfig repository transaction is held.
type Effects interface {
	AssumeRetrievalRole(context.Context, Scope, string) error
	Retrieve(context.Context, Profile, string) (ConfigurationContent, error)
	ValidateLambda(context.Context, Profile, string, string, []byte) error
	Protect(context.Context, Scope, string, string, []byte) ([]byte, string, error)
	Unprotect(context.Context, Scope, string, string, []byte) ([]byte, error)
	Alarm(context.Context, Scope, Monitor) (string, error)
	InvokeExtension(context.Context, Scope, ExtensionAction, []byte) ([]byte, error)
}

// StrategyDocuments joins Systems Manager document state with strategy commands.
// Unlike Effects these methods contain no external I/O and borrow the transaction.
type StrategyDocuments interface {
	CreateStrategyDocument(context.Context, Strategy) error
	UpdateStrategyDocument(context.Context, Strategy) error
	DeleteStrategyDocument(context.Context, Strategy) error
}
