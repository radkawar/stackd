// Package sesv2 owns regional email identities, templates and retained outgoing mail.
package sesv2

import (
	"context"
	"errors"
	"stackd/internal/authorization"
	"time"
)

var ErrNotFound = errors.New("SES resource not found")

type Scope struct{ Partition, AccountID, Region string }
type ResourceKey struct {
	Scope
	Name string
}

func (k ResourceKey) ARN(kind string) string {
	return "arn:" + k.Partition + ":ses:" + k.Region + ":" + k.AccountID + ":" + kind + "/" + k.Name
}

type Identity struct {
	Key                 ResourceKey
	Verified            bool
	VerificationToken   string
	VerificationExpires time.Time
	ConfigurationSet    string
	Tags                map[string]string
	Policies            map[string]authorization.BoundPolicy
}
type Template struct {
	Key                 ResourceKey
	Subject, Text, HTML string
	Created             time.Time
}
type ConfigurationSet struct {
	Key            ResourceKey
	SendingEnabled bool
	Tags           map[string]string
}
type Account struct {
	Scope          Scope
	SendingEnabled bool
}

// Message retains the actual rendered MIME and envelope; BCC is not exposed in MIME.
// CapturePending and Due own retry of the local artifact, never an outbound SMTP send.
type Message struct {
	Key                                                                                            ResourceKey
	From, Feedback, Subject, Text, HTML, ContentKind, TemplateName, TemplateData, ConfigurationSet string
	To, CC, BCC, ReplyTo                                                                           []string
	Tags                                                                                           map[string]string
	MIME                                                                                           []byte
	Accepted, Due                                                                                  time.Time
	CapturePending                                                                                 bool
	CaptureError                                                                                   string
	SourceIdentityARN                                                                              string
}
type Reader interface {
	Context() context.Context
	Identity(ResourceKey) (Identity, error)
	Identities(Scope) ([]Identity, error)
	IdentityByToken(string) (Identity, error)
	Template(ResourceKey) (Template, error)
	Templates(Scope) ([]Template, error)
	ConfigurationSet(ResourceKey) (ConfigurationSet, error)
	ConfigurationSets(Scope) ([]ConfigurationSet, error)
	Account(Scope) (Account, error)
	Message(ResourceKey) (Message, error)
	Messages(Scope) ([]Message, error)
	NextCapture() (Message, bool, error)
}
type Transaction interface {
	Reader
	PutIdentity(Identity) error
	DeleteIdentity(ResourceKey) error
	PutTemplate(Template) error
	DeleteTemplate(ResourceKey) error
	PutConfigurationSet(ConfigurationSet) error
	DeleteConfigurationSet(ResourceKey) error
	PutAccount(Account) error
	PutMessage(Message) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
