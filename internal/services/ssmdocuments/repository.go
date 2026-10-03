// Package ssmdocuments owns immutable SSM documents, separately from Parameter Store.
package ssmdocuments

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("SSM document not found")

type Scope struct{ Partition, AccountID, Region string }
type Key struct {
	Scope
	Name string
}
type VersionKey struct {
	Document Key
	Version  int64
}

// Record owns mutable version pointers and resource tags, not a second content copy.
type Record struct {
	Key  Key
	Type string
	// Application configurations pin a schema version and its document incarnation.
	SchemaName, SchemaDocumentID               string
	SchemaVersion                              int64
	DocumentID                                 string
	DefaultVersion, LatestVersion, NextVersion int64
	Tags                                       map[string]string
	// Shares binds recipient accounts (or "all") to a version selector.
	Shares map[string]string
}

// Version owns immutable content and the asynchronous admission status.
type Version struct {
	Key                                                         VersionKey
	Content, Format, Hash, VersionName, DisplayName, TargetType string
	Created                                                     time.Time
	Status                                                      string
	ReadyAt                                                     time.Time
}

// Activation is derived from a pending version, fenced by its document incarnation.
type Activation struct {
	Key        VersionKey
	DocumentID string
	Due        time.Time
}

type Reader interface {
	Context() context.Context
	Document(Key) (Record, error)
	Documents(Scope) ([]Record, error)
	SharedDocuments(Scope) ([]Record, error)
	Version(VersionKey) (Version, error)
	Versions(Key) ([]Version, error)
	NextActivation() (Activation, error)
}
type Transaction interface {
	Reader
	PutDocument(Record) error
	DeleteDocument(Key) error
	InsertVersion(Version) error
	DeleteVersion(VersionKey) error
	ActivateVersion(VersionKey) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
