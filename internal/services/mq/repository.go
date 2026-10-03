// Package mq owns Amazon MQ broker intent; native engines own queues and messages.
package mq

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("MQ broker not found")

type Scope struct{ Partition, AccountID, Region string }
type BrokerRecord struct {
	Scope
	ID, ARN, Name, Engine, EngineVersion, InstanceType, State string
	CreatorRequestID, Username, Password, Operation, Failure  string
	Version                                                   uint64
	Created, Due                                              time.Time
	Endpoint                                                  Endpoint
	Tags                                                      map[string]string
	Users                                                     []UserRecord
	Configuration, PendingConfiguration                       ConfigurationReference
	ConfigurationHistory                                      []ConfigurationReference
	MaintenanceDay, MaintenanceTime, MaintenanceZone          string
	MaintenanceDue                                            time.Time
	// MaintenanceAdjustments counts admitted window changes since maintenance.
	MaintenanceAdjustments int
	Logs                   LogSettings
	PendingLogs            *LogSettings
	GeneralLogCursor       LogCursor
	AuditLogCursor         LogCursor
	LogDeliveryError       string
	LogDue                 time.Time
}
type Endpoint struct {
	Address, ConsoleURL, NativeID string
	CAPEM                         []byte
}

// UserRecord retains the effective credentials separately from admitted changes.
// Passwords never appear in API responses or lifecycle journal payloads.
type UserRecord struct {
	Username, Password             string
	Groups                         []string
	ConsoleAccess                  bool
	PendingChange, PendingPassword string
	PendingGroups                  []string
	PendingConsoleAccess           bool
}
type ConfigurationReference struct {
	ID       string
	Revision int
	Data     string
}
type ConfigurationRevisionRecord struct {
	Revision          int
	Description, Data string
	Created           time.Time
}
type ConfigurationRecord struct {
	Scope
	ID, ARN, Name, Description, Engine, EngineVersion, AuthenticationStrategy string
	Created                                                                   time.Time
	Tags                                                                      map[string]string
	Revisions                                                                 []ConfigurationRevisionRecord
}
type Reader interface {
	Context() context.Context
	Broker(Scope, string) (BrokerRecord, error)
	AllBrokers() ([]BrokerRecord, error)
	Configuration(Scope, string) (ConfigurationRecord, error)
	AllConfigurations() ([]ConfigurationRecord, error)
}
type Transaction interface {
	Reader
	PutBroker(BrokerRecord) error
	DeleteBroker(Scope, string) error
	PutConfiguration(ConfigurationRecord) error
	DeleteConfiguration(Scope, string) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// Runtime retains the broker's native disk and identity across controller restart.
// Native calls run outside repository transactions. Close detaches, not deletes.
type Runtime interface {
	Ensure(context.Context, BrokerRecord) (Endpoint, error)
	Reboot(context.Context, BrokerRecord) (Endpoint, error)
	Delete(context.Context, BrokerRecord) error
	Close() error
}

// Connection is resolved under current caller mq:DescribeBroker authority.
// The immutable broker ID fences source recreation; no local message ledger exists.
type Connection struct {
	ID, ARN, Engine string
	Endpoint        Endpoint
}
