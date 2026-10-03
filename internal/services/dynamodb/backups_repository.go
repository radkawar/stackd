package dynamodb

import (
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

// BackupKey identifies a table backup independently of the source table's lifetime.
type BackupKey struct {
	Scope
	TableName string
	ID        string
}

func (k BackupKey) ARN() string {
	return "arn:" + k.Partition + ":dynamodb:" + k.Region + ":" + k.AccountID + ":table/" + k.TableName + "/backup/" + k.ID
}

// BackupRecord retains captured schema and public metadata. Item data remains in
// the private native PhysicalName table. SourcePhysicalName identifies the source
// while CREATING; a completed backup does not depend on that source table.
type BackupRecord struct {
	Key                                          BackupKey
	Description                                  api.BackupDescription
	AttributeDefinitions                         api.AttributeDefinitions
	DatabaseID, PhysicalName, SourcePhysicalName string
}

type BackupQuery struct {
	Scope
	TableName, After, Type string
	Lower, Upper, At       time.Time
	Limit                  int
}

type BackupReader interface {
	Backup(BackupKey) (BackupRecord, error)
	// Backups excludes deleted/expired entries, filters type before the limit,
	// applies inclusive creation-time bounds, and orders by canonical ARN.
	Backups(BackupQuery) ([]BackupRecord, error)
	// PendingBackups returns unfinished creation/deletion and due expiry across all scopes.
	PendingBackups(now time.Time) ([]BackupRecord, error)
	// NextBackupExpiry returns the earliest future expiry, or zero when absent.
	NextBackupExpiry(after time.Time) (time.Time, error)
	// UncapturedBackups is the mutation barrier for one native database.
	UncapturedBackups(databaseID string) ([]BackupRecord, error)
	HasDatabaseBackups(databaseID string) (bool, error)
}

type BackupWriter interface {
	PutBackup(BackupRecord) error
	DeleteBackup(BackupKey) error
}
