// Package s3tables owns table buckets, namespaces, table metadata and warehouse authorization.
package s3tables

import (
	"context"
	"errors"
	"time"

	"stackd/internal/services/glue/icebergmeta"
)

var ErrNotFound = errors.New("s3tables resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Bucket struct {
	Scope
	Name, ARN, ID string
	Created       time.Time
}
type Namespace struct {
	Scope
	BucketARN, Name, ID string
	Created             time.Time
}
type Table struct {
	Scope
	BucketARN, Namespace, Name, ARN, ID, VersionToken, Warehouse, MetadataLocation string
	Created, Modified, CleanupAt                                                   time.Time
	// Deleted tables retain private warehouse ownership, not public catalog visibility.
	Deleted, Purged bool
}

// Column is the typed Hive projection of an accepted Iceberg schema.
type Column = icebergmeta.Column
type Reader interface {
	Context() context.Context
	Bucket(Scope, string) (Bucket, error)
	Buckets(Scope) ([]Bucket, error)
	Namespace(Scope, string, string) (Namespace, error)
	Namespaces(Scope, string) ([]Namespace, error)
	Table(Scope, string, string, string) (Table, error)
	Tables(Scope, string) ([]Table, error)
	TableColumns(Scope, string) ([]Column, error)
	Warehouse(Scope, string) (Table, error)
	PendingTables() ([]Table, error)
}
type Transaction interface {
	Reader
	PutBucket(Bucket) error
	DeleteBucket(Scope, string) error
	PutNamespace(Namespace) error
	DeleteNamespace(Scope, string, string) error
	PutTable(Table) error
	PutTableColumns(Scope, string, []Column) error
	DeleteTable(Scope, string, string, string) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// WarehouseObjects is private physical byte storage, never a public authorization
// shortcut. Implementations must confine every operation to the exact warehouse
// supplied by this owner and keep those bytes inaccessible through ordinary S3.
// Calls occur outside resource transactions after current S3 Tables authorization.
type WarehouseObjects interface {
	Read(context.Context, string, string) ([]byte, error)
	Write(context.Context, string, string, []byte, time.Time) error
	Delete(context.Context, string, string) error
	List(context.Context, string, string) ([]ObjectInfo, error)
	ReadObject(context.Context, string, string) ([]byte, ObjectInfo, error)
	Info(context.Context, string, string) (ObjectInfo, error)
	WriteObject(context.Context, string, []byte, ObjectInfo, ObjectConditions, PublicationGuard) (ObjectInfo, error)
	CreateMultipart(context.Context, MultipartUpload, PublicationGuard) error
	GetMultipartUpload(context.Context, string, string, string) (MultipartUpload, error)
	UploadMultipartPart(context.Context, string, string, string, MultipartPart, []byte, PublicationGuard) error
	ListMultipartParts(context.Context, string, string, string) (MultipartUpload, []MultipartPart, error)
	CompleteMultipart(context.Context, string, string, string, []CompletedPart, time.Time, ObjectConditions, ObjectChecksums, PublicationGuard) (ObjectInfo, error)
	AbortMultipart(context.Context, string, string, string, PublicationGuard) error
	PurgeWarehouse(context.Context, string) error
}
type ObjectInfo struct {
	Key, ETag  string
	Size       int64
	Modified   time.Time
	Attributes ObjectAttributes
}

// PublicationGuard runs after physical writes, before their atomic commit.
// Its context carries the physical transaction so current metadata and IAM
// checks share the publication boundary without external byte IO in a resource
// transaction. An error rolls back every physical change.
type PublicationGuard func(context.Context) error

type ObjectChecksums struct {
	CRC32, CRC32C, CRC64NVME, SHA1, SHA256 string
}

type ObjectAttributes struct {
	ContentType, CacheControl, ContentDisposition, ContentEncoding, ContentLanguage string
	Expires                                                                         *time.Time
	ChecksumAlgorithm                                                               string
	Checksums                                                                       ObjectChecksums
}

type ObjectConditions struct {
	IfNoneMatch  string
	ChecksumType string
}

type MultipartPart struct {
	Number    int
	ETag      string
	Size      int64
	Modified  time.Time
	Checksums ObjectChecksums
}

type CompletedPart struct {
	Number    int
	ETag      string
	Checksums ObjectChecksums
}

type MultipartUpload struct {
	ID, Warehouse, Key string
	Created            time.Time
	Attributes         ObjectAttributes
}

// StoredMultipartPart is the typed private physical record, not a wire payload.
type StoredMultipartPart struct {
	MultipartPart
	Data []byte
}
