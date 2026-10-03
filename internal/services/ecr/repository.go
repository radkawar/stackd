// Package ecr owns private registries and their authenticated OCI data plane.
package ecr

import (
	"context"
	"errors"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awsctx"
	"time"
)

var ErrNotFound = errors.New("ECR resource not found")

type Scope struct{ Partition, AccountID, Region string }
type RepositoryKey struct {
	Scope
	Name string
}
type ImageKey struct {
	Repository RepositoryKey
	Digest     string
}
type UploadKey struct {
	Repository RepositoryKey
	ID         string
}

// RepositoryRecord contains metadata, not image bytes. AES keys and KMS grants
// are private; each KMS-encrypted payload retains its own wrapped data key.
type RepositoryRecord struct {
	Key                              RepositoryKey
	ARN                              string
	Created                          time.Time
	Mutability                       string
	Exclusions                       api.ImageTagMutabilityExclusionFilters
	Tags                             map[string]string
	Policy                           authorization.BoundPolicy
	EncryptionType, KMSKeyID         string
	DataKey                          []byte
	Grants, GrantTokens              []string
	ScanOnPush                       bool
	LifecyclePolicy                  string
	LifecycleDue, LifecycleEvaluated time.Time
	PreviewPolicy, PreviewStatus     string
	PreviewResults                   api.LifecyclePolicyPreviewResultList
	PreviewExpires                   time.Time
}
type RegistryRecord struct {
	Scope       Scope
	Policy      authorization.BoundPolicy
	Scanning    api.RegistryScanningConfiguration
	Replication api.ReplicationConfiguration
}
type ImageRecord struct {
	Key                                              ImageKey
	MediaType, ArtifactMediaType                     string
	Payload                                          []byte
	Size                                             int64
	Pushed, LastPull                                 time.Time
	Tags, References, Layers                         []string
	ScanID, ScanStatus, ScanDescription              string
	ScanStarted, ScanCompleted, VulnerabilityUpdated time.Time
	Findings                                         api.ImageScanFindingList
}
type BlobRecord struct {
	Key     ImageKey
	Payload []byte
	Size    int64
}
type UploadRecord struct {
	Key     UploadKey
	Payload []byte
	Size    int64
	Expires time.Time
}

// TokenRecord stores only a password hash and an authenticated caller snapshot.
// Resource permissions are evaluated afresh, never copied into the token.
type TokenRecord struct {
	Hash               string
	Partition, Region  string
	Identity           awsctx.Metadata
	Expires            time.Time
	DownloadRepository RepositoryKey
	DownloadDigest     string
}

type ReplicationKey struct {
	Source      ImageKey
	Destination Scope
}
type ReplicationRecord struct {
	Key           ReplicationKey
	Tags          []string
	Due           time.Time
	Status, Error string
	Origin        awsctx.Metadata
}

type Reader interface {
	Context() context.Context
	Repository(RepositoryKey) (RepositoryRecord, error)
	Repositories(Scope) ([]RepositoryRecord, error)
	AllRepositories() ([]RepositoryRecord, error)
	Registry(Scope) (RegistryRecord, error)
	AllRegistries() ([]RegistryRecord, error)
	Image(ImageKey) (ImageRecord, error)
	Images(RepositoryKey) ([]ImageRecord, error)
	Blob(ImageKey) (BlobRecord, error)
	Upload(UploadKey) (UploadRecord, error)
	Token(string) (TokenRecord, error)
	Replications() ([]ReplicationRecord, error)
}
type Transaction interface {
	Reader
	PutRepository(RepositoryRecord) error
	DeleteRepository(RepositoryKey) error
	PutRegistry(RegistryRecord) error
	PutImage(ImageRecord) error
	DeleteImage(ImageKey) error
	PutBlob(BlobRecord) error
	PutUpload(UploadRecord) error
	DeleteUpload(UploadKey) error
	PutToken(TokenRecord) error
	DeleteExpiredTokens(time.Time) error
	PutReplication(ReplicationRecord) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
