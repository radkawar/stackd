package glue

import "time"

// RegistryRecord owns a regional registry and its current authorization tags.
type RegistryRecord struct {
	CFNOwner              string
	Key                   ResourceKey
	Description           *string
	Status                string
	Created, Updated, Due time.Time
	Tags                  map[string]string
}

type SchemaKey struct {
	Scope
	Registry, Name string
}

func (k SchemaKey) ARN() string {
	return ResourceKey{Scope: k.Scope, Name: k.Registry + "/" + k.Name}.ARN("schema")
}

// SchemaRecord keeps monotonic version allocation independently of deletions.
type SchemaRecord struct {
	CFNOwner                               string
	Key                                    SchemaKey
	Description                            *string
	DataFormat, Compatibility, Status      string
	Checkpoint, LatestVersion, NextVersion int64
	Created, Updated, Due                  time.Time
	Tags                                   map[string]string
}

type SchemaVersionKey struct {
	Schema SchemaKey
	Number int64
}

type SchemaVersionRecord struct {
	CFNOwner                          string
	Key                               SchemaVersionKey
	ID, Definition, Canonical, Status string
	Created, Due                      time.Time
}

type SchemaMetadataRecord struct {
	CFNOwner              string
	VersionID, Key, Value string
	Created               time.Time
	// Ordinal preserves newest-value ordering when the shared clock is frozen.
	Ordinal int64
}

// RegistryLifecycle identifies retained deletion work; UUID version keys cannot
// target a new incarnation after a schema has been deleted and recreated.
type RegistryLifecycle struct {
	Kind      string
	Registry  ResourceKey
	Schema    SchemaKey
	VersionID string
	Due       time.Time
}

type RegistryReader interface {
	Registry(ResourceKey) (RegistryRecord, error)
	Registries(Scope) ([]RegistryRecord, error)
	Schema(SchemaKey) (SchemaRecord, error)
	Schemas(Scope, string) ([]SchemaRecord, error)
	SchemaVersion(SchemaVersionKey) (SchemaVersionRecord, error)
	SchemaVersionByID(Scope, string) (SchemaVersionRecord, error)
	SchemaVersions(SchemaKey) ([]SchemaVersionRecord, error)
	SchemaMetadata(string) ([]SchemaMetadataRecord, error)
	NextRegistryLifecycle() (RegistryLifecycle, error)
}

type RegistryWriter interface {
	PutRegistry(RegistryRecord) error
	DeleteRegistry(ResourceKey) error
	PutSchema(SchemaRecord) error
	DeleteSchema(SchemaKey) error
	PutSchemaVersion(SchemaVersionRecord) error
	DeleteSchemaVersion(SchemaVersionKey) error
	PutSchemaMetadata(SchemaMetadataRecord) error
	DeleteSchemaMetadata(string, string, string) error
}
