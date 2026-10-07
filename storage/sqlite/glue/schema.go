package glue

import (
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
)

func schemaRow(v sqlcgen.GlueSchema) domain.SchemaRecord {
	return domain.SchemaRecord{CFNOwner: v.CfnOwner, Key: domain.SchemaKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Registry: v.RegistryName, Name: v.SchemaName}, Description: registryDescriptionValue(v.Description), DataFormat: v.DataFormat, Compatibility: v.Compatibility, Status: v.Status, Checkpoint: v.Checkpoint, LatestVersion: v.LatestVersion, NextVersion: v.NextVersion, Created: v.CreatedAt, Updated: v.UpdatedAt, Due: v.DueAt}
}
func (r reader) schemaTags(v domain.SchemaRecord) (domain.SchemaRecord, error) {
	k := v.Key
	rows, err := r.q.ListGlueSchemaTags(r.ctx, sqlcgen.ListGlueSchemaTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name})
	if err != nil {
		return v, err
	}
	v.Tags = make(map[string]string, len(rows))
	for _, row := range rows {
		v.Tags[row.TagKey] = row.TagValue
	}
	return v, nil
}
func (r reader) Schema(k domain.SchemaKey) (domain.SchemaRecord, error) {
	v, err := r.q.GetGlueSchema(r.ctx, sqlcgen.GetGlueSchemaParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name})
	if err != nil {
		return domain.SchemaRecord{}, registryMissing(err)
	}
	return r.schemaTags(schemaRow(v))
}
func (r reader) Schemas(scope domain.Scope, registry string) ([]domain.SchemaRecord, error) {
	rows, err := r.q.ListGlueSchemas(r.ctx, sqlcgen.ListGlueSchemasParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, RegistryFilter: registry})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SchemaRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.schemaTags(schemaRow(row))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutSchema(v domain.SchemaRecord) error {
	k := v.Key
	if err := w.q.PutGlueSchema(w.ctx, sqlcgen.PutGlueSchemaParams{CfnOwner: v.CFNOwner, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name, Description: registryDescription(v.Description), DataFormat: v.DataFormat, Compatibility: v.Compatibility, Status: v.Status, Checkpoint: v.Checkpoint, LatestVersion: v.LatestVersion, NextVersion: v.NextVersion, CreatedAt: v.Created, UpdatedAt: v.Updated, DueAt: v.Due}); err != nil {
		return err
	}
	if err := w.q.DeleteGlueSchemaTags(w.ctx, sqlcgen.DeleteGlueSchemaTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutGlueSchemaTag(w.ctx, sqlcgen.PutGlueSchemaTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteSchema(k domain.SchemaKey) error {
	return w.q.DeleteGlueSchema(w.ctx, sqlcgen.DeleteGlueSchemaParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name})
}
func schemaVersionRow(v sqlcgen.GlueSchemaVersion) domain.SchemaVersionRecord {
	return domain.SchemaVersionRecord{CFNOwner: v.CfnOwner, Key: domain.SchemaVersionKey{Schema: domain.SchemaKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Registry: v.RegistryName, Name: v.SchemaName}, Number: v.VersionNumber}, ID: v.VersionID, Definition: v.Definition, Canonical: v.Canonical, Status: v.Status, Created: v.CreatedAt, Due: v.DueAt}
}
func (r reader) SchemaVersion(k domain.SchemaVersionKey) (domain.SchemaVersionRecord, error) {
	s := k.Schema
	v, err := r.q.GetGlueSchemaVersion(r.ctx, sqlcgen.GetGlueSchemaVersionParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, RegistryName: s.Registry, SchemaName: s.Name, VersionNumber: k.Number})
	return schemaVersionRow(v), registryMissing(err)
}
func (r reader) SchemaVersionByID(scope domain.Scope, id string) (domain.SchemaVersionRecord, error) {
	v, err := r.q.GetGlueSchemaVersionByID(r.ctx, sqlcgen.GetGlueSchemaVersionByIDParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, VersionID: id})
	return schemaVersionRow(v), registryMissing(err)
}
func (r reader) SchemaVersions(k domain.SchemaKey) ([]domain.SchemaVersionRecord, error) {
	rows, err := r.q.ListGlueSchemaVersions(r.ctx, sqlcgen.ListGlueSchemaVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SchemaVersionRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, schemaVersionRow(v))
	}
	return out, nil
}
func (w writer) PutSchemaVersion(v domain.SchemaVersionRecord) error {
	k := v.Key.Schema
	return w.q.PutGlueSchemaVersion(w.ctx, sqlcgen.PutGlueSchemaVersionParams{CfnOwner: v.CFNOwner, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name, VersionNumber: v.Key.Number, VersionID: v.ID, Definition: v.Definition, Canonical: v.Canonical, Status: v.Status, CreatedAt: v.Created, DueAt: v.Due})
}
func (w writer) DeleteSchemaVersion(v domain.SchemaVersionKey) error {
	k := v.Schema
	return w.q.DeleteGlueSchemaVersion(w.ctx, sqlcgen.DeleteGlueSchemaVersionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Registry, SchemaName: k.Name, VersionNumber: v.Number})
}
func (r reader) SchemaMetadata(id string) ([]domain.SchemaMetadataRecord, error) {
	rows, err := r.q.ListGlueSchemaMetadata(r.ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.SchemaMetadataRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.SchemaMetadataRecord{CFNOwner: v.CfnOwner, VersionID: v.VersionID, Key: v.MetadataKey, Value: v.MetadataValue, Created: v.CreatedAt, Ordinal: v.Ordinal})
	}
	return out, nil
}
func (w writer) PutSchemaMetadata(v domain.SchemaMetadataRecord) error {
	return w.q.PutGlueSchemaMetadata(w.ctx, sqlcgen.PutGlueSchemaMetadataParams{CfnOwner: v.CFNOwner, VersionID: v.VersionID, MetadataKey: v.Key, MetadataValue: v.Value, CreatedAt: v.Created, Ordinal: v.Ordinal})
}
func (w writer) DeleteSchemaMetadata(id, key, value string) error {
	return w.q.DeleteGlueSchemaMetadata(w.ctx, sqlcgen.DeleteGlueSchemaMetadataParams{VersionID: id, MetadataKey: key, MetadataValue: value})
}
