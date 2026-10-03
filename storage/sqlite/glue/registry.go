package glue

import (
	"database/sql"
	"errors"

	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
)

func registryMissing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func registryDescription(v *string) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *v, Valid: true}
}
func registryDescriptionValue(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return new(v.String)
}
func registryRow(v sqlcgen.GlueRegistry) domain.RegistryRecord {
	return domain.RegistryRecord{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.RegistryName}, Description: registryDescriptionValue(v.Description), Status: v.Status, Created: v.CreatedAt, Updated: v.UpdatedAt, Due: v.DueAt}
}
func (r reader) registryTags(v domain.RegistryRecord) (domain.RegistryRecord, error) {
	rows, err := r.q.ListGlueRegistryTags(r.ctx, sqlcgen.ListGlueRegistryTagsParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, RegistryName: v.Key.Name})
	if err != nil {
		return v, err
	}
	v.Tags = make(map[string]string, len(rows))
	for _, row := range rows {
		v.Tags[row.TagKey] = row.TagValue
	}
	return v, nil
}
func (r reader) Registry(key domain.ResourceKey) (domain.RegistryRecord, error) {
	v, err := r.q.GetGlueRegistry(r.ctx, sqlcgen.GetGlueRegistryParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, RegistryName: key.Name})
	if err != nil {
		return domain.RegistryRecord{}, registryMissing(err)
	}
	return r.registryTags(registryRow(v))
}
func (r reader) Registries(scope domain.Scope) ([]domain.RegistryRecord, error) {
	rows, err := r.q.ListGlueRegistries(r.ctx, sqlcgen.ListGlueRegistriesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RegistryRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.registryTags(registryRow(row))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutRegistry(v domain.RegistryRecord) error {
	k := v.Key
	if err := w.q.PutGlueRegistry(w.ctx, sqlcgen.PutGlueRegistryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Name, Description: registryDescription(v.Description), Status: v.Status, CreatedAt: v.Created, UpdatedAt: v.Updated, DueAt: v.Due}); err != nil {
		return err
	}
	if err := w.q.DeleteGlueRegistryTags(w.ctx, sqlcgen.DeleteGlueRegistryTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutGlueRegistryTag(w.ctx, sqlcgen.PutGlueRegistryTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Name, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteRegistry(k domain.ResourceKey) error {
	return w.q.DeleteGlueRegistry(w.ctx, sqlcgen.DeleteGlueRegistryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RegistryName: k.Name})
}

func registryLifecycleOrder(v domain.RegistryLifecycle) string {
	switch v.Kind {
	case "registry":
		return "registry:" + v.Registry.ARN("registry")
	case "schema":
		return "schema:" + v.Schema.ARN()
	default:
		return "version:" + v.VersionID
	}
}
func (r reader) NextRegistryLifecycle() (domain.RegistryLifecycle, error) {
	var out domain.RegistryLifecycle
	choose := func(v domain.RegistryLifecycle) {
		if out.Kind == "" || v.Due.Before(out.Due) || v.Due.Equal(out.Due) && registryLifecycleOrder(v) < registryLifecycleOrder(out) {
			out = v
		}
	}
	registry, err := r.q.NextGlueRegistryDeletion(r.ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if err == nil {
		v := registryRow(registry)
		choose(domain.RegistryLifecycle{Kind: "registry", Registry: v.Key, Due: v.Due})
	}
	schema, err := r.q.NextGlueSchemaDeletion(r.ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if err == nil {
		v := schemaRow(schema)
		choose(domain.RegistryLifecycle{Kind: "schema", Schema: v.Key, Due: v.Due})
	}
	version, err := r.q.NextGlueSchemaVersionDeletion(r.ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if err == nil {
		v := schemaVersionRow(version)
		choose(domain.RegistryLifecycle{Kind: "version", Schema: v.Key.Schema, VersionID: v.ID, Due: v.Due})
	}
	if out.Kind == "" {
		return out, domain.ErrNotFound
	}
	return out, nil
}
