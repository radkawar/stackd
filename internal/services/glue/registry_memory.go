package glue

import (
	"cmp"
	"maps"
	"slices"
)

type schemaMetadataKey struct{ VersionID, Key, Value string }
type registryMemory struct {
	registries       map[ResourceKey]RegistryRecord
	schemas          map[SchemaKey]SchemaRecord
	schemaVersions   map[SchemaVersionKey]SchemaVersionRecord
	schemaVersionIDs map[string]SchemaVersionKey
	schemaMetadata   map[schemaMetadataKey]SchemaMetadataRecord
}

func initRegistryMemory() registryMemory {
	return registryMemory{map[ResourceKey]RegistryRecord{}, map[SchemaKey]SchemaRecord{}, map[SchemaVersionKey]SchemaVersionRecord{}, map[string]SchemaVersionKey{}, map[schemaMetadataKey]SchemaMetadataRecord{}}
}
func cloneRegistryMemory(v registryMemory) registryMemory {
	v.registries = maps.Clone(v.registries)
	v.schemas = maps.Clone(v.schemas)
	v.schemaVersions = maps.Clone(v.schemaVersions)
	v.schemaVersionIDs = maps.Clone(v.schemaVersionIDs)
	v.schemaMetadata = maps.Clone(v.schemaMetadata)
	return v
}
func cloneRegistry(v RegistryRecord) RegistryRecord {
	v.Tags = maps.Clone(v.Tags)
	if v.Description != nil {
		v.Description = new(*v.Description)
	}
	return v
}
func cloneSchema(v SchemaRecord) SchemaRecord {
	v.Tags = maps.Clone(v.Tags)
	if v.Description != nil {
		v.Description = new(*v.Description)
	}
	return v
}
func (r memoryReader) Registry(k ResourceKey) (RegistryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RegistryRecord{}, err
	}
	v, ok := r.s.registries[k]
	if !ok {
		return RegistryRecord{}, ErrNotFound
	}
	return cloneRegistry(v), nil
}
func (r memoryReader) Registries(scope Scope) ([]RegistryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []RegistryRecord{}
	for k, v := range r.s.registries {
		if k.Scope == scope {
			out = append(out, cloneRegistry(v))
		}
	}
	slices.SortFunc(out, func(a, b RegistryRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) Schema(k SchemaKey) (SchemaRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SchemaRecord{}, err
	}
	v, ok := r.s.schemas[k]
	if !ok {
		return SchemaRecord{}, ErrNotFound
	}
	return cloneSchema(v), nil
}
func (r memoryReader) Schemas(scope Scope, registry string) ([]SchemaRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SchemaRecord{}
	for k, v := range r.s.schemas {
		if k.Scope == scope && (registry == "" || k.Registry == registry) {
			out = append(out, cloneSchema(v))
		}
	}
	slices.SortFunc(out, func(a, b SchemaRecord) int {
		return cmp.Or(cmp.Compare(a.Key.Registry, b.Key.Registry), cmp.Compare(a.Key.Name, b.Key.Name))
	})
	return out, nil
}
func (r memoryReader) SchemaVersion(k SchemaVersionKey) (SchemaVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SchemaVersionRecord{}, err
	}
	v, ok := r.s.schemaVersions[k]
	if !ok {
		return SchemaVersionRecord{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) SchemaVersionByID(scope Scope, id string) (SchemaVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SchemaVersionRecord{}, err
	}
	k, ok := r.s.schemaVersionIDs[id]
	if !ok || k.Schema.Scope != scope {
		return SchemaVersionRecord{}, ErrNotFound
	}
	return r.SchemaVersion(k)
}
func (r memoryReader) SchemaVersions(k SchemaKey) ([]SchemaVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SchemaVersionRecord{}
	for key, v := range r.s.schemaVersions {
		if key.Schema == k {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b SchemaVersionRecord) int { return cmp.Compare(b.Key.Number, a.Key.Number) })
	return out, nil
}
func (r memoryReader) SchemaMetadata(id string) ([]SchemaMetadataRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SchemaMetadataRecord{}
	for k, v := range r.s.schemaMetadata {
		if k.VersionID == id {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b SchemaMetadataRecord) int {
		return cmp.Or(cmp.Compare(a.Key, b.Key), cmp.Compare(a.Ordinal, b.Ordinal), cmp.Compare(a.Value, b.Value))
	})
	return out, nil
}
func (r memoryReader) NextRegistryLifecycle() (RegistryLifecycle, error) {
	if err := r.tx.Check(false); err != nil {
		return RegistryLifecycle{}, err
	}
	var out RegistryLifecycle
	choose := func(v RegistryLifecycle) {
		if out.Kind == "" || v.Due.Before(out.Due) || v.Due.Equal(out.Due) && registryLifecycleKey(v) < registryLifecycleKey(out) {
			out = v
		}
	}
	for k, v := range r.s.registries {
		if v.Status == "DELETING" {
			choose(RegistryLifecycle{Kind: "registry", Registry: k, Due: v.Due})
		}
	}
	for k, v := range r.s.schemas {
		if v.Status == "DELETING" {
			choose(RegistryLifecycle{Kind: "schema", Schema: k, Due: v.Due})
		}
	}
	for _, v := range r.s.schemaVersions {
		if v.Status == "DELETING" {
			choose(RegistryLifecycle{Kind: "version", Schema: v.Key.Schema, VersionID: v.ID, Due: v.Due})
		}
	}
	if out.Kind == "" {
		return out, ErrNotFound
	}
	return out, nil
}
func (w memoryWriter) PutRegistry(v RegistryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if old, ok := w.s.registries[v.Key]; ok {
		v.CFNOwner = old.CFNOwner
	}
	w.s.registries[v.Key] = cloneRegistry(v)
	return nil
}
func (w memoryWriter) PutSchema(v SchemaRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if old, ok := w.s.schemas[v.Key]; ok {
		v.CFNOwner = old.CFNOwner
	}
	w.s.schemas[v.Key] = cloneSchema(v)
	return nil
}
func (w memoryWriter) PutSchemaVersion(v SchemaVersionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.schemaVersions[v.Key] = v
	w.s.schemaVersionIDs[v.ID] = v.Key
	return nil
}
func (w memoryWriter) PutSchemaMetadata(v SchemaMetadataRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.schemaMetadata[schemaMetadataKey{v.VersionID, v.Key, v.Value}] = v
	return nil
}
func (w memoryWriter) DeleteSchemaMetadata(id, key, value string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.schemaMetadata, schemaMetadataKey{id, key, value})
	return nil
}
func (w memoryWriter) DeleteSchemaVersion(k SchemaVersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.s.schemaVersions[k]
	if !ok {
		return ErrNotFound
	}
	for key := range w.s.schemaMetadata {
		if key.VersionID == v.ID {
			delete(w.s.schemaMetadata, key)
		}
	}
	delete(w.s.schemaVersionIDs, v.ID)
	delete(w.s.schemaVersions, k)
	return nil
}
func (w memoryWriter) DeleteSchema(k SchemaKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key := range w.s.schemaVersions {
		if key.Schema == k {
			if err := w.DeleteSchemaVersion(key); err != nil {
				return err
			}
		}
	}
	delete(w.s.schemas, k)
	return nil
}
func (w memoryWriter) DeleteRegistry(k ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key := range w.s.schemas {
		if key.Scope == k.Scope && key.Registry == k.Name {
			if err := w.DeleteSchema(key); err != nil {
				return err
			}
		}
	}
	delete(w.s.registries, k)
	return nil
}
