package s3tables

import (
	"context"
	"net/url"
	"strings"
)

const warehouseBucketSuffix = "--table-s3"

func warehouseKey(warehouse, location string) (string, error) {
	u, e := url.Parse(location)
	if e != nil || u.Scheme != "s3" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", invalid("Invalid table object location")
	}
	if "s3://"+u.Host != warehouse || !strings.HasPrefix(location, warehouse+"/") {
		return "", invalid("Object location must be inside this table's warehouse")
	}
	key := strings.TrimPrefix(u.Path, "/")
	if key == "" {
		return "", invalid("Object key is required")
	}
	for _, part := range strings.Split(key, "/") {
		if part == "." || part == ".." || strings.ContainsRune(part, '\x00') {
			return "", invalid("Invalid table object path")
		}
	}
	return key, nil
}
func parseLocation(location string) (string, string, error) {
	u, e := url.Parse(location)
	if e != nil || u.Scheme != "s3" || !strings.HasSuffix(u.Host, warehouseBucketSuffix) {
		return "", "", invalid("Not a table-owned warehouse")
	}
	warehouse := "s3://" + u.Host
	key, e := warehouseKey(warehouse, location)
	return warehouse, key, e
}
func (s *Service) dataTable(ctx context.Context, warehouse, action string) (Table, error) {
	var out Table
	e := s.repository.View(ctx, func(r Reader) error {
		v, e := r.Warehouse(scopeFor(ctx), warehouse)
		if e != nil {
			return e
		}
		if v.Deleted {
			return ErrNotFound
		}
		if e = s.authorize(r.Context(), action, v.ARN, tableAuthorizationContext(v)); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, e
}

// Read and Write remain the native Iceberg adapters. HTTP uses the typed APIs
// so a multipart ETag and object attributes are never reconstructed from bytes.
func (s *Service) Read(ctx context.Context, location string) ([]byte, error) {
	data, _, err := s.ReadObject(ctx, location)
	return data, err
}
func (s *Service) Write(ctx context.Context, location string, data []byte) error {
	_, err := s.WriteObject(ctx, location, data, ObjectAttributes{}, ObjectConditions{})
	return err
}
func (s *Service) ReadObject(ctx context.Context, location string) ([]byte, ObjectInfo, error) {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "GetTableData")
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return nil, ObjectInfo{}, err
	}
	data, info, err := s.objects.ReadObject(ctx, warehouse, key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	if err = s.recheckDataTable(ctx, table, "GetTableData"); err != nil {
		return nil, ObjectInfo{}, err
	}
	return data, info, nil
}

// ObjectInfo reads metadata without loading the object's payload.
func (s *Service) ObjectInfo(ctx context.Context, location string) (ObjectInfo, error) {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return ObjectInfo{}, err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "GetTableData")
	if err != nil {
		return ObjectInfo{}, err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return ObjectInfo{}, err
	}
	info, err := s.objects.Info(ctx, warehouse, key)
	if err != nil {
		return ObjectInfo{}, err
	}
	if err = s.recheckDataTable(ctx, table, "GetTableData"); err != nil {
		return ObjectInfo{}, err
	}
	return info, nil
}
func (s *Service) WriteObject(ctx context.Context, location string, data []byte, attrs ObjectAttributes, conditions ObjectConditions) (ObjectInfo, error) {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return ObjectInfo{}, err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "PutTableData")
	if err != nil {
		return ObjectInfo{}, err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return ObjectInfo{}, err
	}
	info, err := SingleObjectInfo(key, data, attrs, s.clock.Now())
	if err != nil {
		return ObjectInfo{}, err
	}
	return s.objects.WriteObject(ctx, warehouse, data, info, conditions, s.objectPublicationGuard(table))
}

func (s *Service) objectStorageAvailable() error {
	if s.objects == nil {
		return failure("InternalServerErrorException", "Table warehouse storage is unavailable", 503)
	}
	return nil
}
func (s *Service) recheckDataTable(ctx context.Context, before Table, action string) error {
	current, err := s.dataTable(ctx, before.Warehouse, action)
	if err != nil {
		return err
	}
	if current.ID != before.ID || current.ARN != before.ARN || current.Warehouse != before.Warehouse {
		return ErrNotFound
	}
	return nil
}
func (s *Service) objectPublicationGuard(table Table) PublicationGuard {
	return func(ctx context.Context) error {
		return s.recheckDataTable(ctx, table, "PutTableData")
	}
}
