package s3tables

import (
	"encoding/json"

	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/services/glue/icebergmeta"
)

// initialMetadata translates the pinned Smithy IcebergMetadata contract into a
// real Iceberg v2 metadata document using the same format owner as Glue REST.
func (s *Service) initialMetadata(in *api.CreateTableInput, t Table) (metadata icebergmeta.Metadata, err error) {
	if in.Metadata.Iceberg == nil {
		return metadata, invalid("Iceberg metadata is required")
	}
	m := in.Metadata.Iceberg
	if (m.Schema == nil) == (m.SchemaV2 == nil) {
		return metadata, invalid("Specify exactly one of schema and schemaV2")
	}
	req := icebergmeta.CreateRequest{Name: t.Name, Location: t.Warehouse, Properties: map[string]string{}}
	for k, v := range m.Properties {
		req.Properties[string(k)] = string(v)
	}
	if version, ok := req.Properties["format-version"]; ok && version != "2" {
		// TODO: Comeback support Iceberg v3 metadata, row lineage and deletion vectors; Athena currently requires v2.
		return metadata, invalid("Initial table metadata supports Iceberg format-version 2")
	}
	if m.SchemaV2 != nil {
		data, e := json.Marshal(m.SchemaV2)
		if e != nil {
			return metadata, e
		}
		if e = json.Unmarshal(data, &req.Schema); e != nil {
			return metadata, invalid(e.Error())
		}
	} else {
		req.Schema = icebergmeta.Schema{Type: "struct", Fields: []icebergmeta.Field{}}
		used := map[int]bool{}
		for _, f := range m.Schema.Fields {
			if f.Id != nil {
				used[int(*f.Id)] = true
			}
		}
		next := 1
		for _, f := range m.Schema.Fields {
			if f.Name == nil || f.Type == nil {
				return metadata, invalid("Schema field name and type are required")
			}
			id := 0
			if f.Id != nil {
				id = int(*f.Id)
			} else {
				for used[next] {
					next++
				}
				id = next
				used[id] = true
				next++
			}
			typ, e := json.Marshal(string(*f.Type))
			if e != nil {
				return metadata, e
			}
			required := f.Required != nil && bool(*f.Required)
			req.Schema.Fields = append(req.Schema.Fields, icebergmeta.Field{ID: id, Name: string(*f.Name), Required: required, Type: typ})
		}
	}
	if m.PartitionSpec != nil {
		data, e := json.Marshal(m.PartitionSpec)
		if e != nil {
			return metadata, e
		}
		req.PartitionSpec = &icebergmeta.PartitionSpec{}
		if e = json.Unmarshal(data, req.PartitionSpec); e != nil {
			return metadata, invalid(e.Error())
		}
	}
	if m.WriteOrder != nil {
		data, e := json.Marshal(m.WriteOrder)
		if e != nil {
			return metadata, e
		}
		req.WriteOrder = &icebergmeta.SortOrder{}
		if e = json.Unmarshal(data, req.WriteOrder); e != nil {
			return metadata, invalid(e.Error())
		}
	}
	metadata, e := icebergmeta.New(req, s.clock.Now())
	if e != nil {
		return metadata, invalid(e.Error())
	}
	return metadata, nil
}
