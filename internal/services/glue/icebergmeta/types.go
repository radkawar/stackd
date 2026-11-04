// Package icebergmeta implements Iceberg v1/v2 table metadata and REST commits.
// Wire contracts follow the Apache Iceberg 1.6.1 REST OpenAPI specification and
// https://iceberg.apache.org/spec/ (table metadata and snapshot references).
package icebergmeta

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Error is an Iceberg REST error, independent of the HTTP transport.
type Error struct {
	Code    int
	Type    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func invalid(format string, args ...any) error {
	return &Error{Code: 400, Type: "IllegalArgumentException", Message: fmt.Sprintf(format, args...)}
}

func unsupported(format string, args ...any) error {
	return &Error{Code: 422, Type: "UnsupportedOperationException", Message: fmt.Sprintf(format, args...)}
}

func conflict(format string, args ...any) error {
	return &Error{Code: 409, Type: "CommitFailedException", Message: fmt.Sprintf(format, args...)}
}

type Identifier struct {
	Namespace []string `json:"namespace"`
	Name      string   `json:"name"`
}

type CreateRequest struct {
	Name          string            `json:"name"`
	Location      string            `json:"location"`
	Schema        Schema            `json:"schema"`
	PartitionSpec *PartitionSpec    `json:"partition-spec,omitempty"`
	WriteOrder    *SortOrder        `json:"write-order,omitempty"`
	StageCreate   bool              `json:"stage-create"`
	Properties    map[string]string `json:"properties"`
}

type CommitRequest struct {
	Identifier   *Identifier   `json:"identifier,omitempty"`
	Requirements []Requirement `json:"requirements"`
	Updates      []Update      `json:"updates"`
}

// Requirement is the discriminated REST requirement union. SnapshotID nil
// means that the named reference must not exist (both null and absent on wire).
type Requirement struct {
	Type                    string `json:"type"`
	UUID                    string `json:"uuid,omitempty"`
	Ref                     string `json:"ref,omitempty"`
	SnapshotID              *int64 `json:"snapshot-id,omitempty"`
	LastAssignedFieldID     *int   `json:"last-assigned-field-id,omitempty"`
	CurrentSchemaID         *int   `json:"current-schema-id,omitempty"`
	LastAssignedPartitionID *int   `json:"last-assigned-partition-id,omitempty"`
	DefaultSpecID           *int   `json:"default-spec-id,omitempty"`
	DefaultSortOrderID      *int   `json:"default-sort-order-id,omitempty"`
}

// Update is the discriminated REST table update union. Pointer fields preserve
// required zero IDs without accepting a missing required field as zero.
type Update struct {
	Action              string                   `json:"action"`
	UUID                string                   `json:"uuid,omitempty"`
	FormatVersion       *int                     `json:"format-version,omitempty"`
	Schema              *Schema                  `json:"schema,omitempty"`
	LastColumnID        *int                     `json:"last-column-id,omitempty"`
	SchemaID            *int                     `json:"schema-id,omitempty"`
	Spec                *PartitionSpec           `json:"spec,omitempty"`
	SpecID              *int                     `json:"spec-id,omitempty"`
	SortOrder           *SortOrder               `json:"sort-order,omitempty"`
	SortOrderID         *int                     `json:"sort-order-id,omitempty"`
	Snapshot            *Snapshot                `json:"snapshot,omitempty"`
	RefName             string                   `json:"ref-name,omitempty"`
	Type                string                   `json:"type,omitempty"`
	SnapshotID          *int64                   `json:"snapshot-id,omitempty"`
	MaxRefAgeMS         *int64                   `json:"max-ref-age-ms,omitempty"`
	MaxSnapshotAgeMS    *int64                   `json:"max-snapshot-age-ms,omitempty"`
	MinSnapshotsToKeep  *int                     `json:"min-snapshots-to-keep,omitempty"`
	SnapshotIDs         []int64                  `json:"snapshot-ids,omitempty"`
	Location            string                   `json:"location,omitempty"`
	Updates             map[string]string        `json:"updates,omitempty"`
	Removals            []string                 `json:"removals,omitempty"`
	Statistics          *StatisticsFile          `json:"statistics,omitempty"`
	PartitionStatistics *PartitionStatisticsFile `json:"partition-statistics,omitempty"`
}

type Metadata struct {
	FormatVersion       int                       `json:"format-version"`
	UUID                string                    `json:"table-uuid"`
	Location            string                    `json:"location"`
	LastSequenceNumber  int64                     `json:"last-sequence-number"`
	LastUpdatedMS       int64                     `json:"last-updated-ms"`
	LastColumnID        int                       `json:"last-column-id"`
	Schemas             []Schema                  `json:"schemas"`
	CurrentSchemaID     int                       `json:"current-schema-id"`
	PartitionSpecs      []PartitionSpec           `json:"partition-specs"`
	DefaultSpecID       int                       `json:"default-spec-id"`
	LastPartitionID     int                       `json:"last-partition-id"`
	Properties          map[string]string         `json:"properties"`
	CurrentSnapshotID   *int64                    `json:"current-snapshot-id,omitempty"`
	Snapshots           []Snapshot                `json:"snapshots"`
	SnapshotLog         []SnapshotLogEntry        `json:"snapshot-log"`
	MetadataLog         []MetadataLogEntry        `json:"metadata-log"`
	SortOrders          []SortOrder               `json:"sort-orders"`
	DefaultSortOrderID  int                       `json:"default-sort-order-id"`
	Refs                map[string]SnapshotRef    `json:"refs"`
	Statistics          []StatisticsFile          `json:"statistics,omitempty"`
	PartitionStatistics []PartitionStatisticsFile `json:"partition-statistics,omitempty"`
	// Legacy v1 fields are emitted only for v1 tables, alongside modern fields.
	Schema        *Schema                    `json:"schema,omitempty"`
	PartitionSpec []PartitionField           `json:"partition-spec,omitempty"`
	Extra         map[string]json.RawMessage `json:"-"`
}

type Schema struct {
	Type               string                     `json:"type"`
	SchemaID           int                        `json:"schema-id"`
	IdentifierFieldIDs []int                      `json:"identifier-field-ids,omitempty"`
	Fields             []Field                    `json:"fields"`
	Extra              map[string]json.RawMessage `json:"-"`
}

type Field struct {
	ID       int                        `json:"id"`
	Name     string                     `json:"name"`
	Required bool                       `json:"required"`
	Type     json.RawMessage            `json:"type"`
	Doc      string                     `json:"doc,omitempty"`
	Extra    map[string]json.RawMessage `json:"-"`
}

type PartitionSpec struct {
	SpecID int              `json:"spec-id"`
	Fields []PartitionField `json:"fields"`
}

type PartitionField struct {
	SourceID  int    `json:"source-id"`
	FieldID   int    `json:"field-id"`
	Name      string `json:"name"`
	Transform string `json:"transform"`
}

type SortOrder struct {
	OrderID int         `json:"order-id"`
	Fields  []SortField `json:"fields"`
}

type SortField struct {
	SourceID  int    `json:"source-id"`
	Transform string `json:"transform"`
	Direction string `json:"direction"`
	NullOrder string `json:"null-order"`
}

type Snapshot struct {
	SnapshotID       int64                      `json:"snapshot-id"`
	ParentSnapshotID *int64                     `json:"parent-snapshot-id,omitempty"`
	SequenceNumber   int64                      `json:"sequence-number"`
	TimestampMS      int64                      `json:"timestamp-ms"`
	ManifestList     string                     `json:"manifest-list,omitempty"`
	Manifests        []string                   `json:"manifests,omitempty"`
	Summary          map[string]string          `json:"summary,omitempty"`
	SchemaID         *int                       `json:"schema-id,omitempty"`
	Extra            map[string]json.RawMessage `json:"-"`
}

type SnapshotRef struct {
	SnapshotID         int64  `json:"snapshot-id"`
	Type               string `json:"type"`
	MaxRefAgeMS        *int64 `json:"max-ref-age-ms,omitempty"`
	MaxSnapshotAgeMS   *int64 `json:"max-snapshot-age-ms,omitempty"`
	MinSnapshotsToKeep *int   `json:"min-snapshots-to-keep,omitempty"`
}

type SnapshotLogEntry struct {
	SnapshotID  int64 `json:"snapshot-id"`
	TimestampMS int64 `json:"timestamp-ms"`
}

type MetadataLogEntry struct {
	MetadataFile string `json:"metadata-file"`
	TimestampMS  int64  `json:"timestamp-ms"`
}

type StatisticsFile struct {
	SnapshotID            int64             `json:"snapshot-id"`
	StatisticsPath        string            `json:"statistics-path"`
	FileSizeInBytes       int64             `json:"file-size-in-bytes"`
	FileFooterSizeInBytes int64             `json:"file-footer-size-in-bytes"`
	KeyMetadata           string            `json:"key-metadata,omitempty"`
	BlobMetadata          []json.RawMessage `json:"blob-metadata"`
}

type PartitionStatisticsFile struct {
	SnapshotID      int64  `json:"snapshot-id"`
	StatisticsPath  string `json:"statistics-path"`
	FileSizeInBytes int64  `json:"file-size-in-bytes"`
}

func marshalExtra(value any, extra map[string]json.RawMessage) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(extra) == 0 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for key, raw := range extra {
		if _, known := fields[key]; !known {
			fields[key] = raw
		}
	}
	return json.Marshal(fields)
}

func unmarshalExtra(data []byte, value any) (map[string]json.RawMessage, error) {
	if err := json.Unmarshal(data, value); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	typ := reflect.TypeOf(value).Elem()
	for i := range typ.NumField() {
		name := strings.SplitN(typ.Field(i).Tag.Get("json"), ",", 2)[0]
		if name != "" && name != "-" {
			delete(fields, name)
		}
	}
	return fields, nil
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	type plain Metadata
	value := plain(m)
	if m.FormatVersion == 1 {
		for _, schema := range m.Schemas {
			if schema.SchemaID == m.CurrentSchemaID {
				value.Schema = &schema
				break
			}
		}
		for _, spec := range m.PartitionSpecs {
			if spec.SpecID == m.DefaultSpecID {
				value.PartitionSpec = spec.Fields
				break
			}
		}
	} else {
		value.Schema, value.PartitionSpec = nil, nil
	}
	data, err := marshalExtra(value, m.Extra)
	if err != nil || m.FormatVersion != 1 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	delete(fields, "last-sequence-number")
	if len(m.Snapshots) > 0 {
		legacy := make([]map[string]json.RawMessage, len(m.Snapshots))
		for i, snapshot := range m.Snapshots {
			data, err := json.Marshal(snapshot)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(data, &legacy[i]); err != nil {
				return nil, err
			}
			delete(legacy[i], "sequence-number")
		}
		data, err := json.Marshal(legacy)
		if err != nil {
			return nil, err
		}
		fields["snapshots"] = data
	}
	if len(value.PartitionSpec) == 0 {
		fields["partition-spec"] = json.RawMessage("[]")
	}
	return json.Marshal(fields)
}

func (m *Metadata) UnmarshalJSON(data []byte) error {
	type plain Metadata
	var value plain
	extra, err := unmarshalExtra(data, &value)
	if err != nil {
		return err
	}
	*m = Metadata(value)
	m.Extra = extra
	if len(m.Schemas) == 0 && m.Schema != nil {
		m.Schemas = []Schema{*m.Schema}
		m.CurrentSchemaID = m.Schema.SchemaID
	}
	if len(m.PartitionSpecs) == 0 && m.FormatVersion == 1 {
		fields := m.PartitionSpec
		if fields == nil {
			fields = []PartitionField{}
		}
		for i := range fields {
			if fields[i].FieldID == 0 {
				fields[i].FieldID = 1000 + i
			}
		}
		m.PartitionSpecs = []PartitionSpec{{SpecID: 0, Fields: fields}}
	}
	if len(m.SortOrders) == 0 && m.FormatVersion == 1 {
		m.SortOrders = []SortOrder{{OrderID: 0, Fields: []SortField{}}}
	}
	if m.LastPartitionID < 999 {
		m.LastPartitionID = 999
		for _, spec := range m.PartitionSpecs {
			for _, f := range spec.Fields {
				if f.FieldID > m.LastPartitionID {
					m.LastPartitionID = f.FieldID
				}
			}
		}
	}
	if m.Refs == nil {
		m.Refs = make(map[string]SnapshotRef)
	}
	if m.CurrentSnapshotID != nil && *m.CurrentSnapshotID != -1 {
		if _, ok := m.Refs["main"]; !ok {
			m.Refs["main"] = SnapshotRef{SnapshotID: *m.CurrentSnapshotID, Type: "branch"}
		}
	}
	return nil
}

func (s Snapshot) MarshalJSON() ([]byte, error) {
	type plain Snapshot
	return marshalExtra(plain(s), s.Extra)
}

func (s *Snapshot) UnmarshalJSON(data []byte) error {
	type plain Snapshot
	var value plain
	extra, err := unmarshalExtra(data, &value)
	if err != nil {
		return err
	}
	*s = Snapshot(value)
	s.Extra = extra
	return nil
}
