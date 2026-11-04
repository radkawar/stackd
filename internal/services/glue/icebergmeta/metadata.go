package icebergmeta

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// New creates an empty table with fresh IDs, remapping partition and sort
// sources along with the schema as required by REST create-table semantics.
func New(request CreateRequest, now time.Time) (Metadata, error) {
	if request.Name == "" {
		return Metadata{}, invalid("Table name is required")
	}
	if request.Location == "" {
		return Metadata{}, invalid("Table location is required")
	}
	version := 2
	if value, ok := request.Properties["format-version"]; ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return Metadata{}, invalid("Invalid format-version %q", value)
		}
		version = parsed
	}
	if version != 1 && version != 2 {
		return Metadata{}, unsupported("Unsupported format-version %d", version)
	}
	schema := request.Schema
	schema.Fields = slices.Clone(schema.Fields)
	schema.IdentifierFieldIDs = slices.Clone(schema.IdentifierFieldIDs)
	schema.SchemaID = 0
	remap := make(map[int]int)
	lastID := 0
	if err := walkSchema(&schema, true, func(old int) (int, error) {
		if _, exists := remap[old]; exists {
			return 0, invalid("Duplicate schema field ID %d", old)
		}
		lastID++
		remap[old] = lastID
		return lastID, nil
	}); err != nil {
		return Metadata{}, err
	}
	for i, old := range schema.IdentifierFieldIDs {
		id, ok := remap[old]
		if !ok {
			return Metadata{}, invalid("Missing identifier field ID %d", old)
		}
		schema.IdentifierFieldIDs[i] = id
	}
	spec := PartitionSpec{SpecID: 0, Fields: []PartitionField{}}
	if request.PartitionSpec != nil {
		spec.Fields = slices.Clone(request.PartitionSpec.Fields)
		if spec.Fields == nil {
			return Metadata{}, invalid("Partition spec fields must be an array")
		}
		for i := range spec.Fields {
			id, ok := remap[spec.Fields[i].SourceID]
			if !ok {
				return Metadata{}, invalid("Missing partition source ID %d", spec.Fields[i].SourceID)
			}
			spec.Fields[i].SourceID, spec.Fields[i].FieldID = id, 1000+i
		}
	}
	if err := validateSpec(spec, schema, version); err != nil {
		return Metadata{}, err
	}
	order := SortOrder{OrderID: 0, Fields: []SortField{}}
	if request.WriteOrder != nil {
		order.Fields = slices.Clone(request.WriteOrder.Fields)
		if order.Fields == nil {
			return Metadata{}, invalid("Sort order fields must be an array")
		}
		if len(order.Fields) > 0 {
			order.OrderID = 1
		}
		for i := range order.Fields {
			id, ok := remap[order.Fields[i].SourceID]
			if !ok {
				return Metadata{}, invalid("Missing sort source ID %d", order.Fields[i].SourceID)
			}
			order.Fields[i].SourceID = id
		}
	}
	if err := validateOrder(order, schema); err != nil {
		return Metadata{}, err
	}
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return Metadata{}, fmt.Errorf("generate table UUID: %w", err)
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	uuidString := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	properties := maps.Clone(request.Properties)
	if properties == nil {
		properties = make(map[string]string)
	}
	for key := range properties {
		if reservedProperty(key) {
			delete(properties, key)
		}
	}
	metadata := Metadata{
		FormatVersion: version, UUID: uuidString, Location: strings.TrimRight(request.Location, "/"), LastUpdatedMS: now.UnixMilli(),
		LastColumnID: lastID, Schemas: []Schema{schema}, CurrentSchemaID: 0,
		PartitionSpecs: []PartitionSpec{spec}, DefaultSpecID: 0, LastPartitionID: 999 + len(spec.Fields),
		SortOrders: []SortOrder{order}, DefaultSortOrderID: order.OrderID, Properties: properties,
		Snapshots: []Snapshot{}, SnapshotLog: []SnapshotLogEntry{}, MetadataLog: []MetadataLogEntry{}, Refs: make(map[string]SnapshotRef),
	}
	return metadata, nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

// ValidateRequirements checks all assertions against the original committed
// metadata, never against the progressively modified candidate.
func ValidateRequirements(metadata *Metadata, requirements []Requirement) error {
	for _, requirement := range requirements {
		if requirement.Type == "assert-create" {
			if metadata != nil {
				return conflict("Requirement failed: table already exists")
			}
			continue
		}
		var want *int
		var actual int
		switch requirement.Type {
		case "assert-table-uuid":
			if requirement.UUID == "" {
				return invalid("assert-table-uuid requires uuid")
			}
			if metadata == nil || !strings.EqualFold(metadata.UUID, requirement.UUID) {
				return conflict("Requirement failed: table UUID does not match")
			}
			continue
		case "assert-ref-snapshot-id":
			if requirement.Ref == "" {
				return invalid("assert-ref-snapshot-id requires ref")
			}
			var ref SnapshotRef
			var exists bool
			if metadata != nil {
				ref, exists = metadata.Refs[requirement.Ref]
				if !exists && requirement.Ref == "main" && metadata.CurrentSnapshotID != nil && *metadata.CurrentSnapshotID != -1 {
					ref.SnapshotID, exists = *metadata.CurrentSnapshotID, true
				}
			}
			if requirement.SnapshotID == nil {
				if exists {
					return conflict("Requirement failed: ref %s already exists", requirement.Ref)
				}
			} else if !exists || ref.SnapshotID != *requirement.SnapshotID {
				return conflict("Requirement failed: ref %s snapshot has changed", requirement.Ref)
			}
			continue
		case "assert-last-assigned-field-id":
			want = requirement.LastAssignedFieldID
			if metadata != nil {
				actual = metadata.LastColumnID
			}
		case "assert-current-schema-id":
			want = requirement.CurrentSchemaID
			if metadata != nil {
				actual = metadata.CurrentSchemaID
			}
		case "assert-last-assigned-partition-id":
			want = requirement.LastAssignedPartitionID
			if metadata != nil {
				actual = metadata.LastPartitionID
			}
		case "assert-default-spec-id":
			want = requirement.DefaultSpecID
			if metadata != nil {
				actual = metadata.DefaultSpecID
			}
		case "assert-default-sort-order-id":
			want = requirement.DefaultSortOrderID
			if metadata != nil {
				actual = metadata.DefaultSortOrderID
			}
		default:
			return unsupported("Unsupported requirement %q", requirement.Type)
		}
		if want == nil {
			return invalid("Missing value for requirement %s", requirement.Type)
		}
		if metadata == nil {
			if requirement.Type == "assert-last-assigned-field-id" || requirement.Type == "assert-last-assigned-partition-id" {
				continue
			}
			return conflict("Requirement failed: table does not exist")
		}
		if actual != *want {
			return conflict("Requirement failed: %s expected %d, found %d", requirement.Type, *want, actual)
		}
	}
	return nil
}

func sameValue(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	if bytes.Equal(left, right) {
		return true
	}
	// Raw nested types can have different object key order. Preserve integer
	// precision: snapshot IDs routinely exceed the exact float64 range.
	var l, r any
	leftDecoder := json.NewDecoder(bytes.NewReader(left))
	leftDecoder.UseNumber()
	rightDecoder := json.NewDecoder(bytes.NewReader(right))
	rightDecoder.UseNumber()
	if leftDecoder.Decode(&l) != nil || rightDecoder.Decode(&r) != nil {
		return false
	}
	return equalJSON(l, r)
}

func equalJSON(a, b any) bool {
	switch a := a.(type) {
	case map[string]any:
		b, ok := b.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for key, value := range a {
			other, ok := b[key]
			if !ok || !equalJSON(value, other) {
				return false
			}
		}
		return true
	case []any:
		b, ok := b.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !equalJSON(a[i], b[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}
