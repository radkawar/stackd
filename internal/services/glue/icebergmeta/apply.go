package icebergmeta

import (
	"maps"
	"slices"
	"strings"
	"time"
)

// Apply returns a candidate without mutating the base metadata or request.
// The catalog must atomically compare-and-swap its metadata pointer separately.
// Metadata-log entries require the old metadata file location, which is owned
// by the catalog and must be appended there before serializing the candidate.
func Apply(base Metadata, request CommitRequest, now time.Time) (Metadata, error) {
	var original *Metadata
	if base.FormatVersion != 0 {
		original = &base
	}
	if err := ValidateRequirements(original, request.Requirements); err != nil {
		return Metadata{}, err
	}
	metadata := base
	metadata.Schemas = slices.Clone(base.Schemas)
	metadata.PartitionSpecs = slices.Clone(base.PartitionSpecs)
	metadata.SortOrders = slices.Clone(base.SortOrders)
	metadata.Snapshots = slices.Clone(base.Snapshots)
	metadata.SnapshotLog = slices.Clone(base.SnapshotLog)
	metadata.MetadataLog = slices.Clone(base.MetadataLog)
	metadata.Statistics = slices.Clone(base.Statistics)
	metadata.PartitionStatistics = slices.Clone(base.PartitionStatistics)
	metadata.Properties = maps.Clone(base.Properties)
	metadata.Refs = maps.Clone(base.Refs)
	if metadata.Properties == nil {
		metadata.Properties = make(map[string]string)
	}
	if metadata.Refs == nil {
		metadata.Refs = make(map[string]SnapshotRef)
	}
	if original == nil {
		metadata.FormatVersion, metadata.LastPartitionID = 1, 999
	}
	if metadata.CurrentSnapshotID != nil && *metadata.CurrentSnapshotID != -1 {
		if _, ok := metadata.Refs["main"]; !ok {
			metadata.Refs["main"] = SnapshotRef{SnapshotID: *metadata.CurrentSnapshotID, Type: "branch"}
		}
	}
	lastSchema, lastSpec, lastOrder := -1, -1, -1
	addedSnapshots := make(map[int64]bool)
	mainChanges := make(map[int64]bool)
	metadata.LastUpdatedMS = now.UnixMilli()
	for _, update := range request.Updates {
		var err error
		switch update.Action {
		case "assign-uuid":
			if !validUUID(update.UUID) {
				err = invalid("Invalid table UUID %q", update.UUID)
				break
			}
			// Glue permits assigning a writer UUID after create but before the
			// first snapshot; changing an established table identity is unsafe.
			if len(metadata.Snapshots) > 0 && metadata.UUID != "" && !strings.EqualFold(metadata.UUID, update.UUID) {
				err = invalid("Cannot reassign a table UUID after snapshots exist")
				break
			}
			metadata.UUID = update.UUID
		case "upgrade-format-version":
			if update.FormatVersion == nil {
				err = invalid("upgrade-format-version requires format-version")
				break
			}
			if *update.FormatVersion < metadata.FormatVersion {
				err = invalid("Cannot downgrade table format version")
				break
			}
			if *update.FormatVersion > 2 {
				err = unsupported("Unsupported format-version %d", *update.FormatVersion)
				break
			}
			metadata.FormatVersion = *update.FormatVersion
		case "add-schema":
			lastSchema, err = addSchema(&metadata, update)
		case "set-current-schema":
			id, idErr := resolveID(update.SchemaID, lastSchema, "schema-id")
			if idErr != nil {
				err = idErr
				break
			}
			if _, ok := findSchema(metadata, id); !ok {
				err = invalid("Unknown schema ID %d", id)
				break
			}
			metadata.CurrentSchemaID = id
		case "add-spec":
			lastSpec, err = addSpec(&metadata, update.Spec)
		case "set-default-spec":
			id, idErr := resolveID(update.SpecID, lastSpec, "spec-id")
			if idErr != nil {
				err = idErr
				break
			}
			found := false
			for _, spec := range metadata.PartitionSpecs {
				if spec.SpecID == id {
					found = true
					break
				}
			}
			if !found {
				err = invalid("Unknown partition spec ID %d", id)
				break
			}
			metadata.DefaultSpecID = id
		case "add-sort-order":
			lastOrder, err = addOrder(&metadata, update.SortOrder)
		case "set-default-sort-order":
			id, idErr := resolveID(update.SortOrderID, lastOrder, "sort-order-id")
			if idErr != nil {
				err = idErr
				break
			}
			found := false
			for _, order := range metadata.SortOrders {
				if order.OrderID == id {
					found = true
					break
				}
			}
			if !found {
				err = invalid("Unknown sort order ID %d", id)
				break
			}
			metadata.DefaultSortOrderID = id
		case "add-snapshot":
			err = addSnapshot(&metadata, update.Snapshot)
			if err == nil {
				addedSnapshots[update.Snapshot.SnapshotID] = true
			}
		case "set-snapshot-ref":
			err = setRef(&metadata, update, addedSnapshots)
			if err == nil && update.RefName == "main" {
				mainChanges[*update.SnapshotID] = true
			}
		case "remove-snapshots":
			if update.SnapshotIDs == nil {
				err = invalid("remove-snapshots requires snapshot-ids")
				break
			}
			removeSnapshots(&metadata, update.SnapshotIDs)
		case "remove-snapshot-ref":
			if update.RefName == "" {
				err = invalid("remove-snapshot-ref requires ref-name")
				break
			}
			removeRef(&metadata, update.RefName)
		case "set-location":
			if update.Location == "" {
				err = invalid("set-location requires location")
				break
			}
			metadata.Location = strings.TrimRight(update.Location, "/")
		case "set-properties":
			if update.Updates == nil {
				err = invalid("set-properties requires updates")
				break
			}
			for key, value := range update.Updates {
				if reservedProperty(key) {
					err = invalid("Cannot set reserved property %q; use its metadata update", key)
					break
				}
				metadata.Properties[key] = value
			}
		case "remove-properties":
			if update.Removals == nil {
				err = invalid("remove-properties requires removals")
				break
			}
			for _, key := range update.Removals {
				if reservedProperty(key) {
					err = invalid("Cannot remove reserved property %q", key)
					break
				}
				delete(metadata.Properties, key)
			}
		case "set-statistics", "remove-statistics", "set-partition-statistics", "remove-partition-statistics":
			err = applyStatistics(&metadata, update)
		default:
			err = unsupported("Unsupported metadata update %q", update.Action)
		}
		if err != nil {
			return Metadata{}, err
		}
	}
	// Only the final main snapshot in this transaction was publicly current.
	metadata.SnapshotLog = slices.DeleteFunc(metadata.SnapshotLog, func(entry SnapshotLogEntry) bool {
		return addedSnapshots[entry.SnapshotID] && mainChanges[entry.SnapshotID] && (metadata.CurrentSnapshotID == nil || entry.SnapshotID != *metadata.CurrentSnapshotID)
	})
	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	if metadata.Snapshots == nil {
		metadata.Snapshots = []Snapshot{}
	}
	if metadata.SnapshotLog == nil {
		metadata.SnapshotLog = []SnapshotLogEntry{}
	}
	if metadata.MetadataLog == nil {
		metadata.MetadataLog = []MetadataLogEntry{}
	}
	return metadata, nil
}

func reservedProperty(key string) bool {
	switch key {
	case "format-version", "uuid", "snapshot-count", "current-snapshot-id", "current-snapshot-summary", "current-snapshot-timestamp-ms", "current-schema", "default-partition-spec", "default-sort-order":
		return true
	}
	return false
}

func resolveID(value *int, last int, name string) (int, error) {
	if value == nil {
		return 0, invalid("Missing %s", name)
	}
	if *value == -1 {
		if last < 0 {
			return 0, invalid("Cannot use -1 for %s before adding one", name)
		}
		return last, nil
	}
	if *value < 0 {
		return 0, invalid("Invalid %s %d", name, *value)
	}
	return *value, nil
}

func addSchema(metadata *Metadata, update Update) (int, error) {
	if update.Schema == nil {
		return -1, invalid("add-schema requires schema")
	}
	schema := *update.Schema
	schema.Fields = slices.Clone(schema.Fields)
	_, last, err := schemaIDs(schema)
	if err != nil {
		return -1, err
	}
	if update.LastColumnID != nil {
		if *update.LastColumnID < metadata.LastColumnID || *update.LastColumnID < last {
			return -1, invalid("last-column-id cannot decrease or be below schema field IDs")
		}
		last = *update.LastColumnID
	} else if last < metadata.LastColumnID {
		last = metadata.LastColumnID
	}
	next := 0
	for _, old := range metadata.Schemas {
		candidate := schema
		candidate.SchemaID = old.SchemaID
		if sameValue(candidate, old) {
			metadata.LastColumnID = last
			return old.SchemaID, nil
		}
		if old.SchemaID >= next {
			next = old.SchemaID + 1
		}
	}
	schema.SchemaID = next
	metadata.Schemas = append(metadata.Schemas, schema)
	metadata.LastColumnID = last
	return next, nil
}

func addSpec(metadata *Metadata, value *PartitionSpec) (int, error) {
	if value == nil || value.Fields == nil {
		return -1, invalid("add-spec requires spec with fields")
	}
	schema, ok := findSchema(*metadata, metadata.CurrentSchemaID)
	if !ok {
		return -1, invalid("Current schema does not exist")
	}
	spec := *value
	spec.Fields = slices.Clone(value.Fields)
	nextID, nextField := 0, metadata.LastPartitionID
	for _, field := range spec.Fields {
		if field.FieldID > nextField {
			nextField = field.FieldID
		}
	}
	for i := range spec.Fields {
		if spec.Fields[i].FieldID != 0 {
			continue
		}
		if metadata.FormatVersion == 1 {
			spec.Fields[i].FieldID = 1000 + i
			if spec.Fields[i].FieldID > nextField {
				nextField = spec.Fields[i].FieldID
			}
			continue
		}
		// Reuse a partition field ID for an existing source/transform pair.
		for _, old := range metadata.PartitionSpecs {
			for _, field := range old.Fields {
				if field.SourceID == spec.Fields[i].SourceID && field.Transform == spec.Fields[i].Transform {
					spec.Fields[i].FieldID = field.FieldID
					break
				}
			}
		}
		if spec.Fields[i].FieldID == 0 {
			nextField++
			spec.Fields[i].FieldID = nextField
		}
	}
	if err := validateSpec(spec, schema, metadata.FormatVersion); err != nil {
		return -1, err
	}
	if metadata.FormatVersion > 1 {
		for _, field := range spec.Fields {
			for _, old := range metadata.PartitionSpecs {
				for _, previous := range old.Fields {
					if previous.FieldID == field.FieldID && (previous.SourceID != field.SourceID || previous.Transform != field.Transform) {
						return -1, invalid("Partition field ID %d is already assigned to another source or transform", field.FieldID)
					}
				}
			}
		}
	}
	for _, old := range metadata.PartitionSpecs {
		candidate := spec
		candidate.SpecID = old.SpecID
		if sameValue(candidate, old) {
			return old.SpecID, nil
		}
		if old.SpecID >= nextID {
			nextID = old.SpecID + 1
		}
	}
	spec.SpecID = nextID
	metadata.PartitionSpecs = append(metadata.PartitionSpecs, spec)
	if nextField > metadata.LastPartitionID {
		metadata.LastPartitionID = nextField
	}
	return nextID, nil
}

func addOrder(metadata *Metadata, value *SortOrder) (int, error) {
	if value == nil || value.Fields == nil {
		return -1, invalid("add-sort-order requires sort-order with fields")
	}
	schema, ok := findSchema(*metadata, metadata.CurrentSchemaID)
	if !ok {
		return -1, invalid("Current schema does not exist")
	}
	order := *value
	order.Fields = slices.Clone(value.Fields)
	if err := validateOrder(order, schema); err != nil {
		return -1, err
	}
	next := 1
	for _, old := range metadata.SortOrders {
		if sameValue(order.Fields, old.Fields) {
			return old.OrderID, nil
		}
		if old.OrderID >= next {
			next = old.OrderID + 1
		}
	}
	if len(order.Fields) == 0 {
		next = 0
	}
	order.OrderID = next
	metadata.SortOrders = append(metadata.SortOrders, order)
	return next, nil
}

func findSnapshot(metadata Metadata, id int64) (Snapshot, bool) {
	for _, snapshot := range metadata.Snapshots {
		if snapshot.SnapshotID == id {
			return snapshot, true
		}
	}
	return Snapshot{}, false
}

func addSnapshot(metadata *Metadata, snapshot *Snapshot) error {
	if snapshot == nil {
		return invalid("add-snapshot requires snapshot")
	}
	if len(metadata.Schemas) == 0 || len(metadata.PartitionSpecs) == 0 || len(metadata.SortOrders) == 0 {
		return invalid("Snapshot requires schema, partition spec, and sort order")
	}
	if snapshot.SnapshotID < 0 || snapshot.TimestampMS <= 0 {
		return invalid("Invalid snapshot ID or timestamp")
	}
	if _, exists := findSnapshot(*metadata, snapshot.SnapshotID); exists {
		return invalid("Snapshot ID %d already exists", snapshot.SnapshotID)
	}
	if snapshot.ManifestList == "" && (metadata.FormatVersion > 1 || snapshot.Manifests == nil) {
		return invalid("Snapshot requires manifest-list")
	}
	if metadata.FormatVersion > 1 {
		if snapshot.SequenceNumber < 0 || (snapshot.ParentSnapshotID != nil && snapshot.SequenceNumber <= metadata.LastSequenceNumber) {
			return invalid("Snapshot sequence number must exceed the last sequence number")
		}
		if snapshot.Summary == nil || snapshot.Summary["operation"] == "" {
			return invalid("Snapshot requires summary.operation")
		}
	}
	if snapshot.SchemaID != nil {
		if _, ok := findSchema(*metadata, *snapshot.SchemaID); !ok {
			return invalid("Snapshot schema ID %d does not exist", *snapshot.SchemaID)
		}
	}
	metadata.Snapshots = append(metadata.Snapshots, *snapshot)
	if snapshot.SequenceNumber > metadata.LastSequenceNumber {
		metadata.LastSequenceNumber = snapshot.SequenceNumber
	}
	// Snapshot timestamps are client generated, and identify when a newly
	// written snapshot became current (also used by Java TableMetadata.Builder).
	metadata.LastUpdatedMS = snapshot.TimestampMS
	return nil
}

func setRef(metadata *Metadata, update Update, added map[int64]bool) error {
	if update.RefName == "" || update.SnapshotID == nil {
		return invalid("set-snapshot-ref requires ref-name and snapshot-id")
	}
	if update.Type != "branch" && update.Type != "tag" {
		return invalid("Invalid snapshot reference type %q", update.Type)
	}
	if update.RefName == "main" && update.Type != "branch" {
		return invalid("The main reference must be a branch")
	}
	if update.MaxRefAgeMS != nil && *update.MaxRefAgeMS <= 0 {
		return invalid("max-ref-age-ms must be positive")
	}
	if update.MaxSnapshotAgeMS != nil && *update.MaxSnapshotAgeMS <= 0 {
		return invalid("max-snapshot-age-ms must be positive")
	}
	if update.MinSnapshotsToKeep != nil && *update.MinSnapshotsToKeep <= 0 {
		return invalid("min-snapshots-to-keep must be positive")
	}
	if update.Type == "tag" && (update.MaxSnapshotAgeMS != nil || update.MinSnapshotsToKeep != nil) {
		return invalid("Tags cannot set branch retention properties")
	}
	snapshot, exists := findSnapshot(*metadata, *update.SnapshotID)
	if !exists {
		return invalid("Unknown referenced snapshot %d", *update.SnapshotID)
	}
	ref := SnapshotRef{SnapshotID: *update.SnapshotID, Type: update.Type, MaxRefAgeMS: update.MaxRefAgeMS, MaxSnapshotAgeMS: update.MaxSnapshotAgeMS, MinSnapshotsToKeep: update.MinSnapshotsToKeep}
	old, existed := metadata.Refs[update.RefName]
	if existed && sameValue(old, ref) {
		return nil
	}
	metadata.Refs[update.RefName] = ref
	if added[ref.SnapshotID] {
		metadata.LastUpdatedMS = snapshot.TimestampMS
	}
	if update.RefName == "main" {
		id := ref.SnapshotID
		metadata.CurrentSnapshotID = &id
		metadata.SnapshotLog = append(metadata.SnapshotLog, SnapshotLogEntry{SnapshotID: id, TimestampMS: metadata.LastUpdatedMS})
	}
	return nil
}

func removeRef(metadata *Metadata, name string) {
	delete(metadata.Refs, name)
	if name == "main" {
		metadata.CurrentSnapshotID = nil
		metadata.SnapshotLog = []SnapshotLogEntry{}
	}
}

func removeSnapshots(metadata *Metadata, ids []int64) {
	removed := make(map[int64]bool, len(ids))
	for _, id := range ids {
		removed[id] = true
	}
	metadata.Snapshots = slices.DeleteFunc(metadata.Snapshots, func(snapshot Snapshot) bool { return removed[snapshot.SnapshotID] })
	for name, ref := range metadata.Refs {
		if removed[ref.SnapshotID] {
			removeRef(metadata, name)
		}
	}
	metadata.Statistics = slices.DeleteFunc(metadata.Statistics, func(stats StatisticsFile) bool { return removed[stats.SnapshotID] })
	metadata.PartitionStatistics = slices.DeleteFunc(metadata.PartitionStatistics, func(stats PartitionStatisticsFile) bool { return removed[stats.SnapshotID] })
	// Retain only the continuous history after the last expired log entry.
	start := 0
	for i, entry := range metadata.SnapshotLog {
		if removed[entry.SnapshotID] {
			start = i + 1
		}
	}
	metadata.SnapshotLog = metadata.SnapshotLog[start:]
}

func applyStatistics(metadata *Metadata, update Update) error {
	switch update.Action {
	case "set-statistics":
		stats := update.Statistics
		if stats == nil {
			return invalid("set-statistics requires statistics")
		}
		// Current clients omit the deprecated top-level snapshot-id.
		if update.SnapshotID != nil && *update.SnapshotID != stats.SnapshotID {
			return invalid("Statistics snapshot IDs do not match")
		}
		if _, exists := findSnapshot(*metadata, stats.SnapshotID); !exists {
			return invalid("Unknown statistics snapshot %d", stats.SnapshotID)
		}
		if stats.StatisticsPath == "" || stats.FileSizeInBytes < 0 || stats.FileFooterSizeInBytes < 0 || stats.FileFooterSizeInBytes > stats.FileSizeInBytes || stats.BlobMetadata == nil {
			return invalid("Invalid statistics file")
		}
		metadata.Statistics = slices.DeleteFunc(metadata.Statistics, func(old StatisticsFile) bool { return old.SnapshotID == stats.SnapshotID })
		metadata.Statistics = append(metadata.Statistics, *stats)
	case "set-partition-statistics":
		stats := update.PartitionStatistics
		if stats == nil {
			return invalid("set-partition-statistics requires partition-statistics")
		}
		if _, exists := findSnapshot(*metadata, stats.SnapshotID); !exists {
			return invalid("Unknown partition statistics snapshot %d", stats.SnapshotID)
		}
		if stats.StatisticsPath == "" || stats.FileSizeInBytes < 0 {
			return invalid("Invalid partition statistics file")
		}
		metadata.PartitionStatistics = slices.DeleteFunc(metadata.PartitionStatistics, func(old PartitionStatisticsFile) bool { return old.SnapshotID == stats.SnapshotID })
		metadata.PartitionStatistics = append(metadata.PartitionStatistics, *stats)
	case "remove-statistics":
		if update.SnapshotID == nil {
			return invalid("remove-statistics requires snapshot-id")
		}
		metadata.Statistics = slices.DeleteFunc(metadata.Statistics, func(old StatisticsFile) bool { return old.SnapshotID == *update.SnapshotID })
	case "remove-partition-statistics":
		if update.SnapshotID == nil {
			return invalid("remove-partition-statistics requires snapshot-id")
		}
		metadata.PartitionStatistics = slices.DeleteFunc(metadata.PartitionStatistics, func(old PartitionStatisticsFile) bool { return old.SnapshotID == *update.SnapshotID })
	}
	return nil
}

func validateMetadata(metadata Metadata) error {
	if metadata.FormatVersion != 1 && metadata.FormatVersion != 2 {
		return unsupported("Unsupported format-version %d", metadata.FormatVersion)
	}
	if metadata.FormatVersion == 2 && !validUUID(metadata.UUID) {
		return invalid("A version 2 table requires a valid table UUID")
	}
	if metadata.Location == "" {
		return invalid("Table location is required")
	}
	if _, exists := findSchema(metadata, metadata.CurrentSchemaID); !exists {
		return invalid("Current schema does not exist")
	}
	foundSpec, foundOrder := false, false
	for _, spec := range metadata.PartitionSpecs {
		if spec.SpecID == metadata.DefaultSpecID {
			foundSpec = true
		}
	}
	for _, order := range metadata.SortOrders {
		if order.OrderID == metadata.DefaultSortOrderID {
			foundOrder = true
		}
	}
	if !foundSpec || !foundOrder {
		return invalid("Default partition spec and sort order must exist")
	}
	if metadata.CurrentSnapshotID != nil && *metadata.CurrentSnapshotID != -1 {
		ref, exists := metadata.Refs["main"]
		if !exists || ref.SnapshotID != *metadata.CurrentSnapshotID || ref.Type != "branch" {
			return invalid("Current snapshot and main reference must agree")
		}
	}
	for name, ref := range metadata.Refs {
		if _, exists := findSnapshot(metadata, ref.SnapshotID); !exists {
			return invalid("Reference %s points to an unknown snapshot", name)
		}
	}
	return nil
}
