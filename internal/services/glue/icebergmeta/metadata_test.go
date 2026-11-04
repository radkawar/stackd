package icebergmeta

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testTime = time.UnixMilli(1700000000000)

func decodeRequest(t *testing.T, body string) CommitRequest {
	t.Helper()
	var request CommitRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	return request
}

func newTestTable(t *testing.T) Metadata {
	t.Helper()
	metadata, err := New(CreateRequest{Name: "events", Location: "s3://warehouse/db/events", Schema: Schema{Type: "struct", Fields: []Field{{ID: 7, Name: "id", Type: json.RawMessage(`"long"`), Required: true}}}}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func requireStatus(t *testing.T, err error, code int) {
	t.Helper()
	var restError *Error
	if !errors.As(err, &restError) || restError.Code != code {
		t.Fatalf("error = %#v, want REST status %d", err, code)
	}
	if code == 409 && restError.Type != "CommitFailedException" {
		t.Fatalf("conflict type = %s", restError.Type)
	}
}

func appendSnapshot(t *testing.T, metadata Metadata, id, sequence int64, parent *int64) Metadata {
	t.Helper()
	timestamp := testTime.Add(time.Duration(sequence) * time.Second).UnixMilli()
	candidate, err := Apply(metadata, CommitRequest{
		Requirements: []Requirement{{Type: "assert-table-uuid", UUID: metadata.UUID}, {Type: "assert-ref-snapshot-id", Ref: "main", SnapshotID: parent}},
		Updates: []Update{
			{Action: "add-snapshot", Snapshot: &Snapshot{SnapshotID: id, ParentSnapshotID: parent, SequenceNumber: sequence, TimestampMS: timestamp, ManifestList: "s3://warehouse/manifest.avro", Summary: map[string]string{"operation": "append"}, SchemaID: new(metadata.CurrentSchemaID)}},
			{Action: "set-snapshot-ref", RefName: "main", Type: "branch", SnapshotID: new(id)},
		},
	}, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestNewFreshIDsAndNestedColumns(t *testing.T) {
	var request CreateRequest
	if err := json.Unmarshal([]byte(`{
		"name":"events", "location":"s3://warehouse/db/events/", "schema":{
			"type":"struct", "schema-id":42, "identifier-field-ids":[10], "fields":[
				{"id":10,"name":"id","required":true,"type":"long","doc":"primary key"},
				{"id":20,"name":"payload","required":false,"type":{"type":"struct","fields":[
					{"id":30,"name":"labels","required":false,"type":{"type":"list","element-id":40,"element-required":false,"element":"string"}},
					{"id":50,"name":"attributes","required":false,"type":{"type":"map","key-id":60,"key":"string","value-id":70,"value":"decimal(10,2)","value-required":false}}
				]}}
			]}, "partition-spec":{"spec-id":7,"fields":[{"source-id":10,"field-id":2000,"name":"id_bucket","transform":"bucket[16]"}]},
		"write-order":{"order-id":19,"fields":[{"source-id":10,"transform":"identity","direction":"desc","null-order":"nulls-last"}]},
		"properties":{"format-version":"2","owner":"reader"}
	}`), &request); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(request)
	metadata, err := New(request, testTime)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(request)
	if string(before) != string(after) {
		t.Fatal("New mutated request")
	}
	if metadata.FormatVersion != 2 || !validUUID(metadata.UUID) || metadata.LastColumnID != 7 || metadata.LastPartitionID != 1000 || metadata.CurrentSchemaID != 0 {
		t.Fatalf("bad new metadata: %+v", metadata)
	}
	if metadata.Location != "s3://warehouse/db/events" || metadata.LastUpdatedMS != testTime.UnixMilli() {
		t.Fatalf("bad location/time: %+v", metadata)
	}
	if got := metadata.PartitionSpecs[0].Fields[0]; got.SourceID != 1 || got.FieldID != 1000 {
		t.Fatalf("partition not remapped: %+v", got)
	}
	if metadata.SortOrders[0].OrderID != 1 || metadata.SortOrders[0].Fields[0].SourceID != 1 {
		t.Fatal("sort order not remapped")
	}
	if !reflect.DeepEqual(metadata.Schemas[0].IdentifierFieldIDs, []int{1}) {
		t.Fatal("identifier field not remapped")
	}
	if _, exists := metadata.Properties["format-version"]; exists {
		t.Fatal("reserved format property persisted")
	}
	columns, err := Columns(metadata)
	if err != nil {
		t.Fatal(err)
	}
	want := []Column{{Name: "id", Type: "bigint", Comment: "primary key"}, {Name: "payload", Type: "struct<labels:array<string>,attributes:map<string,decimal(10,2)>>"}}
	if !reflect.DeepEqual(columns, want) {
		t.Fatalf("columns = %#v, want %#v", columns, want)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"format-version", "table-uuid", "location", "last-sequence-number", "last-updated-ms", "last-column-id", "schemas", "current-schema-id", "partition-specs", "default-spec-id", "last-partition-id", "sort-orders", "default-sort-order-id", "snapshots", "snapshot-log", "metadata-log", "refs"} {
		value, exists := fields[key]
		if !exists || string(value) == "null" {
			t.Errorf("required metadata field %s absent/null", key)
		}
	}
}

func TestNewVersionOneAndLegacyRoundtrip(t *testing.T) {
	metadata, err := New(CreateRequest{Name: "v1", Location: "s3://warehouse/v1", Schema: Schema{Type: "struct", Fields: []Field{}}, Properties: map[string]string{"format-version": "1"}}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["schema"]; !exists {
		t.Fatal("v1 schema missing")
	}
	if string(fields["partition-spec"]) != "[]" {
		t.Fatalf("v1 partition spec = %s", fields["partition-spec"])
	}
	if _, exists := fields["last-sequence-number"]; exists {
		t.Fatal("v1 sequence number should not be written")
	}
	legacy := `{"format-version":1,"location":"s3://warehouse/legacy","last-updated-ms":1700000000000,"last-column-id":1,"schema":{"type":"struct","fields":[{"id":1,"name":"id","required":true,"type":"long"}]},"partition-spec":[{"source-id":1,"name":"id","transform":"identity"}],"current-snapshot-id":123,"snapshots":[{"snapshot-id":123,"timestamp-ms":1700000000000,"manifests":["s3://warehouse/manifest.avro"]}],"future-option":{"enabled":true}}`
	if err := json.Unmarshal([]byte(legacy), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Schemas) != 1 || metadata.PartitionSpecs[0].Fields[0].FieldID != 1000 || metadata.LastPartitionID != 1000 || metadata.Refs["main"].SnapshotID != 123 {
		t.Fatalf("v1 normalization failed: %+v", metadata)
	}
	candidate, err := Apply(metadata, decodeRequest(t, `{"updates":[{"action":"assign-uuid","uuid":"11aa22bb-33cc-44dd-88ee-000000000001"},{"action":"upgrade-format-version","format-version":2}]}`), testTime)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	fields = nil
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["future-option"]; !exists {
		t.Fatal("unknown metadata field lost")
	}
	if _, exists := fields["schema"]; exists {
		t.Fatal("legacy schema retained after upgrade")
	}
	if !strings.Contains(string(data), `"sequence-number":0`) {
		t.Fatal("upgraded v1 snapshot must retain sequence number 0")
	}
}

func TestApplyAppendRequirementsAndIsolation(t *testing.T) {
	base := newTestTable(t)
	before, _ := json.Marshal(base)
	candidate := appendSnapshot(t, base, 9007199254740992, 1, nil)
	if candidate.LastSequenceNumber != 1 || *candidate.CurrentSnapshotID != 9007199254740992 || len(candidate.SnapshotLog) != 1 || candidate.SnapshotLog[0].TimestampMS != testTime.Add(time.Second).UnixMilli() {
		t.Fatalf("bad first append: %+v", candidate)
	}
	after, _ := json.Marshal(base)
	if string(before) != string(after) {
		t.Fatal("Apply mutated base")
	}
	second := appendSnapshot(t, candidate, 9007199254740993, 2, candidate.CurrentSnapshotID)
	if *second.CurrentSnapshotID != 9007199254740993 || second.Refs["main"].SnapshotID != 9007199254740993 || len(second.SnapshotLog) != 2 || second.LastSequenceNumber != 2 {
		t.Fatalf("bad second append: %+v", second)
	}
	_, err := Apply(second, CommitRequest{Requirements: []Requirement{{Type: "assert-ref-snapshot-id", Ref: "main", SnapshotID: candidate.CurrentSnapshotID}}}, testTime)
	requireStatus(t, err, 409)
	_, err = Apply(second, CommitRequest{Updates: []Update{{Action: "set-properties", Updates: map[string]string{"must-not-leak": "true"}}, {Action: "unknown-update"}}}, testTime)
	requireStatus(t, err, 422)
	if _, exists := second.Properties["must-not-leak"]; exists {
		t.Fatal("failed commit mutated properties")
	}
}

func TestAllRequirements(t *testing.T) {
	base := appendSnapshot(t, newTestTable(t), 10, 1, nil)
	tests := []struct{ name, valid, stale string }{
		{"uuid", `{"type":"assert-table-uuid","uuid":"` + strings.ToUpper(base.UUID) + `"}`, `{"type":"assert-table-uuid","uuid":"00000000-0000-0000-0000-000000000000"}`},
		{"ref", `{"type":"assert-ref-snapshot-id","ref":"main","snapshot-id":10}`, `{"type":"assert-ref-snapshot-id","ref":"main","snapshot-id":11}`},
		{"field", `{"type":"assert-last-assigned-field-id","last-assigned-field-id":1}`, `{"type":"assert-last-assigned-field-id","last-assigned-field-id":2}`},
		{"schema", `{"type":"assert-current-schema-id","current-schema-id":0}`, `{"type":"assert-current-schema-id","current-schema-id":1}`},
		{"partition", `{"type":"assert-last-assigned-partition-id","last-assigned-partition-id":999}`, `{"type":"assert-last-assigned-partition-id","last-assigned-partition-id":1000}`},
		{"spec", `{"type":"assert-default-spec-id","default-spec-id":0}`, `{"type":"assert-default-spec-id","default-spec-id":1}`},
		{"order", `{"type":"assert-default-sort-order-id","default-sort-order-id":0}`, `{"type":"assert-default-sort-order-id","default-sort-order-id":1}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var valid, stale Requirement
			if err := json.Unmarshal([]byte(test.valid), &valid); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(test.stale), &stale); err != nil {
				t.Fatal(err)
			}
			if err := ValidateRequirements(&base, []Requirement{valid}); err != nil {
				t.Fatal(err)
			}
			requireStatus(t, ValidateRequirements(&base, []Requirement{stale}), 409)
		})
	}
	if err := ValidateRequirements(nil, []Requirement{{Type: "assert-create"}}); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, ValidateRequirements(&base, []Requirement{{Type: "assert-create"}}), 409)
	for _, body := range []string{`{"type":"assert-ref-snapshot-id","ref":"new","snapshot-id":null}`, `{"type":"assert-ref-snapshot-id","ref":"new"}`} {
		var requirement Requirement
		if err := json.Unmarshal([]byte(body), &requirement); err != nil {
			t.Fatal(err)
		}
		if err := ValidateRequirements(&base, []Requirement{requirement}); err != nil {
			t.Fatal(err)
		}
		requirement.Ref = "main"
		requireStatus(t, ValidateRequirements(&base, []Requirement{requirement}), 409)
	}
	requireStatus(t, ValidateRequirements(&base, []Requirement{{Type: "assert-current-schema-id"}}), 400)
	requireStatus(t, ValidateRequirements(&base, []Requirement{{Type: "assert-unknown"}}), 422)
	requireStatus(t, ValidateRequirements(&base, []Requirement{{Type: "assert-ref-snapshot-id", Ref: "missing", SnapshotID: new(int64(1))}}), 409)
}

func TestApplySchemaPartitionSortEvolution(t *testing.T) {
	base := newTestTable(t)
	request := decodeRequest(t, `{"requirements":[{"type":"assert-last-assigned-field-id","last-assigned-field-id":1}],"updates":[
		{"action":"add-schema","schema":{"type":"struct","schema-id":0,"fields":[{"id":1,"name":"id","required":true,"type":"long"},{"id":2,"name":"message","required":false,"type":"string"}]}},
		{"action":"set-current-schema","schema-id":-1},
		{"action":"add-spec","spec":{"fields":[{"source-id":2,"name":"message_bucket","transform":"bucket[8]"}]}},
		{"action":"set-default-spec","spec-id":-1},
		{"action":"add-sort-order","sort-order":{"order-id":0,"fields":[{"source-id":2,"transform":"identity","direction":"asc","null-order":"nulls-first"}]}},
		{"action":"set-default-sort-order","sort-order-id":-1},
		{"action":"set-location","location":"s3://new-warehouse/events/"},
		{"action":"set-properties","updates":{"owner":"writer","temporary":"delete"}},
		{"action":"remove-properties","removals":["temporary"]}
	]}`)
	candidate, err := Apply(base, request, testTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if candidate.CurrentSchemaID != 1 || candidate.LastColumnID != 2 || candidate.DefaultSpecID != 1 || candidate.LastPartitionID != 1000 || candidate.DefaultSortOrderID != 1 {
		t.Fatalf("bad evolved IDs: %+v", candidate)
	}
	if candidate.Location != "s3://new-warehouse/events" || candidate.Properties["owner"] != "writer" {
		t.Fatal("location/property update missing")
	}
	if _, exists := candidate.Properties["temporary"]; exists {
		t.Fatal("property not removed")
	}
	if len(base.Schemas) != 1 || base.LastColumnID != 1 || len(base.PartitionSpecs) != 1 {
		t.Fatal("evolution mutated base")
	}
	// Re-adding equivalent definitions must reuse IDs, including a schema whose
	// requested schema-id is not the server-assigned ID.
	reused, err := Apply(candidate, requestWithoutRequirements(request), testTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(reused.Schemas) != 2 || len(reused.PartitionSpecs) != 2 || len(reused.SortOrders) != 2 {
		t.Fatal("equivalent metadata definitions were duplicated")
	}
}

func requestWithoutRequirements(request CommitRequest) CommitRequest {
	request.Requirements = nil
	return request
}

func TestApplyUUIDAssignmentAndVersion(t *testing.T) {
	base := newTestTable(t)
	chosen := "11aa22bb-33cc-44dd-88ee-000000000001"
	candidate, err := Apply(base, CommitRequest{Updates: []Update{{Action: "assign-uuid", UUID: chosen}}}, testTime)
	if err != nil || candidate.UUID != chosen {
		t.Fatalf("post-create UUID assignment failed: %v", err)
	}
	candidate = appendSnapshot(t, candidate, 1, 1, nil)
	_, err = Apply(candidate, CommitRequest{Updates: []Update{{Action: "assign-uuid", UUID: base.UUID}}}, testTime)
	requireStatus(t, err, 400)
	_, err = Apply(candidate, CommitRequest{Updates: []Update{{Action: "upgrade-format-version", FormatVersion: new(1)}}}, testTime)
	requireStatus(t, err, 400)
	_, err = Apply(candidate, CommitRequest{Updates: []Update{{Action: "upgrade-format-version", FormatVersion: new(3)}}}, testTime)
	requireStatus(t, err, 422)
}

func TestSnapshotRemovalRefsAndStatistics(t *testing.T) {
	base := appendSnapshot(t, newTestTable(t), 10, 1, nil)
	base = appendSnapshot(t, base, 20, 2, new(int64(10)))
	base = appendSnapshot(t, base, 30, 3, new(int64(20)))
	request := decodeRequest(t, `{"updates":[
		{"action":"set-snapshot-ref","ref-name":"release","type":"tag","snapshot-id":20,"max-ref-age-ms":1000},
		{"action":"set-statistics","statistics":{"snapshot-id":20,"statistics-path":"s3://warehouse/stats.puffin","file-size-in-bytes":100,"file-footer-size-in-bytes":20,"blob-metadata":[]}},
		{"action":"set-partition-statistics","partition-statistics":{"snapshot-id":20,"statistics-path":"s3://warehouse/stats.parquet","file-size-in-bytes":100}}
	]}`)
	withStats, err := Apply(base, request, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(withStats.Statistics) != 1 || len(withStats.PartitionStatistics) != 1 {
		t.Fatal("statistics not retained")
	}
	candidate, err := Apply(withStats, decodeRequest(t, `{"updates":[{"action":"remove-snapshots","snapshot-ids":[20]}]}`), testTime.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Snapshots) != 2 || len(candidate.SnapshotLog) != 1 || candidate.SnapshotLog[0].SnapshotID != 30 || len(candidate.Statistics) != 0 || len(candidate.PartitionStatistics) != 0 {
		t.Fatalf("expiration failed: %+v", candidate)
	}
	if _, exists := candidate.Refs["release"]; exists {
		t.Fatal("dangling tag retained")
	}
	candidate, err = Apply(candidate, decodeRequest(t, `{"updates":[{"action":"remove-snapshot-ref","ref-name":"main"}]}`), testTime.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if candidate.CurrentSnapshotID != nil || len(candidate.SnapshotLog) != 0 {
		t.Fatal("removing main did not clear current snapshot")
	}
	if len(base.SnapshotLog) != 3 || len(withStats.Statistics) != 1 {
		t.Fatal("expiration mutated prior metadata")
	}
	// Statistics updates may be replaced and explicitly removed without
	// changing the current snapshot or sequence number.
	candidate, err = Apply(withStats, decodeRequest(t, `{"updates":[{"action":"remove-statistics","snapshot-id":20},{"action":"remove-partition-statistics","snapshot-id":20}]}`), testTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Statistics) != 0 || len(candidate.PartitionStatistics) != 0 || candidate.LastSequenceNumber != 3 {
		t.Fatal("statistics removal changed snapshot state")
	}
}

func TestIntermediateSnapshotsNotInPublicHistory(t *testing.T) {
	base := newTestTable(t)
	request := decodeRequest(t, `{"updates":[
		{"action":"add-snapshot","snapshot":{"snapshot-id":10,"sequence-number":1,"timestamp-ms":1700000001000,"manifest-list":"s3://warehouse/one.avro","summary":{"operation":"append"}}},
		{"action":"set-snapshot-ref","ref-name":"main","type":"branch","snapshot-id":10},
		{"action":"add-snapshot","snapshot":{"snapshot-id":20,"parent-snapshot-id":10,"sequence-number":2,"timestamp-ms":1700000002000,"manifest-list":"s3://warehouse/two.avro","summary":{"operation":"append"}}},
		{"action":"set-snapshot-ref","ref-name":"main","type":"branch","snapshot-id":20}
	]}`)
	candidate, err := Apply(base, request, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Snapshots) != 2 || len(candidate.SnapshotLog) != 1 || candidate.SnapshotLog[0].SnapshotID != 20 || candidate.LastSequenceNumber != 2 {
		t.Fatalf("intermediate snapshots leaked into history: %+v", candidate)
	}
}

func TestUnknownMetadataRoundtrip(t *testing.T) {
	base := appendSnapshot(t, newTestTable(t), 10, 1, nil)
	base.Extra = map[string]json.RawMessage{"vendor-extension": json.RawMessage(`{"nested":[1,true,"ok"]}`)}
	base.Snapshots[0].Extra = map[string]json.RawMessage{"vendor-snapshot": json.RawMessage(`"retained"`)}
	base.MetadataLog = []MetadataLogEntry{{TimestampMS: testTime.UnixMilli(), MetadataFile: "s3://warehouse/previous.json"}}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Metadata
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	candidate, err := Apply(loaded, decodeRequest(t, `{"updates":[{"action":"set-properties","updates":{"updated":"true"}}]}`), testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if string(candidate.Extra["vendor-extension"]) != `{"nested":[1,true,"ok"]}` || string(candidate.Snapshots[0].Extra["vendor-snapshot"]) != `"retained"` || !reflect.DeepEqual(candidate.MetadataLog, base.MetadataLog) {
		t.Fatal("unrelated metadata fields lost")
	}
	// Explicitly null known fields must not be treated as opaque extensions,
	// otherwise removing a reference could accidentally resurrect the old ID.
	var loadedSnapshot Snapshot
	if err := json.Unmarshal([]byte(`{"snapshot-id":11,"timestamp-ms":1700000000000,"parent-snapshot-id":null}`), &loadedSnapshot); err != nil {
		t.Fatal(err)
	}
	if _, exists := loadedSnapshot.Extra["parent-snapshot-id"]; exists {
		t.Fatal("known null field retained as extension")
	}
}

func TestMalformedAndUnsupportedUpdates(t *testing.T) {
	base := newTestTable(t)
	tests := []struct {
		body   string
		status int
	}{
		{`{"updates":[{"action":"unknown"}]}`, 422},
		{`{"updates":[{"action":"set-current-schema","schema-id":-1}]}`, 400},
		{`{"updates":[{"action":"set-default-spec","spec-id":-1}]}`, 400},
		{`{"updates":[{"action":"set-default-sort-order","sort-order-id":-1}]}`, 400},
		{`{"updates":[{"action":"set-current-schema"}]}`, 400},
		{`{"updates":[{"action":"add-schema","last-column-id":0,"schema":{"type":"struct","fields":[{"id":1,"name":"id","type":"long","required":true}]}}]}`, 400},
		{`{"updates":[{"action":"set-properties"}]}`, 400},
		{`{"updates":[{"action":"set-properties","updates":{"format-version":"1"}}]}`, 400},
		{`{"updates":[{"action":"remove-snapshots"}]}`, 400},
		{`{"updates":[{"action":"set-snapshot-ref","ref-name":"main","type":"tag","snapshot-id":10}]}`, 400},
		{`{"updates":[{"action":"add-snapshot","snapshot":{"snapshot-id":10,"timestamp-ms":1700000000000,"sequence-number":1,"manifest-list":"s3://warehouse/one.avro"}}]}`, 400},
	}
	for _, test := range tests {
		t.Run(test.body, func(t *testing.T) {
			_, err := Apply(base, decodeRequest(t, test.body), testTime)
			requireStatus(t, err, test.status)
		})
	}
	base = appendSnapshot(t, base, 10, 1, nil)
	_, err := Apply(base, decodeRequest(t, `{"updates":[{"action":"add-snapshot","snapshot":{"snapshot-id":20,"parent-snapshot-id":10,"sequence-number":1,"timestamp-ms":1700000002000,"manifest-list":"s3://warehouse/two.avro","summary":{"operation":"append"}}}]}`), testTime)
	requireStatus(t, err, 400)
}

func TestCreateTransactionFromUpdates(t *testing.T) {
	request := decodeRequest(t, `{"requirements":[{"type":"assert-create"}],"updates":[
		{"action":"assign-uuid","uuid":"11aa22bb-33cc-44dd-88ee-000000000001"},
		{"action":"upgrade-format-version","format-version":2},
		{"action":"add-schema","schema":{"type":"struct","schema-id":0,"fields":[{"id":1,"name":"id","type":"long","required":true}]}},
		{"action":"set-current-schema","schema-id":-1},
		{"action":"add-spec","spec":{"fields":[]}},
		{"action":"set-default-spec","spec-id":-1},
		{"action":"add-sort-order","sort-order":{"order-id":0,"fields":[]}},
		{"action":"set-default-sort-order","sort-order-id":-1},
		{"action":"set-location","location":"s3://warehouse/new"},
		{"action":"set-properties","updates":{"owner":"writer"}}
	]}`)
	metadata, err := Apply(Metadata{}, request, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.FormatVersion != 2 || metadata.LastColumnID != 1 || metadata.CurrentSchemaID != 0 || metadata.DefaultSpecID != 0 || metadata.DefaultSortOrderID != 0 || metadata.LastPartitionID != 999 || metadata.Location != "s3://warehouse/new" {
		t.Fatalf("bad create transaction: %+v", metadata)
	}
}

func TestPrimitiveHiveColumnTypes(t *testing.T) {
	tests := map[string]string{
		"boolean": "boolean", "int": "int", "long": "bigint", "float": "float", "double": "double",
		"decimal(38, 2)": "decimal(38,2)", "date": "date", "time": "string",
		"timestamp": "timestamp", "timestamptz": "timestamp", "string": "string",
		"uuid": "string", "fixed[16]": "binary", "binary": "binary",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := primitiveHive(input)
			if err != nil || got != want {
				t.Fatalf("Hive type = %q, %v, want %q", got, err, want)
			}
		})
	}
	_, err := primitiveHive("variant")
	requireStatus(t, err, 422)
	_, err = primitiveHive("decimal(39,2)")
	requireStatus(t, err, 400)
}

func TestSchemaExtensionPreservation(t *testing.T) {
	base := newTestTable(t)
	base.Schemas[0].Extra = map[string]json.RawMessage{"vendor-schema": json.RawMessage(`true`)}
	base.Schemas[0].Fields[0].Extra = map[string]json.RawMessage{"vendor-field": json.RawMessage(`{"value":1}`)}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Metadata
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	candidate, err := Apply(loaded, decodeRequest(t, `{"updates":[{"action":"set-properties","updates":{}}]}`), testTime)
	if err != nil {
		t.Fatal(err)
	}
	if string(candidate.Schemas[0].Extra["vendor-schema"]) != "true" || string(candidate.Schemas[0].Fields[0].Extra["vendor-field"]) != `{"value":1}` {
		t.Fatal("schema extension metadata lost")
	}
}

func TestVersionOneAppendAndPartitionEvolution(t *testing.T) {
	base, err := New(CreateRequest{Name: "v1", Location: "s3://warehouse/v1", Schema: Schema{Type: "struct", Fields: []Field{{ID: 10, Name: "id", Type: json.RawMessage(`"long"`), Required: true}}}, Properties: map[string]string{"format-version": "1"}}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	base = appendSnapshot(t, base, 10, 0, nil)
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"sequence-number"`) {
		t.Fatal("v1 snapshot sequence number must not be written")
	}
	candidate, err := Apply(base, decodeRequest(t, `{"updates":[{"action":"add-spec","spec":{"fields":[{"source-id":1,"name":"bucket","transform":"bucket[8]"}]}},{"action":"set-default-spec","spec-id":-1}]}`), testTime)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.LastPartitionID != 1000 || candidate.PartitionSpecs[1].Fields[0].FieldID != 1000 {
		t.Fatal("v1 partition IDs not assigned sequentially")
	}
}

func TestPartitionIDsCannotChangeMeaning(t *testing.T) {
	base := newTestTable(t)
	candidate, err := Apply(base, decodeRequest(t, `{"updates":[{"action":"add-spec","spec":{"fields":[{"source-id":1,"field-id":1000,"name":"bucket","transform":"bucket[8]"}]}},{"action":"set-default-spec","spec-id":-1}]}`), testTime)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(candidate, decodeRequest(t, `{"updates":[{"action":"add-spec","spec":{"fields":[{"source-id":1,"field-id":1000,"name":"bucket","transform":"bucket[16]"}]}}]}`), testTime)
	requireStatus(t, err, 400)
}
