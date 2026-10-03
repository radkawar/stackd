package glue

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/parquet-go/parquet-go"
	api "stackd/internal/awsapi/glue"
)

func classifierColumnTypes(columns api.ColumnList) map[string]string {
	out := map[string]string{}
	for _, column := range columns {
		out[value(column.Name)] = value(column.Type)
	}
	return out
}
func TestClassifierReadsNestedJSONAndCustomCSV(t *testing.T) {
	jsonClassifier := ClassifierRecord{Classifier: api.Classifier{JsonClassifier: &api.JsonClassifier{JsonPath: new(api.JsonPath("$.records[*]"))}}}
	schema, err := classifyCrawlerObject([]byte(`{"ignored":"not a table column","records":[{"id":1,"info":{"name":"a"},"values":[1,2]},{"id":2,"info":{"active":true},"values":[3.5]}]}`), []ClassifierRecord{jsonClassifier})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"id": "bigint", "info": "struct<active:boolean,name:string>", "values": "array<double>"}
	if got := classifierColumnTypes(schema.Columns); !reflect.DeepEqual(got, want) {
		t.Fatalf("nested JSON schema=%v, want %v", got, want)
	}
	csvClassifier := ClassifierRecord{Classifier: api.Classifier{CsvClassifier: &api.CsvClassifier{Delimiter: new(api.CsvColumnDelimiter("|")), ContainsHeader: new(api.CsvHeaderOptionPRESENT), Header: api.CsvHeader{"category", "amount"}}}}
	schema, err = classifyCrawlerObject([]byte("label|value\n\"a|b\"|7\nblue|9.5\n"), []ClassifierRecord{csvClassifier})
	if err != nil {
		t.Fatal(err)
	}
	if got := classifierColumnTypes(schema.Columns); !reflect.DeepEqual(got, map[string]string{"category": "string", "amount": "double"}) || schema.Parameters["skip.header.line.count"] != "1" || schema.SerdeParameters["field.delim"] != "|" {
		t.Fatalf("custom CSV schema=%+v", schema)
	}
}
func TestParquetClassifierUsesRealLogicalSchema(t *testing.T) {
	type record struct {
		ID       int64             `parquet:"id"`
		Category string            `parquet:"category"`
		Scores   []int32           `parquet:"scores,list"`
		Labels   map[string]string `parquet:"labels"`
	}
	var data bytes.Buffer
	if err := parquet.Write(&data, []record{{ID: 7, Category: "actual", Scores: []int32{1, 2}, Labels: map[string]string{"region": "east"}}}); err != nil {
		t.Fatal(err)
	}
	schema, err := classifyCrawlerObject(data.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"id": "bigint", "category": "string", "scores": "array<int>", "labels": "map<string,string>"}
	if got := classifierColumnTypes(schema.Columns); !reflect.DeepEqual(got, want) {
		t.Fatalf("Parquet schema=%v, want %v", got, want)
	}
	if schema.Classification != "parquet" || schema.Serde != "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe" {
		t.Fatalf("Parquet catalog consumer descriptor=%+v", schema)
	}
}
func TestPostgresMetadataUsesNativeSchemaAndExclusions(t *testing.T) {
	// The CSV is the native psql --csv metadata output from the owned postgres:16
	// smoke, including duplicate COALESCE header names and PostgreSQL array UDT.
	data := []byte("table_schema,table_name,column_name,data_type,udt_name,coalesce,coalesce,ordinal_position\nsource,excluded,secret,bytea,bytea,,,1\nsource,sales,id,bigint,int8,64,0,1\nsource,sales,category,text,text,,,2\nsource,sales,amount,numeric,numeric,12,2,3\nsource,sales,happened_on,date,date,,,4\nsource,sales,labels,ARRAY,_text,,,5\n")
	tables, err := postgresCrawlerTables(data, "crawler_smoke", api.JdbcTarget{Path: new(api.Path("crawler_smoke/source/%")), ConnectionName: new(api.ConnectionName("postgres")), Exclusions: api.PathList{"source/excluded"}}, "raw_", "crawler", "jdbc:postgresql://127.0.0.1:5432/crawler_smoke")
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 1 || value(tables[0].Table.Name) != "raw_crawler_smoke_source_sales" {
		t.Fatalf("wrong native table selection: %+v", tables)
	}
	want := map[string]string{"id": "bigint", "category": "string", "amount": "decimal(12,2)", "happened_on": "date", "labels": "array<string>"}
	if got := classifierColumnTypes(tables[0].Table.StorageDescriptor.Columns); !reflect.DeepEqual(got, want) {
		t.Fatalf("native column mapping=%v, want %v", got, want)
	}
}
