package athena

import "testing"

func TestStatementClassDistinguishesCTASFromDDLText(t *testing.T) {
	cases := []struct{ name, sql, want string }{
		{"commented query", "-- a queued read\n/* outer /* nested */ comment */ select 1", "DML"},
		{"CTAS properties", "CREATE TABLE sales_copy WITH (format = 'PARQUET') AS SELECT * FROM sales", "DML"},
		{"quoted AS name", "CREATE TABLE \"AS\" (value varchar)", "DDL"},
		{"AS in column expression", "CREATE TABLE typed (value varchar DEFAULT CAST(1 AS varchar))", "DDL"},
		{"AS in metadata", "CREATE EXTERNAL TABLE typed (value string COMMENT 'AS SELECT') LOCATION 's3://bucket/AS' TBLPROPERTIES ('note'='AS')", "DDL"},
		{"AS in comment", "CREATE TABLE typed (value varchar) /* AS SELECT * FROM sales */", "DDL"},
		{"escaped quote", "CREATE TABLE typed (value varchar COMMENT 'quoted ''AS'' identifier')", "DDL"},
		{"view is not CTAS", "CREATE OR REPLACE VIEW sales_view AS SELECT * FROM sales", "DDL"},
		{"utility query", "EXPLAIN SELECT * FROM sales", "UTILITY"},
		{"unknown syntax", "this_is_not_sql", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokens := statementTokens{sql: tc.sql}
			first, _ := tokens.next()
			if got := statementClass(first, &tokens); got != tc.want {
				t.Fatalf("statement class = %q, want %q", got, tc.want)
			}
		})
	}
}
