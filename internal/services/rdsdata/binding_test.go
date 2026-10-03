package rdsdata

import (
	"reflect"
	"strings"
	"testing"

	api "stackd/internal/awsapi/rdsdata"
)

func stringParameter(name, value string) api.SqlParameter {
	return api.SqlParameter{Name: new(api.ParameterName(name)), Value: &api.Field{StringValue: new(api.String(value))}}
}
func TestBindingPreservesSQLLexicalBoundaries(t *testing.T) {
	tests := []struct {
		name, engine, sql, want string
		args                    []any
	}{
		{"postgres quoting", "aurora-postgresql", `SELECT :p::text, ':p', "x:p", $$:p;$$, $body$:p '$body$, E'\\\':p', :p /* :p /* :p */ */ -- :p
`, `SELECT $1::text, ':p', "x:p", $$:p;$$, $body$:p '$body$, E'\\\':p', $1 /* :p /* :p */ */ -- :p
`, []any{"'; DROP TABLE protected; --"}},
		{"mysql quoting", "aurora-mysql", "SELECT :p, ':p', `:p`, \"x:p\", 'a\\':p', :p /* :p */ # :p\n", "SELECT ?, ':p', `:p`, \"x:p\", 'a\\':p', ? /* :p */ # :p\n", []any{"'; DROP TABLE protected; --", "'; DROP TABLE protected; --"}},
		{"terminal comment", "aurora-postgresql", "select :p; /* ; :p */ -- second\n", "select $1; /* ; :p */ -- second\n", []any{"'; DROP TABLE protected; --"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bindSQL(tt.sql, tt.engine, api.SqlParametersList{stringParameter("p", "'; DROP TABLE protected; --")})
			if err != nil {
				t.Fatal(err)
			}
			if got.sql != tt.want || !reflect.DeepEqual(got.args, tt.args) {
				t.Fatalf("SQL/arguments = %q %#v; want %q %#v", got.sql, got.args, tt.want, tt.args)
			}
		})
	}
}
func TestBindingRejectsAmbiguousAndMultipleStatements(t *testing.T) {
	for _, sql := range []string{"select :missing", "select :p; delete from protected", "select :p;;", "select ':p", "select :p /* broken", "select :p, $1", "select :p, $tag$broken"} {
		if _, err := bindSQL(sql, "aurora-postgresql", api.SqlParametersList{stringParameter("p", "safe")}); err == nil {
			t.Errorf("accepted %q", sql)
		}
	}
	for _, sql := range []string{"select :p, ?", "select :p /*! ; DELETE FROM protected */"} {
		if _, err := bindSQL(sql, "aurora-mysql", api.SqlParametersList{stringParameter("p", "safe")}); err == nil {
			t.Errorf("accepted %q", sql)
		}
	}
	if _, err := bindSQL("select :p", "aurora-postgresql", api.SqlParametersList{stringParameter("p", "a"), stringParameter("p", "b")}); err == nil {
		t.Fatal("accepted duplicate parameter names")
	}
}
func TestBindingRoutesReturningAndCTEToNativeRows(t *testing.T) {
	for _, sql := range []string{"(SELECT 1)", "(WITH x AS (SELECT 1) SELECT * FROM x)", "WITH x AS (SELECT 1) VALUES (2)", "WITH x AS (SELECT 1) SELECT * FROM x", "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x RETURNING id", "INSERT INTO t VALUES (1) RETURNING id"} {
		got, err := bindSQL(sql, "aurora-postgresql", nil)
		if err != nil || !got.rows {
			t.Fatalf("row SQL %q: %#v %v", sql, got, err)
		}
	}
	got, err := bindSQL("WITH x AS (SELECT 1) UPDATE t SET id=(SELECT * FROM x)", "aurora-postgresql", nil)
	if err != nil || got.rows || !got.mutation {
		t.Fatalf("update routing: %#v %v", got, err)
	}
}
func TestTypedParameterBoundsAndSafeAnnotations(t *testing.T) {
	p := stringParameter("p", "12345678901234567890.1234567890")
	p.TypeHint = new(api.TypeHintDECIMAL)
	got, err := bindSQL("SELECT :p", "aurora-mysql", api.SqlParametersList{p})
	if err != nil {
		t.Fatal(err)
	}
	if got.sql != "SELECT CAST(? AS decimal(30,10))" || got.args[0] != string(*p.Value.StringValue) {
		t.Fatalf("decimal precision lost: %#v", got)
	}
	p.Value.StringValue = new(api.String("0.1); DROP TABLE t; --"))
	if _, err := bindSQL("SELECT :p", "aurora-mysql", api.SqlParametersList{p}); err == nil {
		t.Fatal("accepted invalid decimal annotation")
	}
	p = api.SqlParameter{Name: new(api.ParameterName("p")), Value: &api.Field{BlobValue: api.Blob{}}}
	got, err = bindSQL("SELECT :p", "aurora-postgresql", api.SqlParametersList{p})
	if err != nil || !strings.Contains(got.sql, "bytea") || got.args[0] == nil {
		t.Fatalf("empty blob lost: %#v %v", got, err)
	}
	p.Value.IsNull = new(api.BoxedBoolean(true))
	if _, err := bindSQL("SELECT :p", "aurora-postgresql", api.SqlParametersList{p}); err == nil {
		t.Fatal("accepted multi-member union")
	}
}
func TestResultNullBlobDecimalAndLongOptions(t *testing.T) {
	for _, v := range []any{"12345678901234567890.1234567890", []byte("12345678901234567890.1234567890")} {
		field, err := resultField(v, "NUMERIC", nil)
		if err != nil || value(field.StringValue) != "12345678901234567890.1234567890" {
			t.Fatalf("decimal precision lost: %#v %v", field, err)
		}
	}
	field, err := resultField(nil, "BYTEA", nil)
	if err != nil || field.IsNull == nil || !*field.IsNull {
		t.Fatalf("null: %#v %v", field, err)
	}
	field, err = resultField([]byte{}, "BYTEA", nil)
	if err != nil || field.BlobValue == nil || field.IsNull != nil {
		t.Fatalf("empty blob became null: %#v %v", field, err)
	}
	field, err = resultField(int64(9223372036854775807), "INT8", &api.ResultSetOptions{LongReturnType: new(api.LongReturnTypeSTRING)})
	if err != nil || value(field.StringValue) != "9223372036854775807" {
		t.Fatalf("long precision lost: %#v %v", field, err)
	}
	options := &api.ResultSetOptions{DecimalReturnType: new(api.DecimalReturnTypeDOUBLE_OR_LONG)}
	field, err = resultField("42", "NUMERIC", options)
	if err != nil || field.LongValue == nil || *field.LongValue != 42 {
		t.Fatalf("integral decimal: %#v %v", field, err)
	}
	field, err = resultField("42.25", "NUMERIC", options)
	if err != nil || field.DoubleValue == nil || *field.DoubleValue != 42.25 {
		t.Fatalf("fractional decimal: %#v %v", field, err)
	}
}
func TestResultArrayNullsAndDimensions(t *testing.T) {
	field, err := resultField("{1,NULL,3}", "_INT4", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := field.ArrayValue.LongValues
	if len(got) != 3 || *got[0] != 1 || got[1] != nil || *got[2] != 3 {
		t.Fatalf("array nulls: %#v", field)
	}
	if _, err := resultField("{{1,2},{3,4}}", "_INT4", nil); err == nil {
		t.Fatal("accepted multidimensional result")
	}
	field, err = resultField("{1.5,NULL,3}", "_NUMERIC", &api.ResultSetOptions{DecimalReturnType: new(api.DecimalReturnTypeDOUBLE_OR_LONG)})
	if err != nil {
		t.Fatal(err)
	}
	numbers := field.ArrayValue.DoubleValues
	if len(numbers) != 3 || numbers[0] == nil || *numbers[0] != 1.5 || numbers[1] != nil || numbers[2] == nil || *numbers[2] != 3 {
		t.Fatalf("decimal array options/nulls: %#v", field)
	}
}
