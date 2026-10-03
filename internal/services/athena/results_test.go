package athena

import (
	"reflect"
	"testing"

	api "stackd/internal/awsapi/athena"
)

func datumStrings(rows api.RowList) [][]*string {
	out := make([][]*string, len(rows))
	for i, row := range rows {
		out[i] = make([]*string, len(row.Data))
		for j, datum := range row.Data {
			if datum.VarCharValue != nil {
				v := string(*datum.VarCharValue)
				out[i][j] = &v
			}
		}
	}
	return out
}

func TestResultCSVPreservesSQLValuesAcrossPages(t *testing.T) {
	data := []byte("\"nullable\",\"empty\",\"message\"\r\n,\"\",\"comma, quote \"\" and\nnewline\"\r\n\"last\",,\"value\"\r\n")
	first, more, err := resultRows(data, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]*string{{new("nullable"), new("empty"), new("message")}, {nil, new(""), new("comma, quote \" and\nnewline")}}
	if !more || !reflect.DeepEqual(datumStrings(first), want) {
		t.Fatalf("first page = %#v, more %v; want %#v", datumStrings(first), more, want)
	}
	second, more, err := resultRows(data, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	want = [][]*string{{new("last"), nil, new("value")}}
	if more || !reflect.DeepEqual(datumStrings(second), want) {
		t.Fatalf("second page = %#v, more %v; want %#v", datumStrings(second), more, want)
	}
}

func TestResultCSVPreservesSingleColumnNullRows(t *testing.T) {
	rows, more, err := resultRows([]byte("\"v\"\n\n\"\"\n\n"), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]*string{{new("v")}, {nil}, {new("")}, {nil}}
	if more || !reflect.DeepEqual(datumStrings(rows), want) {
		t.Fatalf("rows = %#v, more %v; want %#v", datumStrings(rows), more, want)
	}
}

func TestResultCSVRejectsTruncatedAndMalformedObjects(t *testing.T) {
	for _, data := range []string{"\"unterminated", "\"closed\"garbage\n", "unquoted\"quote\n", "one\rtwo"} {
		t.Run(data, func(t *testing.T) {
			if _, _, err := resultRows([]byte(data), 0, 10); err == nil {
				t.Fatalf("malformed S3 result accepted: %q", data)
			}
		})
	}
	if _, _, err := resultRows([]byte("\"v\"\n"), 2, 10); err == nil {
		t.Fatal("out-of-range result cursor accepted")
	}
}
