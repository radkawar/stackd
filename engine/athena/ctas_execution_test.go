package athena

import (
	"strings"
	"testing"
)

func TestCTASRegisteredTargetCatalog(t *testing.T) {
	request := ctasTestRequest()
	request.Catalogs = []CatalogRegistration{
		{Name: "awsdatacatalog", CatalogID: request.AccountID, Kind: "GLUE"},
		{Name: "reports", CatalogID: "other-account", Kind: "GLUE"},
		{Name: "iceberg", CatalogID: "collision-account", Kind: "GLUE"},
	}
	plan := ctasTestPlan(
		ctasProperty{"table_type", ctasTestString("ICEBERG")},
		ctasProperty{"is_external", ctasValue{Kind: "boolean"}},
		ctasProperty{"location", ctasTestString("s3://reports/ctas/")},
	)
	plan.Identifier = []string{"reports", "analytics", "result"}
	sql, session, err := ctasDDL(plan, request)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := icebergCatalogFor(request, "reports")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, quoteSQLIdentifier(alias)+`."analytics"."result"`) || session != alias+".compression_codec=ZSTD" {
		t.Fatalf("registered target mismatch: sql=%s session=%s", sql, session)
	}
	plan.Identifier[0] = "unauthorized"
	if _, _, err := ctasDDL(plan, request); err == nil {
		t.Fatal("unregistered CTAS target was accepted")
	}
}
