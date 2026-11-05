package athena

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllRegistrationsPreservePublicNamesAndAuthority(t *testing.T) {
	request := Request{AccountID: "123456789012", Region: "us-east-1", Catalog: "lake", CatalogID: "123456789012:research", Catalogs: []CatalogRegistration{
		{Name: "AwsDataCatalog", CatalogID: "123456789012", Kind: "GLUE"},
		{Name: "lake", CatalogID: "123456789012:research", Kind: "GLUE"},
		{Name: "iceberg", CatalogID: "123456789012:s3tablescatalog/warehouse", Kind: "GLUE"},
		{Name: "__stackd_iceberg", CatalogID: "123456789012:alternate", Kind: "GLUE"},
		{Name: "Remote", CatalogID: "123456789012:remote", Kind: "GLUE"},
	}, AuthorizeCatalog: func(context.Context, CatalogRegistration) error { return nil }}
	byName := map[string]queryCatalog{}
	for _, catalog := range queryCatalogs(request, "http://127.0.0.1:1", "capability") {
		if _, exists := byName[catalog.name]; exists {
			t.Fatalf("duplicate native catalog %q", catalog.name)
		}
		byName[catalog.name] = catalog
	}
	for _, registration := range request.Catalogs {
		name := strings.ToLower(registration.Name)
		catalog, exists := byName[name]
		if !exists || catalog.connector != "hive" || catalog.properties["hive.metastore.glue.catalogid"] != registration.CatalogID {
			t.Fatalf("missing public registration %q", name)
		}
		for _, property := range []string{"hive.iceberg-catalog-name", "hive.delta-lake-catalog-name"} {
			redirect := byName[catalog.properties[property]]
			if redirect.properties["hive.metastore.glue.catalogid"] != registration.CatalogID || redirect.properties["s3.endpoint"] != catalog.properties["s3.endpoint"] {
				t.Fatalf("redirect crosses catalog capability: %s", name)
			}
		}
		if !strings.HasSuffix(catalog.properties["s3.endpoint"], "/__stackd_catalog/"+name) {
			t.Fatal("object callback is not registration scoped")
		}
		alias, err := icebergCatalogFor(request, name)
		if err != nil || byName[alias].connector != "iceberg" {
			t.Fatalf("Iceberg target resolution %q: %v", alias, err)
		}
	}
	if _, err := request.CatalogIDFor("not-admitted"); err == nil {
		t.Fatal("arbitrary catalog exposed")
	}
}

func TestCatalogCallbackRechecksAuthorityAndRejectsSubstitution(t *testing.T) {
	revoked := false
	var calls int
	request := Request{Catalogs: []CatalogRegistration{{Name: "lake", CatalogID: "123456789012:warehouse", Kind: "GLUE"}}, AuthorizeCatalog: func(_ context.Context, registration CatalogRegistration) error {
		calls++
		if registration.Name != "lake" {
			t.Fatal("wrong registration")
		}
		if revoked {
			return errors.New("current IAM denied")
		}
		return nil
	}}
	invoke := func(path, target, body string) (*httptest.ResponseRecorder, *http.Request, bool) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("X-Amz-Target", target)
		w := httptest.NewRecorder()
		return w, r, admitCatalogCallback(w, r, request)
	}
	w, r, ok := invoke("http://callback/__stackd_catalog/lake/", "AWSGlue.GetTables", `{"DatabaseName":"analytics"}`)
	if !ok || w.Code != 200 || r.URL.Path != "/" {
		t.Fatalf("valid scoped callback rejected: %d", w.Code)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), `"CatalogId":"123456789012:warehouse"`) {
		t.Fatal("missing catalog id was not pinned")
	}
	for _, test := range []struct{ path, target, body string }{
		{"http://callback/", "AWSGlue.GetTables", `{}`},
		{"http://callback/__stackd_catalog/other/", "AWSGlue.GetTables", `{}`},
		{"http://callback/__stackd_catalog/lake/", "AWSGlue.GetTables", `{"CatalogId":"999999999999"}`},
		{"http://callback/__stackd_catalog/lake/", "AWSGlue.PutResourcePolicy", `{}`},
	} {
		w, _, ok := invoke(test.path, test.target, test.body)
		if ok || w.Code != http.StatusForbidden {
			t.Fatalf("callback escape admitted: %+v", test)
		}
	}
	revoked = true
	for _, target := range []string{"AWSGlue.GetTables", ""} {
		w, _, ok := invoke("http://callback/__stackd_catalog/lake/fixture--table-s3/data/a.parquet", target, `{}`)
		if ok || w.Code != http.StatusForbidden {
			t.Fatalf("IAM revocation bypassed through %q", target)
		}
	}
	if calls < 3 {
		t.Fatal("current authorization was not consulted")
	}
}
