package athena

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func publicCatalogs(request Request) []CatalogRegistration {
	if request.Catalogs != nil {
		return request.Catalogs
	}
	selected := request.CatalogID
	if selected == "" {
		selected = request.AccountID
	}
	rows := []CatalogRegistration{{Name: "awsdatacatalog", CatalogID: request.AccountID, Kind: "GLUE"}}
	if !strings.EqualFold(request.Catalog, "awsdatacatalog") && request.Catalog != "" {
		rows = append(rows, CatalogRegistration{Name: request.Catalog, CatalogID: selected, Kind: "GLUE"})
	}
	return rows
}

// CatalogIDFor resolves only an admitted registration, never an arbitrary account
// or catalog identifier supplied by SQL.
func (request Request) CatalogIDFor(name string) (string, error) {
	for _, catalog := range publicCatalogs(request) {
		if strings.EqualFold(catalog.Name, name) && catalog.Kind == "GLUE" {
			return catalog.CatalogID, nil
		}
	}
	return "", fmt.Errorf("catalog %q is not configured or authorized", name)
}

// IsHiveCatalog distinguishes public Hive connector outputs from private
// Iceberg/Delta redirects when retaining native write manifests.
func (request Request) IsHiveCatalog(name string) bool {
	if name == "" {
		return false
	}
	for _, catalog := range publicCatalogs(request) {
		if strings.EqualFold(name, catalog.Name) && catalog.Kind == "GLUE" {
			return true
		}
	}
	return false
}

type catalogRedirects struct{ iceberg, delta string }

func registrationRedirects(request Request) map[string]catalogRedirects {
	registrations := append([]CatalogRegistration(nil), publicCatalogs(request)...)
	sort.Slice(registrations, func(i, j int) bool {
		return strings.ToLower(registrations[i].Name) < strings.ToLower(registrations[j].Name)
	})
	used := map[string]bool{}
	for _, catalog := range registrations {
		used[strings.ToLower(catalog.Name)] = true
	}
	allocate := func(preferred string) string {
		name := preferred
		for used[name] {
			name = "__stackd_" + name
		}
		used[name] = true
		return name
	}
	result := map[string]catalogRedirects{}
	selected := strings.ToLower(request.Catalog)
	if selected == "" {
		selected = "awsdatacatalog"
	}
	// Preserve the selected catalog's established convenience aliases unless a
	// public registration occupies one. Public names always win collisions.
	selectedID, _ := request.CatalogIDFor(selected)
	if selectedID != "" {
		result[selected] = catalogRedirects{allocate("iceberg"), allocate("deltalake")}
	}
	if selected != "awsdatacatalog" {
		if id, err := request.CatalogIDFor("awsdatacatalog"); err == nil {
			if id == selectedID && selectedID != "" && request.AuthorizeCatalog == nil {
				result["awsdatacatalog"] = result[selected]
			} else {
				result["awsdatacatalog"] = catalogRedirects{allocate("awsdatacatalog_iceberg"), allocate("awsdatacatalog_deltalake")}
			}
		}
	}
	for _, catalog := range registrations {
		name := strings.ToLower(catalog.Name)
		if catalog.Kind != "GLUE" {
			continue
		}
		if _, ok := result[name]; ok {
			continue
		}
		result[name] = catalogRedirects{allocate("__stackd_" + name + "_iceberg"), allocate("__stackd_" + name + "_deltalake")}
	}
	return result
}

func icebergCatalogFor(request Request, publicCatalog string) (string, error) {
	if redirect, ok := registrationRedirects(request)[strings.ToLower(publicCatalog)]; ok {
		return redirect.iceberg, nil
	}
	return "", fmt.Errorf("catalog %q is not configured or authorized", publicCatalog)
}

func catalogEndpoint(request Request, endpoint, name string) string {
	if request.AuthorizeCatalog == nil {
		return endpoint
	}
	return endpoint + "/__stackd_catalog/" + url.PathEscape(strings.ToLower(name))
}
