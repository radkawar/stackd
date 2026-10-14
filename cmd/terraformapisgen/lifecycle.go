package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This inventory records provider registrations and static source evidence. It
// deliberately has no pass state: runnable lifecycle and engine evidence belongs
// to separately retained workflow results, not the API registration generator.
type lifecycleInventory struct {
	Interpretation      string               `json:"interpretation"`
	Totals              lifecycleTotals      `json:"totals"`
	ImplementedServices []implementedService `json:"implemented_services"`
	Items               []providerItem       `json:"provider_types"`
}

type lifecycleTotals struct {
	Resources                  int `json:"resources"`
	DataSources                int `json:"data_sources"`
	ImplementedServices        int `json:"implemented_services"`
	ServicesWithoutDirectTypes int `json:"services_without_direct_provider_types"`
	ItemsWithStaticGaps        int `json:"types_with_static_api_gaps"`
	Unverified                 int `json:"unverified_types"`
}

type implementedService struct {
	Service                    string   `json:"stackd_service"`
	RegisteredAPIs             int      `json:"registered_partial_apis"`
	ProviderServices           []string `json:"direct_provider_services"`
	DependencyProviderServices []string `json:"dependency_provider_services"`
	Disposition                string   `json:"disposition"`
	Resources                  int      `json:"resources"`
	DataSources                int      `json:"data_sources"`
	TypesWithStaticGaps        int      `json:"types_with_static_api_gaps"`
	Lifecycle                  string   `json:"terraform_lifecycle_evidence"`
	Engine                     string   `json:"native_engine_evidence"`
}

type providerItem struct {
	Type            string        `json:"terraform_type"`
	Kind            string        `json:"kind"`
	Framework       string        `json:"framework"`
	ProviderService string        `json:"provider_service"`
	StackdService   string        `json:"stackd_service,omitempty"`
	Factory         string        `json:"factory"`
	Registration    callsite      `json:"registration"`
	SourceFiles     []string      `json:"source_files"`
	APIs            []requirement `json:"source_file_apis"`
	Unresolved      []unresolved  `json:"source_file_unresolved"`
	Dependencies    []string      `json:"stackd_api_dependencies"`
	Gaps            []string      `json:"static_api_gaps"`
	APIDisposition  string        `json:"api_disposition"`
	Lifecycle       string        `json:"terraform_lifecycle_evidence"`
	Engine          string        `json:"native_engine_evidence"`
}

type parsedSource struct {
	Path      string
	File      *ast.File
	Positions *token.FileSet
}

type factorySource struct {
	Path        string
	Declaration *ast.FuncDecl
}

// The generated package methods are the provider's authoritative registration
// list. Parsing annotations alone would miss aliases such as aws_alb/aws_lb.
func registeredItems(provider string, sources []parsedSource, apis []requirement, unknown []unresolved) ([]providerItem, error) {
	factories := map[string][]factorySource{}
	methods := map[string][]string{}
	for _, source := range sources {
		scope := filepath.Dir(source.Path) + "/"
		for _, decl := range source.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv == nil {
				factories[scope+fn.Name.Name] = append(factories[scope+fn.Name.Name], factorySource{source.Path, fn})
			} else if len(fn.Recv.List) == 1 {
				receiver := localType(fn.Recv.List[0].Type)
				methods[scope+receiver] = append(methods[scope+receiver], source.Path)
			}
		}
	}
	items := []providerItem{}
	seen := map[string]bool{}
	for _, source := range sources {
		if filepath.Base(source.Path) != "service_package_gen.go" {
			continue
		}
		for _, decl := range source.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue
			}
			kind, framework := "", ""
			switch fn.Name.Name {
			case "SDKResources":
				kind, framework = "resource", "sdk"
			case "FrameworkResources":
				kind, framework = "resource", "framework"
			case "SDKDataSources":
				kind, framework = "data_source", "sdk"
			case "FrameworkDataSources":
				kind, framework = "data_source", "framework"
			default:
				continue // Actions, ephemeral resources and list discovery are separate categories.
			}
			var parseErr error
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if parseErr != nil {
					return false
				}
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				var typeName, factory string
				for _, element := range literal.Elts {
					kv, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					switch key.Name {
					case "TypeName":
						value, ok := kv.Value.(*ast.BasicLit)
						if !ok || value.Kind != token.STRING {
							parseErr = fmt.Errorf("%s: nonliteral TypeName", source.Path)
							return false
						}
						typeName, parseErr = strconv.Unquote(value.Value)
					case "Factory":
						value, ok := kv.Value.(*ast.Ident)
						if !ok {
							parseErr = fmt.Errorf("%s: nonlocal Factory", source.Path)
							return false
						}
						factory = value.Name
					}
				}
				if typeName == "" && factory == "" {
					return true
				}
				if typeName == "" || factory == "" {
					parseErr = fmt.Errorf("%s: incomplete registration", source.Path)
					return false
				}
				key := kind + "/" + typeName
				if seen[key] {
					parseErr = fmt.Errorf("%s: duplicate %s", source.Path, key)
					return false
				}
				seen[key] = true
				scope := filepath.Dir(source.Path) + "/"
				definitions := factories[scope+factory]
				if len(definitions) == 0 {
					parseErr = fmt.Errorf("%s: missing factory %s", source.Path, factory)
					return false
				}
				files := map[string]bool{}
				for _, definition := range definitions {
					files[definition.Path] = true
					// Framework lifecycle methods can be in files separate from the factory.
					ast.Inspect(definition.Declaration.Body, func(node ast.Node) bool {
						if literal, ok := node.(*ast.CompositeLit); ok {
							for _, path := range methods[scope+localType(literal.Type)] {
								files[path] = true
							}
						}
						return true
					})
				}
				item := providerItem{Type: typeName, Kind: kind, Framework: framework, ProviderService: provider, Factory: factory,
					Registration: callsite{Path: source.Path, Line: source.Positions.Position(literal.Pos()).Line, Function: fn.Name.Name, Expression: typeName, Evidence: "provider_service_package_registration"},
					SourceFiles:  sortedKeys(files), APIs: []requirement{}, Unresolved: []unresolved{}}
				for _, api := range apis {
					linked := api
					linked.Callsites = []callsite{}
					for _, site := range api.Callsites {
						if files[site.Path] {
							linked.Callsites = append(linked.Callsites, site)
						}
					}
					if len(linked.Callsites) != 0 {
						item.APIs = append(item.APIs, linked)
					}
				}
				for _, unresolved := range unknown {
					if files[unresolved.Callsite.Path] {
						item.Unresolved = append(item.Unresolved, unresolved)
					}
				}
				items = append(items, item)
				return false
			})
			if parseErr != nil {
				return nil, parseErr
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return itemKey(items[i]) < itemKey(items[j]) })
	return items, nil
}

func localType(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return localType(value.X)
	case *ast.ParenExpr:
		return localType(value.X)
	default:
		return ""
	}
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func itemKey(item providerItem) string {
	return item.ProviderService + "/" + item.Kind + "/" + item.Type
}

// Provider directory names are not SDK or stackd service IDs.
func providerID(provider string) string {
	switch provider {
	case "sfn":
		return "stepfunctions"
	case "appautoscaling":
		return "applicationautoscaling"
	case "events":
		return "eventbridge"
	case "elasticsearch":
		return "es"
	default:
		return provider
	}
}

// Use the generated NewClient signature, not the spelling of a directory, as
// the primary service identity. Aliases above cover packages without a client.
func packageSDK(sources []parsedSource) string {
	for _, source := range sources {
		if filepath.Base(source.Path) != "service_package_gen.go" {
			continue
		}
		a := analyzer{imports: sdkImports(source.File)}
		for _, decl := range source.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "NewClient" || fn.Type.Results == nil {
				continue
			}
			for _, result := range fn.Type.Results.List {
				if sdk, typ := a.infer(result.Type, 0); sdk != "" && typ == "Client" {
					return sdk
				}
			}
		}
	}
	return ""
}

func refreshLifecycle(r *report, inventory retained) {
	l := &r.Lifecycle
	l.Interpretation = "Exhaustive registered provider resources and data sources, not support claims. Direct owner matches use provider service identity, not resource-name prefixes. Source-file APIs can include unrelated branches and omit transitive helpers, shared tagging and provider initialization. Static gaps are scheduling signals only. Every stackd service with registered partial operations has a disposition, including data-only services without direct provider types. API registration, Terraform lifecycle evidence and real native-engine evidence are separate; both evidence fields default to unverified."
	l.Totals = lifecycleTotals{}
	l.ImplementedServices = []implementedService{}
	if l.Items == nil {
		l.Items = []providerItem{}
	}
	selected := map[string]bool{}
	implemented := map[string]int{}
	for _, service := range inventory.Services {
		selected[service.ID] = true
		for _, operation := range service.Operations {
			if operation.Status == "partial" {
				implemented[service.ID]++
			}
		}
	}
	for _, service := range inventory.Additional {
		for _, operation := range service.Operations {
			if operation.Status == "partial" {
				implemented[service.Service]++
			}
		}
	}
	owners := map[string]string{}
	for _, provider := range r.Services {
		owner := providerID(provider.Name)
		for _, service := range inventory.Services {
			if provider.SDKService != "" && sdkID(service.ID) == provider.SDKService {
				owner = service.ID
				break
			}
		}
		for _, service := range inventory.Additional {
			if provider.SDKService != "" && sdkID(service.Service) == provider.SDKService {
				owner = service.Service
				break
			}
		}
		owners[provider.Name] = owner
	}
	sort.Slice(l.Items, func(i, j int) bool { return itemKey(l.Items[i]) < itemKey(l.Items[j]) })
	for i := range l.Items {
		item := &l.Items[i]
		item.StackdService = ""
		if owner := owners[item.ProviderService]; selected[owner] || implemented[owner] != 0 {
			item.StackdService = owner
		}
		item.Lifecycle, item.Engine = "unverified", "unverified"
		dependencies := map[string]bool{}
		gaps := map[string]bool{}
		for _, api := range item.APIs {
			if api.StackdService != "" && api.StackdService != item.StackdService {
				dependencies[api.StackdService] = true
			}
			if api.Status != "registered-partial" {
				gaps[api.SDKService+"/"+api.Operation+":"+api.Status] = true
			}
		}
		item.Dependencies, item.Gaps = sortedKeys(dependencies), sortedKeys(gaps)
		switch {
		case len(item.Gaps) > 0:
			item.APIDisposition = "static-api-gaps"
		case len(item.Unresolved) > 0:
			item.APIDisposition = "unresolved-source-calls"
		case len(item.APIs) == 0:
			item.APIDisposition = "no-source-file-api-evidence"
		default:
			item.APIDisposition = "source-file-apis-registered-partial-not-lifecycle-proof"
		}
		if item.Kind == "resource" {
			l.Totals.Resources++
		} else {
			l.Totals.DataSources++
		}
		if len(item.Gaps) != 0 {
			l.Totals.ItemsWithStaticGaps++
		}
		l.Totals.Unverified++
	}
	ids := make([]string, 0, len(implemented))
	for id := range implemented {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := implementedService{Service: id, RegisteredAPIs: implemented[id], Lifecycle: "unverified", Engine: "unverified"}
		direct, dependencies := map[string]bool{}, map[string]bool{}
		for _, service := range r.Services {
			if owners[service.Name] == id {
				direct[service.Name] = true
			}
			for _, api := range service.Requirements {
				if api.StackdService == id && owners[service.Name] != id {
					dependencies[service.Name] = true
				}
			}
		}
		for _, item := range l.Items {
			if item.StackdService != id {
				continue
			}
			if item.Kind == "resource" {
				row.Resources++
			} else {
				row.DataSources++
			}
			if len(item.Gaps) != 0 {
				row.TypesWithStaticGaps++
			}
		}
		row.ProviderServices, row.DependencyProviderServices = sortedKeys(direct), sortedKeys(dependencies)
		switch {
		case row.Resources > 0:
			row.Disposition = "direct-provider-resources-unverified"
		case row.DataSources > 0:
			row.Disposition = "direct-provider-data-sources-only-unverified"
		default:
			row.Disposition = "no-direct-provider-resources-or-data-sources"
			l.Totals.ServicesWithoutDirectTypes++
		}
		l.ImplementedServices = append(l.ImplementedServices, row)
	}
	l.Totals.ImplementedServices = len(l.ImplementedServices)
}

// A missing checkout permits inventory-only refresh from the checked-in source
// snapshot. This cannot prove the checkout still matches the retained digest.
func generate(o options) (report, error) {
	_, err := os.Stat(o.Provider)
	if !o.RetainedSource && !os.IsNotExist(err) {
		return generateFromProvider(o)
	}
	data, err := os.ReadFile(o.Out)
	if err != nil {
		return report{}, fmt.Errorf("retained provider source report: %w; generate once with the pinned checkout", err)
	}
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	if r.SchemaVersion != 2 || r.Source.Revision != o.Revision || r.Source.Version != o.Version || len(r.Source.SHA256) != 64 {
		return r, fmt.Errorf("retained provider report has no matching schema-v2 pinned source evidence; regenerate with the checkout")
	}
	if _, err := hex.DecodeString(r.Source.SHA256); err != nil {
		return r, fmt.Errorf("invalid retained provider source digest: %w", err)
	}
	if err := validateRetained(r); err != nil {
		return r, err
	}
	inventoryData, err := os.ReadFile(o.Inventory)
	if err != nil {
		return r, err
	}
	var inventory retained
	if err := json.Unmarshal(inventoryData, &inventory); err != nil {
		return r, err
	}
	statuses := map[string]map[string]string{}
	for _, service := range inventory.Services {
		key := sdkID(service.ID)
		if statuses[key] != nil {
			return r, fmt.Errorf("ambiguous SDK service mapping for %s", service.ID)
		}
		statuses[key] = map[string]string{}
		for _, operation := range service.Operations {
			statuses[key][operation.Name] = operation.Status
		}
	}
	digest := sha256.Sum256(inventoryData)
	r.Inventory = map[string]any{"path": filepath.ToSlash(o.Inventory), "sha256": hex.EncodeToString(digest[:]), "source": inventory.Source}
	for i := range r.Services {
		for j := range r.Services[i].Requirements {
			api := &r.Services[i].Requirements[j]
			api.Status, api.StackdService = classify(api.SDKService, api.Operation, inventory, statuses)
		}
	}
	for i := range r.Lifecycle.Items {
		for j := range r.Lifecycle.Items[i].APIs {
			api := &r.Lifecycle.Items[i].APIs[j]
			api.Status, api.StackdService = classify(api.SDKService, api.Operation, inventory, statuses)
		}
	}
	refreshAPISummary(&r)
	refreshLifecycle(&r, inventory)
	fmt.Fprintln(os.Stderr, "terraformapisgen: using retained provider source evidence; provider source drift is NOT checked")
	return r, nil
}

func refreshAPISummary(r *report) {
	r.Totals = totals{Services: len(r.Services)}
	r.Priorities, r.TopGaps = []priority{}, []gap{}
	unique := map[string]bool{}
	for _, service := range r.Services {
		r.Totals.Files += service.Files
		r.Totals.Unresolved += len(service.Unresolved)
		p := priority{Service: service.Name}
		for _, api := range service.Requirements {
			unique[api.SDKService+"/"+api.Operation] = true
			r.Totals.Requirements++
			r.Totals.Callsites += len(api.Callsites)
			for _, site := range api.Callsites {
				if site.Evidence == "sdk_paginator_constructor" {
					r.Totals.Paginators++
				}
			}
			switch api.Status {
			case "registered-partial":
				r.Totals.Partial++
			case "unimplemented":
				r.Totals.Unimplemented++
				p.Unimplemented++
				p.Callsites += len(api.Callsites)
				if len(api.Callsites) != 0 {
					r.TopGaps = append(r.TopGaps, gap{service.Name, api.SDKService, api.Operation, len(api.Callsites), api.Callsites[0]})
				}
			case "outside-selected-service-scope":
				r.Totals.Outside++
				p.Outside++
			default:
				r.Totals.Unknown++
				p.Unknown++
			}
		}
		r.Priorities = append(r.Priorities, p)
	}
	r.Totals.UniqueAPIs = len(unique)
	sort.Slice(r.Priorities, func(i, j int) bool {
		a, b := r.Priorities[i], r.Priorities[j]
		if a.Unimplemented != b.Unimplemented {
			return a.Unimplemented > b.Unimplemented
		}
		if a.Callsites != b.Callsites {
			return a.Callsites > b.Callsites
		}
		return a.Service < b.Service
	})
	sort.Slice(r.TopGaps, func(i, j int) bool {
		a, b := r.TopGaps[i], r.TopGaps[j]
		if a.Callsites != b.Callsites {
			return a.Callsites > b.Callsites
		}
		return strings.Join([]string{a.ProviderService, a.SDKService, a.Operation}, "/") < strings.Join([]string{b.ProviderService, b.SDKService, b.Operation}, "/")
	})
	if len(r.TopGaps) > 30 {
		r.TopGaps = r.TopGaps[:30]
	}
}

// Validate retained evidence structure without claiming to verify source bytes.
// Only generation with a checkout can reproduce production_source_sha256.
func validateRetained(r report) error {
	services := map[string]map[string]bool{}
	for _, service := range r.Services {
		if service.Name == "" || services[service.Name] != nil {
			return fmt.Errorf("invalid retained provider service %q", service.Name)
		}
		apis := map[string]bool{}
		for _, api := range service.Requirements {
			if api.SDKService == "" || api.Operation == "" || len(api.Callsites) == 0 {
				return fmt.Errorf("invalid retained API in %s", service.Name)
			}
			apis[api.SDKService+"/"+api.Operation] = true
		}
		services[service.Name] = apis
	}
	if len(services) == 0 || r.Lifecycle.Items == nil {
		return fmt.Errorf("retained report has no source inventory")
	}
	seen := map[string]bool{}
	for _, item := range r.Lifecycle.Items {
		if services[item.ProviderService] == nil || (item.Kind != "resource" && item.Kind != "data_source") ||
			(item.Framework != "sdk" && item.Framework != "framework") || !strings.HasPrefix(item.Type, "aws_") ||
			item.Factory == "" || len(item.SourceFiles) == 0 || seen[item.Kind+"/"+item.Type] {
			return fmt.Errorf("invalid retained provider registration %s", itemKey(item))
		}
		seen[item.Kind+"/"+item.Type] = true
		root := "internal/service/" + item.ProviderService + "/"
		if item.Registration.Path != root+"service_package_gen.go" || item.Registration.Line <= 0 ||
			item.Registration.Evidence != "provider_service_package_registration" {
			return fmt.Errorf("invalid retained registration source for %s", item.Type)
		}
		files := map[string]bool{}
		for _, path := range item.SourceFiles {
			if !strings.HasPrefix(path, root) || strings.Contains(path, "..") || !strings.HasSuffix(path, ".go") {
				return fmt.Errorf("invalid retained factory source %q", path)
			}
			files[path] = true
		}
		for _, api := range item.APIs {
			if !services[item.ProviderService][api.SDKService+"/"+api.Operation] || len(api.Callsites) == 0 {
				return fmt.Errorf("invalid retained API link for %s", item.Type)
			}
			for _, site := range api.Callsites {
				if !files[site.Path] || site.Line <= 0 {
					return fmt.Errorf("invalid retained API source for %s", item.Type)
				}
			}
		}
		for _, unresolved := range item.Unresolved {
			if !files[unresolved.Callsite.Path] || unresolved.Callsite.Line <= 0 {
				return fmt.Errorf("invalid retained unresolved source for %s", item.Type)
			}
		}
	}
	return nil
}
