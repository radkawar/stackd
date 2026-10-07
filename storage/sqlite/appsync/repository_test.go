package appsync_test

import (
	"context"
	"errors"
	"path/filepath"
	api "stackd/internal/awsapi/appsync"
	domain "stackd/internal/services/appsync"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/appsync"
	"testing"
)

func TestDefinitionsRemainAtomicScopedAndReferential(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var repo domain.Repository
			restart := func() {}
			if kind == "memory" {
				repo = domain.NewMemoryRepository(nil)
			} else {
				path := filepath.Join(t.TempDir(), "appsync.sqlite")
				db, e := sqlite.Open(t.Context(), path)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = backend.New(db)
				restart = func() {
					if e := db.Close(); e != nil {
						t.Fatal(e)
					}
					db, e = sqlite.Open(t.Context(), path)
					if e != nil {
						t.Fatal(e)
					}
					repo = backend.New(db)
				}
			}
			k := domain.Key{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", ID: "api"}
			original := domain.APIRecord{Key: k, Schema: "type Query { value: String }", SchemaStatus: "SUCCESS", API: api.GraphqlApi{Name: new(api.ResourceName("original")), AuthenticationType: new(api.AuthenticationType("API_KEY")), ApiType: new(api.GraphQLApiType("GRAPHQL")), Visibility: new(api.GraphQLApiVisibility("GLOBAL")), IntrospectionConfig: new(api.GraphQLApiIntrospectionConfig("ENABLED")), Tags: api.TagMap{"owner": "team"}, AdditionalAuthenticationProviders: api.AdditionalAuthenticationProviders{{AuthenticationType: new(api.AuthenticationType("OPENID_CONNECT")), OpenIDConnectConfig: &api.OpenIDConnectConfig{Issuer: new(api.String("https://issuer.example")), ClientId: new(api.String("client")), AuthTTL: new(api.Long(1234))}}}}}
			source := domain.DataSourceRecord{API: k, DataSource: api.DataSource{Name: new(api.ResourceName("none")), Type: new(api.DataSourceType("NONE"))}}
			function := domain.FunctionRecord{API: k, Function: api.FunctionConfiguration{FunctionId: new(api.String("fn")), Name: new(api.ResourceName("fn")), DataSourceName: source.DataSource.Name, Code: new(api.Code("export function request(ctx){return {payload:ctx.arguments};} export function response(ctx){return ctx.result;}")), Runtime: &api.AppSyncRuntime{Name: new(api.RuntimeName("APPSYNC_JS")), RuntimeVersion: new(api.String("1.0.0"))}}}
			resolver := domain.ResolverRecord{API: k, Resolver: api.Resolver{TypeName: new(api.ResourceName("Query")), FieldName: new(api.ResourceName("value")), Kind: new(api.ResolverKind("PIPELINE")), PipelineConfig: &api.PipelineConfig{Functions: api.FunctionsIds{"fn", "fn"}}, Code: function.Function.Code, Runtime: function.Function.Runtime}}
			key := domain.APIKeyRecord{API: k, Key: api.ApiKey{Id: new(api.String("da2-retained")), Expires: new(api.Long(2000000000)), Deletes: new(api.Long(2005184000))}}
			original.SchemaOwnership = "schema-incarnation"
			original.Ownership = "api-incarnation"
			source.Ownership, function.Ownership, resolver.Ownership, key.Ownership = "source-incarnation", "function-incarnation", "resolver-incarnation", "key-incarnation"
			if e := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if e := tx.PutAPI(original); e != nil {
					return e
				}
				if e := tx.PutDataSource(source); e != nil {
					return e
				}
				if e := tx.PutFunction(function); e != nil {
					return e
				}
				if e := tx.PutResolver(resolver); e != nil {
					return e
				}
				return tx.PutAPIKey(key)
			}); e != nil {
				t.Fatal(e)
			}
			original.API.Tags["owner"] = "caller-mutated"
			*function.Function.Code = "caller-mutated"
			abort := errors.New("abort")
			if e := repo.Update(t.Context(), func(tx domain.Transaction) error {
				p, e := tx.API(k)
				if e != nil {
					return e
				}
				*p.API.Name = "aborted"
				p.API.Tags["owner"] = "aborted"
				if e = tx.PutAPI(p); e != nil {
					return e
				}
				if e = tx.DeleteResolver(k, "Query", "value"); e != nil {
					return e
				}
				return abort
			}); !errors.Is(e, abort) {
				t.Fatalf("rollback result: %v", e)
			}
			for _, delete := range []func(domain.Transaction) error{func(tx domain.Transaction) error { return tx.DeleteDataSource(k, "none") }, func(tx domain.Transaction) error { return tx.DeleteFunction(k, "fn") }} {
				if e := repo.Attempt(t.Context(), delete); !errors.Is(e, domain.ErrConflict) {
					t.Fatalf("referenced deletion result: %v", e)
				}
			}
			foreign := k
			foreign.AccountID = "222222222222"
			if e := repo.View(t.Context(), func(r domain.Reader) error {
				if _, e := r.API(foreign); !errors.Is(e, domain.ErrNotFound) {
					t.Fatalf("foreign API lookup: %v", e)
				}
				if _, e := r.Functions(foreign); !errors.Is(e, domain.ErrNotFound) {
					t.Fatalf("foreign child lookup: %v", e)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			restart()
			if e := repo.View(t.Context(), func(r domain.Reader) error {
				p, e := r.APIByID("api")
				if e != nil {
					return e
				}
				if p.Key != k || *p.API.Name != "original" || p.API.Tags["owner"] != "team" || p.Schema != "type Query { value: String }" {
					t.Fatalf("lost API snapshot: %#v", p)
				}
				if p.SchemaOwnership != "schema-incarnation" {
					t.Fatal("schema incarnation lost on restart")
				}
				if p.Ownership != "api-incarnation" {
					t.Fatal("API incarnation lost on restart")
				}
				sources, e := r.DataSources(k)
				if e != nil {
					return e
				}
				if len(sources) != 1 || sources[0].Ownership != "source-incarnation" {
					t.Fatal("data source incarnation lost on restart")
				}
				a := p.API.AdditionalAuthenticationProviders[0].OpenIDConnectConfig
				if *a.Issuer != "https://issuer.example" || *a.AuthTTL != 1234 {
					t.Fatalf("lost auth config: %#v", a)
				}
				fs, e := r.Functions(k)
				if e != nil {
					return e
				}
				if string(*fs[0].Function.Code) == "caller-mutated" {
					t.Fatal("caller mutation escaped repository")
				}
				if fs[0].Ownership != "function-incarnation" {
					t.Fatal("function incarnation lost on restart")
				}
				rs, e := r.Resolvers(k)
				if e != nil {
					return e
				}
				ids := rs[0].Resolver.PipelineConfig.Functions
				if len(ids) != 2 || ids[0] != "fn" || ids[1] != "fn" {
					t.Fatalf("pipeline order/multiplicity lost: %v", ids)
				}
				if rs[0].Ownership != "resolver-incarnation" {
					t.Fatal("resolver incarnation lost on restart")
				}
				keys, e := r.APIKeys(k)
				if e != nil {
					return e
				}
				if *keys[0].Key.Deletes-*keys[0].Key.Expires != 5184000 {
					t.Fatal("key lifetime lost")
				}
				if keys[0].Ownership != "key-incarnation" {
					t.Fatal("key incarnation lost on restart")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if e := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteAPI(k) }); e != nil {
				t.Fatal(e)
			}
			if e := repo.View(context.Background(), func(r domain.Reader) error { _, e := r.APIByID(k.ID); return e }); !errors.Is(e, domain.ErrNotFound) {
				t.Fatalf("deleted API remained: %v", e)
			}
		})
	}
}
