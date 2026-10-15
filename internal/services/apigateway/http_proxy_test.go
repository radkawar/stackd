package apigateway

import (
	"errors"
	"testing"
	"time"

	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

func TestHTTPProxyAdmissionRejectsUnsupportedContracts(t *testing.T) {
	s := New(Config{})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	key := MethodKey{ResourceKey: ResourceKey{APIKey: APIKey{Scope: scopeFor(ctx), ID: "api"}, ResourceID: "root"}, HTTPMethod: "GET"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutAPI(APIRecord{Key: key.APIKey, RootResourceID: "root", Created: time.Now()}); err != nil {
			return err
		}
		if err := tx.PutResource(ResourceRecord{Key: key.ResourceKey, Path: "/"}); err != nil {
			return err
		}
		return tx.PutMethod(MethodRecord{Key: key, AuthorizationType: "NONE"})
	}); err != nil {
		t.Fatal(err)
	}
	base := func() *api.PutIntegrationRequest {
		return &api.PutIntegrationRequest{RestApiId: ptr("api"), ResourceId: ptr("root"), HttpMethod: ptr("GET"), Type: new(api.IntegrationTypeHTTP_PROXY), IntegrationHttpMethod: ptr("GET"), Uri: ptr("http://127.0.0.1:14843/"), ConnectionType: new(api.ConnectionTypeINTERNET), TimeoutInMillis: new(api.NullableInteger(29000))}
	}
	for _, test := range []struct {
		name   string
		mutate func(*api.PutIntegrationRequest)
	}{
		{"private", func(in *api.PutIntegrationRequest) { in.ConnectionType = new(api.ConnectionTypeVPC_LINK) }},
		{"credentials", func(in *api.PutIntegrationRequest) { in.Credentials = ptr("arn:aws:iam::111111111111:role/backend") }},
		{"template", func(in *api.PutIntegrationRequest) {
			in.RequestTemplates = api.MapOfStringToString{"application/json": "{}"}
		}},
		{"mapping", func(in *api.PutIntegrationRequest) {
			in.RequestParameters = api.MapOfStringToString{"integration.request.header.Host": "'attacker'"}
		}},
		{"cache", func(in *api.PutIntegrationRequest) {
			in.CacheKeyParameters = api.ListOfString{"method.request.path.id"}
		}},
		{"stream", func(in *api.PutIntegrationRequest) { in.ResponseTransferMode = new(api.ResponseTransferModeSTREAM) }},
		{"tls", func(in *api.PutIntegrationRequest) {
			in.TlsConfig = &api.TlsConfig{InsecureSkipVerification: new(api.Boolean(true))}
		}},
		{"userinfo", func(in *api.PutIntegrationRequest) { in.Uri = ptr("https://user:pass@backend.example/") }},
		{"fragment", func(in *api.PutIntegrationRequest) { in.Uri = ptr("https://backend.example/#fragment") }},
		{"network", func(in *api.PutIntegrationRequest) { in.Uri = ptr("file:///etc/passwd") }},
		{"stage", func(in *api.PutIntegrationRequest) { in.Uri = ptr("https://${stageVariables.host}/") }},
		{"host-placeholder", func(in *api.PutIntegrationRequest) { in.Uri = ptr("https://{host}/") }},
		{"port", func(in *api.PutIntegrationRequest) { in.Uri = ptr("https://backend.example:22/") }},
		{"timeout-low", func(in *api.PutIntegrationRequest) { in.TimeoutInMillis = new(api.NullableInteger(49)) }},
		{"timeout-high", func(in *api.PutIntegrationRequest) { in.TimeoutInMillis = new(api.NullableInteger(29001)) }},
		{"method", func(in *api.PutIntegrationRequest) { in.IntegrationHttpMethod = ptr("CONNECT") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := base()
			test.mutate(in)
			if err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.putIntegration(tx, in); return err }); err == nil {
				t.Fatal("unsupported HTTP proxy contract admitted")
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				_, err := r.Integration(key)
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("failed admission persisted integration: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.putIntegration(tx, base())
		if err != nil {
			return err
		}
		if value(out.Type) != "HTTP_PROXY" || value(out.HttpMethod) != "GET" || value(out.ConnectionType) != "INTERNET" || value(out.Uri) != "http://127.0.0.1:14843/" {
			t.Fatalf("integration output=%+v", out)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPProxyPathMappingsAndImmutableDeployment(t *testing.T) {
	s := New(Config{})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	owner := APIKey{Scope: scopeFor(ctx), ID: "api"}
	root := ResourceKey{APIKey: owner, ResourceID: "root"}
	resource := ResourceKey{APIKey: owner, ResourceID: "proxy"}
	methodKey := MethodKey{ResourceKey: resource, HTTPMethod: "ANY"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutAPI(APIRecord{Key: owner, RootResourceID: "root", Created: time.Now()}); err != nil {
			return err
		}
		if err := tx.PutResource(ResourceRecord{Key: root, Path: "/"}); err != nil {
			return err
		}
		if err := tx.PutResource(ResourceRecord{Key: resource, ParentID: "root", PathPart: "{proxy+}", Path: "/{proxy+}"}); err != nil {
			return err
		}
		_, err := s.putMethod(tx, &api.PutMethodRequest{RestApiId: ptr("api"), ResourceId: ptr("proxy"), HttpMethod: ptr("ANY"), AuthorizationType: ptr("NONE"), RequestParameters: api.MapOfStringToBoolean{"method.request.path.proxy": true}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putIntegration(tx, &api.PutIntegrationRequest{RestApiId: ptr("api"), ResourceId: ptr("proxy"), HttpMethod: ptr("ANY"), Type: new(api.IntegrationTypeHTTP_PROXY), IntegrationHttpMethod: ptr("ANY"), Uri: ptr("https://backend.example/site/{path}"), RequestParameters: api.MapOfStringToString{"integration.request.path.path": "method.request.path.proxy"}, TimeoutInMillis: new(api.NullableInteger(50))})
		if err != nil {
			return err
		}
		_, err = s.createDeployment(tx, &api.CreateDeploymentRequest{RestApiId: ptr("api"), StageName: ptr("live")})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	patch := func(patches api.ListOfPatchOperation) error {
		return s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.updateIntegration(tx, &api.UpdateIntegrationRequest{RestApiId: ptr("api"), ResourceId: ptr("proxy"), HttpMethod: ptr("ANY"), PatchOperations: patches})
			return err
		})
	}
	uriPatch := api.PatchOperation{Op: new(api.Op("replace")), Path: ptr("/uri"), Value: ptr("https://new.example/site/{path}")}
	if err := patch(api.ListOfPatchOperation{uriPatch, {Op: new(api.Op("replace")), Path: ptr("/credentials"), Value: ptr("not-http")}}); err == nil {
		t.Fatal("unsupported later patch did not roll back")
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		row, err := r.Integration(methodKey)
		if err != nil {
			return err
		}
		if row.HTTPProxy.URI != "https://backend.example/site/{path}" {
			t.Fatal("failed patch changed URI")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := patch(api.ListOfPatchOperation{uriPatch}); err != nil {
		t.Fatal(err)
	}
	route, err := s.Resolve(ctx, "api", "live", "PATCH", "/a/b")
	if err != nil {
		t.Fatal(err)
	}
	if route.HTTPProxy == nil || route.HTTPProxy.URI != "https://backend.example/site/{path}" || route.PathParameters["proxy"] != "a/b" || route.IntegrationTimeoutMillis != 50 {
		t.Fatalf("deployed route=%+v", route)
	}
	for _, method := range []string{"TRACE", "PROPFIND", "ANY", "get"} {
		_, err := s.Resolve(ctx, "api", "live", method, "/a/b")
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.StatusCode != 403 {
			t.Fatalf("unsupported invocation method %q: %v", method, err)
		}
	}
	route.HTTPProxy.PathParameters["path"] = "outside"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteMethod(methodKey) }); err != nil {
		t.Fatal(err)
	}
	route, err = s.Resolve(ctx, "api", "live", "PATCH", "/a/b")
	if err != nil || route.HTTPProxy.PathParameters["path"] != "proxy" {
		t.Fatalf("mutable configuration changed deployed proxy: %v %+v", err, route)
	}
	for _, test := range []struct {
		uri      string
		paths    map[string]string
		declared map[string]bool
	}{
		{"https://backend.example/{missing}", nil, nil},
		{"https://backend.example/{path}", map[string]string{"path": "absent"}, nil},
		{"https://backend.example/prefix{path}", map[string]string{"path": "proxy"}, map[string]bool{"method.request.path.proxy": true}},
		{"https://backend.example/%7Bpath%7D", map[string]string{"path": "proxy"}, map[string]bool{"method.request.path.proxy": true}},
	} {
		if err := validateHTTPProxy(&apigatewayexec.HTTPProxyIntegration{URI: test.uri, Method: "GET", PathParameters: test.paths}, MethodRecord{RequestParameters: test.declared}, ResourceRecord{Path: "/{proxy+}"}); err == nil {
			t.Fatalf("invalid mapping admitted: %+v", test)
		}
	}
}
