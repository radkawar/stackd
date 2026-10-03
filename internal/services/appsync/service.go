// Package appsync owns GraphQL API definitions and their executable data plane.
package appsync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Endpoint   string
	Sources    DataSources
	Auth       Authenticator
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	endpoint   string
	sources    DataSources
	auth       Authenticator
	realtime   *Realtime
	operations map[string]func(context.Context) (any, *awswire.Error)
	schemaMu   sync.Mutex
	schemas    map[string]compiledSchema
}

func NewWithConfig(c Config) *Service {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	if c.Auth == nil {
		c.Auth = NewAuthenticator(AuthConfig{Clock: c.Clock})
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, endpoint: strings.TrimRight(c.Endpoint, "/"), sources: c.Sources, auth: c.Auth, operations: map[string]func(context.Context) (any, *awswire.Error){}, schemas: map[string]compiledSchema{}}
	registerControls(s)
	registerSchemaExport(s)
	s.realtime = NewRealtime(s)
	return s
}

func (s *Service) Close() error { return s.realtime.Close() }
func (s *Service) Operations() []string {
	names := make([]string, 0, len(s.operations))
	for n := range s.operations {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	fn, ok := s.operations[string(d.Operation.Name)]
	if !ok {
		// TODO: Comeback: merged APIs, Events APIs, caching, custom domains and the
		// remaining modeled controls need their own real execution effects.
		rejected := wireError(unsupported("This AppSync operation is not implemented"))
		if err := s.RecordRequestError(ctx, d, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("appsync")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, &awswire.Error{Code: "InternalFailureException", Message: "Missing generated request", StatusCode: 500})
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, wireError(err))
		return
	}
	for k, v := range response.Header {
		w.Header()[k] = v
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (s *Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	in, err := api.NewInput(string(op.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("appsync")
	if awsapi.BindHTTP(model, op, r, in) != nil {
		return nil
	}
	return in
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	return &awswire.Error{Code: "BadRequestException", Message: err.Error(), StatusCode: 400}
}

// Snapshot is a detached, transactionally consistent set of execution definitions.
// No repository lock is held while customer code or a data source runs.
type Snapshot struct {
	API         APIRecord
	DataSources map[string]api.DataSource
	Resolvers   map[string]api.Resolver
	Functions   map[string]api.FunctionConfiguration
	Keys        []api.ApiKey
}

func (s *Service) snapshot(ctx context.Context, id string) (Snapshot, error) {
	result := Snapshot{DataSources: map[string]api.DataSource{}, Resolvers: map[string]api.Resolver{}, Functions: map[string]api.FunctionConfiguration{}}
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		result.API, err = r.APIByID(id)
		if err != nil {
			return err
		}
		sources, err := r.DataSources(result.API.Key)
		if err != nil {
			return err
		}
		for _, v := range sources {
			result.DataSources[value(v.DataSource.Name)] = v.DataSource
		}
		resolvers, err := r.Resolvers(result.API.Key)
		if err != nil {
			return err
		}
		for _, v := range resolvers {
			result.Resolvers[value(v.Resolver.TypeName)+"."+value(v.Resolver.FieldName)] = v.Resolver
		}
		functions, err := r.Functions(result.API.Key)
		if err != nil {
			return err
		}
		for _, v := range functions {
			result.Functions[value(v.Function.FunctionId)] = v.Function
		}
		keys, err := r.APIKeys(result.API.Key)
		if err != nil {
			return err
		}
		for _, v := range keys {
			result.Keys = append(result.Keys, v.Key)
		}
		return nil
	})
	return result, err
}

func dataAPIPath(path string) (id string, realtime bool, ok bool) {
	path, ok = strings.CutPrefix(path, "/_stackd/appsync/")
	if !ok {
		return "", false, false
	}
	id, suffix, found := strings.Cut(path, "/")
	if !found || id == "" {
		return "", false, false
	}
	return id, suffix == "graphql/realtime", suffix == "graphql" || suffix == "graphql/realtime"
}
func (*Service) HandlesDataRequest(r *http.Request) bool {
	_, _, ok := dataAPIPath(r.URL.Path)
	return ok
}
func (s *Service) ServeDataHTTP(w http.ResponseWriter, r *http.Request) {
	id, realtime, ok := dataAPIPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if realtime {
		s.realtime.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "content-type,x-api-key,authorization,x-amz-date,x-amz-security-token")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST,GET,OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}
	snapshot, err := s.snapshot(ctx, id)
	if err != nil {
		writeGraphQLError(w, http.StatusNotFound, "NotFoundException", "GraphQL API not found")
		return
	}
	if s.auth == nil {
		writeGraphQLError(w, http.StatusUnauthorized, "UnauthorizedException", "Authentication is unavailable")
		return
	}
	identity, err := s.auth.Authenticate(ctx, snapshot.API, r, snapshot.Keys)
	if err != nil {
		writeGraphQLError(w, http.StatusUnauthorized, "UnauthorizedException", err.Error())
		return
	}
	if identity.Context != nil {
		ctx = identity.Context
	}
	request := GraphQLRequest{}
	if r.Method == http.MethodGet {
		request.Query = r.URL.Query().Get("query")
		request.OperationName = r.URL.Query().Get("operationName")
		if variables := r.URL.Query().Get("variables"); variables != "" {
			err = json.Unmarshal([]byte(variables), &request.Variables)
		}
	} else {
		decoder := json.NewDecoder(r.Body)
		err = decoder.Decode(&request)
		if err == nil {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				err = bad("Request must contain one JSON document")
			}
		}
	}
	if err != nil {
		writeGraphQLError(w, 400, "BadRequestException", "Invalid GraphQL request: "+err.Error())
		return
	}
	if r.Method == http.MethodGet {
		prepared, e := s.prepare(ctx, snapshot, request, identity)
		if e != nil {
			_ = json.NewEncoder(w).Encode(graphQLFailure(e))
			return
		}
		if prepared.Operation.Operation != "query" {
			writeGraphQLError(w, 405, "BadRequestException", "GET requests may only execute queries")
			return
		}
	}
	_ = json.NewEncoder(w).Encode(s.execute(ctx, snapshot, request, identity))
}
func writeGraphQLError(w http.ResponseWriter, status int, kind, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []GraphQLError{{Message: message, ErrorType: kind}}})
}
