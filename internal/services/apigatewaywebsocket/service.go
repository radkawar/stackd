// Package apigatewaywebsocket owns live API Gateway WebSocket connections.
package apigatewaywebsocket

import (
	"context"
	"net/http"
	"sync"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/services/apigatewayexec"
)

// Resolver selects current deployed state, including for already-open sockets.
// An empty route key selects a MESSAGE route from body. Missing reserved routes
// return owner/stage metadata with an empty FunctionARN, not ErrUnknownAPI.
type Resolver interface {
	ResolveWebSocket(context.Context, string, string, string, []byte) (*apigatewayexec.Route, error)
}

type Config struct {
	Resolver      Resolver
	Functions     apigatewayexec.Functions
	Roles         apigatewayexec.InvocationRoles
	Authorization authorization.Authorizer
	Clock         clock.Clock
	Metrics       apigatewayexec.Metrics
	Logs          apigatewayexec.LogPublisher
}

type Service struct {
	resolver      Resolver
	functions     apigatewayexec.Functions
	roles         apigatewayexec.InvocationRoles
	authorizers   *apigatewayexec.AuthorizerExecutor
	authorization authorization.Authorizer
	clock         clock.Clock
	metrics       apigatewayexec.Metrics
	logs          apigatewayexec.LogPublisher
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	closed        bool
	connections   map[connectionKey]*connection
	workers       sync.WaitGroup
}

type endpoint struct {
	partition, account, region, api, stage string
}

type connectionKey struct {
	partition, account, region, api, id string
}

type endpointContextKey struct{}

func (e endpoint) connectionKey(id string) connectionKey {
	return connectionKey{e.partition, e.account, e.region, e.api, id}
}

const (
	maxFrameSize       = 32 << 10
	maxMessageSize     = 128 << 10
	idleTimeout        = 10 * time.Minute
	maxLifetime        = 2 * time.Hour
	writeTimeout       = 5 * time.Second
	integrationTimeout = 29 * time.Second
)

func New(c Config) *Service {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorization == nil {
		c.Authorization = authorization.NewWithClock(nil, nil, c.Clock)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{resolver: c.Resolver, functions: c.Functions, roles: c.Roles, authorizers: apigatewayexec.NewAuthorizerExecutor(c.Functions, c.Roles), authorization: c.Authorization,
		clock: c.Clock, metrics: c.Metrics, logs: c.Logs, ctx: ctx, cancel: cancel, connections: make(map[connectionKey]*connection)}
}

func owner(route *apigatewayexec.Route) endpoint {
	return endpoint{route.Partition, route.AccountID, route.Region, route.APIID, route.Stage}
}

func (e endpoint) arn(suffix string) string {
	return "arn:" + e.partition + ":execute-api:" + e.region + ":" + e.account + ":" + e.api + "/" + e.stage + "/" + suffix
}

// begin serializes worker admission with Close. No worker can be added after
// Close starts waiting, including a handshake that is still invoking Lambda.
func (s *Service) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.workers.Add(1)
	return true
}

func (s *Service) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

// Close physically closes all owned sockets and waits for the reader, expiry,
// and in-flight execution workers. This instance cannot be reopened.
func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	connections := make([]*connection, 0, len(s.connections))
	for _, c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	for _, c := range connections {
		c.terminate(context.Background(), 1001, "Going away", false)
	}
	s.workers.Wait()
	return nil
}

func (s *Service) Operations() []string {
	return []string{"DeleteConnection", "GetConnection", "PostToConnection"}
}

func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

func unavailable() *awswire.Error {
	return failure("ServiceUnavailableException", "Service unavailable", http.StatusServiceUnavailable)
}

func forbidden() *awswire.Error {
	return failure("ForbiddenException", "Forbidden", http.StatusForbidden)
}

func gone() *awswire.Error {
	return failure("GoneException", "", http.StatusGone)
}

func setText[T ~string](p **T, value string) { *p = new(T(value)) }
func text[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

var _ gateway.Provider = (*Service)(nil)
var _ awscommands.CommandExecutor = (*Service)(nil)
