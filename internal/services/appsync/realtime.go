package appsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

const realtimeMessageLimit = 1 << 20
const realtimeWriteTimeout = 5 * time.Second

// Realtime owns only live sockets. No connection/subscription is persisted or
// reconstructed after restart; clients establish fresh authenticated sessions.
type Realtime struct {
	service     *Service
	mu          sync.Mutex
	connections map[*realtimeConnection]struct{}
	closed      bool
	workers     sync.WaitGroup
}

type realtimeConnection struct {
	realtime      *Realtime
	apiID         string
	request       *http.Request
	identity      Identity
	ctx           context.Context
	cancel        context.CancelFunc
	socket        net.Conn
	writeMu       sync.Mutex
	mu            sync.Mutex
	subscriptions map[string]*realtimeSubscription
	initialized   bool
	closeOnce     sync.Once
}

type realtimeSubscription struct {
	mu          sync.Mutex
	active      bool
	request     GraphQLRequest
	authRequest *http.Request
	identity    Identity
}

type realtimeMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func NewRealtime(service *Service) *Realtime {
	return &Realtime{service: service, connections: make(map[*realtimeConnection]struct{})}
}

func (rt *Realtime) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/_stackd/appsync/")
	apiID, suffix, found := strings.Cut(path, "/")
	if !found || suffix != "graphql/realtime" || apiID == "" {
		http.NotFound(w, request)
		return
	}
	snapshot, err := rt.service.snapshot(request.Context(), apiID)
	if err != nil {
		http.Error(w, "GraphQL API not found", http.StatusNotFound)
		return
	}
	headers, err := realtimeHeaders(request)
	if err != nil {
		http.Error(w, "Invalid authorization headers", http.StatusBadRequest)
		return
	}
	if !hasGraphQLProtocol(request) {
		http.Error(w, "The graphql-ws subprotocol is required", http.StatusBadRequest)
		return
	}
	authRequest, err := realtimeAuthRequest(request, snapshot.API, headers, "{}", true)
	if err != nil {
		http.Error(w, "Invalid authorization host", http.StatusUnauthorized)
		return
	}
	identity, err := rt.service.auth.Authenticate(request.Context(), snapshot.API, authRequest, snapshot.Keys)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	upgrader := ws.HTTPUpgrader{Timeout: realtimeWriteTimeout, Protocol: func(protocol string) bool { return protocol == "graphql-ws" }}
	socket, buffered, _, err := upgrader.Upgrade(request, w)
	if err != nil {
		if socket != nil {
			_ = socket.Close()
		}
		return
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(request.Context()))
	c := &realtimeConnection{realtime: rt, apiID: apiID, identity: identity, ctx: ctx, cancel: cancel, socket: socket, subscriptions: make(map[string]*realtimeSubscription)}
	// The retained request is the authenticated canonical connect request, not
	// the upgrade envelope. It is only needed by custom Authenticators.
	c.request = authRequest.Clone(ctx)
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		cancel()
		_ = socket.Close()
		return
	}
	rt.connections[c] = struct{}{}
	rt.workers.Add(2)
	rt.mu.Unlock()
	go c.read(buffered.Reader)
	go c.keepAlive()
}

func hasGraphQLProtocol(request *http.Request) bool {
	for _, header := range request.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(header, ",") {
			if strings.TrimSpace(protocol) == "graphql-ws" {
				return true
			}
		}
	}
	return false
}

func realtimeHeaders(request *http.Request) (http.Header, error) {
	encoded := request.URL.Query().Get("header")
	for _, header := range request.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(header, ",") {
			if token, found := strings.CutPrefix(strings.TrimSpace(protocol), "header-"); found {
				if encoded != "" {
					return nil, errors.New("ambiguous authorization headers")
				}
				encoded = token
			}
		}
	}
	if encoded == "" {
		headers := request.Header.Clone()
		headers.Set("Host", request.Host)
		return headers, nil
	}
	if len(encoded) > 32768 {
		return nil, errors.New("authorization headers too large")
	}
	var decoded []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err = encoding.DecodeString(encoded)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	return decodeRealtimeHeaders(decoded)
}

func decodeRealtimeHeaders(raw []byte) (http.Header, error) {
	var values map[string]string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, errors.New("invalid authorization object")
	}
	headers := make(http.Header, len(values))
	for key, val := range values {
		canonical := http.CanonicalHeaderKey(key)
		if _, exists := headers[canonical]; exists || strings.ContainsAny(key+val, "\r\n") {
			return nil, errors.New("invalid authorization header")
		}
		headers.Set(key, val)
	}
	return headers, nil
}

func realtimeAuthRequest(base *http.Request, record APIRecord, headers http.Header, body string, connect bool) (*http.Request, error) {
	endpoint := &url.URL{Scheme: "https", Host: base.Host, Path: "/_stackd/appsync/" + record.Key.ID + "/graphql"}
	if configured := string(record.API.Uris["GRAPHQL"]); configured != "" {
		parsed, err := url.Parse(configured)
		if err != nil || parsed.Host == "" {
			return nil, errors.New("invalid GraphQL endpoint")
		}
		endpoint = parsed
	}
	if host := headers.Get("Host"); host != "" && !strings.EqualFold(host, endpoint.Host) {
		return nil, errors.New("authorization host does not match the API endpoint")
	}
	if connect {
		endpoint.Path += "/connect"
	}
	request, err := http.NewRequestWithContext(base.Context(), http.MethodPost, endpoint.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header = headers.Clone()
	request.Header.Del("Host")
	request.Host = endpoint.Host
	request.RemoteAddr, request.TLS = base.RemoteAddr, base.TLS
	return request, nil
}

func (c *realtimeConnection) read(source io.Reader) {
	defer c.realtime.workers.Done()
	defer c.close()
	reader := wsutil.Reader{Source: source, State: ws.StateServerSide, CheckUTF8: true, MaxFrameSize: realtimeMessageLimit}
	reader.OnIntermediate = c.control
	for c.ctx.Err() == nil {
		header, err := reader.NextFrame()
		if err != nil {
			return
		}
		if header.OpCode.IsControl() {
			if c.control(header, &reader) != nil {
				return
			}
			continue
		}
		if header.OpCode != ws.OpText {
			c.closeFrame(ws.StatusUnsupportedData, "Only text messages are supported")
			return
		}
		body, err := io.ReadAll(io.LimitReader(&reader, realtimeMessageLimit+1))
		if err != nil {
			return
		}
		if len(body) > realtimeMessageLimit {
			c.closeFrame(ws.StatusMessageTooBig, "Message too big")
			return
		}
		var message realtimeMessage
		if json.Unmarshal(body, &message) != nil || message.Type == "" {
			c.failure("", "BadRequestException", "Invalid message")
			continue
		}
		switch message.Type {
		case "connection_init":
			if c.initialized {
				c.failure("", "BadRequestException", "Connection already initialized")
				return
			}
			c.initialized = true
			if c.send("connection_ack", "", map[string]any{"connectionTimeoutMs": 300000}) != nil {
				return
			}
			if c.send("ka", "", nil) != nil {
				return
			}
		case "start":
			c.start(message)
		case "stop":
			c.stop(message.ID)
		case "connection_terminate":
			return
		default:
			c.failure(message.ID, "BadRequestException", "Unsupported message type")
		}
	}
}

func (c *realtimeConnection) control(header ws.Header, source io.Reader) error {
	payload, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.socket.SetWriteDeadline(time.Now().Add(realtimeWriteTimeout))
	handler := wsutil.ControlHandler{Src: bytes.NewReader(payload), Dst: c.socket, State: ws.StateServerSide, DisableSrcCiphering: true}
	return handler.Handle(header)
}

func (c *realtimeConnection) start(message realtimeMessage) {
	if message.ID == "" {
		c.failure("", "BadRequestException", "Subscription ID is required")
		return
	}
	c.mu.Lock()
	_, duplicate := c.subscriptions[message.ID]
	c.mu.Unlock()
	if duplicate {
		c.failure(message.ID, "BadRequestException", "Subscription ID is already registered")
		return
	}
	var payload struct {
		Data       string `json:"data"`
		Extensions struct {
			Authorization json.RawMessage `json:"authorization"`
		} `json:"extensions"`
	}
	if json.Unmarshal(message.Payload, &payload) != nil {
		c.failure(message.ID, "BadRequestException", "Invalid start payload")
		return
	}
	var request GraphQLRequest
	if json.Unmarshal([]byte(payload.Data), &request) != nil {
		c.failure(message.ID, "BadRequestException", "Invalid GraphQL request")
		return
	}
	headers, err := decodeRealtimeHeaders(payload.Extensions.Authorization)
	if err != nil {
		c.failure(message.ID, "UnauthorizedException", "Subscription authorization is required")
		return
	}
	snapshot, err := c.realtime.service.snapshot(c.ctx, c.apiID)
	if err != nil {
		c.failure(message.ID, "UnauthorizedException", "API is no longer available")
		return
	}
	if _, err := c.revalidate(c.identity, c.request, snapshot); err != nil {
		c.failure(message.ID, "UnauthorizedException", "Connection authorization is no longer valid")
		c.close()
		return
	}
	authRequest, err := realtimeAuthRequest(c.request, snapshot.API, headers, payload.Data, false)
	if err != nil {
		c.failure(message.ID, "UnauthorizedException", "Invalid authorization host")
		return
	}
	identity, err := c.realtime.service.auth.Authenticate(c.ctx, snapshot.API, authRequest, snapshot.Keys)
	if err != nil {
		c.failure(message.ID, "UnauthorizedException", "Subscription is not authorized")
		return
	}
	if _, err := c.realtime.service.subscriptionStart(c.ctx, snapshot, request, identity); err != nil {
		c.failure(message.ID, "BadRequestException", err.Error())
		return
	}
	subscription := &realtimeSubscription{active: true, request: request, authRequest: authRequest, identity: identity}
	subscription.mu.Lock()
	c.mu.Lock()
	c.subscriptions[message.ID] = subscription
	c.mu.Unlock()
	// Publish cannot overtake start_ack for the newly visible subscription.
	_ = c.send("start_ack", message.ID, nil)
	subscription.mu.Unlock()
}

func (c *realtimeConnection) stop(id string) {
	c.mu.Lock()
	subscription := c.subscriptions[id]
	delete(c.subscriptions, id)
	c.mu.Unlock()
	if subscription == nil {
		return
	}
	subscription.mu.Lock()
	defer subscription.mu.Unlock()
	subscription.active = false
	_ = c.send("complete", id, nil)
}

func (c *realtimeConnection) revalidate(identity Identity, request *http.Request, snapshot Snapshot) (Identity, error) {
	if identity.refresh != nil {
		return identity.refresh(c.ctx, snapshot.API, snapshot.Keys)
	}
	copy := request.Clone(c.ctx)
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return Identity{}, err
		}
		copy.Body = body
	}
	return c.realtime.service.auth.Authenticate(c.ctx, snapshot.API, copy, snapshot.Keys)
}

func (c *realtimeConnection) keepAlive() {
	defer c.realtime.workers.Done()
	defer c.close()
	started := c.realtime.service.clock.Now()
	for {
		timer := c.realtime.service.clock.NewTimer(60 * time.Second)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
			timer.Stop()
		}
		if !c.realtime.service.clock.Now().Before(started.Add(24 * time.Hour)) {
			c.closeFrame(ws.StatusGoingAway, "Connection duration exceeded")
			return
		}
		snapshot, err := c.realtime.service.snapshot(c.ctx, c.apiID)
		if err == nil {
			_, err = c.revalidate(c.identity, c.request, snapshot)
		}
		if err != nil {
			c.failure("", "UnauthorizedException", "Connection authorization is no longer valid")
			return
		}
		if c.send("ka", "", nil) != nil {
			return
		}
	}
}

// Publish delivers actual successful mutation selections, never resolver inputs
// or a fabricated event. The execution owner performs subscription projection and
// argument filtering against the current schema, under each subscriber identity.
func (rt *Realtime) Publish(ctx context.Context, apiID, mutationName string, payload any) {
	rt.mu.Lock()
	connections := make([]*realtimeConnection, 0, len(rt.connections))
	for c := range rt.connections {
		if c.apiID == apiID {
			connections = append(connections, c)
		}
	}
	rt.mu.Unlock()
	for _, c := range connections {
		if ctx.Err() != nil {
			return
		}
		c.publish(mutationName, payload)
	}
}

func (c *realtimeConnection) publish(mutationName string, payload any) {
	c.mu.Lock()
	subscriptions := make(map[string]*realtimeSubscription, len(c.subscriptions))
	for id, subscription := range c.subscriptions {
		subscriptions[id] = subscription
	}
	c.mu.Unlock()
	for id, subscription := range subscriptions {
		subscription.mu.Lock()
		if !subscription.active || c.ctx.Err() != nil {
			subscription.mu.Unlock()
			continue
		}
		snapshot, err := c.realtime.service.snapshot(c.ctx, c.apiID)
		if err == nil {
			_, err = c.revalidate(c.identity, c.request, snapshot)
		}
		var identity Identity
		if err == nil {
			identity, err = c.revalidate(subscription.identity, subscription.authRequest, snapshot)
		}
		var prepared *preparedOperation
		if err == nil {
			prepared, err = c.realtime.service.prepare(c.ctx, snapshot, subscription.request, identity)
		}
		if err != nil {
			subscription.active = false
			c.failure(id, "UnauthorizedException", "Subscription authorization or schema is no longer valid")
			subscription.mu.Unlock()
			c.mu.Lock()
			if c.subscriptions[id] == subscription {
				delete(c.subscriptions, id)
			}
			c.mu.Unlock()
			continue
		}
		response, deliver := c.realtime.service.subscriptionEvent(c.ctx, snapshot, prepared, identity, mutationName, payload)
		if deliver {
			_ = c.send("data", id, response)
		}
		subscription.mu.Unlock()
	}
}

func (c *realtimeConnection) failure(id, kind, message string) {
	_ = c.send("error", id, map[string]any{"errors": []GraphQLError{{Message: message, ErrorType: kind}}})
}

func (c *realtimeConnection) send(kind, id string, payload any) error {
	var raw json.RawMessage
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = encoded
	}
	body, err := json.Marshal(realtimeMessage{Type: kind, ID: id, Payload: raw})
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	if c.ctx.Err() != nil {
		c.writeMu.Unlock()
		return c.ctx.Err()
	}
	_ = c.socket.SetWriteDeadline(time.Now().Add(realtimeWriteTimeout))
	err = wsutil.WriteServerMessage(c.socket, ws.OpText, body)
	c.writeMu.Unlock()
	if err != nil {
		c.close()
	}
	return err
}

func (c *realtimeConnection) closeFrame(code ws.StatusCode, reason string) {
	c.writeMu.Lock()
	_ = c.socket.SetWriteDeadline(time.Now().Add(realtimeWriteTimeout))
	_ = ws.WriteFrame(c.socket, ws.NewCloseFrame(ws.NewCloseFrameBody(code, reason)))
	c.writeMu.Unlock()
}

func (c *realtimeConnection) close() {
	c.closeOnce.Do(func() {
		c.cancel()
		_ = c.socket.Close()
		c.realtime.mu.Lock()
		delete(c.realtime.connections, c)
		c.realtime.mu.Unlock()
	})
}

func (rt *Realtime) Close() error {
	rt.mu.Lock()
	rt.closed = true
	connections := make([]*realtimeConnection, 0, len(rt.connections))
	for c := range rt.connections {
		connections = append(connections, c)
	}
	rt.mu.Unlock()
	for _, c := range connections {
		c.close()
	}
	rt.workers.Wait()
	return nil
}

// TODO: Comeback implement enhanced subscription filters/invalidation, AppSync
// Events, native quota/backpressure semantics and custom-domain/private endpoints.
// These live GraphQL sockets intentionally do not imply durable event replay.
