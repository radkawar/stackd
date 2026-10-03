package appsync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"stackd/clock"
	api "stackd/internal/awsapi/appsync"
)

const realtimeSchema = `
type Query { ping: String }
type Mutation { publish(id: ID!, text: String!): Message }
type Subscription { changed(id: ID): Message @aws_subscribe(mutations: ["publish"]) }
type Message { id: ID! text: String secret: String }
`

func realtimeFixture(t *testing.T) (*Service, Repository, *httptest.Server, []APIRecord) {
	t.Helper()
	manual := clock.NewManual(time.Unix(1800000000, 0))
	repository := NewMemoryRepository(nil)
	service := NewWithConfig(Config{Repository: repository, Clock: manual})
	server := httptest.NewServer(http.HandlerFunc(service.ServeDataHTTP))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	var records []APIRecord
	for _, id := range []string{"first-api", "other-api"} {
		record := authRecord("API_KEY")
		record.Key.ID = id
		record.Schema, record.SchemaStatus = realtimeSchema, "SUCCESS"
		record.API.Uris = api.MapOfStringToString{"GRAPHQL": api.String(server.URL + "/_stackd/appsync/" + id + "/graphql")}
		err := repository.Update(t.Context(), func(tx Transaction) error {
			if err := tx.PutAPI(record); err != nil {
				return err
			}
			for _, key := range []string{"subscriber", "publisher"} {
				if err := tx.PutAPIKey(APIKeyRecord{API: record.Key, Key: api.ApiKey{Id: new(api.String(key)), Expires: new(api.Long(manual.Now().Add(time.Hour).Unix()))}}); err != nil {
					return err
				}
			}
			if err := tx.PutDataSource(DataSourceRecord{API: record.Key, DataSource: api.DataSource{Name: new(api.ResourceName("none")), Type: new(api.DataSourceType("NONE"))}}); err != nil {
				return err
			}
			return tx.PutResolver(ResolverRecord{API: record.Key, Resolver: api.Resolver{TypeName: new(api.ResourceName("Mutation")), FieldName: new(api.ResourceName("publish")), DataSourceName: new(api.ResourceName("none")), Kind: new(api.ResolverKind("UNIT")), Code: new(api.Code(`export function request(ctx) { return {payload: {id: ctx.args.id, text: ctx.args.text, secret: "not selected by mutation"}}; } export function response(ctx) { return ctx.result; }`))}})
		})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return service, repository, server, records
}

type realtimeClient struct {
	conn   net.Conn
	reader io.Reader
}

func dialRealtime(t *testing.T, serverURL, apiID, key, headerMode string) *realtimeClient {
	t.Helper()
	endpoint, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]string{"host": endpoint.Host, "x-api-key": key})
	if err != nil {
		t.Fatal(err)
	}
	dialer := ws.Dialer{Protocols: []string{"graphql-ws"}}
	address := "ws" + strings.TrimPrefix(serverURL, "http") + "/_stackd/appsync/" + apiID + "/graphql/realtime"
	if headerMode == "protocol" {
		dialer.Protocols = append(dialer.Protocols, "header-"+base64.RawURLEncoding.EncodeToString(header))
	} else {
		address += "?header=" + url.QueryEscape(base64.StdEncoding.EncodeToString(header)) + "&payload=e30="
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, buffered, handshake, err := dialer.Dial(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	if handshake.Protocol != "graphql-ws" {
		conn.Close()
		t.Fatalf("negotiated %q", handshake.Protocol)
	}
	client := &realtimeClient{conn: conn, reader: conn}
	if buffered != nil {
		client.reader = buffered
	}
	t.Cleanup(func() { _ = conn.Close() })
	client.send(t, map[string]any{"type": "connection_init"})
	client.expect(t, "connection_ack", "")
	client.expect(t, "ka", "")
	return client
}

func (c *realtimeClient) send(t *testing.T, message any) {
	t.Helper()
	body, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := wsutil.WriteClientMessage(c.conn, ws.OpText, body); err != nil {
		t.Fatal(err)
	}
}

func (c *realtimeClient) expect(t *testing.T, kind, id string) realtimeMessage {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	body, op, err := wsutil.ReadServerData(struct {
		io.Reader
		io.Writer
	}{c.reader, c.conn})
	if err != nil {
		t.Fatal(err)
	}
	if op != ws.OpText {
		t.Fatalf("message opcode=%v", op)
	}
	var message realtimeMessage
	if err := json.Unmarshal(body, &message); err != nil {
		t.Fatal(err)
	}
	if message.Type != kind || message.ID != id {
		t.Fatalf("received %s/%s (%s), want %s/%s", message.Type, message.ID, message.Payload, kind, id)
	}
	return message
}

func (c *realtimeClient) start(t *testing.T, serverURL, id, key, filter string) {
	t.Helper()
	endpoint, _ := url.Parse(serverURL)
	request, err := json.Marshal(GraphQLRequest{Query: `subscription($id: ID) { event: changed(id: $id) { id body: text secret } }`, Variables: map[string]any{"id": filter}})
	if err != nil {
		t.Fatal(err)
	}
	c.send(t, map[string]any{"type": "start", "id": id, "payload": map[string]any{"data": string(request), "extensions": map[string]any{"authorization": map[string]string{"host": endpoint.Host, "x-api-key": key}}}})
}

func realtimeMutation(t *testing.T, serverURL, apiID, id, text string) {
	t.Helper()
	body, err := json.Marshal(GraphQLRequest{Query: `mutation($id: ID!, $text: String!) { publish(id:$id,text:$text) { id text } }`, Variables: map[string]any{"id": id, "text": text}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), "POST", serverURL+"/_stackd/appsync/"+apiID+"/graphql", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("x-api-key", "publisher")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result GraphQLResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || len(result.Errors) != 0 {
		t.Fatalf("mutation failed: HTTP %d %+v", response.StatusCode, result)
	}
	published, _ := result.Data["publish"].(map[string]any)
	if published["id"] != id || published["text"] != text {
		t.Fatalf("mutation result = %#v", result.Data)
	}
}

func (c *realtimeClient) barrier(t *testing.T) {
	t.Helper()
	// The mutation HTTP response is sent after synchronous publication. A
	// protocol-error response fences the socket without sleeps/quiet timeouts.
	c.send(t, map[string]any{"type": "unsupported-barrier", "id": "barrier"})
	c.expect(t, "error", "barrier")
}

func TestRealtimeSelectionFilteringIsolationStopAndRevocation(t *testing.T) {
	_, repository, server, records := realtimeFixture(t)
	first := dialRealtime(t, server.URL, records[0].Key.ID, "subscriber", "query")
	other := dialRealtime(t, server.URL, records[1].Key.ID, "subscriber", "protocol")
	first.start(t, server.URL, "main", "wrong-key", "one")
	first.expect(t, "error", "main")
	first.start(t, server.URL, "main", "subscriber", "one")
	first.expect(t, "start_ack", "main")
	other.start(t, server.URL, "main", "subscriber", "one")
	other.expect(t, "start_ack", "main")
	first.start(t, server.URL, "main", "subscriber", "one")
	first.expect(t, "error", "main")

	realtimeMutation(t, server.URL, records[0].Key.ID, "two", "filtered")
	first.barrier(t)
	other.barrier(t)
	realtimeMutation(t, server.URL, records[0].Key.ID, "one", "delivered")
	message := first.expect(t, "data", "main")
	var result GraphQLResponse
	if err := json.Unmarshal(message.Payload, &result); err != nil {
		t.Fatal(err)
	}
	event, _ := result.Data["event"].(map[string]any)
	if len(result.Errors) != 0 || event["id"] != "one" || event["body"] != "delivered" || event["secret"] != nil {
		t.Fatalf("subscription projected unselected payload or lost aliases: %s", message.Payload)
	}
	other.barrier(t)
	first.send(t, map[string]any{"type": "stop", "id": "main"})
	first.expect(t, "complete", "main")
	realtimeMutation(t, server.URL, records[0].Key.ID, "one", "after-stop")
	first.barrier(t)
	first.start(t, server.URL, "revoked", "subscriber", "one")
	first.expect(t, "start_ack", "revoked")
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.DeleteAPIKey(records[0].Key, "subscriber") }); err != nil {
		t.Fatal(err)
	}
	realtimeMutation(t, server.URL, records[0].Key.ID, "one", "after-revocation")
	first.expect(t, "error", "revoked")
	other.barrier(t)
}
