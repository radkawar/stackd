package mq

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	amqp "github.com/rabbitmq/amqp091-go"
	"net"
	"net/url"
	service "stackd/internal/services/mq"
	"strconv"
	"sync"
	"time"
)

type Credentials struct{ Username, Password string }
type Message struct {
	ID     string
	Data   []byte
	Record json.RawMessage
}

// Consumer exposes real native delivery ownership, not a control-plane queue.
type Consumer interface {
	Fetch(context.Context, int) ([]Message, error)
	Acknowledge(context.Context, int) error
	Close() error
}

func (r *Runtime) OpenConsumer(ctx context.Context, broker service.Connection, credentials Credentials, queue, vhost string) (Consumer, error) {
	if credentials.Username == "" || credentials.Password == "" {
		return nil, errors.New("MQ credentials require username and password")
	}
	if broker.Engine == "ACTIVEMQ" {
		return r.openJMS(ctx, broker, credentials, queue)
	}
	if broker.Engine != "RABBITMQ" {
		return nil, errors.New("unsupported MQ native engine")
	}
	uri, err := url.Parse(broker.Endpoint.Address)
	if err != nil || uri.Scheme != "amqps" {
		return nil, errors.New("RabbitMQ requires a TLS endpoint")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(broker.Endpoint.CAPEM) {
		return nil, errors.New("MQ broker owner omitted TLS trust")
	}
	var socket net.Conn
	connection, err := amqp.DialConfig(broker.Endpoint.Address, amqp.Config{SASL: []amqp.Authentication{&amqp.PlainAuth{Username: credentials.Username, Password: credentials.Password}}, Vhost: vhost, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Heartbeat: 30 * time.Second, Dial: func(network, address string) (net.Conn, error) {
		var e error
		socket, e = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
		if e == nil {
			_ = socket.SetDeadline(time.Now().Add(10 * time.Second))
		}
		return socket, e
	}})
	if err != nil {
		return nil, errors.New("RabbitMQ TLS authentication failed: " + err.Error())
	}
	channel, err := connection.Channel()
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if _, err = channel.QueueDeclarePassive(queue, false, false, false, false, nil); err != nil {
		_ = connection.Close()
		return nil, err
	}
	_ = socket.SetDeadline(time.Time{})
	return &rabbitConsumer{connection: connection, channel: channel, socket: socket, queue: queue}, nil
}

type rabbitConsumer struct {
	mu         sync.Mutex
	connection *amqp.Connection
	channel    *amqp.Channel
	socket     net.Conn
	queue      string
	pending    []uint64
	closed     bool
}

func (c *rabbitConsumer) begin(ctx context.Context) (func(), error) {
	if c.closed {
		return nil, errors.New("MQ consumer is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.socket.SetDeadline(time.Now()) })
	return func() { stop(); _ = c.socket.SetDeadline(time.Time{}) }, nil
}
func (c *rabbitConsumer) Fetch(ctx context.Context, limit int) ([]Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	end, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	out := make([]Message, 0, min(limit, 100))
	for len(out) < limit {
		delivery, ok, e := c.channel.Get(c.queue, false)
		if e != nil {
			return nil, e
		}
		if !ok {
			break
		}
		record, e := rabbitRecord(delivery)
		if e != nil {
			return nil, e
		}
		c.pending = append(c.pending, delivery.DeliveryTag)
		id := delivery.MessageId
		if id == "" {
			id = strconv.FormatUint(delivery.DeliveryTag, 10)
		}
		out = append(out, Message{ID: id, Data: delivery.Body, Record: record})
	}
	return out, nil
}
func (c *rabbitConsumer) Acknowledge(ctx context.Context, count int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	end, err := c.begin(ctx)
	if err != nil {
		return err
	}
	defer end()
	if count < 1 || count > len(c.pending) {
		return errors.New("invalid MQ acknowledgment range")
	}
	if err = c.channel.Ack(c.pending[count-1], true); err != nil {
		return err
	}
	c.pending = c.pending[count:]
	return nil
}
func (c *rabbitConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	_ = c.socket.SetDeadline(time.Now().Add(time.Second))
	return c.connection.Close()
}
func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func rabbitRecord(v amqp.Delivery) ([]byte, error) {
	timestamp := any(nil)
	if !v.Timestamp.IsZero() {
		timestamp = v.Timestamp.UTC().Format("Jan 2, 2006, 3:04:05 PM")
	}
	properties := map[string]any{"contentType": nullString(v.ContentType), "contentEncoding": nullString(v.ContentEncoding), "headers": rabbitHeaders(v.Headers), "deliveryMode": v.DeliveryMode, "priority": v.Priority, "correlationId": nullString(v.CorrelationId), "replyTo": nullString(v.ReplyTo), "expiration": nullString(v.Expiration), "messageId": nullString(v.MessageId), "timestamp": timestamp, "type": nullString(v.Type), "userId": nullString(v.UserId), "appId": nullString(v.AppId), "clusterId": nil, "bodySize": len(v.Body)}
	return json.Marshal(struct {
		BasicProperties map[string]any `json:"basicProperties"`
		Redelivered     bool           `json:"redelivered"`
		Data            []byte         `json:"data"`
	}{properties, v.Redelivered, v.Body})
}
func rabbitHeaders(v amqp.Table) map[string]any {
	out := make(map[string]any, len(v))
	for k, value := range v {
		out[k] = rabbitHeader(value)
	}
	return out
}
func rabbitHeader(v any) any {
	switch x := v.(type) {
	case string:
		return rabbitBytes([]byte(x))
	case []byte:
		return rabbitBytes(x)
	case amqp.Table:
		return rabbitHeaders(x)
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = rabbitHeader(value)
		}
		return out
	default:
		return v
	}
}
func rabbitBytes(v []byte) any {
	out := make([]int, len(v))
	for i, x := range v {
		out[i] = int(x)
	}
	return map[string]any{"bytes": out}
}
