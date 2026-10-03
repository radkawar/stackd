package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	native "stackd/compute/mq"
	"stackd/internal/authorization"
	secretapi "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/services/lambda"
	mq "stackd/internal/services/mq"
	"sync"
)

type LambdaMQBrokers interface {
	ResolveBroker(context.Context, string) (mq.Connection, error)
}
type LambdaMQNative interface {
	OpenConsumer(context.Context, mq.Connection, native.Credentials, string, string) (native.Consumer, error)
}

// LambdaMQ resolves all source authority on every native fetch, retry and ack.
// Secrets Manager owns secret versions/KMS decryption; EC2 owns network authority.
type LambdaMQ struct {
	Roles      ServiceRoles
	Brokers    LambdaMQBrokers
	Secrets    PipesKafkaSecrets
	Authorizer authorization.Authorizer
	Native     LambdaMQNative
}
type mqAccess struct {
	broker      mq.Connection
	credentials native.Credentials
}

func (a *LambdaMQ) access(ctx context.Context, session *lambdaSourceSession, mapping lambda.EventSourceMappingRecord) (mqAccess, error) {
	var out mqAccess
	ctx, wire := session.context(ctx)
	if wire != nil {
		return out, wire
	}
	if a.Brokers == nil || a.Secrets == nil || a.Authorizer == nil || a.Native == nil {
		return out, errors.New("MQ source requires broker, native protocol, network authority and Secrets Manager owners")
	}
	var err error
	out.broker, err = a.Brokers.ResolveBroker(ctx, mapping.EventSourceARN)
	if err != nil {
		return out, err
	}
	expected := mapping.Settings.MQ.Identity
	if expected.BrokerID != "" && (expected.BrokerID != out.broker.ID || expected.Engine != out.broker.Engine) {
		return out, errors.New("MQ source broker incarnation changed")
	}
	for _, action := range []string{"CreateNetworkInterface", "DeleteNetworkInterface", "DescribeNetworkInterfaces", "DescribeSecurityGroups", "DescribeSubnets", "DescribeVpcs"} {
		if rejected := a.Authorizer.Authorize(ctx, authorization.Request{Action: "ec2:" + action, ResourceARN: "*"}); rejected != nil {
			return out, rejected
		}
	}
	secret, wire := a.Secrets.GetSecretValue(awsctx.WithViaService(ctx, "lambda.amazonaws.com"), &secretapi.GetSecretValueInput{SecretId: new(secretapi.SecretIdType(mapping.Settings.MQ.SecretARN))})
	if wire != nil {
		return out, wire
	}
	if secret.SecretString == nil {
		return out, errors.New("MQ BASIC_AUTH secret must contain JSON SecretString")
	}
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.Unmarshal([]byte(*secret.SecretString), &credentials) != nil || credentials.Username == "" || credentials.Password == "" {
		return out, errors.New("MQ BASIC_AUTH secret requires username and password")
	}
	out.credentials = native.Credentials{Username: credentials.Username, Password: credentials.Password}
	return out, nil
}
func (a *LambdaMQ) sourceAccess(ctx context.Context, function lambda.FunctionKey, role string, mapping lambda.EventSourceMappingRecord) (*lambdaSourceSession, mqAccess, error) {
	if mapping.Settings.MQ == nil {
		return nil, mqAccess{}, errors.New("MQ mapping settings are required")
	}
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return nil, mqAccess{}, wire
	}
	access, err := a.access(ctx, session, mapping)
	return session, access, err
}

func (a *LambdaMQ) Check(ctx context.Context, function lambda.FunctionKey, role string, mapping lambda.EventSourceMappingRecord) (lambda.MQIdentity, error) {
	_, access, err := a.sourceAccess(ctx, function, role, mapping)
	if err != nil {
		return lambda.MQIdentity{}, err
	}
	return lambda.MQIdentity{BrokerID: access.broker.ID, Engine: access.broker.Engine}, nil
}

func (a *LambdaMQ) Open(ctx context.Context, function lambda.FunctionKey, role string, mapping lambda.EventSourceMappingRecord) (lambda.MQConsumer, error) {
	session, access, err := a.sourceAccess(ctx, function, role, mapping)
	if err != nil {
		return nil, err
	}
	consumer, err := a.Native.OpenConsumer(ctx, access.broker, access.credentials, mapping.Settings.MQ.Queue, mapping.Settings.MQ.VirtualHost)
	if err != nil {
		return nil, err
	}
	return &lambdaMQConsumer{adapter: a, session: session, mapping: mapping, access: access, native: consumer}, nil
}

type lambdaMQConsumer struct {
	mu      sync.Mutex
	adapter *LambdaMQ
	session *lambdaSourceSession
	mapping lambda.EventSourceMappingRecord
	access  mqAccess
	native  native.Consumer
	closed  bool
}

func (c *lambdaMQConsumer) current(ctx context.Context) error {
	if c.closed {
		return errors.New("MQ consumer is closed")
	}
	access, err := c.adapter.access(ctx, c.session, c.mapping)
	if err != nil {
		return err
	}
	if access.broker.ID != c.access.broker.ID || access.broker.Engine != c.access.broker.Engine || access.broker.Endpoint.NativeID != c.access.broker.Endpoint.NativeID || access.broker.Endpoint.Address != c.access.broker.Endpoint.Address || !bytes.Equal(access.broker.Endpoint.CAPEM, c.access.broker.Endpoint.CAPEM) || access.credentials != c.access.credentials {
		return errors.New("MQ source endpoint or current credentials changed; reconnect without acknowledging")
	}
	return nil
}
func (c *lambdaMQConsumer) Identity(ctx context.Context) (lambda.MQIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.current(ctx); err != nil {
		return lambda.MQIdentity{}, err
	}
	return lambda.MQIdentity{BrokerID: c.access.broker.ID, Engine: c.access.broker.Engine}, nil
}
func (c *lambdaMQConsumer) Fetch(ctx context.Context, limit int) ([]lambda.MQMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.current(ctx); err != nil {
		return nil, err
	}
	records, err := c.native.Fetch(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]lambda.MQMessage, len(records))
	for i, v := range records {
		out[i] = lambda.MQMessage{ID: v.ID, Data: v.Data, Record: v.Record}
	}
	return out, nil
}
func (c *lambdaMQConsumer) Acknowledge(ctx context.Context, count int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.current(ctx); err != nil {
		return err
	}
	return c.native.Acknowledge(ctx, count)
}
func (c *lambdaMQConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.native.Close()
}
