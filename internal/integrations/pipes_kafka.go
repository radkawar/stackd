package integrations

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
	secretapi "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	msk "stackd/internal/services/kafka"
	"stackd/internal/services/pipes"
)

type PipesKafkaClusters interface {
	ResolveCluster(context.Context, string, msk.ClusterDescribePermission) (msk.ClusterConnection, error)
}
type PipesKafkaSecrets interface {
	GetSecretValue(context.Context, *secretapi.GetSecretValueInput) (*secretapi.GetSecretValueOutput, *awswire.Error)
}

// PipesKafka connects only to explicit self-managed addresses or an owned MSK
// cluster resolved with current Pipes execution-role authority. No ambient AWS
// credentials, secret cache, or alternate weaker listener is used.
type PipesKafka struct {
	Roles    ServiceRoles
	Clusters PipesKafkaClusters
	Secrets  PipesKafkaSecrets
}

type pipesKafkaAccess struct {
	brokers                []string
	incarnation, mechanism string
	tls                    bool
	ca, credentials        []byte
}

func (a pipesKafkaAccess) equal(b pipesKafkaAccess) bool {
	return a.incarnation == b.incarnation && a.mechanism == b.mechanism && a.tls == b.tls && slices.Equal(a.brokers, b.brokers) && bytes.Equal(a.ca, b.ca) && bytes.Equal(a.credentials, b.credentials)
}

func (a *PipesKafka) access(ctx context.Context, p pipes.PipeRecord, session *pipesSession) (pipesKafkaAccess, error) {
	var access pipesKafkaAccess
	ctx, rejected := session.context(ctx)
	if rejected != nil {
		return access, rejected
	}
	if p.Source.Kind == "msk" {
		if a.Clusters == nil {
			return access, pipesDependency("MSK")
		}
		cluster, err := a.Clusters.ResolveCluster(ctx, p.SourceARN, msk.RequireDescribeClusterV2)
		if err != nil {
			return access, err
		}
		access.brokers, access.incarnation, access.tls, access.ca = cluster.Brokers, cluster.Incarnation, cluster.TLS, cluster.ServerCAPEM
		if cluster.SASLMechanism != p.Source.Kafka.Authentication {
			return access, &awswire.Error{Code: "ValidationException", Message: "Pipes source credentials must match the MSK cluster's strongest enabled authentication mode.", StatusCode: 400}
		}
	} else {
		access.brokers = append([]string{strings.TrimPrefix(p.SourceARN, "smk://")}, p.Source.Kafka.BootstrapServers...)
		access.tls = p.Source.Kafka.Authentication != "" || p.Source.Kafka.RootCASecretARN != ""
	}
	access.mechanism = p.Source.Kafka.Authentication
	if p.Source.Kafka.SecretARN != "" {
		value, err := a.secret(ctx, p.Source.Kafka.SecretARN)
		if err != nil {
			return access, err
		}
		access.credentials = value
	}
	if p.Source.Kafka.RootCASecretARN != "" {
		value, err := a.secret(ctx, p.Source.Kafka.RootCASecretARN)
		if err != nil {
			return access, err
		}
		var document struct {
			Certificate string `json:"certificate"`
		}
		if json.Unmarshal(value, &document) != nil || document.Certificate == "" {
			return access, errors.New("kafka server CA secret must contain a certificate PEM field")
		}
		access.ca = []byte(document.Certificate)
	}
	if len(access.brokers) == 0 {
		return access, errors.New("kafka source has no bootstrap brokers")
	}
	return access, nil
}
func (a *PipesKafka) secret(ctx context.Context, arn string) ([]byte, error) {
	if a.Secrets == nil {
		return nil, pipesDependency("Secrets Manager")
	}
	ctx = awsctx.WithViaService(ctx, "pipes.amazonaws.com")
	out, rejected := a.Secrets.GetSecretValue(ctx, &secretapi.GetSecretValueInput{SecretId: new(secretapi.SecretIdType(arn))})
	if rejected != nil {
		return nil, rejected
	}
	if out.SecretString == nil {
		return nil, errors.New("kafka source secret must contain a JSON SecretString")
	}
	return []byte(*out.SecretString), nil
}

func (a pipesKafkaAccess) security() (*tls.Config, sasl.Mechanism, error) {
	var config *tls.Config
	if a.tls {
		config = &tls.Config{MinVersion: tls.VersionTLS12}
		if len(a.ca) != 0 {
			config.RootCAs = x509.NewCertPool()
			if !config.RootCAs.AppendCertsFromPEM(a.ca) {
				return nil, nil, errors.New("kafka server CA secret does not contain a valid certificate")
			}
		}
	}
	if a.mechanism == "" {
		return config, nil, nil
	}
	if config == nil {
		return nil, nil, errors.New("kafka authentication requires TLS")
	}
	var document struct {
		Username           string `json:"username"`
		Password           string `json:"password"`
		Certificate        string `json:"certificate"`
		PrivateKey         string `json:"privateKey"`
		PrivateKeyPassword string `json:"privateKeyPassword"`
	}
	if json.Unmarshal(a.credentials, &document) != nil {
		return nil, nil, errors.New("kafka credential secret must be a JSON object")
	}
	if a.mechanism == "MTLS" {
		// TODO: Comeback: PBES1-encrypted PKCS#8 client private keys require a supported decryption implementation.
		if document.PrivateKeyPassword != "" || strings.Contains(document.PrivateKey, "ENCRYPTED") {
			return nil, nil, pipesDependency("Encrypted Kafka client private keys")
		}
		cert, err := tls.X509KeyPair([]byte(document.Certificate), []byte(document.PrivateKey))
		if err != nil {
			return nil, nil, errors.New("kafka client certificate secret contains an invalid certificate/privateKey pair")
		}
		config.Certificates = []tls.Certificate{cert}
		return config, nil, nil
	}
	if document.Username == "" || document.Password == "" {
		return nil, nil, errors.New("kafka credential secret requires nonempty username and password fields")
	}
	switch a.mechanism {
	case "PLAIN":
		return config, plain.Mechanism{Username: document.Username, Password: document.Password}, nil
	case "SCRAM-SHA-256":
		mechanism, err := scram.Mechanism(scram.SHA256, document.Username, document.Password)
		return config, mechanism, err
	case "SCRAM-SHA-512":
		mechanism, err := scram.Mechanism(scram.SHA512, document.Username, document.Password)
		return config, mechanism, err
	default:
		return nil, nil, pipesDependency("Kafka authentication mode " + a.mechanism)
	}
}

func (a *PipesKafka) Open(_ context.Context, p pipes.PipeRecord, identity pipes.KafkaIdentity) (pipes.KafkaConsumer, error) {
	session := &pipesSession{roles: a.Roles, pipe: p}
	return &pipesKafkaConsumer{source: kafkaMemberConfig{topic: p.Source.Kafka.Topic, groupID: pipes.KafkaGroup(p), clientID: "stackd-pipes-" + p.ID, startingPosition: p.Source.StartingPosition}, resolve: func(ctx context.Context) (pipesKafkaAccess, error) { return a.access(ctx, p, session) }, identity: identity}, nil
}
func (a *PipesKafka) Delete(ctx context.Context, p pipes.PipeRecord) error {
	if p.Source.Kafka.ConsumerGroupID != "" {
		return nil
	}
	if p.ID == "" {
		return errors.New("kafka group deletion requires an immutable pipe incarnation")
	}
	access, err := a.access(ctx, p, &pipesSession{roles: a.Roles, pipe: p})
	if err != nil {
		// An owned cluster that has already been deleted has no remaining groups.
		if p.Source.Kind == "msk" && errors.Is(err, msk.ErrNotFound) {
			return nil
		}
		return err
	}
	tlsConfig, mechanism, err := access.security()
	if err != nil {
		return err
	}
	transport := &kafka.Transport{TLS: tlsConfig, SASL: mechanism, ClientID: "stackd-pipes-" + p.ID}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := &kafka.Client{Addr: kafka.TCP(access.brokers...), Transport: transport}
	group := pipes.KafkaGroup(p)
	response, err := client.DeleteGroups(ctx, &kafka.DeleteGroupsRequest{GroupIDs: []string{group}})
	if err != nil {
		return err
	}
	result, present := response.Errors[group]
	if !present {
		return errors.New("kafka group deletion omitted the owned group")
	}
	if errors.Is(result, kafka.GroupIdNotFound) {
		return nil
	}
	return result
}

type pipesKafkaConsumer struct {
	source        kafkaMemberConfig
	resolve       func(context.Context) (pipesKafkaAccess, error)
	mu            sync.Mutex
	access        pipesKafkaAccess
	member        *pipesKafkaMember
	closed        bool
	identity      pipes.KafkaIdentity
	sourceChanged bool
}

func (c *pipesKafkaConsumer) current(ctx context.Context) (*pipesKafkaMember, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("kafka consumer is closed")
	}
	if c.sourceChanged {
		return nil, pipes.ErrKafkaSourceChanged
	}
	access, err := c.resolve(ctx)
	if err != nil {
		if c.member != nil {
			_ = c.member.close()
			c.member = nil
		}
		return nil, err
	}
	if c.member != nil && c.access.equal(access) {
		if err := c.checkIdentity(ctx, c.member); err != nil {
			return nil, err
		}
		return c.member, nil
	}
	if c.member != nil {
		if err := c.member.close(); err != nil {
			return nil, err
		}
		c.member = nil
	}
	member, err := newPipesKafkaMember(ctx, c.source, access)
	if err != nil {
		return nil, err
	}
	c.access, c.member = access, member
	if err := c.acceptIdentity(member.identity); err != nil {
		_ = member.close()
		c.member = nil
		return nil, err
	}
	return member, nil
}
func (c *pipesKafkaConsumer) acceptIdentity(identity pipes.KafkaIdentity) error {
	if c.identity == (pipes.KafkaIdentity{}) {
		c.identity = identity
	}
	if c.identity != identity {
		c.sourceChanged = true
		if c.member != nil {
			c.member.cancel()
		}
		return pipes.ErrKafkaSourceChanged
	}
	return nil
}
func (c *pipesKafkaConsumer) checkIdentity(ctx context.Context, member *pipesKafkaMember) error {
	identity, err := member.sourceIdentity(ctx)
	if err != nil {
		return err
	}
	return c.acceptIdentity(identity)
}
func (c *pipesKafkaConsumer) Identity(ctx context.Context) (pipes.KafkaIdentity, error) {
	member, err := c.current(ctx)
	if err != nil {
		return pipes.KafkaIdentity{}, err
	}
	return member.identity, nil
}
func (c *pipesKafkaConsumer) Assignments(ctx context.Context) ([]pipes.KafkaPartition, error) {
	member, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	return member.assignments(ctx)
}
func (c *pipesKafkaConsumer) Fetch(ctx context.Context, partition int, offset int64, limit int) (pipes.KafkaPage, error) {
	member, err := c.current(ctx)
	if err != nil {
		return pipes.KafkaPage{}, err
	}
	page, err := member.fetch(ctx, partition, offset, limit)
	if err != nil {
		return pipes.KafkaPage{}, err
	}
	// Fetch v11 addresses a name, so discard bytes if recreation overlapped it.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkIdentity(ctx, member); err != nil {
		return pipes.KafkaPage{}, err
	}
	return page, nil
}
func (c *pipesKafkaConsumer) Commit(ctx context.Context, offsets map[int]int64) error {
	member, err := c.current(ctx)
	if err != nil {
		return err
	}
	if err := member.commit(ctx, offsets); err != nil {
		return err
	}
	// OffsetCommit on Kafka 3.7 cannot atomically compare the topic ID. Detect
	// an overlapping replacement but do not pretend this can undo its commit.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkIdentity(ctx, member)
}
func (c *pipesKafkaConsumer) Lease(ctx context.Context, partition int) (context.Context, context.CancelFunc, error) {
	member, err := c.current(ctx)
	if err != nil {
		return nil, nil, err
	}
	return member.lease(ctx, partition)
}
func (c *pipesKafkaConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.member != nil {
		return c.member.close()
	}
	return nil
}
