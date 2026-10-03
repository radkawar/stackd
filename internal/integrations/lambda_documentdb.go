package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	engine "stackd/engine/docdb"
	secretapi "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/docdb"
	"stackd/internal/services/lambda"
)

type LambdaDocumentDBClusters interface {
	ResolveCluster(context.Context, string) (docdb.SourceCluster, error)
}
type LambdaDocumentDBSecrets interface {
	GetSecretValue(context.Context, *secretapi.GetSecretValueInput) (*secretapi.GetSecretValueOutput, *awswire.Error)
}

// LambdaDocumentDB borrows the authoritative DocumentDB endpoint. Neither source
// documents, passwords nor cluster metadata are retained in Lambda storage.
type LambdaDocumentDB struct {
	Roles    ServiceRoles
	Clusters LambdaDocumentDBClusters
	Secrets  LambdaDocumentDBSecrets
}
type documentDBAccess struct {
	cluster            docdb.SourceCluster
	username, password string
}
type lambdaDocumentDBConsumer struct {
	adapter  *LambdaDocumentDB
	session  *lambdaSourceSession
	mapping  lambda.EventSourceMappingRecord
	access   documentDBAccess
	client   *mongo.Client
	stream   *mongo.ChangeStream
	position lambda.DocumentDBCheckpoint
}

func (a *LambdaDocumentDB) sourceAccess(ctx context.Context, function lambda.FunctionKey, role string, mapping lambda.EventSourceMappingRecord, checkpoint lambda.DocumentDBCheckpoint) (*lambdaSourceSession, documentDBAccess, error) {
	var empty documentDBAccess
	if mapping.Settings.DocumentDB == nil {
		return nil, empty, errors.New("DocumentDB source configuration is required")
	}
	if a.Clusters == nil || a.Secrets == nil {
		return nil, empty, errors.New("DocumentDB source requires the DocumentDB and Secrets Manager owners")
	}
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return nil, empty, wire
	}
	c := lambdaDocumentDBConsumer{adapter: a, session: session, mapping: mapping, position: checkpoint}
	access, err := c.resolve(ctx)
	return session, access, err
}

// Check validates current authority and source identity without opening a watch.
func (a *LambdaDocumentDB) Check(ctx context.Context, function lambda.FunctionKey, role string, mapping lambda.EventSourceMappingRecord, checkpoint lambda.DocumentDBCheckpoint) (string, error) {
	_, access, err := a.sourceAccess(ctx, function, role, mapping, checkpoint)
	return access.cluster.RuntimeID, err
}

func (a *LambdaDocumentDB) Open(ctx context.Context, function lambda.FunctionKey, role string, mapping lambda.EventSourceMappingRecord, checkpoint lambda.DocumentDBCheckpoint) (lambda.DocumentDBConsumer, error) {
	session, access, err := a.sourceAccess(ctx, function, role, mapping, checkpoint)
	if err != nil {
		return nil, err
	}
	if err := access.ready(); err != nil {
		return nil, err
	}
	client, err := engine.Open(ctx, access.cluster.Endpoint, access.username, access.password)
	if err != nil {
		return nil, err
	}
	c := &lambdaDocumentDBConsumer{adapter: a, session: session, mapping: mapping, position: checkpoint, access: access, client: client}
	if err = c.openStream(ctx); err != nil {
		_ = c.Close()
		return nil, documentDBStreamError(err)
	}
	return c, nil
}
func (c *lambdaDocumentDBConsumer) resolve(ctx context.Context) (documentDBAccess, error) {
	var access documentDBAccess
	ctx, wire := c.session.context(ctx)
	if wire != nil {
		return access, wire
	}
	d := c.mapping.Settings.DocumentDB
	out, wire := c.adapter.Secrets.GetSecretValue(awsctx.WithViaService(ctx, "lambda.amazonaws.com"), &secretapi.GetSecretValueInput{SecretId: new(secretapi.SecretIdType(d.SecretARN))})
	if wire != nil {
		return access, wire
	}
	if out.SecretString == nil {
		return access, errors.New("DocumentDB BASIC_AUTH secret requires a JSON SecretString")
	}
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(*out.SecretString), &credentials); err != nil || credentials.Username == "" || credentials.Password == "" {
		return access, errors.New("DocumentDB BASIC_AUTH secret requires username and password")
	}
	cluster, err := c.adapter.Clusters.ResolveCluster(ctx, c.mapping.EventSourceARN)
	if err != nil {
		return access, err
	}
	if cluster.ARN != c.mapping.EventSourceARN || cluster.RuntimeID == "" {
		return access, errors.New("DocumentDB owner returned an invalid source identity")
	}
	if d.Incarnation != "" && d.Incarnation != cluster.RuntimeID || c.position.Incarnation != "" && c.position.Incarnation != cluster.RuntimeID {
		return access, errors.New("DocumentDB source incarnation changed; recreate the event source mapping")
	}
	access.cluster = cluster
	access.username = credentials.Username
	access.password = credentials.Password
	return access, nil
}

func (a documentDBAccess) ready() error {
	if !a.cluster.Ready {
		return errors.New("DocumentDB cluster has no ready native writer")
	}
	// The current owner exposes only host-local native engines and rejects VPC
	// attachment requests. Never turn that explicit boundary into an arbitrary
	// network connection or an unverified TLS fallback.
	// TODO: Comeback consume owner-managed private endpoints through Lambda's
	// source-network lease when the DocumentDB owner supports VPC attachments.
	host := a.cluster.Endpoint.Address
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("DocumentDB source requires an owner-managed loopback endpoint")
		}
	}
	return nil
}

func (c *lambdaDocumentDBConsumer) Check(ctx context.Context) error {
	access, err := c.resolve(ctx)
	if err != nil {
		return err
	}
	if err := access.ready(); err != nil {
		return err
	}
	a, b := access.cluster.Endpoint, c.access.cluster.Endpoint
	if access.username != c.access.username || access.password != c.access.password || a.Address != b.Address || a.Port != b.Port || a.ReplicaSet != b.ReplicaSet || !bytes.Equal(a.CA, b.CA) {
		return errors.New("DocumentDB source connection or credentials changed")
	}
	return nil
}
func (c *lambdaDocumentDBConsumer) openStream(ctx context.Context) error {
	d := c.mapping.Settings.DocumentDB
	c.position.Mapping = c.mapping.Key
	c.position.Incarnation = c.access.cluster.RuntimeID
	opts := options.ChangeStream().SetBatchSize(int32(c.mapping.Settings.BatchSize)).SetMaxAwaitTime(100 * time.Millisecond)
	if d.FullDocument == "UpdateLookup" {
		opts.SetFullDocument(options.UpdateLookup)
	} else {
		opts.SetFullDocument(options.Default)
	}
	if len(c.position.ResumeToken) > 0 {
		opts.SetResumeAfter(bson.Raw(c.position.ResumeToken))
	} else {
		if c.position.StartSeconds == 0 {
			var stamp bson.Timestamp
			switch d.StartingPosition {
			case "AT_TIMESTAMP":
				stamp = bson.Timestamp{T: uint32(d.StartingPositionTimestamp.Unix())}
			case "TRIM_HORIZON":
				// This is the real compatible MongoDB engine's retention bound. No Lambda
				// wall-clock estimate or copied document journal substitutes for its oplog.
				var oldest struct {
					Timestamp bson.Timestamp `bson:"ts"`
				}
				if err := c.client.Database("local").Collection("oplog.rs").FindOne(ctx, bson.D{}, options.FindOne().SetSort(bson.D{{Key: "$natural", Value: 1}}).SetProjection(bson.D{{Key: "ts", Value: 1}})).Decode(&oldest); err != nil {
					return err
				}
				stamp = oldest.Timestamp
			default:
				var hello struct {
					OperationTime bson.Timestamp `bson:"operationTime"`
				}
				if err := c.client.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello); err != nil {
					return err
				}
				stamp = hello.OperationTime
				// startAtOperationTime is inclusive; LATEST begins after the
				// observed native operation, not by replaying that last write.
				stamp.I++
				if stamp.I == 0 {
					stamp.T++
				}
			}
			if stamp.T == 0 {
				return errors.New("DocumentDB source did not supply an initial operation timestamp")
			}
			c.position.StartSeconds, c.position.StartIncrement = stamp.T, stamp.I
		}
		opts.SetStartAtOperationTime(&bson.Timestamp{T: c.position.StartSeconds, I: c.position.StartIncrement})
	}
	var err error
	database := c.client.Database(d.Database)
	if d.Collection != "" {
		c.stream, err = database.Collection(d.Collection).Watch(ctx, mongo.Pipeline{}, opts)
	} else {
		c.stream, err = database.Watch(ctx, mongo.Pipeline{}, opts)
	}
	return err
}
func (c *lambdaDocumentDBConsumer) Position() lambda.DocumentDBCheckpoint {
	v := c.position
	v.ResumeToken = slices.Clone(v.ResumeToken)
	return v
}
func (c *lambdaDocumentDBConsumer) Next(ctx context.Context) (lambda.DocumentDBRecord, bool, error) {
	if err := c.Check(ctx); err != nil {
		return lambda.DocumentDBRecord{}, false, err
	}
	if !c.stream.TryNext(ctx) {
		if err := documentDBStreamError(c.stream.Err()); err != nil {
			return lambda.DocumentDBRecord{}, false, err
		}
		if c.stream.ID() == 0 {
			return lambda.DocumentDBRecord{}, false, lambda.ErrDocumentDBStreamClosed
		}
		return lambda.DocumentDBRecord{}, false, nil
	}
	raw, err := bson.MarshalExtJSON(c.stream.Current, false, false)
	if err != nil {
		return lambda.DocumentDBRecord{}, false, err
	}
	token := c.stream.ResumeToken()
	if len(token) == 0 {
		return lambda.DocumentDBRecord{}, false, errors.New("DocumentDB change stream omitted its resume token")
	}
	record := lambda.DocumentDBRecord{Event: raw, ResumeToken: slices.Clone(token)}
	if t, _, ok := c.stream.Current.Lookup("clusterTime").TimestampOK(); ok {
		record.Time = time.Unix(int64(t), 0)
	}
	return record, true, nil
}
func documentDBStreamError(err error) error {
	var command mongo.CommandError
	if errors.As(err, &command) && (command.Code == 286 || command.Code == 136) {
		return fmt.Errorf("%w: %s", lambda.ErrDocumentDBHistoryLost, command.Name)
	}
	return err
}
func (c *lambdaDocumentDBConsumer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var streamErr, clientErr error
	if c.stream != nil {
		streamErr = c.stream.Close(ctx)
	}
	if c.client != nil {
		clientErr = c.client.Disconnect(ctx)
	}
	return errors.Join(streamErr, clientErr)
}
