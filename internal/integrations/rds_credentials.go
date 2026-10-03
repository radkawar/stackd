package integrations

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/rds"
	"stackd/internal/services/rdsdata"
)

// RDSCredentialCipher protects retained native bootstrap credentials through KMS.
// It does not advertise cloud-volume encryption or create a public secret.
type RDSCredentialCipher struct {
	Roles *RDSRoles
	Keys  ServiceDataKeys
}
type rdsDatabaseCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a RDSCredentialCipher) Seal(ctx context.Context, resource, username, password string) ([]byte, error) {
	ctx, err := a.Roles.context(ctx, resource, true)
	if err != nil {
		return nil, err
	}
	key, rejected := a.Keys.EnsureServiceKey(ctx, "rds")
	if rejected != nil {
		return nil, rejected
	}
	plain, err := json.Marshal(rdsDatabaseCredential{Username: username, Password: password})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	cipher, _, rejected := a.Keys.Encrypt(ctx, key, plain, map[string]string{"aws:rds:db-arn": resource})
	if rejected != nil {
		return nil, rejected
	}
	return cipher, nil
}

func (a RDSCredentialCipher) Open(ctx context.Context, resource string, ciphertext []byte) (string, string, error) {
	ctx, err := a.Roles.context(ctx, resource, false)
	if err != nil {
		return "", "", err
	}
	plain, _, rejected := a.Keys.Decrypt(ctx, ciphertext, map[string]string{"aws:rds:db-arn": resource})
	if rejected != nil {
		return "", "", rejected
	}
	defer clear(plain)
	var credential rdsDatabaseCredential
	if json.Unmarshal(plain, &credential) != nil || credential.Username == "" || credential.Password == "" {
		return "", "", errors.New("invalid retained RDS credential")
	}
	return credential.Username, credential.Password, nil
}

// RDSDataSecrets forwards the current Data API caller to the ordinary secret
// owner. Secret host/port/engine fields never select a network destination.
type RDSDataSecrets struct {
	Secrets interface {
		GetSecretValue(context.Context, *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error)
	}
}

func (a RDSDataSecrets) Credentials(ctx context.Context, reference string) (string, string, error) {
	m := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
	}
	m.RequestID = uuid.NewString()
	m.InvokedBy = "rds-data.amazonaws.com"
	m.SourceIP, m.UserAgent = m.InvokedBy, m.InvokedBy
	m.TransportKnown, m.SecureTransport = true, true
	ctx = awsctx.WithViaService(awsctx.WithMetadata(ctx, m), m.InvokedBy)
	out, rejected := a.Secrets.GetSecretValue(ctx, &api.GetSecretValueInput{SecretId: new(api.SecretIdType(reference))})
	if rejected != nil {
		return "", "", rejected
	}
	var credential rdsDatabaseCredential
	if out.SecretString == nil || json.Unmarshal([]byte(*out.SecretString), &credential) != nil || credential.Username == "" || credential.Password == "" {
		return "", "", &awswire.Error{Code: "InvalidSecretException", Message: "The secret must contain database username and password string fields.", StatusCode: 400}
	}
	return credential.Username, credential.Password, nil
}

// RDSDataClusters exposes no native administrator credential to the Data API.
type RDSDataClusters struct {
	Databases interface {
		ResolveDataCluster(context.Context, string) (rds.DataCluster, error)
	}
}

func (a RDSDataClusters) ResolveDataCluster(ctx context.Context, reference string) (rdsdata.Cluster, error) {
	cluster, err := a.Databases.ResolveDataCluster(ctx, reference)
	if err != nil {
		return rdsdata.Cluster{}, err
	}
	return rdsdata.Cluster{ARN: cluster.ARN, Engine: cluster.Engine, Database: cluster.Database, Status: cluster.Status, Endpoint: cluster.Endpoint, HTTPEnabled: cluster.HTTPEnabled, Tags: cluster.Tags}, nil
}
