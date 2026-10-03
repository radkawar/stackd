package integrations

import (
	"context"
	"encoding/json"
	"errors"

	secretapi "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	msk "stackd/internal/services/kafka"
	"stackd/internal/services/lambda"
)

func (a *LambdaKafka) access(ctx context.Context, mapping lambda.EventSourceMappingRecord) (pipesKafkaAccess, error) {
	d := mapping.Settings.Kafka
	access := pipesKafkaAccess{mechanism: d.Authentication}
	if len(d.BootstrapServers) != 0 {
		access.brokers = d.BootstrapServers
		access.tls = d.Authentication != "" || d.RootCASecretARN != ""
	} else {
		if a.Clusters == nil {
			return access, errors.New("MSK source requires the MSK cluster owner")
		}
		cluster, err := a.Clusters.ResolveCluster(ctx, mapping.EventSourceARN, msk.AllowEitherDescribeCluster)
		if err != nil {
			return access, err
		}
		if cluster.SASLMechanism != d.Authentication {
			return access, errors.New("MSK source credentials must match the cluster's strongest enabled authentication mode")
		}
		access.brokers, access.incarnation, access.tls, access.ca = cluster.Brokers, cluster.Incarnation, cluster.TLS, cluster.ServerCAPEM
	}
	if d.SecretARN != "" {
		credentials, err := a.secret(ctx, d.SecretARN)
		if err != nil {
			return access, err
		}
		access.credentials = credentials
	}
	if d.RootCASecretARN != "" {
		value, err := a.secret(ctx, d.RootCASecretARN)
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
	return access, nil
}

func (a *LambdaKafka) secret(ctx context.Context, arn string) ([]byte, error) {
	if a.Secrets == nil {
		return nil, errors.New("kafka source authentication requires Secrets Manager")
	}
	out, wire := a.Secrets.GetSecretValue(awsctx.WithViaService(ctx, "lambda.amazonaws.com"), &secretapi.GetSecretValueInput{SecretId: new(secretapi.SecretIdType(arn))})
	if wire != nil {
		return nil, wire
	}
	if out.SecretString == nil {
		return nil, errors.New("kafka source credentials must contain a JSON SecretString")
	}
	return []byte(*out.SecretString), nil
}
