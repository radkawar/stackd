package rdsdata

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type target struct {
	cluster                              Cluster
	secret, database, username, password string
}

func (s *Service) resolve(ctx context.Context, action, resource, secret, database string) (target, error) {
	var t target
	m := awsctx.FromContext(ctx)
	a, err := arn.Parse(resource)
	if err != nil || a.Service != "rds" || !strings.HasPrefix(a.Resource, "cluster:") || len(a.Resource) == len("cluster:") {
		return t, failure("BadRequestException", "resourceArn must identify an Aurora DB cluster.")
	}
	if a.Partition != m.Partition || a.AccountID != m.AccountID || a.Region != m.Region {
		return t, failure("AccessDeniedException", "The cluster is outside the caller's account, partition or region.", 403)
	}
	if secret == "" {
		return t, failure("InvalidSecretException", "A secret is required.")
	}
	if strings.HasPrefix(secret, "arn:") {
		a, err := arn.Parse(secret)
		if err != nil || a.Service != "secretsmanager" || !strings.HasPrefix(a.Resource, "secret:") {
			return t, failure("InvalidSecretException", "The secret identifier is invalid.")
		}
		if a.Partition != m.Partition || a.AccountID != m.AccountID || a.Region != m.Region {
			return t, failure("AccessDeniedException", "The secret is outside the caller's account, partition or region.", 403)
		}
	}
	if s.clusters == nil || s.secrets == nil {
		return t, failure("ServiceUnavailableError", "The database or secret authority is unavailable.", 503)
	}
	c, lookupErr := s.clusters.ResolveDataCluster(ctx, resource)
	conditions := map[string][]string{}
	for k, v := range c.Tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], k)
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "rds-data:" + action, ResourceARN: resource, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}); rejected != nil {
		return t, rejected
	}
	if lookupErr != nil {
		var wire *awswire.Error
		if errors.As(lookupErr, &wire) && (wire.Code == "DBClusterNotFoundFault" || wire.Code == "DBClusterNotFound" || wire.Code == "ResourceNotFoundException") {
			return t, failure("HttpEndpointNotEnabledException", "HttpEndpoint is not enabled for resource "+resource+".")
		}
		return t, lookupErr
	}
	if c.ARN != resource || (c.Engine != "aurora-postgresql" && c.Engine != "aurora-mysql") {
		return t, failure("BadRequestException", "Only modeled Aurora clusters support the Data API.")
	}
	if !c.HTTPEnabled {
		return t, failure("HttpEndpointNotEnabledException", "HttpEndpoint is not enabled for resource "+resource+".")
	}
	if c.Status != "available" {
		return t, failure("DatabaseUnavailableException", "The DB cluster writer is unavailable.", 504)
	}
	if c.Endpoint.Address == "" || c.Endpoint.Port == 0 {
		return t, failure("DatabaseNotFoundException", "The DB cluster has no available DB instance.", 404)
	}
	username, password, err := s.secrets.Credentials(ctx, secret)
	if err != nil {
		var wire *awswire.Error
		if errors.As(err, &wire) && (wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException") {
			return t, wire
		}
		if errors.As(err, &wire) && wire.Code == "InvalidSecretException" {
			return t, wire
		}
		return t, failure("SecretsErrorException", "Unable to retrieve the database secret.")
	}
	if username == "" || password == "" {
		return t, failure("InvalidSecretException", "The secret must contain a database username and password.")
	}
	if database == "" {
		database = c.Database
	}
	return target{c, secret, database, username, password}, nil
}
