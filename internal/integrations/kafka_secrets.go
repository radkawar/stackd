package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	kmsapi "stackd/internal/awsapi/kms"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/kafka"
)

// KafkaSecrets keeps native SCRAM passwords out of the MSK repository. Secret
// reads use the current Secrets Manager/KMS command boundary, never ambient AWS.
type KafkaSecrets struct {
	Secrets interface {
		DescribeSecret(context.Context, *api.DescribeSecretInput) (*api.DescribeSecretOutput, *awswire.Error)
		GetSecretValue(context.Context, *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error)
		GetResourcePolicy(context.Context, *api.GetResourcePolicyInput) (*api.GetResourcePolicyOutput, *awswire.Error)
		PutResourcePolicy(context.Context, *api.PutResourcePolicyInput) (*api.PutResourcePolicyOutput, *awswire.Error)
		DeleteResourcePolicy(context.Context, *api.DeleteResourcePolicyInput) (*api.DeleteResourcePolicyOutput, *awswire.Error)
	}
	KMS interface {
		DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	}
	Activity IAMActivity
}

func kafkaSecretInvalid(message string) *awswire.Error {
	return &awswire.Error{Code: "BadRequestException", Message: message, StatusCode: 400}
}

func kafkaSecretScope(clusterARN, secretARN string) (arn.ARN, error) {
	cluster, err := arn.Parse(clusterARN)
	if err != nil || cluster.Service != "kafka" || !strings.HasPrefix(cluster.Resource, "cluster/") {
		return arn.ARN{}, kafkaSecretInvalid("Invalid MSK cluster ARN.")
	}
	secret, err := arn.Parse(secretARN)
	if err != nil || secret.Service != "secretsmanager" || secret.Partition != cluster.Partition || secret.Region != cluster.Region || secret.AccountID != cluster.AccountID || !strings.HasPrefix(secret.Resource, "secret:AmazonMSK_") {
		return arn.ARN{}, kafkaSecretInvalid("SCRAM secret must have an AmazonMSK_ name in the cluster account and Region.")
	}
	return cluster, nil
}

func (a KafkaSecrets) ResolveSCRAM(ctx context.Context, clusterARN, secretARN string) (kafka.SCRAMUser, error) {
	if _, err := kafkaSecretScope(clusterARN, secretARN); err != nil {
		return kafka.SCRAMUser{}, err
	}
	metadata, rejected := a.Secrets.DescribeSecret(ctx, &api.DescribeSecretInput{SecretId: new(api.SecretIdType(secretARN))})
	if rejected != nil {
		return kafka.SCRAMUser{}, rejected
	}
	if metadata.KmsKeyId == nil || !strings.HasPrefix(string(*metadata.Name), "AmazonMSK_") {
		return kafka.SCRAMUser{}, kafkaSecretInvalid("SCRAM secret requires an AmazonMSK_ name and a customer managed KMS key.")
	}
	if rejected := recordKMSActivity(ctx, a.Activity, "DescribeKey"); rejected != nil {
		return kafka.SCRAMUser{}, rejected
	}
	key, rejected := a.KMS.DescribeKey(ctx, string(*metadata.KmsKeyId))
	if rejected != nil {
		return kafka.SCRAMUser{}, rejected
	}
	if key.KeyManager == nil || string(*key.KeyManager) != "CUSTOMER" {
		return kafka.SCRAMUser{}, kafkaSecretInvalid("SCRAM secret must use a customer managed KMS key.")
	}
	user, err := a.read(ctx, secretARN)
	if err != nil {
		return kafka.SCRAMUser{}, err
	}
	return user, nil
}

// AssociateSCRAM joins the MSK resource transaction. This mutates only typed
// policy state; native credential application follows as a retained job.
func (a KafkaSecrets) AssociateSCRAM(ctx context.Context, clusterARN, secretARN string) error {
	if _, err := kafkaSecretScope(clusterARN, secretARN); err != nil {
		return err
	}
	return a.policy(ctx, clusterARN, secretARN, false)
}

func (a KafkaSecrets) LoadSCRAM(ctx context.Context, clusterARN, secretARN string) (kafka.SCRAMUser, error) {
	cluster, err := kafkaSecretScope(clusterARN, secretARN)
	if err != nil {
		return kafka.SCRAMUser{}, err
	}
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: cluster.Partition, AccountID: cluster.AccountID, Region: cluster.Region,
		RequestID: uuid.NewString(), ParentEventID: origin.ParentEventID,
		InvokedBy: "kafka.amazonaws.com", SourceIP: "kafka.amazonaws.com", UserAgent: "kafka.amazonaws.com",
		TransportKnown: true, SecureTransport: true,
	})
	ctx = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "kafka.amazonaws.com", SourceARN: clusterARN, Type: "AWSService"})
	return a.read(ctx, secretARN)
}

func (a KafkaSecrets) read(ctx context.Context, secretARN string) (kafka.SCRAMUser, error) {
	out, rejected := a.Secrets.GetSecretValue(ctx, &api.GetSecretValueInput{SecretId: new(api.SecretIdType(secretARN))})
	if rejected != nil {
		return kafka.SCRAMUser{}, rejected
	}
	var value struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if out.SecretString == nil || json.Unmarshal([]byte(*out.SecretString), &value) != nil || value.Username == "" || value.Password == "" {
		return kafka.SCRAMUser{}, kafkaSecretInvalid("SCRAM secret must contain nonempty username and password strings.")
	}
	return kafka.SCRAMUser{Username: value.Username, Password: value.Password}, nil
}

// ReleaseSCRAM requires the current control-plane caller. A broker service
// principal has only read authority and cannot rewrite customer secret policies.
func (a KafkaSecrets) ReleaseSCRAM(ctx context.Context, clusterARN, secretARN string) error {
	if _, err := kafkaSecretScope(clusterARN, secretARN); err != nil {
		return err
	}
	return a.policy(ctx, clusterARN, secretARN, true)
}

func (a KafkaSecrets) policy(ctx context.Context, clusterARN, secretARN string, remove bool) error {
	out, rejected := a.Secrets.GetResourcePolicy(ctx, &api.GetResourcePolicyInput{SecretId: new(api.SecretIdType(secretARN))})
	if rejected != nil {
		if remove && rejected.Code == "ResourceNotFoundException" {
			return nil
		}
		return rejected
	}
	doc := map[string]json.RawMessage{"Version": json.RawMessage(`"2012-10-17"`)}
	if out.ResourcePolicy != nil {
		if err := json.Unmarshal([]byte(*out.ResourcePolicy), &doc); err != nil {
			return err
		}
	}
	var statements []json.RawMessage
	raw := doc["Statement"]
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &statements); err != nil {
			var single map[string]json.RawMessage
			if err := json.Unmarshal(raw, &single); err != nil {
				return err
			}
			statements = []json.RawMessage{raw}
		}
	}
	id := fmt.Sprintf("StackdMSKSCRAM%x", sha256.Sum256([]byte(clusterARN)))
	retained := make([]json.RawMessage, 0, len(statements)+1)
	found := false
	for _, statement := range statements {
		var fields struct {
			SID string `json:"Sid"`
		}
		if err := json.Unmarshal(statement, &fields); err != nil {
			return err
		}
		if fields.SID == id {
			found = true
			continue
		}
		retained = append(retained, statement)
	}
	if remove && !found {
		return nil
	}
	if !remove {
		cluster, _ := arn.Parse(clusterARN)
		statement, err := json.Marshal(map[string]any{
			"Sid": id, "Effect": "Allow", "Principal": map[string]string{"Service": "kafka.amazonaws.com"},
			"Action": "secretsmanager:GetSecretValue", "Resource": secretARN,
			"Condition": map[string]any{"StringEquals": map[string]string{"aws:SourceAccount": cluster.AccountID}, "ArnEquals": map[string]string{"aws:SourceArn": clusterARN}},
		})
		if err != nil {
			return err
		}
		retained = append(retained, statement)
	}
	if len(retained) == 0 {
		_, rejected = a.Secrets.DeleteResourcePolicy(ctx, &api.DeleteResourcePolicyInput{SecretId: new(api.SecretIdType(secretARN))})
		if rejected != nil {
			return rejected
		}
		return nil
	}
	encoded, err := json.Marshal(retained)
	if err != nil {
		return err
	}
	doc["Statement"] = encoded
	encoded, err = json.Marshal(doc)
	if err != nil {
		return err
	}
	_, rejected = a.Secrets.PutResourcePolicy(ctx, &api.PutResourcePolicyInput{SecretId: new(api.SecretIdType(secretARN)), ResourcePolicy: new(api.NonEmptyResourcePolicyType(encoded)), BlockPublicPolicy: new(api.BooleanType(true))})
	if rejected != nil {
		return rejected
	}
	return nil
}
