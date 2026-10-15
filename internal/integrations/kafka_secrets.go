package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	"stackd/internal/awsapi"
	kmsapi "stackd/internal/awsapi/kms"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/kafka"
	"stackd/internal/services/kms"
	"stackd/internal/services/secretsmanager"
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
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
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
	keyARN, err := a.key(ctx, secretARN)
	if err != nil {
		return kafka.SCRAMUser{}, err
	}
	return a.read(ctx, secretARN, keyARN)
}

// key checks the current configured CMK, not a historical version's fallback
// envelope. Callers hold the shared resource transaction when using its result.
func (a KafkaSecrets) key(ctx context.Context, secretARN string) (string, error) {
	metadata, rejected := a.Secrets.DescribeSecret(ctx, &api.DescribeSecretInput{SecretId: new(api.SecretIdType(secretARN))})
	if rejected != nil {
		return "", rejected
	}
	if metadata.KmsKeyId == nil || metadata.Name == nil || !strings.HasPrefix(string(*metadata.Name), "AmazonMSK_") {
		return "", kafkaSecretInvalid("SCRAM secret requires an AmazonMSK_ name and a customer managed KMS key.")
	}
	keyID := string(*metadata.KmsKeyId)
	if strings.HasPrefix(keyID, "alias/") || strings.Contains(keyID, ":alias/") {
		return "", kafkaSecretInvalid("SCRAM secret must specify a KMS key ID or key ARN, not an alias.")
	}
	if rejected := recordKMSActivity(ctx, a.Activity, "DescribeKey"); rejected != nil {
		return "", rejected
	}
	key, rejected := a.KMS.DescribeKey(kms.WithViaService(ctx, "kafka"), keyID)
	if rejected != nil {
		return "", rejected
	}
	if key.KeyManager == nil || string(*key.KeyManager) != "CUSTOMER" || key.Arn == nil {
		return "", kafkaSecretInvalid("SCRAM secret must use a customer managed KMS key.")
	}
	return string(*key.Arn), nil
}

func kafkaSCRAMAssociationFence(incarnation string, association kafka.SCRAMAssociation, legacy bool) error {
	if incarnation == "" || association.SecretARN == "" {
		return kafkaSecretInvalid("SCRAM association requires the exact cluster incarnation and secret ARN.")
	}
	if legacy && association.KMSKeyARN == "" && association.GrantID == "" && association.Incarnation == "" {
		return nil
	}
	if association.Incarnation != incarnation || association.KMSKeyARN == "" || association.GrantID == "" {
		return kafkaSecretInvalid("SCRAM secret requires reassociation with the current cluster incarnation and KMS key.")
	}
	return nil
}

func (a KafkaSecrets) command(ctx context.Context, name string, input any) (any, *awswire.Error) {
	if rejected := recordKMSActivity(ctx, a.Activity, name); rejected != nil {
		return nil, rejected
	}
	model, _ := awscatalog.LookupService("kms")
	operation, _ := model.Operation(name)
	return a.KMS.ExecuteCommand(kms.WithViaService(ctx, "kafka"), awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
}

// AssociateSCRAM joins the caller's shared resource transaction. AWS documents
// CreateGrant/RetireGrant dependencies and reassociation after CMK changes:
// https://docs.aws.amazon.com/msk/latest/developerguide/msk-password-tutorial.html
// The exact AWS SCRAM grant shape is uncaptured. This local least-privilege
// contract grants only current-key inspection and decrypt for this SecretARN,
// while the secret resource policy separately fences the exact source cluster.
func (a KafkaSecrets) AssociateSCRAM(ctx context.Context, clusterARN, incarnation, secretARN string, previous kafka.SCRAMAssociation) (kafka.SCRAMAssociation, error) {
	cluster, err := kafkaSecretScope(clusterARN, secretARN)
	if err != nil {
		return kafka.SCRAMAssociation{}, err
	}
	if cluster.Partition != "aws" {
		return kafka.SCRAMAssociation{}, kafkaSecretInvalid("SCRAM KMS grant associations are supported only in the aws partition.")
	}
	if incarnation == "" || previous.SecretARN != "" && previous.SecretARN != secretARN {
		return kafka.SCRAMAssociation{}, kafkaSecretInvalid("SCRAM association does not belong to this cluster and secret.")
	}
	if previous.SecretARN != "" {
		if err := kafkaSCRAMAssociationFence(incarnation, previous, true); err != nil {
			return kafka.SCRAMAssociation{}, err
		}
	}
	keyARN, err := a.key(ctx, secretARN)
	if err != nil {
		return kafka.SCRAMAssociation{}, err
	}
	// Recheck AWSCURRENT with the actual caller inside the same transaction.
	// Preflight credential validation must not authorize a later changed secret.
	if _, err := a.read(ctx, secretARN, keyARN); err != nil {
		return kafka.SCRAMAssociation{}, err
	}
	output, rejected := a.command(kms.WithAWSResourceGrant(ctx), "CreateGrant", &kmsapi.CreateGrantInput{
		KeyId:             new(kmsapi.KeyIdType(keyARN)),
		GranteePrincipal:  new(kmsapi.PrincipalIdType("kafka.amazonaws.com")),
		RetiringPrincipal: new(kmsapi.PrincipalIdType("kafka.amazonaws.com")),
		Operations:        kmsapi.GrantOperationList{"Decrypt", "DescribeKey"},
		// Secrets Manager also supplies SecretVersionId. A subset permits
		// ordinary AWSCURRENT rotation without granting access to other secrets.
		Constraints: &kmsapi.GrantConstraints{EncryptionContextSubset: kmsapi.EncryptionContextType{"SecretARN": kmsapi.EncryptionContextValue(secretARN)}},
	})
	if rejected != nil {
		return kafka.SCRAMAssociation{}, rejected
	}
	grant := output.(*kmsapi.CreateGrantOutput)
	association := kafka.SCRAMAssociation{SecretARN: secretARN, KMSKeyARN: keyARN, GrantID: string(*grant.GrantId), Incarnation: incarnation}
	if err := a.policy(ctx, clusterARN, secretARN, false); err != nil {
		return kafka.SCRAMAssociation{}, err
	}
	// Only retire an identity retained by this association; never discover or
	// adopt grants by principal, context, name, or ambient key-policy authority.
	if previous.GrantID != "" {
		if err := a.retire(ctx, previous); err != nil {
			return kafka.SCRAMAssociation{}, err
		}
	}
	return association, nil
}

func (a KafkaSecrets) LoadSCRAM(ctx context.Context, clusterARN, incarnation string, association kafka.SCRAMAssociation) (kafka.SCRAMUser, error) {
	cluster, err := kafkaSecretScope(clusterARN, association.SecretARN)
	if err != nil {
		return kafka.SCRAMUser{}, err
	}
	if err := kafkaSCRAMAssociationFence(incarnation, association, false); err != nil {
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
	currentKey, err := a.key(ctx, association.SecretARN)
	if err != nil {
		return kafka.SCRAMUser{}, err
	}
	if currentKey != association.KMSKeyARN {
		return kafka.SCRAMUser{}, kafkaSecretInvalid("SCRAM secret KMS key changed; re-associate the secret with the cluster.")
	}
	return a.read(ctx, association.SecretARN, currentKey)
}

func (a KafkaSecrets) read(ctx context.Context, secretARN, keyARN string) (kafka.SCRAMUser, error) {
	ctx = secretsmanager.WithRequiredKMSKey(ctx, keyARN)
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

// ReleaseSCRAM requires the current control-plane caller. Grant retirement and
// policy removal commit with the association, or all changes roll back together.
func (a KafkaSecrets) ReleaseSCRAM(ctx context.Context, clusterARN, incarnation string, association kafka.SCRAMAssociation) error {
	if _, err := kafkaSecretScope(clusterARN, association.SecretARN); err != nil {
		return err
	}
	if err := kafkaSCRAMAssociationFence(incarnation, association, true); err != nil {
		return err
	}
	if association.GrantID != "" {
		if err := a.retire(ctx, association); err != nil {
			return err
		}
	}
	return a.policy(ctx, clusterARN, association.SecretARN, true)
}

func (a KafkaSecrets) retire(ctx context.Context, association kafka.SCRAMAssociation) error {
	_, rejected := a.command(ctx, "RetireGrant", &kmsapi.RetireGrantInput{KeyId: new(kmsapi.KeyIdType(association.KMSKeyARN)), GrantId: new(kmsapi.GrantIdType(association.GrantID))})
	// A separately revoked grant (or deleted key) has no remaining authority.
	if rejected != nil && rejected.Code != "NotFoundException" {
		return rejected
	}
	return nil
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
			"Action": []string{"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"}, "Resource": secretARN,
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
