package integrations

import (
	"context"
	"errors"
	"testing"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
	msk "stackd/internal/services/kafka"
	"stackd/internal/services/lambda"
)

// Only native readiness is controlled here. Permissions, managed-policy loading,
// role assumption and policy revocation use the real IAM/credential owners.
type mskAuthorityRuntime struct{}

func (mskAuthorityRuntime) Ensure(context.Context, msk.Specification) (msk.Endpoint, error) {
	return msk.Endpoint{}, errors.New("unexpected broker creation")
}
func (mskAuthorityRuntime) Status(context.Context, msk.Specification) (msk.Endpoint, error) {
	return msk.Endpoint{SecurityMode: "PLAINTEXT", Brokers: []msk.Broker{{ID: 1, Address: "127.0.0.1:19092"}}}, nil
}
func (mskAuthorityRuntime) Reboot(context.Context, msk.Specification, int32) (msk.Endpoint, error) {
	return msk.Endpoint{}, errors.New("unexpected broker reboot")
}
func (mskAuthorityRuntime) Delete(context.Context, msk.Specification) error {
	return errors.New("unexpected broker deletion")
}
func (mskAuthorityRuntime) Close() error { return nil }

func TestLambdaMSKDescribeAlternativesUseCurrentExecutionRole(t *testing.T) {
	// AWS permits either describe API version, while Pipes retains its V2
	// requirement. Managed-policy reference and alternate-action documentation:
	// https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSLambdaMSKExecutionRole.html
	// https://docs.aws.amazon.com/lambda/latest/dg/with-msk-permissions.html
	f := newLambdaRoleFixture(t)
	repository := msk.NewMemoryRepository(nil)
	cluster := msk.ClusterRecord{Scope: msk.Scope{Partition: f.scope.Partition, AccountID: f.scope.AccountID, Region: "us-east-1"}, ARN: "arn:aws:kafka:us-east-1:123456789012:cluster/owned/incarnation", Name: "owned", Incarnation: "incarnation", KafkaVersion: "3.7.1", SecurityMode: "PLAINTEXT", Brokers: 1, State: "ACTIVE", Version: 1, Created: f.clock.Now()}
	if err := repository.Update(t.Context(), func(tx msk.Transaction) error { return tx.PutCluster(cluster) }); err != nil {
		t.Fatal(err)
	}
	service := msk.New(msk.Config{Repository: repository, Runtime: mskAuthorityRuntime{}, Authorizer: f.adapter.Authorizer, Clock: f.clock})
	t.Cleanup(func() { _ = service.Close() })
	owner := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: f.scope.Partition, AccountID: f.scope.AccountID, Region: "us-east-1"})
	session, wire := openLambdaSourceSession(owner, f.adapter.ServiceRoles, lambda.FunctionKey{Scope: lambda.Scope{Partition: f.scope.Partition, Account: f.scope.AccountID, Region: "us-east-1"}, Name: "f"}, f.role.Arn)
	if wire != nil {
		t.Fatal(wire)
	}
	const managed = "arn:aws:iam::aws:policy/service-role/AWSLambdaMSKExecutionRole"
	const boundary = "arn:aws:iam::123456789012:policy/v2-source-boundary"
	f.update(t, func(tx iam.WriteTx) error {
		return tx.PutManagedPolicy(f.scope, iam.ManagedPolicy{Arn: boundary, PolicyName: "v2-source-boundary", PolicyId: "ANPAMSKBOUNDARY", DefaultVersionId: "v1", IsAttachable: true, Versions: map[string]*iam.PolicyVersion{"v1": {VersionId: "v1", IsDefaultVersion: true, Document: `{"Statement":{"Effect":"Allow","Action":["kafka:DescribeClusterV2","kafka:GetBootstrapBrokers"],"Resource":"*"}}`}}})
	})
	for _, row := range []struct {
		name              string
		managed, boundary bool
		policy            string
		lambda, pipes     bool
	}{
		{name: "managed execution policy", managed: true, lambda: true, pipes: true},
		{name: "legacy describe only", policy: `{"Statement":{"Effect":"Allow","Action":["kafka:DescribeCluster","kafka:GetBootstrapBrokers"],"Resource":"*"}}`, lambda: true},
		{name: "V2 describe only", policy: `{"Statement":{"Effect":"Allow","Action":["kafka:DescribeClusterV2","kafka:GetBootstrapBrokers"],"Resource":"*"}}`, lambda: true, pipes: true},
		{name: "V2 denied but independent legacy API permitted", managed: true, policy: `{"Statement":{"Effect":"Deny","Action":"kafka:DescribeClusterV2","Resource":"*"}}`, lambda: true},
		{name: "legacy denied but V2 permitted", managed: true, policy: `{"Statement":{"Effect":"Deny","Action":"kafka:DescribeCluster","Resource":"*"}}`, lambda: true, pipes: true},
		{name: "bootstrap denied", managed: true, policy: `{"Statement":{"Effect":"Deny","Action":"kafka:GetBootstrapBrokers","Resource":"*"}}`},
		{name: "both descriptions denied", managed: true, policy: `{"Statement":{"Effect":"Deny","Action":["kafka:DescribeCluster","kafka:DescribeClusterV2"],"Resource":"*"}}`},
		{name: "describe alternatives cannot cross identity and boundary grants", boundary: true, policy: `{"Statement":{"Effect":"Allow","Action":["kafka:DescribeCluster","kafka:GetBootstrapBrokers"],"Resource":"*"}}`},
		{name: "execution policy detached"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f.role.IdentityPolicies = iam.IdentityPolicies{Inline: map[string]string{}, Attached: map[string]struct{}{}}
			f.role.PermissionsBoundary = nil
			if row.boundary {
				f.role.PermissionsBoundary = &iam.Boundary{PermissionsBoundaryType: "Policy", PermissionsBoundaryArn: boundary}
			}
			if row.managed {
				f.role.Attached[managed] = struct{}{}
			}
			if row.policy != "" {
				f.role.Inline["current"] = row.policy
			}
			f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
			current, wire := session.context(owner)
			if wire != nil {
				t.Fatal(wire)
			}
			for _, consumer := range []struct {
				name       string
				permission msk.ClusterDescribePermission
				allowed    bool
			}{{"Lambda", msk.AllowEitherDescribeCluster, row.lambda}, {"Pipes", msk.RequireDescribeClusterV2, row.pipes}} {
				connection, err := service.ResolveCluster(current, cluster.ARN, consumer.permission)
				if consumer.allowed {
					if err != nil || connection.ARN != cluster.ARN || connection.Incarnation != cluster.Incarnation {
						t.Fatalf("%s current role rejected: %+v %v", consumer.name, connection, err)
					}
				} else {
					var denied *awswire.Error
					if !errors.As(err, &denied) || denied.StatusCode != 403 || len(connection.Brokers) != 0 {
						t.Fatalf("%s exposed endpoint without required authority: %+v %v", consumer.name, connection, err)
					}
				}
			}
		})
	}
}
