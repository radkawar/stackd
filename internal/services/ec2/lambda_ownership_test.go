package ec2_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqliam "stackd/storage/sqlite/iam"
)

func lambdaEC2Command(t *testing.T, ctx context.Context, service interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}, name, action string, input any) any {
	t.Helper()
	model, _ := awscatalog.LookupService(name)
	op, _ := model.Operation(action)
	out, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		t.Fatalf("%s: %v", action, rejected)
	}
	return out
}

func lambdaEC2RoleContext(ctx context.Context, role *iamapi.Role) context.Context {
	m := awsctx.FromContext(ctx)
	m.PrincipalARN = "arn:aws:sts::" + m.AccountID + ":assumed-role/" + string(*role.RoleName) + "/lambda"
	m.PrincipalID = string(*role.RoleId) + ":lambda"
	m.IssuerARN, m.IssuerID = string(*role.Arn), string(*role.RoleId)
	m.InvokedBy, m.SessionType = "lambda.amazonaws.com", "AssumeRole"
	return awsctx.WithMetadata(ctx, m)
}

func TestLambdaSourceNetworkOwnershipAndCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			var networks ec2.Repository
			var identities iam.Repository
			var database *sql.DB
			var service *ec2.Service
			var roles *iam.Service
			path := filepath.Join(t.TempDir(), "lambda-ownership.sqlite")
			open := func() {
				if backend == "memory" {
					domain := memory.NewDomain()
					networks, identities = ec2.NewMemoryRepository(domain), iam.NewMemoryRepository(domain)
				} else {
					var err error
					database, err = sqlite.Open(root, path)
					if err != nil {
						t.Fatal(err)
					}
					networks, identities = sqlec2.New(database), sqliam.New(database)
				}
				roles = iam.NewWithConfig(iam.Config{Repository: identities})
				service = ec2.New(ec2.Config{Repository: networks, Authorizer: authorization.New(roles, nil)})
			}
			close := func() {
				service.Close()
				roles.Close()
				if database != nil {
					database.Close()
				}
			}
			open()
			t.Cleanup(close)
			createRole := func() *iamapi.Role {
				return lambdaEC2Command(t, root, roles, "iam", "CreateRole", &iamapi.CreateRoleRequest{RoleName: new(iamapi.RoleNameType("lambda-source")), AssumeRolePolicyDocument: new(iamapi.PolicyDocumentType(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`))}).(*iamapi.CreateRoleResponse).Role
			}
			policy := func(document string) {
				lambdaEC2Command(t, root, roles, "iam", "PutRolePolicy", &iamapi.PutRolePolicyRequest{RoleName: new(iamapi.RoleNameType("lambda-source")), PolicyName: new(iamapi.PolicyNameType("network")), PolicyDocument: new(iamapi.PolicyDocumentType(document))})
			}
			allow := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:CreateNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DescribeSubnets","ec2:DescribeSecurityGroups","ec2:DeleteNetworkInterface"],"Resource":"*"}}`
			role := createRole()
			policy(allow)
			ctx := lambdaEC2RoleContext(root, role)
			vpc := lambdaEC2Command(t, root, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.89.0.0/16"))}).(*api.CreateVpcResult).Vpc
			subnet := lambdaEC2Command(t, root, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String("10.89.1.0/24")), AvailabilityZone: new(api.String("us-east-1a"))}).(*api.CreateSubnetResult).Subnet
			mapping := "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:00000000-0000-4000-8000-000000000001"
			selected, err := service.SelectLambdaSourceSubnet(ctx, mapping, []string{string(*subnet.SubnetId)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			allocation, err := service.AllocateLambdaSourceNetwork(ctx, mapping, selected.Key.ID, nil)
			if err != nil {
				t.Fatal(err)
			}
			id := string(*allocation.Interface.NetworkInterfaceId)
			repeated, err := service.AllocateLambdaSourceNetwork(ctx, mapping, selected.Key.ID, nil)
			if err != nil || string(*repeated.Interface.NetworkInterfaceId) != id || repeated.Network.Address != allocation.Network.Address {
				t.Fatalf("allocation retry changed identity: %#v %v", repeated, err)
			}
			if err := networks.Update(root, func(tx ec2.Transaction) error {
				record, err := tx.NetworkInterface(ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: id})
				if err != nil {
					return err
				}
				if record.TaskOwnerARN != "" || record.LambdaMappingOwnerARN != mapping {
					t.Fatalf("wrong immutable owner: %#v", record)
				}
				record.Data.Description = new(api.String("mutable display description"))
				return tx.PutNetworkInterface(record)
			}); err != nil {
				t.Fatal(err)
			}
			if backend == "sqlite" {
				close()
				open()
			}
			retained, err := service.LookupLambdaSourceNetwork(ctx, mapping)
			if err != nil || string(*retained.Interface.NetworkInterfaceId) != id || retained.Network.Address != allocation.Network.Address {
				t.Fatalf("restart lost exact network: %#v %v", retained, err)
			}
			other := mapping[:len(mapping)-1] + "2"
			if err := service.ReleaseLambdaSourceNetwork(ctx, other, id); err == nil {
				t.Fatal("other mapping released ENI")
			}
			customer := lambdaEC2Command(t, root, service, "ec2", "CreateNetworkInterface", &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(selected.Key.ID)), Description: new(api.String(mapping))}).(*api.CreateNetworkInterfaceResult).NetworkInterface
			if err := service.ReleaseLambdaSourceNetwork(ctx, mapping, string(*customer.NetworkInterfaceId)); err == nil {
				t.Fatal("description spoof released customer ENI")
			}
			policy(`{"Statement":{"Effect":"Deny","Action":"ec2:*","Resource":"*"}}`)
			if _, err := service.ResolveLambdaSourceNetwork(ctx, mapping, id); err == nil {
				t.Fatal("current IAM deny ignored")
			}
			if err := service.ReleaseLambdaSourceNetwork(ctx, mapping, id); err == nil {
				t.Fatal("delete IAM deny ignored")
			}
			lambdaEC2Command(t, root, roles, "iam", "DeleteRolePolicy", &iamapi.DeleteRolePolicyRequest{RoleName: role.RoleName, PolicyName: new(iamapi.PolicyNameType("network"))})
			lambdaEC2Command(t, root, roles, "iam", "DeleteRole", &iamapi.DeleteRoleRequest{RoleName: role.RoleName})
			fresh := createRole()
			policy(allow)
			if _, err := service.ResolveLambdaSourceNetwork(ctx, mapping, id); err == nil {
				t.Fatal("deleted role session acquired recreated principal authority")
			}
			ctx = lambdaEC2RoleContext(root, fresh)
			if err := service.ReleaseLambdaSourceNetwork(ctx, mapping, id); err != nil {
				t.Fatal(err)
			}
			if backend == "sqlite" {
				close()
				open()
			}
			if _, err := service.LookupLambdaSourceNetwork(ctx, mapping); !errors.Is(err, ec2.ErrNotFound) {
				t.Fatalf("released mapping recovered after restart: %v", err)
			}
			if err := service.ReleaseLambdaSourceNetwork(ctx, mapping, id); err != nil {
				t.Fatalf("idempotent release: %v", err)
			}
			if _, err := service.AllocateLambdaSourceNetwork(ctx, mapping, selected.Key.ID, nil); err == nil {
				t.Fatal("stale allocation resurrected deleted mapping ENI")
			}
			remaining := lambdaEC2Command(t, root, service, "ec2", "DescribeNetworkInterfaces", &api.DescribeNetworkInterfacesRequest{NetworkInterfaceIds: api.NetworkInterfaceIdList{api.NetworkInterfaceId(*customer.NetworkInterfaceId)}}).(*api.DescribeNetworkInterfacesResult)
			if len(remaining.NetworkInterfaces) != 1 || string(*remaining.NetworkInterfaces[0].NetworkInterfaceId) != string(*customer.NetworkInterfaceId) {
				t.Fatal("customer ENI mutated during managed cleanup")
			}
		})
	}
}

func TestLambdaManagedTerminationCannotAdoptCustomerInstance(t *testing.T) {
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	domain := memory.NewDomain()
	repository := ec2.NewMemoryRepository(domain)
	identity := iam.NewWithConfig(iam.Config{Repository: iam.NewMemoryRepository(domain)})
	t.Cleanup(func() { identity.Close() })
	service := ec2.New(ec2.Config{Repository: repository, Authorizer: authorization.New(identity, nil)})
	t.Cleanup(func() { service.Close() })
	if err := identity.EnsureServiceLinkedRole(root, "lambda.amazonaws.com"); err != nil {
		t.Fatal(err)
	}
	role := lambdaEC2Command(t, root, identity, "iam", "GetRole", &iamapi.GetRoleRequest{RoleName: new(iamapi.RoleNameType("AWSServiceRoleForLambda"))}).(*iamapi.GetRoleResponse).Role
	ctx := lambdaEC2RoleContext(root, role)
	provider := "arn:aws:lambda:us-east-1:123456789012:capacity-provider:owned"
	managedID, customerID := "i-00000000000000001", "i-00000000000000002"
	if err := repository.Update(root, func(tx ec2.Transaction) error {
		for _, id := range []string{managedID, customerID} {
			record := ec2.InstanceRecord{Key: ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: id}, Generation: 1, Data: api.Instance{InstanceId: new(api.String(id)), State: &api.InstanceState{Name: new(api.InstanceStateName("stopped")), Code: new(api.Integer(80))}}}
			if id == managedID {
				record.LambdaCapacityProviderARN, record.LambdaManagedGeneration = provider, "immutable-guest-generation"
			}
			if err := tx.PutInstance(record); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request := &api.TerminateInstancesRequest{InstanceIds: api.InstanceIdStringList{api.InstanceId(managedID), api.InstanceId(customerID)}}
	if _, err := service.TerminateLambdaManagedInstance(ctx, provider, request); err == nil {
		t.Fatal("mixed managed/customer termination accepted")
	}
	if err := repository.View(root, func(tx ec2.Reader) error {
		record, err := tx.Instance(ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: managedID})
		if err != nil {
			return err
		}
		if string(*record.Data.State.Name) != "stopped" {
			t.Fatal("partial managed termination committed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request.InstanceIds = request.InstanceIds[:1]
	if _, err := service.TerminateLambdaManagedInstance(ctx, provider+"-other", request); err == nil {
		t.Fatal("wrong provider terminated instance")
	}
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("TerminateInstances")
	if _, err := service.ExecuteCommand(root, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: request}); err == nil {
		t.Fatal("public EC2 bypassed Lambda ownership")
	}
	result, err := service.TerminateLambdaManagedInstance(ctx, provider, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TerminatingInstances) != 1 || string(*result.TerminatingInstances[0].CurrentState.Name) != "shutting-down" {
		t.Fatalf("managed termination did not change actual state: %#v", result)
	}
}
