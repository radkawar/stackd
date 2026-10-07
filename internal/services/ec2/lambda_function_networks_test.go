package ec2_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqliam "stackd/storage/sqlite/iam"
)

func TestLambdaFunctionNetworkIncarnationAuthorityAndPersistence(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			var repository ec2.Repository
			var identities iam.Repository
			var database *sql.DB
			var service *ec2.Service
			var roles *iam.Service
			path := filepath.Join(t.TempDir(), "function-network.sqlite")
			open := func() {
				if backend == "memory" {
					domain := memory.NewDomain()
					repository, identities = ec2.NewMemoryRepository(domain), iam.NewMemoryRepository(domain)
				} else {
					var err error
					database, err = sqlite.Open(root, path)
					if err != nil {
						t.Fatal(err)
					}
					repository, identities = sqlec2.New(database), sqliam.New(database)
				}
				roles = iam.NewWithConfig(iam.Config{Repository: identities})
				service = ec2.New(ec2.Config{Repository: repository, Authorizer: authorization.New(roles, nil)})
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
			role := lambdaEC2Command(t, root, roles, "iam", "CreateRole", &iamapi.CreateRoleRequest{RoleName: new(iamapi.RoleNameType("lambda-function")), AssumeRolePolicyDocument: new(iamapi.PolicyDocumentType(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`))}).(*iamapi.CreateRoleResponse).Role
			policy := func(body string) {
				lambdaEC2Command(t, root, roles, "iam", "PutRolePolicy", &iamapi.PutRolePolicyRequest{RoleName: role.RoleName, PolicyName: new(iamapi.PolicyNameType("network")), PolicyDocument: new(iamapi.PolicyDocumentType(body))})
			}
			allow := `{"Statement":{"Effect":"Allow","Action":["ec2:CreateNetworkInterface","ec2:DeleteNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DescribeSubnets","ec2:DescribeSecurityGroups"],"Resource":"*"}}`
			policy(allow)
			ctx := lambdaEC2RoleContext(root, role)
			vpc := lambdaEC2Command(t, root, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.90.0.0/16"))}).(*api.CreateVpcResult).Vpc
			subnet := lambdaEC2Command(t, root, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String("10.90.1.0/24")), AvailabilityZone: new(api.String("us-east-1a"))}).(*api.CreateSubnetResult).Subnet
			group := lambdaEC2Command(t, root, service, "ec2", "CreateSecurityGroup", &api.CreateSecurityGroupRequest{VpcId: new(api.VpcId(*vpc.VpcId)), GroupName: new(api.String("function")), Description: new(api.String("function"))}).(*api.CreateSecurityGroupResult)
			function, incarnation := "arn:aws:lambda:us-east-1:123456789012:function:owned", "function-create-1/environment-1"
			subnets, groups := []string{string(*subnet.SubnetId)}, []string{string(*group.GroupId)}
			selected, err := service.SelectLambdaFunctionSubnet(ctx, function, incarnation, subnets, groups)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.SelectLambdaFunctionSubnet(root, function, incarnation, subnets, groups); err == nil {
				t.Fatal("root identity was treated as Lambda execution role")
			}
			allocation, err := service.AllocateLambdaFunctionNetwork(ctx, function, incarnation, selected.Key.ID, groups)
			if err != nil {
				t.Fatal(err)
			}
			id := string(*allocation.Interface.NetworkInterfaceId)
			repeated, err := service.AllocateLambdaFunctionNetwork(ctx, function, incarnation, selected.Key.ID, groups)
			if err != nil || string(*repeated.Interface.NetworkInterfaceId) != id {
				t.Fatalf("retry changed ENI: %v", err)
			}
			if err := repository.Update(root, func(tx ec2.Transaction) error {
				record, err := tx.NetworkInterface(ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: id})
				if err != nil {
					return err
				}
				if record.LambdaFunctionOwnerARN != function || record.LambdaFunctionOwnerIncarnation != incarnation || record.TaskOwnerARN != "" || record.LambdaMappingOwnerARN != "" {
					t.Fatal("incorrect immutable function owner")
				}
				record.Data.Description = new(api.String("spoofed mutable description"))
				return tx.PutNetworkInterface(record)
			}); err != nil {
				t.Fatal(err)
			}
			if backend == "sqlite" {
				close()
				open()
			}
			spec, err := service.ResolveLambdaFunctionNetwork(ctx, function, incarnation, id)
			if err != nil || spec.Address != allocation.Network.Address {
				t.Fatalf("restart lost ENI identity: %v", err)
			}
			owners, err := service.ListLambdaFunctionNetworks(ctx, function, "function-create-1")
			if err != nil || len(owners) != 1 || owners[0].Incarnation != incarnation {
				t.Fatalf("immutable recovery owner lost: %#v %v", owners, err)
			}
			if err := service.ReleaseLambdaFunctionNetwork(ctx, function, "function-create-2/environment-1", id); err == nil {
				t.Fatal("recreated function acquired predecessor ENI")
			}
			if _, err := service.ResolveLambdaFunctionNetwork(ctx, "arn:aws:lambda:us-east-2:123456789012:function:owned", incarnation, id); err == nil {
				t.Fatal("cross-Region owner accepted")
			}
			policy(`{"Statement":{"Effect":"Deny","Action":"ec2:*","Resource":"*"}}`)
			if _, err := service.ResolveLambdaFunctionNetwork(ctx, function, incarnation, id); err == nil {
				t.Fatal("current role deny ignored")
			}
			if err := service.ReleaseLambdaFunctionNetwork(ctx, function, incarnation, id); err == nil {
				t.Fatal("current delete deny ignored")
			}
			policy(allow)
			if err := service.ReleaseLambdaFunctionNetwork(ctx, function, incarnation, id); err != nil {
				t.Fatal(err)
			}
			if err := service.ReleaseLambdaFunctionNetwork(ctx, function, incarnation, id); err != nil {
				t.Fatal(err)
			}
			if _, err := service.AllocateLambdaFunctionNetwork(ctx, function, incarnation, selected.Key.ID, groups); err == nil {
				t.Fatal("stale allocation resurrected released incarnation")
			}
			fresh, err := service.AllocateLambdaFunctionNetwork(ctx, function, "function-create-2/environment-1", selected.Key.ID, groups)
			if err != nil || string(*fresh.Interface.NetworkInterfaceId) == id {
				t.Fatalf("new incarnation did not allocate independent ENI: %v", err)
			}
		})
	}
}
