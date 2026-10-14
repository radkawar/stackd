package ec2_test

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

func eipSDKError(t *testing.T, err error, code string) {
	t.Helper()
	var apiError smithy.APIError
	if !errors.As(err, &apiError) || apiError.ErrorCode() != code {
		t.Fatalf("SDK error=%v, want %s", err, code)
	}
}

// This boundary runs actual SDK Query encoders, service model decoding and
// response/error decoding. SigV4 authentication is covered by gateway tests;
// metadata below represents the already-authenticated gateway caller.
func eipSDKClient(t *testing.T, service func() *ec2.Service, metadata awsctx.Metadata) *sdk.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		service().ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
	}))
	t.Cleanup(server.Close)
	return sdk.New(sdk.Options{Region: metadata.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
}

func eipRoot(account, region string) awsctx.Metadata {
	return awsctx.Metadata{Partition: "aws", AccountID: account, Region: region, PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account}
}

func TestEIPAttributesSDKLifecyclePaginationAndIsolation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repository ec2.Repository = ec2.NewMemoryRepository(nil)
			var db *sql.DB
			var service *ec2.Service
			path := filepath.Join(t.TempDir(), "eip.sqlite")
			open := func() {
				t.Helper()
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repository = sqlec2.New(db)
				}
				service = ec2.New(ec2.Config{Repository: repository})
			}
			close := func() {
				_ = service.Close()
				if db != nil {
					_ = db.Close()
					db = nil
				}
			}
			open()
			t.Cleanup(close)
			metadata := eipRoot("111111111111", "us-east-1")
			client := eipSDKClient(t, func() *ec2.Service { return service }, metadata)
			ctx := t.Context()
			allocated := map[string]string{}
			for range 3 {
				out, err := client.AllocateAddress(ctx, &sdk.AllocateAddressInput{Domain: types.DomainTypeVpc})
				if err != nil {
					t.Fatal(err)
				}
				allocated[aws.ToString(out.AllocationId)] = aws.ToString(out.PublicIp)
			}
			ids := make([]string, 0, len(allocated))
			for id := range allocated {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			check := func(address types.AddressAttribute) {
				t.Helper()
				id := aws.ToString(address.AllocationId)
				if allocated[id] == "" || aws.ToString(address.PublicIp) != allocated[id] || address.PtrRecord != nil || address.PtrRecordUpdate != nil {
					t.Fatalf("incorrect unset domain attribute: %#v", address)
				}
			}
			// Provider v6.68.0 uses this exact selector and SDK paginator.
			for _, id := range ids {
				pages := sdk.NewDescribeAddressesAttributePaginator(client, &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{id}, Attribute: types.AddressAttributeNameDomainName})
				page, err := pages.NextPage(ctx)
				if err != nil || len(page.Addresses) != 1 || pages.HasMorePages() {
					t.Fatalf("provider read page=%#v error=%v", page, err)
				}
				check(page.Addresses[0])
			}
			// Omitted Attribute describes the sole supported attribute too.
			first, err := client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{MaxResults: aws.Int32(1)})
			if err != nil || len(first.Addresses) != 1 || first.NextToken == nil || aws.ToString(first.Addresses[0].AllocationId) != ids[0] {
				t.Fatalf("first page=%#v error=%v", first, err)
			}
			check(first.Addresses[0])
			close()
			open()
			pages := sdk.NewDescribeAddressesAttributePaginator(client, &sdk.DescribeAddressesAttributeInput{Attribute: types.AddressAttributeNameDomainName, MaxResults: aws.Int32(1), NextToken: first.NextToken})
			seen := []string{ids[0]}
			for pages.HasMorePages() {
				page, err := pages.NextPage(ctx)
				if err != nil || len(page.Addresses) != 1 {
					t.Fatalf("continuation=%#v error=%v", page, err)
				}
				check(page.Addresses[0])
				seen = append(seen, aws.ToString(page.Addresses[0].AllocationId))
			}
			if !slices.Equal(seen, ids) {
				t.Fatalf("unstable pages=%v want %v", seen, ids)
			}
			selected, err := client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{ids[2], ids[0], ids[0]}, MaxResults: aws.Int32(1)})
			if err != nil || len(selected.Addresses) != 1 || selected.NextToken == nil {
				t.Fatalf("selected pagination=%#v error=%v", selected, err)
			}
			last, err := client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{ids[0], ids[2]}, MaxResults: aws.Int32(1), NextToken: selected.NextToken})
			if err != nil || len(last.Addresses) != 1 || aws.ToString(last.Addresses[0].AllocationId) != ids[2] || last.NextToken != nil {
				t.Fatalf("canonical selector continuation=%#v error=%v", last, err)
			}
			_, err = client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{NextToken: selected.NextToken})
			eipSDKError(t, err, "InvalidParameterValue")
			for _, outsider := range []awsctx.Metadata{eipRoot("222222222222", "us-east-1"), eipRoot("111111111111", "us-west-2")} {
				other := eipSDKClient(t, func() *ec2.Service { return service }, outsider)
				out, err := other.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{})
				if err != nil || len(out.Addresses) != 0 {
					t.Fatalf("scope scan leaked=%#v error=%v", out, err)
				}
				_, err = other.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{ids[0]}})
				eipSDKError(t, err, "InvalidAllocationID.NotFound")
				_, err = other.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{NextToken: first.NextToken})
				eipSDKError(t, err, "InvalidParameterValue")
			}
			for _, input := range []*sdk.DescribeAddressesAttributeInput{{MaxResults: aws.Int32(0)}, {MaxResults: aws.Int32(1001)}, {NextToken: aws.String("invalid")}, {Attribute: types.AddressAttributeName("unsupported")}} {
				_, err := client.DescribeAddressesAttribute(ctx, input)
				eipSDKError(t, err, "InvalidParameterValue")
			}
			_, err = client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{"bad-id"}})
			eipSDKError(t, err, "InvalidAllocationID.Malformed")
			_, err = client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{ids[0], "eipalloc-fffffffffffffffff"}})
			eipSDKError(t, err, "InvalidAllocationID.NotFound")
			_, err = client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{DryRun: aws.Bool(true)})
			eipSDKError(t, err, "DryRunOperation")
			for _, id := range ids {
				_, err = client.ReleaseAddress(ctx, &sdk.ReleaseAddressInput{AllocationId: aws.String(id)})
				if err != nil {
					t.Fatal(err)
				}
				_, err = client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{id}, Attribute: types.AddressAttributeNameDomainName})
				eipSDKError(t, err, "InvalidAllocationID.NotFound")
			}
		})
	}
}

func TestEIPAttributesSDKCurrentIAM(t *testing.T) {
	metadata := eipRoot("111111111111", "us-east-1")
	root := awsctx.WithMetadata(t.Context(), metadata)
	identity := iam.NewWithConfig(iam.Config{})
	t.Cleanup(func() { _ = identity.Close() })
	service := ec2.New(ec2.Config{Authorizer: authorization.New(identity, nil)})
	t.Cleanup(func() { _ = service.Close() })
	allocation := subnetResult[api.AllocateAddressResult](t, root, service, "ec2", "AllocateAddress", &api.AllocateAddressRequest{Domain: new(api.DomainType("vpc"))})
	user := subnetResult[iamapi.CreateUserResponse](t, root, identity, "iam", "CreateUser", &iamapi.CreateUserRequest{UserName: new(iamapi.UserNameType("eip-reader"))}).User
	metadata.PrincipalARN, metadata.PrincipalID = string(*user.Arn), string(*user.UserId)
	client := eipSDKClient(t, func() *ec2.Service { return service }, metadata)
	input := &sdk.DescribeAddressesAttributeInput{AllocationIds: []string{string(*allocation.AllocationId)}, Attribute: types.AddressAttributeNameDomainName}
	_, err := client.DescribeAddressesAttribute(t.Context(), input)
	eipSDKError(t, err, "UnauthorizedOperation")
	_, err = client.DescribeAddressesAttribute(t.Context(), &sdk.DescribeAddressesAttributeInput{DryRun: aws.Bool(true)})
	eipSDKError(t, err, "UnauthorizedOperation")
	putPolicy := func(document string) {
		t.Helper()
		subnetResult[iamapi.Unit](t, root, identity, "iam", "PutUserPolicy", &iamapi.PutUserPolicyRequest{UserName: new(iamapi.ExistingUserNameType("eip-reader")), PolicyName: new(iamapi.PolicyNameType("read")), PolicyDocument: new(iamapi.PolicyDocumentType(document))})
	}
	putPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeAddresses","Resource":"*"}]}`)
	_, err = client.DescribeAddressesAttribute(t.Context(), input)
	eipSDKError(t, err, "UnauthorizedOperation")
	putPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeAddressesAttribute","Resource":"*"}]}`)
	out, err := client.DescribeAddressesAttribute(t.Context(), input)
	if err != nil || len(out.Addresses) != 1 {
		t.Fatalf("authorized read=%#v error=%v", out, err)
	}
	_, err = client.DescribeAddressesAttribute(t.Context(), &sdk.DescribeAddressesAttributeInput{DryRun: aws.Bool(true)})
	eipSDKError(t, err, "DryRunOperation")
	putPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:DescribeAddressesAttribute","Resource":"*"}]}`)
	_, err = client.DescribeAddressesAttribute(t.Context(), input)
	eipSDKError(t, err, "UnauthorizedOperation")
}

func TestEIPAttributesSDKPreservesAssociationAndRejectsPTRMutation(t *testing.T) {
	repository := ec2.NewMemoryRepository(nil)
	service := ec2.New(ec2.Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	metadata := eipRoot("111111111111", "us-east-1")
	client := eipSDKClient(t, func() *ec2.Service { return service }, metadata)
	ctx := t.Context()
	owner := awsctx.WithMetadata(ctx, metadata)
	scope := ec2.Scope{Partition: "aws", AccountID: metadata.AccountID, Region: metadata.Region}
	if err := repository.Update(owner, func(tx ec2.Transaction) error {
		return tx.PutPublicAddress(ec2.PublicAddressRecord{Key: ec2.ResourceKey{Scope: scope, ID: "automatic-address"}, Automatic: true, Data: api.Address{PublicIp: new(api.String("198.18.0.1"))}})
	}); err != nil {
		t.Fatal(err)
	}
	vpc, err := client.CreateVpc(ctx, &sdk.CreateVpcInput{CidrBlock: aws.String("10.77.0.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := client.CreateInternetGateway(ctx, &sdk.CreateInternetGatewayInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachInternetGateway(ctx, &sdk.AttachInternetGatewayInput{InternetGatewayId: gateway.InternetGateway.InternetGatewayId, VpcId: vpc.Vpc.VpcId}); err != nil {
		t.Fatal(err)
	}
	subnet, err := client.CreateSubnet(ctx, &sdk.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.77.0.0/25")})
	if err != nil {
		t.Fatal(err)
	}
	eni, err := client.CreateNetworkInterface(ctx, &sdk.CreateNetworkInterfaceInput{SubnetId: subnet.Subnet.SubnetId})
	if err != nil {
		t.Fatal(err)
	}
	allocation, err := client.AllocateAddress(ctx, &sdk.AllocateAddressInput{Domain: types.DomainTypeVpc})
	if err != nil {
		t.Fatal(err)
	}
	association, err := client.AssociateAddress(ctx, &sdk.AssociateAddressInput{AllocationId: allocation.AllocationId, NetworkInterfaceId: eni.NetworkInterface.NetworkInterfaceId})
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := client.DescribeAddressesAttribute(ctx, &sdk.DescribeAddressesAttributeInput{})
	if err != nil || len(attributes.Addresses) != 1 || aws.ToString(attributes.Addresses[0].AllocationId) != aws.ToString(allocation.AllocationId) || aws.ToString(attributes.Addresses[0].PublicIp) != aws.ToString(allocation.PublicIp) {
		t.Fatalf("associated read or automatic address exclusion=%#v error=%v", attributes, err)
	}
	// aws_eip never calls these mutation APIs. aws_eip_domain_name does, and
	// must still fail rather than fabricate externally published PTR state.
	_, err = client.ModifyAddressAttribute(ctx, &sdk.ModifyAddressAttributeInput{AllocationId: allocation.AllocationId, DomainName: aws.String("mail.example.test")})
	eipSDKError(t, err, "UnsupportedOperation")
	_, err = client.ResetAddressAttribute(ctx, &sdk.ResetAddressAttributeInput{AllocationId: allocation.AllocationId, Attribute: types.AddressAttributeNameDomainName})
	eipSDKError(t, err, "UnsupportedOperation")
	addresses, err := client.DescribeAddresses(ctx, &sdk.DescribeAddressesInput{AllocationIds: []string{aws.ToString(allocation.AllocationId)}})
	if err != nil || len(addresses.Addresses) != 1 {
		t.Fatalf("association refresh=%#v error=%v", addresses, err)
	}
	address := addresses.Addresses[0]
	if aws.ToString(address.AssociationId) != aws.ToString(association.AssociationId) || aws.ToString(address.NetworkInterfaceId) != aws.ToString(eni.NetworkInterface.NetworkInterfaceId) || aws.ToString(address.PublicIp) != aws.ToString(allocation.PublicIp) || aws.ToString(address.PrivateIpAddress) != aws.ToString(eni.NetworkInterface.PrivateIpAddress) {
		t.Fatalf("attribute operations changed EIP association: %#v", address)
	}
	if _, err := client.DisassociateAddress(ctx, &sdk.DisassociateAddressInput{AssociationId: association.AssociationId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReleaseAddress(ctx, &sdk.ReleaseAddressInput{AllocationId: allocation.AllocationId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteNetworkInterface(ctx, &sdk.DeleteNetworkInterfaceInput{NetworkInterfaceId: eni.NetworkInterface.NetworkInterfaceId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteSubnet(ctx, &sdk.DeleteSubnetInput{SubnetId: subnet.Subnet.SubnetId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DetachInternetGateway(ctx, &sdk.DetachInternetGatewayInput{InternetGatewayId: gateway.InternetGateway.InternetGatewayId, VpcId: vpc.Vpc.VpcId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteInternetGateway(ctx, &sdk.DeleteInternetGatewayInput{InternetGatewayId: gateway.InternetGateway.InternetGatewayId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteVpc(ctx, &sdk.DeleteVpcInput{VpcId: vpc.Vpc.VpcId}); err != nil {
		t.Fatal(err)
	}
}
