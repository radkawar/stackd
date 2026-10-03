package stackd_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd"
	"stackd/clock"
	native "stackd/compute/ec2"
	ebsdomain "stackd/internal/services/ebs"
)

func TestEC2NativePublicAddresses(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/ec2/public_addresses.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Calls []ec2NetworkCapture }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var audit struct {
		History struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
	}
	awsReadFixture(t, "ec2/public_addresses_lifecycle_audit.json", &audit)
	events := make(map[string]map[string]any, len(audit.History.Events))
	for _, row := range audit.History.Events {
		events[row.Label] = row.Event
	}
	var rows []ec2NetworkCapture
	for _, row := range fixture.Calls {
		// Real guest lifecycle uses the executable firmware workflow; this replay
		// isolates native address admission, conflict and ENI dependency transitions.
		if row.Label == "published-al2023-images" {
			break
		}
		if row.Label == "available-standard-zones" {
			continue
		}
		if row.Label == "associate-both-targets-actual" || row.Label == "associate-missing-instance-actual" {
			// Native opaque long-ID admission is an existing EC2 boundary.
			// Preserve these captures without special-casing their zero payload
			// or changing short-ID admission measured by the instance fixtures.
			t.Logf("unresolved native opaque instance ID: %s", row.Label)
			continue
		}
		row.Audit = events["public_addresses.json:"+row.Label]
		if row.Audit == nil {
			t.Fatalf("missing exact-request native audit for %s", row.Label)
		}
		rows = append(rows, row)
	}
	replayEC2NetworkRows(t, rows)
}

func TestEC2PublicAddressQuotaScopeAndAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			clientFor := func(region, key, secret string) *ec2.Client {
				return ec2.New(ec2.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			root := clientFor("us-east-1", eventDeliveryAccount, "test")
			// Serialized allocation admission must enforce one account/Region's five-EIP
			// quota even when SDK requests enter concurrently.
			var wg sync.WaitGroup
			outcomes := make(chan *ec2.AllocateAddressOutput, 8)
			failures := make(chan error, 8)
			for range 8 {
				wg.Go(func() {
					out, err := root.AllocateAddress(t.Context(), &ec2.AllocateAddressInput{})
					if err != nil {
						failures <- err
					} else {
						outcomes <- out
					}
				})
			}
			wg.Wait()
			close(outcomes)
			close(failures)
			if len(outcomes) != 5 || len(failures) != 3 {
				t.Fatalf("quota success=%d failure=%d", len(outcomes), len(failures))
			}
			for err := range failures {
				assertAPIError(t, err, "AddressLimitExceeded")
			}
			addresses := map[string]bool{}
			var allocation string
			for out := range outcomes {
				ip := aws.ToString(out.PublicIp)
				if addresses[ip] {
					t.Fatalf("duplicate reservation %s", ip)
				}
				addresses[ip] = true
				allocation = aws.ToString(out.AllocationId)
			}
			clients = reopen()
			root = clientFor("us-east-1", eventDeliveryAccount, "test")
			retained, err := root.DescribeAddresses(t.Context(), &ec2.DescribeAddressesInput{})
			if err != nil || len(retained.Addresses) != 5 {
				t.Fatalf("retained quota: %+v %v", retained, err)
			}
			for _, region := range []string{"us-west-2"} {
				foreign := clientFor(region, eventDeliveryAccount, "test")
				_, err := foreign.ReleaseAddress(t.Context(), &ec2.ReleaseAddressInput{AllocationId: &allocation})
				assertAPIError(t, err, "InvalidAllocationID.NotFound")
				out, err := foreign.AllocateAddress(t.Context(), &ec2.AllocateAddressInput{})
				if err != nil {
					t.Fatal(err)
				}
				if addresses[aws.ToString(out.PublicIp)] {
					t.Fatal("physical public IPv4 collides across regions")
				}
			}
			_, key, secret := clients.user(t, eventDeliveryAccount, "PublicAddressOperator")
			iam := clients.iam(eventDeliveryAccount, "test", "")
			putUserPolicy(t, iam, "PublicAddressOperator", `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`)
			delegated := clientFor("us-east-1", key, secret)
			_, err = delegated.CreateTags(t.Context(), &ec2.CreateTagsInput{Resources: []string{allocation}, Tags: []ec2types.Tag{{Key: aws.String("authority"), Value: aws.String("revoked")}}})
			if err != nil {
				t.Fatal(err)
			}
			putUserPolicy(t, iam, "PublicAddressOperator", `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":"ec2:ReleaseAddress","Resource":"*","Condition":{"StringEquals":{"ec2:ResourceTag/authority":"revoked"}}}]}`)
			for _, dry := range []bool{false, true} {
				_, err := delegated.ReleaseAddress(t.Context(), &ec2.ReleaseAddressInput{AllocationId: &allocation, DryRun: aws.Bool(dry)})
				assertAPIError(t, err, "UnauthorizedOperation")
			}
			_, err = root.DeleteTags(t.Context(), &ec2.DeleteTagsInput{Resources: []string{allocation}, Tags: []ec2types.Tag{{Key: aws.String("authority")}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := delegated.ReleaseAddress(t.Context(), &ec2.ReleaseAddressInput{AllocationId: &allocation}); err != nil {
				t.Fatal(err)
			}
			if _, err := root.AllocateAddress(t.Context(), &ec2.AllocateAddressInput{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEC2PublicAddressInterfaceAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			clientFor := func(key, secret string) *ec2.Client {
				return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			root := clientFor(eventDeliveryAccount, "test")
			vpc, err := root.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.76.0.0/24")})
			check(err)
			subnet, err := root.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.76.0.0/25")})
			check(err)
			gateway, err := root.CreateInternetGateway(t.Context(), &ec2.CreateInternetGatewayInput{})
			check(err)
			_, err = root.AttachInternetGateway(t.Context(), &ec2.AttachInternetGatewayInput{InternetGatewayId: gateway.InternetGateway.InternetGatewayId, VpcId: vpc.Vpc.VpcId})
			check(err)
			eni, err := root.CreateNetworkInterface(t.Context(), &ec2.CreateNetworkInterfaceInput{SubnetId: subnet.Subnet.SubnetId})
			check(err)
			address, err := root.AllocateAddress(t.Context(), &ec2.AllocateAddressInput{})
			check(err)
			association, err := root.AssociateAddress(t.Context(), &ec2.AssociateAddressInput{AllocationId: address.AllocationId, NetworkInterfaceId: eni.NetworkInterface.NetworkInterfaceId})
			check(err)
			_, key, secret := clients.user(t, eventDeliveryAccount, "AddressInterfaceOperator")
			clients = reopen()
			root = clientFor(eventDeliveryAccount, "test")
			delegated := clientFor(key, secret)
			iam := clients.iam(eventDeliveryAccount, "test", "")
			mutations := []struct {
				name string
				run  func(bool) error
			}{
				{"AssociateAddress", func(dry bool) error {
					_, err := delegated.AssociateAddress(t.Context(), &ec2.AssociateAddressInput{AllocationId: address.AllocationId, NetworkInterfaceId: eni.NetworkInterface.NetworkInterfaceId, DryRun: aws.Bool(dry)})
					return err
				}},
				{"DisassociateAddress", func(dry bool) error {
					_, err := delegated.DisassociateAddress(t.Context(), &ec2.DisassociateAddressInput{AssociationId: association.AssociationId, DryRun: aws.Bool(dry)})
					return err
				}},
				{"ReleaseAddress", func(dry bool) error {
					_, err := delegated.ReleaseAddress(t.Context(), &ec2.ReleaseAddressInput{AllocationId: address.AllocationId, DryRun: aws.Bool(dry)})
					return err
				}},
				{"CreateTags", func(dry bool) error {
					_, err := delegated.CreateTags(t.Context(), &ec2.CreateTagsInput{Resources: []string{aws.ToString(address.AllocationId)}, Tags: []ec2types.Tag{{Key: aws.String("guard"), Value: aws.String("changed")}}, DryRun: aws.Bool(dry)})
					return err
				}},
				{"DeleteTags", func(dry bool) error {
					_, err := delegated.DeleteTags(t.Context(), &ec2.DeleteTagsInput{Resources: []string{aws.ToString(address.AllocationId)}, Tags: []ec2types.Tag{{Key: aws.String("guard")}}, DryRun: aws.Bool(dry)})
					return err
				}},
			}
			for _, condition := range []struct{ key, value string }{
				{"ec2:AllocationId", aws.ToString(address.AllocationId)},
				{"ec2:PublicIpAddress", aws.ToString(address.PublicIp)},
			} {
				putUserPolicy(t, iam, "AddressInterfaceOperator", `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":"ec2:*","Resource":"*","Condition":{"StringEquals":{"`+condition.key+`":"`+condition.value+`"}}}]}`)
				for _, mutation := range mutations {
					t.Run(condition.key+"/"+mutation.name, func(t *testing.T) {
						for _, dry := range []bool{true, false} {
							assertAPIError(t, mutation.run(dry), "UnauthorizedOperation")
						}
					})
				}
			}
			resource := "arn:aws:ec2:us-east-1:" + eventDeliveryAccount + ":network-interface/" + aws.ToString(eni.NetworkInterface.NetworkInterfaceId)
			putUserPolicy(t, iam, "AddressInterfaceOperator", `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":"ec2:DisassociateAddress","Resource":"`+resource+`"}]}`)
			for _, dry := range []bool{true, false} {
				_, err := delegated.DisassociateAddress(t.Context(), &ec2.DisassociateAddressInput{AssociationId: association.AssociationId, DryRun: aws.Bool(dry)})
				assertAPIError(t, err, "UnauthorizedOperation")
			}
			retained, err := root.DescribeAddresses(t.Context(), &ec2.DescribeAddressesInput{AllocationIds: []string{aws.ToString(address.AllocationId)}})
			check(err)
			if len(retained.Addresses) != 1 || aws.ToString(retained.Addresses[0].AssociationId) != aws.ToString(association.AssociationId) {
				t.Fatalf("denied disassociation changed authority: %+v", retained)
			}
			putUserPolicy(t, iam, "AddressInterfaceOperator", `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`)
			_, err = delegated.DisassociateAddress(t.Context(), &ec2.DisassociateAddressInput{AssociationId: association.AssociationId})
			check(err)
			subnetARN := "arn:aws:ec2:us-east-1:" + eventDeliveryAccount + ":subnet/" + aws.ToString(subnet.Subnet.SubnetId)
			putUserPolicy(t, iam, "AddressInterfaceOperator", `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":"ec2:AssociateAddress","Resource":"`+resource+`","Condition":{"ArnEquals":{"ec2:Subnet":"`+subnetARN+`"}}}]}`)
			for _, dry := range []bool{true, false} {
				_, err := delegated.AssociateAddress(t.Context(), &ec2.AssociateAddressInput{AllocationId: address.AllocationId, NetworkInterfaceId: eni.NetworkInterface.NetworkInterfaceId, DryRun: aws.Bool(dry)})
				assertAPIError(t, err, "UnauthorizedOperation")
			}
		})
	}
}

// These native calls are DryRun only. Reaching execution is a test failure,
// not an emulated successful guest; the CLI proof uses the real QEMU executor.
type publicAddressDryRunExecutor struct{}

func (publicAddressDryRunExecutor) Prepare(context.Context, native.Specification) (native.Instance, error) {
	panic("DryRun reached native guest preparation")
}
func (publicAddressDryRunExecutor) Reopen(context.Context, native.Specification) (native.Instance, error) {
	panic("DryRun reached native guest reattachment")
}
func (publicAddressDryRunExecutor) Remove(context.Context, native.Specification) error {
	panic("DryRun reached native guest removal")
}

func TestEC2NativePublicAddressIAMConditions(t *testing.T) {
	var fixture struct {
		Account, Region string
		Owned           struct {
			AllocationID string `json:"allocation_id"`
			PublicIP     string `json:"public_ip"`
			SubnetID     string `json:"subnet_id"`
		}
		Calls []ebsNativeCall
	}
	awsReadFixture(t, "ec2/public_addresses_iam_federation.json", &fixture)
	var audit struct {
		History struct {
			Events []struct{ Event map[string]any }
		}
	}
	awsReadFixture(t, "ec2/public_addresses_iam_audit.json", &audit)
	nativeEvents := map[string]map[string]any{}
	for _, row := range audit.History.Events {
		nativeEvents[row.Event["requestID"].(string)] = row.Event
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			source := clock.NewManual(time.Date(2026, 9, 27, 2, 0, 0, 0, time.UTC))
			var cloud *stackd.Stack
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source, EC2Executor: publicAddressDryRunExecutor{}}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				var err error
				cloud, err = stackd.New(config)
				if err != nil {
					t.Fatal(err)
				}
				return cloud, httptest.NewServer(cloud)
			})
			assertAudit := func(t *testing.T, row ebsNativeCall, result any, callErr error, bindings map[string]string) {
				t.Helper()
				want := nativeEvents[row.RequestID]
				if want == nil {
					t.Fatalf("missing native audit record for %s", row.Label)
				}
				trails := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				requestID := nativeAuditRequestID(t, result, callErr)
				got := auditLookupRecord(t, trails, requestID, row.Operation)
				assertEC2AuditCapture(t, source.Now(), want, got, requestID, callErr, bindings, nil)
			}
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			clientFor := func(provider aws.CredentialsProvider) *ec2.Client {
				return ec2.New(ec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: provider, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			rootProvider := credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")
			root := clientFor(rootProvider)
			direct := ebs.New(ebs.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: rootProvider, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			snapshot, err := direct.StartSnapshot(ctx, &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1)})
			check(err)
			_, err = direct.CompleteSnapshot(ctx, &ebs.CompleteSnapshotInput{SnapshotId: snapshot.SnapshotId, ChangedBlocksCount: aws.Int32(0)})
			check(err)
			source.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
			_, err = cloud.RunDueJobs(ctx, 100)
			check(err)
			image, err := root.RegisterImage(ctx, &ec2.RegisterImageInput{Name: aws.String("public-ip-dry-run"), Architecture: ec2types.ArchitectureValuesX8664, VirtualizationType: aws.String("hvm"), RootDeviceName: aws.String("/dev/sda1"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/sda1"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: snapshot.SnapshotId, VolumeSize: aws.Int32(1), VolumeType: ec2types.VolumeTypeGp3, DeleteOnTermination: aws.Bool(true)}}}})
			check(err)
			vpc, err := root.CreateVpc(ctx, &ec2.CreateVpcInput{CidrBlock: aws.String("10.76.0.0/24")})
			check(err)
			subnet, err := root.CreateSubnet(ctx, &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.76.0.0/25")})
			check(err)
			address, err := root.AllocateAddress(ctx, &ec2.AllocateAddressInput{})
			check(err)
			bindings := map[string]string{fixture.Owned.SubnetID: aws.ToString(subnet.Subnet.SubnetId), fixture.Owned.AllocationID: aws.ToString(address.AllocationId), fixture.Owned.PublicIP: aws.ToString(address.PublicIp)}
			for _, row := range fixture.Calls {
				if row.Operation == "RunInstances" {
					var input ec2.RunInstancesInput
					awsDecodeJSON(t, row.Input, &input)
					bindings[aws.ToString(input.ImageId)] = aws.ToString(image.ImageId)
				}
			}
			_, key, secret := clients.user(t, fixture.Account, "PublicIPv4NativeIAM")
			putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "PublicIPv4NativeIAM", `{"Statement":{"Effect":"Allow","Action":["ec2:*","sts:GetFederationToken"],"Resource":"*"}}`)
			sessions := map[string]aws.CredentialsProvider{}
			clients = reopen()
			for _, row := range fixture.Calls {
				switch row.Operation {
				case "GetFederationToken":
					var input sts.GetFederationTokenInput
					awsDecodeJSON(t, ec2AuditReplace(t, row.Input, bindings), &input)
					if input.Policy != nil {
						input.Policy = aws.String(string(ec2AuditReplace(t, []byte(*input.Policy), bindings)))
					}
					session, err := clients.sts(key, secret, "").GetFederationToken(ctx, &input)
					check(err)
					sessions[aws.ToString(input.Name)] = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
				case "ModifySubnetAttribute":
					var input ec2.ModifySubnetAttributeInput
					awsDecodeJSON(t, ec2AuditReplace(t, row.Input, bindings), &input)
					_, err := clientFor(rootProvider).ModifySubnetAttribute(ctx, &input)
					check(err)
					clients = reopen()
				case "RunInstances":
					t.Run(row.Label, func(t *testing.T) {
						var input ec2.RunInstancesInput
						awsDecodeJSON(t, ec2AuditReplace(t, row.Input, bindings), &input)
						if !aws.ToBool(input.DryRun) {
							t.Fatal("native IAM fixture must never launch a guest")
						}
						// Boto generated this wire token; retain it rather than
						// treating a newly generated SDK token as an audit difference.
						parameters := nativeEvents[row.RequestID]["requestParameters"].(map[string]any)
						input.ClientToken = aws.String(parameters["clientToken"].(string))
						result, err := clientFor(sessions[row.Caller]).RunInstances(ctx, &input)
						assertAPIError(t, err, row.Code)
						assertAudit(t, row, result, err, bindings)
					})
				case "ReleaseAddress":
					var input ec2.ReleaseAddressInput
					awsDecodeJSON(t, ec2AuditReplace(t, row.Input, bindings), &input)
					if aws.ToBool(input.DryRun) {
						t.Run(row.Label, func(t *testing.T) {
							result, err := clientFor(sessions[row.Caller]).ReleaseAddress(ctx, &input)
							assertAPIError(t, err, row.Code)
							assertAudit(t, row, result, err, bindings)
						})
					}
				}
			}
			instances, err := clientFor(rootProvider).DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
			check(err)
			interfaces, err := clientFor(rootProvider).DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
			check(err)
			volumes, err := clientFor(rootProvider).DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
			check(err)
			if len(instances.Reservations) != 0 || len(interfaces.NetworkInterfaces) != 0 || len(volumes.Volumes) != 0 {
				t.Fatal("DryRun authorization created compute resources")
			}
		})
	}
}
