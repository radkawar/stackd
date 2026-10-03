package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"stackd"
)

func TestEC2DHCPLifecycle(t *testing.T) {
	var fixture struct {
		Observations map[string]struct {
			Code   string
			Output struct{ DhcpOptions json.RawMessage }
		}
	}
	data, err := os.ReadFile("../testdata/aws/ec2/dhcp_options.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var native ec2types.DhcpOptions
	if err := json.Unmarshal(fixture.Observations["create_custom"].Output.DhcpOptions, &native); err != nil {
		t.Fatal(err)
	}
	configurations := func(options ec2types.DhcpOptions) map[string][]string {
		out := map[string][]string{}
		for _, config := range options.DhcpConfigurations {
			for _, value := range config.Values {
				out[aws.ToString(config.Key)] = append(out[aws.ToString(config.Key)], aws.ToString(value.Value))
			}
		}
		return out
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			clientFor := func(key, secret string) *ec2.Client {
				return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			client := clientFor(eventDeliveryAccount, "test")
			vpc, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.247.0.0/24")})
			if err != nil {
				t.Fatal(err)
			}
			defaultID := aws.ToString(vpc.Vpc.DhcpOptionsId)
			defaults, err := client.DescribeDhcpOptions(t.Context(), &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: []string{defaultID}})
			if err != nil || len(defaults.DhcpOptions) != 1 {
				t.Fatalf("VPC default is not owned: %+v %v", defaults, err)
			}
			var nativeDefaults []ec2types.DhcpOptions
			if err := json.Unmarshal(fixture.Observations["describe_default"].Output.DhcpOptions, &nativeDefaults); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(configurations(defaults.DhcpOptions[0]), configurations(nativeDefaults[0])) {
				t.Fatal("regional DHCP default differs from native")
			}
			input := &ec2.CreateDhcpOptionsInput{TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeDhcpOptions, Tags: native.Tags}}}
			for _, config := range native.DhcpConfigurations {
				v := ec2types.NewDhcpConfiguration{Key: config.Key}
				for _, value := range config.Values {
					v.Values = append(v.Values, aws.ToString(value.Value))
				}
				input.DhcpConfigurations = append(input.DhcpConfigurations, v)
			}
			custom, err := client.CreateDhcpOptions(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			id := aws.ToString(custom.DhcpOptions.DhcpOptionsId)
			if _, err := client.AssociateDhcpOptions(t.Context(), &ec2.AssociateDhcpOptionsInput{DhcpOptionsId: &id, VpcId: vpc.Vpc.VpcId}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			client = clientFor(eventDeliveryAccount, "test")
			retained, err := client.DescribeDhcpOptions(t.Context(), &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: []string{id}})
			if err != nil || len(retained.DhcpOptions) != 1 {
				t.Fatalf("retained options: %+v %v", retained, err)
			}
			if !reflect.DeepEqual(configurations(retained.DhcpOptions[0]), configurations(native)) || !reflect.DeepEqual(retained.DhcpOptions[0].Tags, native.Tags) {
				t.Fatal("reopen lost DHCP values or tags")
			}
			_, err = client.DeleteDhcpOptions(t.Context(), &ec2.DeleteDhcpOptionsInput{DhcpOptionsId: &id})
			assertAPIError(t, err, fixture.Observations["delete_in_use"].Code)
			_, err = client.DeleteDhcpOptions(t.Context(), &ec2.DeleteDhcpOptionsInput{DhcpOptionsId: &id, DryRun: aws.Bool(true)})
			assertAPIError(t, err, fixture.Observations["delete_in_use_dry"].Code)
			_, err = client.AssociateDhcpOptions(t.Context(), &ec2.AssociateDhcpOptionsInput{DhcpOptionsId: aws.String("default"), VpcId: vpc.Vpc.VpcId, DryRun: aws.Bool(true)})
			assertAPIError(t, err, fixture.Observations["associate_dry"].Code)
			_, err = client.AssociateDhcpOptions(t.Context(), &ec2.AssociateDhcpOptionsInput{DhcpOptionsId: aws.String("none"), VpcId: vpc.Vpc.VpcId})
			assertAPIError(t, err, fixture.Observations["associate_none"].Code)
			unchanged, err := client.DescribeVpcs(t.Context(), &ec2.DescribeVpcsInput{VpcIds: []string{aws.ToString(vpc.Vpc.VpcId)}})
			if err != nil || len(unchanged.Vpcs) != 1 || aws.ToString(unchanged.Vpcs[0].DhcpOptionsId) != id {
				t.Fatalf("failed association changed VPC: %+v %v", unchanged, err)
			}
			if _, err := client.AssociateDhcpOptions(t.Context(), &ec2.AssociateDhcpOptionsInput{DhcpOptionsId: aws.String("default"), VpcId: vpc.Vpc.VpcId}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeleteDhcpOptions(t.Context(), &ec2.DeleteDhcpOptionsInput{DhcpOptionsId: &id}); err != nil {
				t.Fatal(err)
			}
			_, err = client.DescribeDhcpOptions(t.Context(), &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: []string{id}})
			assertAPIError(t, err, fixture.Observations["delete_after_deleted"].Code)
			// A deleted regional default is not recreated by Describe or CreateVpc.
			if _, err := client.DeleteDhcpOptions(t.Context(), &ec2.DeleteDhcpOptionsInput{DhcpOptionsId: &defaultID}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			client = clientFor(eventDeliveryAccount, "test")
			empty, err := client.DescribeDhcpOptions(t.Context(), &ec2.DescribeDhcpOptionsInput{})
			if err != nil || len(empty.DhcpOptions) != 0 {
				t.Fatalf("deleted default resurrected: %+v %v", empty, err)
			}
			second, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.248.0.0/24")})
			if err != nil || aws.ToString(second.Vpc.DhcpOptionsId) != "default" {
				t.Fatalf("VPC resurrected deleted default: %+v %v", second, err)
			}

			// Tag-on-create has a separate CreateTags authorization boundary.
			_, userKey, userSecret := clients.user(t, eventDeliveryAccount, "DHCPDelegated")
			putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "DHCPDelegated", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:CreateDhcpOptions","Resource":"*"}]}`)
			delegated := clientFor(userKey, userSecret)
			_, err = delegated.CreateDhcpOptions(t.Context(), input)
			assertAPIError(t, err, "UnauthorizedOperation")
			afterDenied, err := client.DescribeDhcpOptions(t.Context(), &ec2.DescribeDhcpOptionsInput{})
			if err != nil || len(afterDenied.DhcpOptions) != 0 {
				t.Fatalf("denied tagging persisted a resource: %+v %v", afterDenied, err)
			}
		})
	}
}
