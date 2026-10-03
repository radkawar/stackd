package stackd_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestEC2NativeInstanceTypes(t *testing.T) {
	var fixture struct {
		Account, Region string
		Calls           []ebsNativeCall
		Catalog         json.RawMessage
	}
	awsReadFixture(t, "ec2/instance_types.json", &fixture)
	var inputs struct{ Calls []ebsNativeCall }
	awsReadFixture(t, "ec2/instance_type_inputs.json", &inputs)
	var native ec2.DescribeInstanceTypesOutput
	if err := awstest.DecodeSDK(fixture.Catalog, &native); err != nil {
		t.Fatal(err)
	}
	// The complete captured catalog is the independent oracle for dimensions,
	// not a second hand-maintained list of vCPU, EBS, memory or network values.
	// Selection/filter cases derive subsets of those actual native documents.
	selected := []ec2types.InstanceType{"t2.micro", "t3.nano", "t4g.nano", "c7g.medium", "i3en.metal", "p4d.24xlarge"}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: clock.NewManual(fixture.Calls[0].StartedAt)})
			client := func(region string) *ec2.Client {
				return ec2.New(ec2.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			var capturedInput ec2.DescribeInstanceTypesInput
			awsDecodeJSON(t, fixture.Calls[0].Input, &capturedInput)
			for _, scenario := range []struct {
				name       string
				input      ec2.DescribeInstanceTypesInput
				selectType func(ec2types.InstanceTypeInfo) bool
			}{
				{"captured-pagination", capturedInput, func(ec2types.InstanceTypeInfo) bool { return true }},
				{"selected-hardware", ec2.DescribeInstanceTypesInput{InstanceTypes: selected, MaxResults: aws.Int32(5)}, func(info ec2types.InstanceTypeInfo) bool {
					return slices.Contains(selected, info.InstanceType)
				}},
				{"wildcard-family", ec2.DescribeInstanceTypesInput{Filters: []ec2types.Filter{{Name: aws.String("instance-type"), Values: []string{"t3.*"}}}, MaxResults: aws.Int32(5)}, func(info ec2types.InstanceTypeInfo) bool {
					return strings.HasPrefix(string(info.InstanceType), "t3.")
				}},
				{"architecture-and-memory", ec2.DescribeInstanceTypesInput{Filters: []ec2types.Filter{
					{Name: aws.String("processor-info.supported-architecture"), Values: []string{"x86_64"}},
					{Name: aws.String("memory-info.size-in-mib"), Values: []string{"512"}},
				}}, func(info ec2types.InstanceTypeInfo) bool {
					return info.ProcessorInfo != nil && slices.Contains(info.ProcessorInfo.SupportedArchitectures, ec2types.ArchitectureType("x86_64")) && info.MemoryInfo != nil && aws.ToInt64(info.MemoryInfo.SizeInMiB) == 512
				}},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					want := map[string]any{}
					for _, info := range native.InstanceTypes {
						if scenario.selectType(info) {
							want[string(info.InstanceType)] = ec2NetworkDocument(t, info)
						}
					}
					if scenario.name == "selected-hardware" && len(want) != len(selected) {
						t.Fatal("selected hardware lacks independent native evidence")
					}
					got := map[string]any{}
					tokens := map[string]bool{}
					input := scenario.input
					for {
						output, err := client(fixture.Region).DescribeInstanceTypes(t.Context(), &input)
						if err != nil {
							t.Fatal(err)
						}
						if input.MaxResults != nil && len(output.InstanceTypes) > int(*input.MaxResults) {
							t.Fatalf("page has %d types with MaxResults %d", len(output.InstanceTypes), *input.MaxResults)
						}
						for _, info := range output.InstanceTypes {
							name := string(info.InstanceType)
							if _, duplicate := got[name]; duplicate {
								t.Fatalf("pagination repeated instance type %q", name)
							}
							got[name] = ec2NetworkDocument(t, info)
						}
						// Tokens are capabilities, not fixture strings or AWS's
						// incidental partitioning of randomly ordered pages.
						// Reopen between issuance and use, then compare the union.
						clients = reopen()
						next := aws.ToString(output.NextToken)
						if next == "" {
							break
						}
						if tokens[next] || len(tokens) >= len(native.InstanceTypes) {
							t.Fatal("catalog pagination did not terminate")
						}
						tokens[next] = true
						input.NextToken = output.NextToken
					}
					ec2NetworkSort(t, want, nil, false)
					ec2NetworkSort(t, got, nil, false)
					ec2NetworkCompare(t, "catalog", want, got, map[string]string{})
				})
			}

			for _, call := range inputs.Calls {
				t.Run(call.Label, func(t *testing.T) {
					var input ec2.DescribeInstanceTypesInput
					awsDecodeJSON(t, call.Input, &input)
					output, err := client(fixture.Region).DescribeInstanceTypes(t.Context(), &input)
					if call.Code != "Success" {
						assertAPIError(t, err, call.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					var expected ec2.DescribeInstanceTypesOutput
					if err := awstest.DecodeSDK(call.Output, &expected); err != nil {
						t.Fatal(err)
					}
					want, got := ec2NetworkDocument(t, expected), ec2NetworkDocument(t, output)
					ec2NetworkSort(t, want, nil, false)
					ec2NetworkSort(t, got, nil, false)
					ec2NetworkCompare(t, "response", want, got, map[string]string{})
				})
			}

			// These are explicit local capability/admission boundaries, not
			// native-error fixtures: the capture contains only this Region's
			// supported catalog, and cannot justify a cross-Region or
			// IncludeUnsupportedInRegion union manufactured from that catalog.
			for _, scenario := range []struct {
				name, region, code string
				input              ec2.DescribeInstanceTypesInput
			}{
				{"wrong-region", "us-west-2", "UnsupportedOperation", ec2.DescribeInstanceTypesInput{InstanceTypes: selected[:1]}},
				{"unsupported-union", fixture.Region, "UnsupportedOperation", ec2.DescribeInstanceTypesInput{IncludeUnsupportedInRegion: aws.Bool(true)}},
				{"undersized-page", fixture.Region, "InvalidParameterValue", ec2.DescribeInstanceTypesInput{MaxResults: aws.Int32(4)}},
				{"oversized-page", fixture.Region, "InvalidParameterValue", ec2.DescribeInstanceTypesInput{MaxResults: aws.Int32(101)}},
				{"invalid-token", fixture.Region, "InvalidParameterValue", ec2.DescribeInstanceTypesInput{NextToken: aws.String("not-a-page-token")}},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					_, err := client(scenario.region).DescribeInstanceTypes(t.Context(), &scenario.input)
					assertAPIError(t, err, scenario.code)
					clients = reopen()
				})
			}
		})
	}
}
