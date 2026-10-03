package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestEC2NativePagination(t *testing.T) {
	type capture struct {
		ec2NetworkCapture
		Region string
	}
	var networking []capture
	for _, row := range ec2NetworkCaptures(t) {
		if row.Sequence >= 149 {
			networking = append(networking, capture{ec2NetworkCapture: row, Region: "us-east-1"})
		}
	}
	data, err := os.ReadFile("../testdata/aws/ec2/pagination.json")
	if err != nil {
		t.Fatal(err)
	}
	var supplement struct{ Calls []capture }
	if err := json.Unmarshal(data, &supplement); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name string
		rows []capture
	}{{"networking", networking}, {"scope_and_filters", supplement.Calls}} {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(fixture.name+"/"+backend, func(t *testing.T) {
				source := clock.NewManual(fixture.rows[0].StartedAt)
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source})
				bindings := map[string]string{}
				native := map[string]map[string]any{}
				inventory := map[string]map[string]any{}
				actualPages := map[string][]any{}
				nativePages := map[string][]any{}
				options := ec2.Options{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1}
				// Decode with the independent SDK, including all captured describe
				// pages, so each returned resource is checked against native content.
				// AWS does not promise matching page membership for independently
				// allocated resource IDs or the same opaque scan ordering.
				for _, row := range fixture.rows {
					if row.Service != "ec2" || row.Code != "Success" {
						continue
					}
					options.HTTPClient = nativeXMLResponse(row.RawResponseBody)
					output, err := awstest.CallSDK(t.Context(), ec2.New(options), ec2NetworkAction(row.Operation), row.Input)
					if err != nil {
						t.Fatalf("decode %s: %v", row.Label, err)
					}
					document := ec2NetworkDocument(t, output)
					ec2NetworkSort(t, document, nil, true)
					native[row.Label] = document
					for _, collection := range []string{"SecurityGroups", "Subnets"} {
						for _, item := range ec2PaginationItems(document[collection]) {
							resource := item.(map[string]any)
							id, _ := resource[ec2PaginationID(collection)].(string)
							inventory[id] = resource
						}
					}
				}
				for _, row := range fixture.rows {
					if row.StartedAt.After(source.Now()) {
						source.Advance(row.StartedAt.Sub(source.Now()))
					}
					if !t.Run(fmt.Sprintf("%03d_%s", row.Sequence, row.Label), func(t *testing.T) {
						if row.Service != "ec2" {
							// Networking row213 records the native actor, not an EC2
							// request. All other rows149–215 are replayed below.
							if fixture.name != "networking" || row.Sequence != 213 || row.Operation != "get-caller-identity" {
								t.Fatalf("unaccounted non-EC2 capture: %+v", row)
							}
							t.Skip("STS actor provenance; not EC2 pagination behavior")
						}
						action := ec2NetworkAction(row.Operation)
						input := ec2AuditReplace(t, row.Input, bindings)
						wire := &awstest.WireClient{Client: clients.server.Client()}
						options.BaseEndpoint = aws.String(clients.server.URL)
						options.Region = row.Region
						options.HTTPClient = wire
						output, err := awstest.CallSDK(t.Context(), ec2.New(options), action, input)
						if row.Code != "Success" {
							assertAPIError(t, err, row.Code)
						} else if err != nil {
							t.Fatal(err)
						}
						if wire.Status != row.HTTPStatus {
							t.Fatalf("HTTP status %d, native %d", wire.Status, row.HTTPStatus)
						}
						if err != nil {
							return
						}
						got, want := ec2NetworkDocument(t, output), native[row.Label]
						ec2NetworkSort(t, got, bindings, false)
						if action == "CreateSubnet" {
							// Omitted AZ is native placement, not a fixed zone-name
							// contract: the cohorts chose different AZs. Keep one
							// stable name binding just as the existing comparator
							// binds the independently selected physical zone ID.
							before := want["Subnet"].(map[string]any)["AvailabilityZone"].(string)
							after := got["Subnet"].(map[string]any)["AvailabilityZone"].(string)
							if prior, exists := bindings[before]; exists && prior != after {
								t.Fatalf("automatic AZ changed from %s to %s", prior, after)
							}
							bindings[before] = after
						}
						var request struct {
							MaxResults *int
							NextToken  string
						}
						if err := json.Unmarshal(row.Input, &request); err != nil {
							t.Fatal(err)
						}
						collection := ""
						if action == "DescribeSecurityGroups" {
							collection = "SecurityGroups"
						} else if action == "DescribeSubnets" {
							collection = "Subnets"
						}
						if collection == "" || request.MaxResults == nil && request.NextToken == "" {
							ec2NetworkCompare(t, "response", want, got, bindings)
							return
						}
						items, expected := ec2PaginationItems(got[collection]), ec2PaginationItems(want[collection])
						// The original VPC-only cohort has no filtered-out scan
						// candidates, so its 5/2 and 5/1 page sizes are exact.
						// Supplement SG tag scans can have a short first page:
						// row14 was 4/5; its default SG is not tagged. The native
						// partition is deliberately not hard-coded to local IDs.
						if fixture.name == "networking" || collection == "Subnets" || len(expected) == 0 || row.Label == "group-vpc-first" {
							if len(items) != len(expected) {
								t.Fatalf("page size %d, native %d", len(items), len(expected))
							}
						}
						if request.MaxResults != nil && len(items) > *request.MaxResults {
							t.Fatalf("page size %d exceeds MaxResults %d", len(items), *request.MaxResults)
						}
						seen := map[string]bool{}
						for _, item := range items {
							resource := item.(map[string]any)
							id := resource[ec2PaginationID(collection)].(string)
							if seen[id] {
								t.Fatalf("duplicate resource %s in page", id)
							}
							seen[id] = true
							var reference map[string]any
							for original, document := range inventory {
								if bindings[original] == id {
									reference = document
									break
								}
							}
							if reference == nil && collection == "SecurityGroups" && resource["GroupName"] == "default" {
								// The supplement first observes the provider-created
								// default SG on its VPC-scoped page, not at creation.
								for _, document := range inventory {
									vpc, _ := document["VpcId"].(string)
									if document["GroupName"] == "default" && bindings[vpc] == resource["VpcId"] {
										reference = document
										break
									}
								}
							}
							if reference == nil {
								t.Fatalf("page returned resource absent from native inventory: %s", id)
							}
							ec2NetworkCompare(t, "resource", reference, resource, bindings)
						}
						actualPages[row.Label], nativePages[row.Label] = items, expected
						// Bind opaque tokens, preserving absence versus presence;
						// later fixture requests consume these actual tokens after
						// reopening storage, including after resource deletion.
						metadata := func(document map[string]any) map[string]any {
							result := make(map[string]any, len(document)-1)
							for key, value := range document {
								if key != collection {
									result[key] = value
								}
							}
							return result
						}
						ec2NetworkCompare(t, "response", metadata(want), metadata(got), bindings)
						pairs := map[string]string{
							"pagination-second-describe-security-groups": "pagination-first-describe-security-groups",
							"pagination-second-describe-subnets":         "pagination-first-describe-subnets",
							"group-second":                               "group-first", "subnet-second": "subnet-first",
						}
						if first, ok := pairs[row.Label]; ok {
							allActual := append(append([]any{}, actualPages[first]...), items...)
							allNative := append(append([]any{}, nativePages[first]...), expected...)
							ec2NetworkSort(t, allActual, bindings, false)
							ec2NetworkSort(t, allNative, bindings, true)
							ec2NetworkCompare(t, "complete-pages", allNative, allActual, bindings)
						}
						if row.Label == "group-vpc-token-same-vpc-plus-tag" {
							// Adding the probe tag excludes the untagged default
							// SG but preserves the VPC cursor. Check precisely the
							// tagged resources not already consumed by that scan.
							consumed := map[string]bool{}
							for _, item := range actualPages["group-vpc-first"] {
								consumed[item.(map[string]any)["GroupId"].(string)] = true
							}
							var remaining []any
							for _, page := range []string{"group-first", "group-second"} {
								for _, item := range actualPages[page] {
									if !consumed[item.(map[string]any)["GroupId"].(string)] {
										remaining = append(remaining, item)
									}
								}
							}
							ec2NetworkSort(t, remaining, bindings, false)
							if !reflect.DeepEqual(items, remaining) {
								t.Fatalf("added tag changed the VPC continuation: %#v, remaining tagged resources %#v", items, remaining)
							}
						}
						repeats := map[string]string{
							"pagination-repeat-token-describe-security-groups": "pagination-second-describe-security-groups",
							"pagination-repeat-token-describe-subnets":         "pagination-second-describe-subnets",
							"group-repeat-token":                               "group-second", "subnet-repeat-token": "subnet-second",
							"group-larger-page": "group-second", "subnet-larger-page": "subnet-second",
							"group-no-max": "group-second", "subnet-no-max": "subnet-second",
						}
						if prior, ok := repeats[row.Label]; ok && !reflect.DeepEqual(items, actualPages[prior]) {
							t.Fatalf("reusing token changed resources: %#v, previously %#v", items, actualPages[prior])
						}
					}) {
						return
					}
					// Reconstruct services even between first/second/repeated reads,
					// not merely after writes: continuation must survive reopen.
					clients = reopen()
				}
			})
		}
	}
}

func ec2PaginationItems(value any) []any {
	items, _ := value.([]any)
	return items
}

func ec2PaginationID(collection string) string {
	if collection == "SecurityGroups" {
		return "GroupId"
	}
	return "SubnetId"
}

// As in the SG/subnet replay above, compare complete sets rather than AWS's
// undocumented scan-page membership. Native ENI captures include short pages.
func ec2NetworkInterfacePages(t *testing.T, client *ec2.Client, rows []ec2NetworkCapture, native, actual *ec2.DescribeNetworkInterfacesOutput, bindings map[string]string) (map[string]any, map[string]any, int) {
	t.Helper()
	want, got := *native, *actual
	want.NetworkInterfaces = slices.Clone(native.NetworkInterfaces)
	got.NetworkInterfaces = slices.Clone(actual.NetworkInterfaces)
	consumed := 1
	for native.NextToken != nil && *native.NextToken != "" {
		if consumed == len(rows) {
			t.Fatal("native ENI pagination capture ends before its terminal page")
		}
		row := rows[consumed]
		var input ec2.DescribeNetworkInterfacesInput
		if err := json.Unmarshal(row.Input, &input); err != nil {
			t.Fatal(err)
		}
		if ec2NetworkAction(row.Operation) != "DescribeNetworkInterfaces" || row.Code != "Success" || aws.ToString(input.NextToken) != *native.NextToken {
			t.Fatalf("native ENI continuation does not follow its retained token: %s", row.Label)
		}
		options := client.Options()
		options.HTTPClient = nativeXMLResponse(row.RawResponseBody)
		page, err := ec2.New(options).DescribeNetworkInterfaces(t.Context(), &input)
		if err != nil {
			t.Fatal(err)
		}
		want.NetworkInterfaces = append(want.NetworkInterfaces, page.NetworkInterfaces...)
		native = page
		consumed++
	}
	var input ec2.DescribeNetworkInterfacesInput
	if err := json.Unmarshal(ec2NetworkInput(t, rows[0], bindings), &input); err != nil {
		t.Fatal(err)
	}
	checkPage := func(page *ec2.DescribeNetworkInterfacesOutput) {
		if input.MaxResults != nil && len(page.NetworkInterfaces) > int(*input.MaxResults) {
			t.Fatalf("ENI page exceeded MaxResults: %d > %d", len(page.NetworkInterfaces), *input.MaxResults)
		}
	}
	checkPage(actual)
	if actual.NextToken != nil && *actual.NextToken != "" {
		input.NextToken = actual.NextToken
		paginator := ec2.NewDescribeNetworkInterfacesPaginator(client, &input, func(options *ec2.DescribeNetworkInterfacesPaginatorOptions) {
			options.StopOnDuplicateToken = true
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			checkPage(page)
			got.NetworkInterfaces = append(got.NetworkInterfaces, page.NetworkInterfaces...)
			actual = page
		}
		if aws.ToString(actual.NextToken) != "" {
			t.Fatal("ENI pagination repeated a nonterminal token")
		}
	}
	want.NextToken, got.NextToken = nil, nil
	return ec2NetworkDocument(t, &want), ec2NetworkDocument(t, &got), consumed
}
