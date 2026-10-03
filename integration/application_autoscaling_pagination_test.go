package stackd_test

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type aasSDKPaginator[T any] interface {
	HasMorePages() bool
	NextPage(context.Context, ...func(*applicationautoscaling.Options)) (*T, error)
}

func aasSDKPages[T any](t *testing.T, paginator aasSDKPaginator[T], wire *awstest.WireClient) []map[string]any {
	t.Helper()
	var pages []map[string]any
	for paginator.HasMorePages() {
		if len(pages) == 3 {
			t.Fatal("SDK paginator continued beyond the retained two-page population")
		}
		if _, err := paginator.NextPage(t.Context()); err != nil {
			t.Fatal(err)
		}
		pages = append(pages, ecsControlBody(t, wire.Body))
	}
	return pages
}

func TestApplicationAutoScalingNativePaginationAcrossReopen(t *testing.T) {
	wide, scoped := aasFixture(t, "wide_pages"), aasFixture(t, "continuation")
	boundaries := aasFixture(t, "policy_page_boundaries")
	policies := func(t *testing.T, client *applicationautoscaling.Client, wire *awstest.WireClient, input json.RawMessage) []map[string]any {
		var request applicationautoscaling.DescribeScalingPoliciesInput
		if err := json.Unmarshal(input, &request); err != nil {
			t.Fatal(err)
		}
		return aasSDKPages(t, applicationautoscaling.NewDescribeScalingPoliciesPaginator(client, &request), wire)
	}
	tests := []struct {
		name, field, remove, nameField string
		fixture                        aasControlFixture
		setup                          [][2]int
		first, second                  int
		limits, replay                 []int
		paginate                       func(*testing.T, *applicationautoscaling.Client, *awstest.WireClient, json.RawMessage) []map[string]any
	}{
		{name: "policies", field: "ScalingPolicies", remove: "DeleteScalingPolicy", nameField: "PolicyName", fixture: wide, setup: [][2]int{{6, 9}, {167, 179}}, first: 180, second: 181, limits: []int{183, 184, 185, 186, 187, 188, 189}, paginate: policies},
		{name: "scoped-policies", field: "ScalingPolicies", remove: "DeleteScalingPolicy", nameField: "PolicyName", fixture: scoped, setup: [][2]int{{4, 36}}, first: 44, second: 45, limits: []int{42, 43, 64}, replay: []int{65, 66, 67, 68, 69}, paginate: policies},
		{name: "named-policies-across-resources", field: "ScalingPolicies", remove: "DeleteScalingPolicy", nameField: "PolicyName", fixture: scoped, setup: [][2]int{{4, 36}}, first: 52, second: 53, limits: []int{50, 51}, paginate: policies},
		{name: "exact-policy-cap", field: "ScalingPolicies", remove: "DeleteScalingPolicy", nameField: "PolicyName", fixture: boundaries, setup: [][2]int{{4, 20}}, first: 21, second: 22, limits: []int{23, 24, 25, 26}, replay: []int{27, 28, 29, 30, 31, 32, 33, 34, 35, 36}, paginate: policies},
		{name: "named-policy-order", field: "ScalingPolicies", remove: "DeleteScalingPolicy", nameField: "PolicyName", fixture: boundaries, setup: [][2]int{{4, 20}}, first: 37, second: 38, replay: []int{39, 40}, paginate: policies},
		{name: "schedules", field: "ScheduledActions", remove: "DeleteScheduledAction", nameField: "ScheduledActionName", fixture: wide, setup: [][2]int{{6, 11}, {114, 166}}, first: 201, second: 202, limits: []int{204, 205, 206, 207, 208, 209}, paginate: func(t *testing.T, client *applicationautoscaling.Client, wire *awstest.WireClient, input json.RawMessage) []map[string]any {
			var request applicationautoscaling.DescribeScheduledActionsInput
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			return aasSDKPages(t, applicationautoscaling.NewDescribeScheduledActionsPaginator(client, &request), wire)
		}},
		// Native initial MaxResults=1/2 returned unexplained empty pages with
		// tokens for the 53-target population. Do not turn that observation into
		// a population-specific implementation or a universal truncation claim.
		{name: "targets", field: "ScalableTargets", remove: "DeregisterScalableTarget", fixture: wide, setup: [][2]int{{6, 113}}, first: 192, second: 193, limits: []int{195, 196, 197, 200}, paginate: func(t *testing.T, client *applicationautoscaling.Client, wire *awstest.WireClient, input json.RawMessage) []map[string]any {
			var request applicationautoscaling.DescribeScalableTargetsInput
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			return aasSDKPages(t, applicationautoscaling.NewDescribeScalableTargetsPaginator(client, &request), wire)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rowAt := func(sequence int) aasControlRow {
				for _, row := range test.fixture.Calls {
					if row.Sequence == sequence {
						return row
					}
				}
				t.Fatalf("missing native sequence %d", sequence)
				return aasControlRow{}
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					source := clock.NewManual(test.fixture.Calls[0].StartedAt)
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: test.fixture.Account, Clock: source, ECSExecutor: aasExecutor(t), ComputeEndpoint: "http://stackd.invalid"})
					bindings, times := map[string]string{}, map[float64]float64{}
					for _, row := range test.fixture.Calls {
						if !slices.ContainsFunc(test.setup, func(interval [2]int) bool { return row.Sequence >= interval[0] && row.Sequence <= interval[1] }) {
							continue
						}
						if row.StartedAt.After(source.Now()) {
							source.Advance(row.StartedAt.Sub(source.Now()))
						}
						aasFixtureRow(t, clients, row, bindings, times)
					}
					first, second := rowAt(test.first), rowAt(test.second)
					wire := &awstest.WireClient{Client: clients.server.Client()}
					client := aasClient(clients, test.fixture.Region, "test", "test", wire)
					pages := test.paginate(t, client, wire, aasInput(t, first, bindings))
					if len(pages) != 2 {
						t.Fatalf("SDK paginator returned %d pages; native returned two", len(pages))
					}
					var want, got []any
					for index, row := range []aasControlRow{first, second} {
						native := ecsControlBody(t, row.Output)[test.field].([]any)
						actual := pages[index][test.field].([]any)
						if len(actual) != len(native) {
							t.Fatalf("page %d: native %d records; got %d", index, len(native), len(actual))
						}
						want, got = append(want, native...), append(got, actual...)
					}
					aasCompare(t, test.name, map[string]any{test.field: want}, map[string]any{test.field: got}, bindings, times)
					nativeToken := ecsControlBody(t, first.Output)["NextToken"].(string)
					token := pages[0]["NextToken"].(string)
					bindings[nativeToken] = token
					clients = reopen()
					call := func(operation string, input json.RawMessage) map[string]any {
						wire := &awstest.WireClient{Client: clients.server.Client()}
						client := aasClient(clients, test.fixture.Region, "test", "test", wire)
						if _, err := awstest.CallSDK(t.Context(), client, operation, input); err != nil {
							t.Fatal(err)
						}
						return ecsControlBody(t, wire.Body)
					}
					continued := aasInput(t, second, bindings)
					if page := call(first.Operation, continued); !reflect.DeepEqual(page, pages[1]) {
						t.Fatalf("continued page changed across reopen: %v / %v", page, pages[1])
					}
					for _, sequence := range test.limits {
						row := rowAt(sequence)
						page := call(row.Operation, aasInput(t, row, bindings))
						native := ecsControlBody(t, row.Output)
						_, nativeNext := native["NextToken"]
						_, actualNext := page["NextToken"]
						if len(page[test.field].([]any)) != len(native[test.field].([]any)) || actualNext != nativeNext {
							t.Fatalf("%s: native page size/token %d/%t; got %d/%t", row.Label, len(native[test.field].([]any)), nativeNext, len(page[test.field].([]any)), actualNext)
						}
					}
					for _, sequence := range test.replay {
						aasReplay(t, clients, rowAt(sequence), bindings, times)
					}
					for _, scope := range []struct{ region, key string }{{"eu-west-1", "test"}, {"us-east-1", "111122223333"}} {
						foreignWire := &awstest.WireClient{Client: clients.server.Client()}
						foreign := aasClient(clients, scope.region, scope.key, "test", foreignWire)
						_, err := awstest.CallSDK(t.Context(), foreign, first.Operation, continued)
						assertAPIError(t, err, "InvalidNextTokenException")
					}
					initialRows, remaining := pages[0][test.field].([]any), pages[1][test.field].([]any)
					// Delete both the cursor record and one remaining record. A token
					// must remain a position, not an offset or a lookup of a live row.
					for _, value := range []any{initialRows[len(initialRows)-1], remaining[0]} {
						row := value.(map[string]any)
						input := map[string]any{"ServiceNamespace": row["ServiceNamespace"], "ResourceId": row["ResourceId"], "ScalableDimension": row["ScalableDimension"]}
						if test.nameField != "" {
							input[test.nameField] = row[test.nameField]
						}
						data, err := json.Marshal(input)
						if err != nil {
							t.Fatal(err)
						}
						call(test.remove, data)
					}
					clients = reopen()
					if page := call(first.Operation, continued); !reflect.DeepEqual(page[test.field], remaining[1:]) {
						t.Fatalf("continued survivors after deletion: %v; want %v", page[test.field], remaining[1:])
					}
				})
			}
		})
	}
}
