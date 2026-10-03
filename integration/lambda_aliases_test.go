package stackd_test

import (
	"os"
	"strings"
	"testing"
)

func TestLambdaAliasesNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaFixture[lambdaQualifiedFixture](t, "alias_routing")
			r := newLambdaQualifiedReplay(t, backend)
			skipUntil := 0
			for i, row := range f.Observations {
				if i < skipUntil {
					continue
				}
				// Recovery cleaned an interrupted native provisioning attempt,
				// not resources created by this behavioral replay.
				if row.Service == "iam" && strings.HasPrefix(row.Label, "recovery_") {
					continue
				}
				if row.Operation == "list-aliases" && row.Result.Code == "Success" && row.Input["Marker"] == nil {
					if !t.Run(row.Label, func(t *testing.T) {
						skipUntil = i + r.inventoryPages(t, f.Observations[i:], "Aliases", "AliasArn")
					}) {
						t.FailNow()
					}
					continue
				}
				if row.Label == "routing_invoke_direct_version_1" {
					r.reopen(t, row.Input["FunctionName"].(string))
				}
				if !t.Run(row.Label, func(t *testing.T) { r.replay(t, row) }) {
					t.FailNow()
				}
			}
			for _, row := range lambdaFixture[lambdaQualifiedFixture](t, "alias_pagination").Observations {
				if row.Result.Code == "CLIError" {
					continue // native client rejected this request before HTTP
				}
				if !t.Run("pagination/"+row.Label, func(t *testing.T) { r.replay(t, row) }) {
					t.FailNow()
				}
			}
		})
	}
}

// The IAM fixture's synchronous matrix isolates requested-resource scope from
// deployment selection. Async applied settings and retargeting are replayed by
// the focused marker/destination tests, rather than reproducing its overlapping
// wall-clock busy-environment capture as a serial sequence.
func TestLambdaQualifiedIAMNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, fixture := range []string{"qualified_invocation", "qualified_tags"} {
				t.Run(fixture, func(t *testing.T) {
					f := lambdaFixture[lambdaQualifiedFixture](t, fixture)
					r := newLambdaQualifiedReplay(t, backend)
					for _, row := range f.Observations {
						if fixture == "qualified_invocation" && strings.HasPrefix(row.Label, "qualified__async_") {
							break
						}
						if row.Operation == "get-account-settings" {
							continue
						} // Native account-wide capacity is not fixture-owned state.
						if !t.Run(row.Label, func(t *testing.T) { r.replay(t, row) }) {
							t.FailNow()
						}
					}
				})
			}
		})
	}
}
