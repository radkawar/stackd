package stackd_test

import (
	"os"
	"reflect"
	"testing"
)

// A single portable ZIP moves between CPU architectures while versions and an
// alias retain their deployment identity. The complete native handler result
// includes platform.machine(), so configuration-only architecture changes or
// dispatching a retained version through $LATEST's image cannot pass this replay.
func TestLambdaArchitecturesDockerNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaConcurrencyLocal(t, lambdaFixture[lambdaQualifiedFixture](t, "architectures"))
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newLambdaQualifiedReplay(t, backend)
			for _, row := range fixture.Observations {
				if !t.Run(row.Label, func(t *testing.T) {
					actual := r.replay(t, row)
					if actual == nil {
						return
					}
					if want, ok := row.Result.Output["Architectures"]; ok && !reflect.DeepEqual(actual["Architectures"], want) {
						t.Fatalf("architectures=%v; native=%v", actual["Architectures"], want)
					}
					if row.Operation == "list-versions-by-function" {
						versions := actual["Versions"].([]any)
						for index, expected := range row.Result.Output["Versions"].([]any) {
							got, want := versions[index].(map[string]any), expected.(map[string]any)
							if !reflect.DeepEqual(got["Architectures"], want["Architectures"]) {
								t.Fatalf("version %v architectures=%v; native=%v", want["Version"], got["Architectures"], want["Architectures"])
							}
						}
					}
					if row.Operation == "invoke" && !reflect.DeepEqual(actual["Payload"], row.Result.Output["Payload"]) {
						t.Fatalf("runtime identity=%#v; native=%#v", actual["Payload"], row.Result.Output["Payload"])
					}
				}) {
					t.FailNow()
				}
			}
		})
	}
}
