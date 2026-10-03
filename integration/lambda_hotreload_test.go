package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"stackd"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	computelambda "stackd/compute/lambda"
)

type lambdaHotReloadVariant struct{ Code, Layer, Extension string }
type lambdaHotReloadFixture struct {
	Handler, Layer, Extension string
	Variants                  map[string]lambdaHotReloadVariant
}
type lambdaHotReloadResult struct {
	Source, Layer, Extension, Boot, Tmp, Version string
	ReadOnlyErrno                                int `json:"read_only_errno"`
}

func (f lambdaHotReloadFixture) files(variant string) (map[string]string, map[string]string) {
	value := f.Variants[variant]
	replace := func(template, marker, value string) string {
		encoded, _ := json.Marshal(value) // A string always has a JSON representation.
		return strings.ReplaceAll(template, marker, string(encoded))
	}
	return map[string]string{"entry.py": replace(f.Handler, "@CODE@", value.Code)}, map[string]string{
		"python/shared.py":              replace(f.Layer, "@LAYER@", value.Layer),
		"extensions/" + value.Extension: replace(f.Extension, "@EXTENSION@", value.Extension),
	}
}

func writeLambdaDevelopmentTree(t *testing.T, directory string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "extensions/") {
			mode = 0o755
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
}

// A directory replacement must discover the new extension from the customer's
// mount, not the keeper's old inode. A busy invocation owns its runtime until it
// finishes; the next generation retains /tmp but cannot mutate published code.
func TestLambdaHotReloadDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	data, err := os.ReadFile("../testdata/lambda/hot_reload.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture lambdaHotReloadFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	root := t.TempDir()
	codeDirectory, layerDirectory := filepath.Join(root, "code"), filepath.Join(root, "layers")
	code, layers := fixture.files("initial")
	writeLambdaDevelopmentTree(t, codeDirectory, code)
	writeLambdaDevelopmentTree(t, layerDirectory, layers)
	const name = "hot-reload"
	_, server := newLambdaDockerStack(t, stackd.Config{Storage: nil, Clock: nil}, &computelambda.DockerConfig{HotReload: map[string]computelambda.HotReloadDirectories{
		"arn:aws:lambda:us-east-1:000000000000:function:" + name: {Code: codeDirectory, Layers: layerDirectory},
	}})
	clients := cloudClients{server}
	role, err := clients.iam("test", "test", "").CreateRole(ctx, &iam.CreateRoleInput{
		RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	code, layers = fixture.files("uploaded")
	layer, err := client.PublishLayerVersion(ctx, &awslambda.PublishLayerVersionInput{LayerName: aws.String(name), Content: &lambdatypes.LayerVersionContentInput{ZipFile: lambdaZIP(t, layers, "extensions/"+fixture.Variants["uploaded"].Extension)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateFunction(ctx, &awslambda.CreateFunctionInput{FunctionName: aws.String(name), Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("entry.invoke"), Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, code)}, Layers: []string{aws.ToString(layer.LayerVersionArn)}, Timeout: aws.Int32(30), MemorySize: aws.Int32(1024)})
	if err != nil {
		t.Fatal(err)
	}
	if err := awslambda.NewFunctionActiveWaiter(client, fastLambdaActiveWaiter).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	decode := func(output *awslambda.InvokeOutput, err error) lambdaHotReloadResult {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if output.FunctionError != nil {
			t.Fatalf("runtime error: %s", output.Payload)
		}
		var value lambdaHotReloadResult
		if err := json.Unmarshal(output.Payload, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	invoke := func(qualifier string) lambdaHotReloadResult {
		t.Helper()
		input := &awslambda.InvokeInput{FunctionName: aws.String(name), Payload: []byte("{}")}
		if qualifier != "" {
			input.Qualifier = aws.String(qualifier)
		}
		return decode(client.Invoke(ctx, input))
	}
	check := func(value lambdaHotReloadResult, variant string) {
		t.Helper()
		want := fixture.Variants[variant]
		if value.Source != want.Code || value.Layer != want.Layer || value.Extension != want.Extension || value.ReadOnlyErrno != 30 {
			t.Fatalf("runtime=%+v; want=%+v with read-only deployment", value, want)
		}
	}
	initial := invoke("")
	check(initial, "initial")
	warm := invoke("")
	if warm.Boot != initial.Boot || warm.Tmp != initial.Tmp {
		t.Fatalf("unchanged source lost warm state: initial=%+v warm=%+v", initial, warm)
	}
	published, err := client.PublishVersion(ctx, &awslambda.PublishVersionInput{FunctionName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateAlias(ctx, &awslambda.CreateAliasInput{FunctionName: aws.String(name), Name: aws.String("published"), FunctionVersion: published.Version}); err != nil {
		t.Fatal(err)
	}
	retained := invoke("published")
	check(retained, "uploaded")

	entered := make(chan struct{}, 1)
	hold, release := context.WithCancel(ctx)
	barrier := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-hold.Done()
		w.WriteHeader(http.StatusOK)
	}))
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	barrier.Listener.Close()
	barrier.Listener = listener
	barrier.Start()
	t.Cleanup(barrier.Close)
	t.Cleanup(release)
	payload, err := json.Marshal(map[string]string{"hold_url": fmt.Sprintf("http://host.docker.internal:%d", listener.Addr().(*net.TCPAddr).Port)})
	if err != nil {
		t.Fatal(err)
	}
	type callResult struct {
		output *awslambda.InvokeOutput
		err    error
	}
	finished := make(chan callResult, 1)
	go func() {
		output, err := client.Invoke(ctx, &awslambda.InvokeInput{FunctionName: aws.String(name), Payload: payload})
		finished <- callResult{output, err}
	}()
	select {
	case <-entered:
	case result := <-finished:
		t.Fatalf("invocation ended before holding: output=%+v error=%v", result.output, result.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	code, layers = fixture.files("updated")
	writeLambdaDevelopmentTree(t, codeDirectory, map[string]string{"entry.next": code["entry.py"]})
	if err := os.Rename(filepath.Join(codeDirectory, "entry.next"), filepath.Join(codeDirectory, "entry.py")); err != nil {
		t.Fatal(err)
	}
	writeLambdaDevelopmentTree(t, layerDirectory+"-next", layers)
	if err := os.Rename(layerDirectory, layerDirectory+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(layerDirectory+"-next", layerDirectory); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case result := <-finished:
		active := decode(result.output, result.err)
		check(active, "initial")
		if active.Boot != initial.Boot {
			t.Fatalf("editing source replaced an active runtime: initial=%+v active=%+v", initial, active)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	updated := invoke("")
	// Filesystem notification arrival is outside the virtual service clock.
	// Poll successful invocations, not internal watcher state or a fixed sleep.
	for updated.Source == initial.Source {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
		updated = invoke("")
	}
	check(updated, "updated")
	if updated.Boot == initial.Boot || updated.Tmp != initial.Tmp {
		t.Fatalf("reload must replace initialized code while retaining /tmp: initial=%+v updated=%+v", initial, updated)
	}
	if warm := invoke(""); warm.Boot != updated.Boot {
		t.Fatalf("unchanged reloaded code restarted: updated=%+v warm=%+v", updated, warm)
	}
	after := invoke("published")
	check(after, "uploaded")
	if after.Boot != retained.Boot || after.Version != aws.ToString(published.Version) {
		t.Fatalf("local edits changed published execution: before=%+v after=%+v", retained, after)
	}
}
