package lambda

import (
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

func TestDockerImagePinOwnershipRequiresNativeMarker(t *testing.T) {
	executor := &DockerExecutor{config: DockerConfig{Namespace: "retained-image-owner"}}
	lease, reference := executor.imagePinNames(strings.Repeat("a", 48))
	original := nativeContainer{ID: "native-marker", Names: []string{"/" + lease}, Labels: map[string]string{namespaceLabel: executor.config.Namespace, "io.stackd.kind": imagePinKind, imagePinReferenceLabel: reference, imagePinIDLabel: imageRegressionFirstID}}
	image, err := executor.imagePin(original)
	if err != nil || image.ID != imageRegressionFirstID || image.PinLease != lease || image.PinReference != reference {
		t.Fatalf("native ownership marker = %+v, %v", image, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*nativeContainer)
	}{
		{"foreign-namespace", func(item *nativeContainer) { item.Labels[namespaceLabel] = "another-owner" }},
		{"runtime-not-a-pin", func(item *nativeContainer) { item.Labels["io.stackd.kind"] = "lambda-runtime" }},
		{"user-tag", func(item *nativeContainer) {
			item.Labels[imagePinReferenceLabel] = "user-image:" + strings.Repeat("a", 48)
		}},
		{"lookalike-native-name", func(item *nativeContainer) { item.Names = []string{"/" + lease + "-foreign"} }},
		{"invented-config-id", func(item *nativeContainer) { item.Labels[imagePinIDLabel] = "sha256:" + strings.Repeat("z", 64) }},
		{"invalid-lease-token", func(item *nativeContainer) { item.Labels[imagePinReferenceLabel] = reference[:len(reference)-1] + "z" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := original
			item.Labels = maps.Clone(original.Labels)
			test.mutate(&item)
			if image, err := executor.imagePin(item); err == nil || image.PinReference != "" || image.ID != "" {
				t.Fatalf("foreign ownership accepted: %+v, %v", image, err)
			}
		})
	}
}

// The proxy only withholds the real daemon's commit response. Cancellation
// therefore loses PinImageID without replacing the native commit or its labels.
func TestDockerImagePinCanceledCommitRemainsCollectable(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for actual image commit cleanup")
	}
	engine, err := docker.New(t.Context(), docker.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	sourceRepository := "stackd-lambda-image-retention-" + strings.ToLower(rand.Text())
	sourceTag := sourceRepository + ":latest"
	if err := engine.JSON(t.Context(), "POST", "/images/"+url.PathEscape(ProvidedAL2023X8664Image)+"/tag?repo="+url.QueryEscape(sourceRepository)+"&tag=latest", nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := engine.JSON(cleanup, "DELETE", "/images/"+url.PathEscape(sourceTag)+"?noprune=true", nil, nil); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
	}}
	t.Cleanup(transport.CloseIdleConnections)
	committed := make(chan struct{})
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: "docker"})
	proxy.Transport = transport
	proxy.ModifyResponse = func(response *http.Response) error {
		if strings.HasSuffix(response.Request.URL.Path, "/commit") && response.StatusCode == http.StatusCreated {
			close(committed)
			<-response.Request.Context().Done()
			return response.Request.Context().Err()
		}
		return nil
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	proxied, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxied.Close)
	executor, err := NewDockerExecutor(t.Context(), DockerConfig{Client: proxied, Namespace: sourceRepository})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := executor.ReconcileImages(cleanup, nil); err != nil {
			t.Error(err)
		}
		if err := executor.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	image, err := executor.ResolveImage(t.Context(), sourceTag, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	admission, cancelAdmission := context.WithCancel(t.Context())
	t.Cleanup(cancelAdmission)
	result := make(chan error, 1)
	go func() {
		_, err := executor.RetainImage(admission, image)
		result <- err
	}()
	select {
	case <-committed:
	case <-time.After(time.Minute):
		t.Fatal("native image commit never reached the response fence")
	}
	cancelAdmission()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled native commit returned %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("canceled image admission did not return")
	}
	var artifacts []nativePinnedImage
	if err := engine.JSON(t.Context(), "GET", "/images/json?all=true&filters="+executor.filters(imagePinKind), nil, &artifacts); err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].ID == image.ID {
		t.Fatalf("canceled admission lost its distinct native committed artifact: %+v", artifacts)
	}
	if _, err := executor.imagePinLabels(artifacts[0].Labels); err != nil {
		t.Fatal("late committed image has no native ownership labels: ", err)
	}
	if err := executor.ReconcileImages(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := engine.JSON(t.Context(), "GET", "/images/json?all=true&filters="+executor.filters(imagePinKind), nil, &artifacts); err != nil {
		t.Fatal(err)
	}
	markers, err := executor.containers(t.Context(), imagePinKind)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 0 || len(markers) != 0 {
		t.Fatalf("canceled admission retained rootless native artifacts: images=%+v markers=%+v", artifacts, markers)
	}
	var source struct {
		ID string `json:"Id"`
	}
	if err := engine.JSON(t.Context(), "GET", "/images/"+url.PathEscape(sourceTag)+"/json", nil, &source); err != nil || source.ID != image.ID {
		t.Fatalf("native collection changed the user's source tag: ID=%s, err=%v", source.ID, err)
	}
}
