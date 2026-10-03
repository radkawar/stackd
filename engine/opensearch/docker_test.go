package opensearch

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
	service "stackd/internal/services/opensearch"
)

func TestLifecycleGateCancellationAndClose(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	d := &Docker{native: &http.Client{}, gate: make(chan struct{}, 1), lifetime: lifetime, cancel: cancel}
	active, leave, err := d.enter(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	waiting, stop := context.WithCancel(t.Context())
	rejected := make(chan error, 1)
	go func() {
		_, release, err := d.enter(waiting)
		if release != nil {
			release()
		}
		rejected <- err
	}()
	stop()
	if err := <-rejected; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting lifecycle call: %v", err)
	}
	closed := make(chan struct{})
	go func() { d.Close(); close(closed) }()
	<-active.Done()
	select {
	case <-closed:
		t.Fatal("Close did not join the active lifecycle operation")
	default:
	}
	leave()
	<-closed
	if _, release, err := d.enter(t.Context()); err == nil {
		release()
		t.Fatal("closed controller admitted native work")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectUnsafeAdvancedOptions(t *testing.T) {
	for _, options := range []map[string]string{
		{"network.host": "0.0.0.0"},
		{"plugins.security.disabled": "true"},
		{"path.data": "/tmp"},
		{"indices.query.bool.max_clause_count": "0"},
		{"indices.query.bool.max_clause_count": "2147483648"},
		{"indices.query.bool.max_clause_count": "+10"},
		{"rest.action.multi.allow_explicit_index": "1"},
	} {
		if err := ValidateAdvancedOptions(options); err == nil {
			t.Errorf("accepted unsafe or invalid settings %v", options)
		}
	}
}

func nativeRuntime(t *testing.T) *Docker {
	t.Helper()
	if os.Getenv("STACKD_OPENSEARCH_DOCKER") != "1" {
		t.Skip("set STACKD_OPENSEARCH_DOCKER=1 to exercise the installed pinned OpenSearch image")
	}
	d, err := NewDocker(DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: "opensearch-regression-" + rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestNativeCleanupRefusesForeignOwnership(t *testing.T) {
	d := nativeRuntime(t)
	for _, role := range []string{"node", "data", "network"} {
		t.Run(role, func(t *testing.T) {
			id := rand.Text()
			labels := d.labels(id, role)
			labels[labelPrefix+"id"] = "foreign-incarnation"
			name := d.name(id, role)
			var resourceID string
			switch role {
			case "node":
				var created struct {
					ID string `json:"Id"`
				}
				err := d.client.JSON(t.Context(), http.MethodPost, "/containers/create?name="+url.QueryEscape(name), docker.ContainerConfig{Image: d.image, Entrypoint: []string{"/bin/true"}, Labels: labels}, &created)
				if err != nil {
					t.Fatal(err)
				}
				resourceID = created.ID
			case "data":
				err := d.client.JSON(t.Context(), http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: name, Labels: labels}, nil)
				if err != nil {
					t.Fatal(err)
				}
				resourceID = name
			case "network":
				var created struct {
					ID string `json:"Id"`
				}
				err := d.client.JSON(t.Context(), http.MethodPost, "/networks/create", struct {
					Name, Driver string
					Internal     bool
					Labels       map[string]string
				}{name, "bridge", true, labels}, &created)
				if err != nil {
					t.Fatal(err)
				}
				resourceID = created.ID
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				var err error
				// These exact IDs were created by this test, not selected by broad labels.
				switch role {
				case "node":
					err = d.client.RemoveContainer(ctx, resourceID)
				case "data":
					err = d.client.JSON(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(resourceID), nil, nil)
				case "network":
					err = d.client.JSON(ctx, http.MethodDelete, "/networks/"+url.PathEscape(resourceID), nil, nil)
				}
				if err != nil {
					t.Error(err)
				}
			})
			if err := d.Delete(t.Context(), id); err == nil {
				t.Fatal("deleted a foreign resource at an owned-looking name")
			}
			switch role {
			case "node":
				if state, err := d.inspect(t.Context(), resourceID); err != nil || state.ID != resourceID {
					t.Fatalf("foreign container not preserved: %v", err)
				}
			case "data":
				if state, err := d.inspectVolume(t.Context(), resourceID); err != nil || state.Name != resourceID {
					t.Fatalf("foreign volume not preserved: %v", err)
				}
			case "network":
				if state, err := d.inspectNetwork(t.Context(), resourceID); err != nil || state.ID != resourceID {
					t.Fatalf("foreign network not preserved: %v", err)
				}
			}
		})
	}
}

func TestNativeAdvancedOptionsPreserveDocuments(t *testing.T) {
	d := nativeRuntime(t)
	spec := service.NativeSpecification{ID: rand.Text(), EngineVersion: EngineVersion, AdvancedOptions: map[string]string{
		"indices.query.bool.max_clause_count":    "2",
		"rest.action.multi.allow_explicit_index": "false",
	}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := d.Delete(ctx, spec.ID); err != nil {
			t.Error(err)
		}
	})
	endpoint, err := d.Ensure(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, status int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, endpoint+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := d.native.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			t.Fatalf("%s %s: want %d got %d: %s", method, path, status, response.StatusCode, data)
		}
		return data
	}
	request(http.MethodPut, "/records", `{"settings":{"number_of_shards":1,"number_of_replicas":0},"mappings":{"properties":{"value":{"type":"keyword"}}}}`, http.StatusOK)
	request(http.MethodPut, "/records/_doc/sentinel?refresh=true", `{"value":"retained"}`, http.StatusCreated)
	const query = `{"query":{"bool":{"should":[{"term":{"value":"retained"}},{"term":{"value":"other"}},{"term":{"value":"third"}}]}}}`
	if body := request(http.MethodPost, "/records/_search", query, http.StatusBadRequest); !strings.Contains(string(body), "too_many") {
		t.Fatalf("query rejected for an unrelated reason: %s", body)
	}
	const bulk = "{\"index\":{\"_index\":\"records\",\"_id\":\"second\"}}\n{\"value\":\"additional\"}\n"
	if body := request(http.MethodPost, "/_bulk?refresh=true", bulk, http.StatusBadRequest); !strings.Contains(string(body), "explicit index") {
		t.Fatalf("bulk rejected for an unrelated reason: %s", body)
	}
	spec.AdvancedOptions = nil
	endpoint, err = d.Ensure(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var search struct {
		Hits struct {
			Hits []struct {
				ID     string                 `json:"_id"`
				Source struct{ Value string } `json:"_source"`
			}
		}
	}
	if err := json.Unmarshal(request(http.MethodPost, "/records/_search", query, http.StatusOK), &search); err != nil {
		t.Fatal(err)
	}
	if len(search.Hits.Hits) != 1 || search.Hits.Hits[0].ID != "sentinel" || search.Hits.Hits[0].Source.Value != "retained" {
		t.Fatalf("configuration replacement lost or changed the stored document: %+v", search)
	}
	var indexed struct {
		Errors bool
		Items  []struct {
			Index struct {
				ID, Result string
				Status     int
			}
		}
	}
	if err := json.Unmarshal(request(http.MethodPost, "/_bulk?refresh=true", bulk, http.StatusOK), &indexed); err != nil {
		t.Fatal(err)
	}
	if indexed.Errors || len(indexed.Items) != 1 || indexed.Items[0].Index.Status != http.StatusCreated || indexed.Items[0].Index.Result != "created" {
		t.Fatalf("restoring explicit-index support did not create the document: %+v", indexed)
	}
}
