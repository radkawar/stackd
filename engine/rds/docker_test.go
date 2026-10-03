package rds

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"stackd/compute/docker"
)

func nativeRuntime(t *testing.T) *Docker {
	t.Helper()
	if os.Getenv("STACKD_RDS_DOCKER") != "1" {
		t.Skip("set STACKD_RDS_DOCKER=1 to exercise installed native PostgreSQL and MySQL images")
	}
	d, err := NewDocker(DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: "rds-regression-" + rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// Upstream MySQL bootstrap interpolates passwords as SQL, and *_PASSWORD_FILE
// removes trailing newlines. Neither may alter the actual credential supplied
// to this runtime. MySQL ALTER USER also cannot bind a password placeholder.
func TestNativePasswordLiteralAndRotation(t *testing.T) {
	for _, engine := range []string{"postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			d := nativeRuntime(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			spec := Specification{ID: rand.Text(), Engine: engine, Username: "root", Password: "initial'\\雪\n"}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := d.Delete(cleanup, spec.ID); err != nil {
					t.Error(err)
				}
			})
			endpoint, err := d.Ensure(ctx, spec)
			if err != nil {
				t.Fatal(err)
			}
			const desired = "rotated'\\東京\n"
			if err := d.SetPassword(ctx, spec, desired); err != nil {
				t.Fatal(err)
			}
			if err := d.SetPassword(ctx, spec, desired); err != nil {
				t.Fatalf("retry after native credential commit: %v", err)
			}
			if old, err := Open(ctx, spec.Engine, endpoint, "", spec.Username, spec.Password); err == nil {
				old.Close()
				t.Fatal("old credential remains accepted after rotation")
			}
			current, err := Open(ctx, spec.Engine, endpoint, "", spec.Username, desired)
			if err != nil {
				t.Fatal(err)
			}
			defer current.Close()
			var value int
			if err := current.QueryRowContext(ctx, "SELECT 41 + 1").Scan(&value); err != nil || value != 42 {
				t.Fatalf("authenticated native query: value=%d error=%v", value, err)
			}
		})
	}
}

func TestNativeCleanupRefusesForeignOwnership(t *testing.T) {
	d := nativeRuntime(t)
	ctx := t.Context()
	id := rand.Text()
	var created struct {
		ID string `json:"Id"`
	}
	config := docker.ContainerConfig{Image: d.postgresImage, Entrypoint: []string{"/bin/true"}, Labels: map[string]string{labelPrefix + "namespace": "foreign"}}
	name := d.name(id, "database")
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), config, &created); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := d.client.RemoveContainer(cleanup, created.ID); err != nil {
			t.Error(err)
		}
	})
	if err := d.Delete(ctx, id); err == nil {
		t.Fatal("deleted a foreign container with colliding native resource name")
	}
	if retained, err := d.inspect(ctx, created.ID); err != nil || retained.ID != created.ID {
		t.Fatalf("foreign container was not preserved: %v", err)
	}
	volumeID := rand.Text()
	volumeName := d.name(volumeID, "data")
	var volume volumeState
	if err := d.client.JSON(ctx, http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: volumeName, Labels: map[string]string{labelPrefix + "namespace": "foreign"}}, &volume); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := d.client.JSON(cleanup, http.MethodDelete, "/volumes/"+url.PathEscape(volumeName), nil, nil); err != nil {
			t.Error(err)
		}
	})
	if err := d.Delete(ctx, volumeID); err == nil {
		t.Fatal("deleted a foreign durable volume with colliding native resource name")
	}
	if retained, err := d.inspectVolume(ctx, volumeName); err != nil || retained.Name != volumeName {
		t.Fatalf("foreign volume was not preserved: %v", err)
	}
}
