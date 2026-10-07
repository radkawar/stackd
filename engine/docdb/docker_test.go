package docdb

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"stackd/compute/docker"
	"stackd/compute/ports"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func nativeRuntime(t *testing.T) *Docker {
	t.Helper()
	if os.Getenv("STACKD_DOCDB_DOCKER") != "1" {
		t.Skip("set STACKD_DOCDB_DOCKER=1 to exercise the explicitly installed MongoDB image")
	}
	d, err := NewDocker(DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: "docdb-regression-" + rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}
func nativeClient(t *testing.T, ctx context.Context, endpoint Endpoint, spec Specification) *mongo.Client {
	t.Helper()
	client, err := Open(ctx, endpoint, spec.Username, spec.Password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Disconnect(context.Background()) })
	return client
}
func documentValue(t *testing.T, ctx context.Context, client *mongo.Client, want int32) {
	t.Helper()
	var doc struct {
		Value int32 `bson:"value"`
	}
	if err := client.Database("application").Collection("documents").FindOne(ctx, bson.D{{Key: "_id", Value: "retained"}}).Decode(&doc); err != nil || doc.Value != want {
		t.Fatalf("retained native document: value=%d want=%d error=%v", doc.Value, want, err)
	}
}

func TestNativeTLSAuthenticationChangesAndRetainedLifecycle(t *testing.T) {
	d := nativeRuntime(t)
	reservation, err := (ports.Range{}).Listen(t.Context(), "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	selected := uint16(reservation.Addr().(*net.TCPAddr).Port)
	reservation.Close()
	d.portRange = ports.Range{First: selected, Last: selected}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	spec := Specification{ID: rand.Text(), Username: "master", Password: "initial'\\東京"}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		defer d.Close()
		if err := d.Delete(cleanup, spec.ID); err != nil {
			t.Error(err)
		}
	})
	endpoint, err := d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Port != int32(selected) {
		t.Fatalf("native document endpoint %d escaped singleton pool %d", endpoint.Port, selected)
	}
	competing := spec
	competing.ID = rand.Text()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := d.Delete(cleanup, competing.ID); err != nil {
			t.Error(err)
		}
	})
	if _, err := d.Ensure(ctx, competing); !errors.Is(err, ports.ErrExhausted) {
		t.Fatalf("native document pool exhaustion: %v", err)
	}
	client := nativeClient(t, ctx, endpoint, spec)
	collection := client.Database("application").Collection("documents")
	if err := client.Database("application").CreateCollection(ctx, "documents"); err != nil {
		t.Fatal(err)
	}
	stream, err := collection.Watch(ctx, mongo.Pipeline{}, options.ChangeStream().SetMaxAwaitTime(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close(context.Background())
	if _, err := collection.InsertOne(ctx, bson.D{{Key: "_id", Value: "retained"}, {Key: "value", Value: int32(41)}}); err != nil {
		t.Fatal(err)
	}
	if !stream.Next(ctx) {
		t.Fatalf("native change stream did not observe insert: %v", stream.Err())
	}
	var event struct {
		Operation string `bson:"operationType"`
		Document  struct {
			ID    string `bson:"_id"`
			Value int32  `bson:"value"`
		} `bson:"fullDocument"`
	}
	if err := stream.Decode(&event); err != nil || event.Operation != "insert" || event.Document.ID != "retained" || event.Document.Value != 41 {
		t.Fatalf("native change event: %+v error=%v", event, err)
	}
	token := append(bson.Raw(nil), stream.ResumeToken()...)
	stream.Close(ctx)
	documentValue(t, ctx, client, 41)
	if wrong, err := Open(ctx, endpoint, spec.Username, "wrong-password"); err == nil {
		wrong.Disconnect(ctx)
		t.Fatal("incorrect credential accepted")
	}
	config, err := clientOptions(endpoint, spec.Username, spec.Password, false)
	if err != nil {
		t.Fatal(err)
	}
	config.Auth = nil
	anonymous, err := mongo.Connect(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = anonymous.Database("application").Collection("documents").InsertOne(ctx, bson.D{{Key: "_id", Value: "unauthorized"}})
	anonymous.Disconnect(ctx)
	if err == nil {
		t.Fatal("unauthenticated write accepted")
	}
	for _, tc := range []struct {
		name string
		tls  *tls.Config
	}{{"untrusted", &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}}, {"plaintext", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			probe, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			client, err := mongo.Connect(options.Client().SetHosts([]string{net.JoinHostPort(endpoint.Address, portString(endpoint.Port))}).SetDirect(true).SetTLSConfig(tc.tls).SetServerSelectionTimeout(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Disconnect(context.Background())
			if err := client.Ping(probe, nil); err == nil {
				t.Fatal("connection bypassed required trusted TLS")
			}
		})
	}
	if err := d.SetPassword(ctx, spec, "rotated'\\雪"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPassword(ctx, spec, "rotated'\\雪"); err != nil {
		t.Fatalf("credential commit retry: %v", err)
	}
	if old, err := Open(ctx, endpoint, spec.Username, spec.Password); err == nil {
		old.Disconnect(ctx)
		t.Fatal("old credential accepted after rotation")
	}
	spec.Password = "rotated'\\雪"
	client.Disconnect(ctx)
	if err := d.Stop(ctx, spec.ID); err != nil {
		t.Fatal(err)
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil || state.State.Running {
		t.Fatalf("native database did not stop: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = NewDocker(DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: d.namespace, PortRange: ports.Range{First: 1, Last: 1}})
	if err != nil {
		t.Fatal(err)
	}
	retained, err := d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Port != endpoint.Port || retained.Address != endpoint.Address || !bytes.Equal(retained.CA, endpoint.CA) {
		t.Fatal("reopen changed retained endpoint or trust")
	}
	client = nativeClient(t, ctx, retained, spec)
	documentValue(t, ctx, client, 41)
	collection = client.Database("application").Collection("documents")
	stream, err = collection.Watch(ctx, mongo.Pipeline{}, options.ChangeStream().SetResumeAfter(token).SetMaxAwaitTime(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close(context.Background())
	if _, err := collection.InsertOne(ctx, bson.D{{Key: "_id", Value: "after-reopen"}}); err != nil {
		t.Fatal(err)
	}
	if !stream.Next(ctx) {
		t.Fatalf("retained change stream token: %v", stream.Err())
	}
	if err := stream.Decode(&event); err != nil || event.Operation != "insert" || event.Document.ID != "after-reopen" {
		t.Fatalf("resumed native change: %+v error=%v", event, err)
	}
	stream.Close(ctx)
	client.Disconnect(ctx)
	// Container loss must retain the volume, native credential, TLS identity and
	// advertised member, not silently allocate an empty replacement database.
	state, err = d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
		t.Fatal(err)
	}
	retained, err = d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	client = nativeClient(t, ctx, retained, spec)
	documentValue(t, ctx, client, 41)
	client.Disconnect(ctx)
	if err := d.Delete(ctx, spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.inspect(ctx, d.name(spec.ID, "database")); !dockerStatus(err, http.StatusNotFound) {
		t.Fatalf("native container retained after deletion: %v", err)
	}
	if _, err := d.volume(ctx, spec.ID, "data", nil, false); !dockerStatus(err, http.StatusNotFound) {
		t.Fatalf("native volume retained after deletion: %v", err)
	}
}

func TestNativeSnapshotIndependentRestore(t *testing.T) {
	d := nativeRuntime(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	source := Specification{ID: rand.Text(), Username: "master", Password: rand.Text()}
	target := source
	target.ID = rand.Text()
	snapshot := rand.Text()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, id := range []string{target.ID, source.ID} {
			if err := d.Delete(cleanup, id); err != nil {
				t.Error(err)
			}
		}
		if err := d.DeleteSnapshot(cleanup, snapshot); err != nil {
			t.Error(err)
		}
	})
	endpoint, err := d.Ensure(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	client := nativeClient(t, ctx, endpoint, source)
	if _, err := client.Database("application").Collection("documents").InsertOne(ctx, bson.D{{Key: "_id", Value: "retained"}, {Key: "value", Value: int32(41)}}); err != nil {
		t.Fatal(err)
	}
	client.Disconnect(ctx)
	if err := d.Snapshot(ctx, source, snapshot); err != nil {
		t.Fatal(err)
	}
	restored, err := d.Restore(ctx, target, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Port == endpoint.Port || bytes.Equal(restored.CA, endpoint.CA) {
		t.Fatal("restored incarnation reused source endpoint/trust identity")
	}
	client = nativeClient(t, ctx, restored, target)
	documentValue(t, ctx, client, 41)
	if _, err := client.Database("application").Collection("documents").UpdateOne(ctx, bson.D{{Key: "_id", Value: "retained"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "value", Value: int32(42)}}}}); err != nil {
		t.Fatal(err)
	}
	client.Disconnect(ctx)
	if err := d.DeleteSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, source.ID); err != nil {
		t.Fatal(err)
	}
	retried, err := d.Restore(ctx, target, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	client = nativeClient(t, ctx, retried, target)
	documentValue(t, ctx, client, 42)
}

func TestNativeCleanupRefusesForeignOwnership(t *testing.T) {
	d := nativeRuntime(t)
	ctx := t.Context()
	id := rand.Text()
	var created struct {
		ID string `json:"Id"`
	}
	config := docker.ContainerConfig{Image: d.image, Entrypoint: []string{"/bin/true"}, Labels: map[string]string{labelPrefix + "namespace": "foreign"}}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(d.name(id, "database")), config, &created); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.client.RemoveContainer(context.Background(), created.ID); err != nil {
			t.Error(err)
		}
	})
	if err := d.Delete(ctx, id); err == nil {
		t.Fatal("deleted foreign colliding container")
	}
	if state, err := d.inspect(ctx, created.ID); err != nil || state.ID != created.ID {
		t.Fatalf("foreign container not preserved: %v", err)
	}
	volumeID := rand.Text()
	name := d.name(volumeID, "data")
	if err := d.client.JSON(ctx, http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: name, Labels: map[string]string{labelPrefix + "namespace": "foreign"}}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.client.JSON(context.Background(), http.MethodDelete, "/volumes/"+url.PathEscape(name), nil, nil); err != nil {
			t.Error(err)
		}
	})
	if err := d.Delete(ctx, volumeID); err == nil {
		t.Fatal("deleted foreign colliding volume")
	}
	var retained volumeState
	if err := d.client.JSON(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, &retained); err != nil || retained.Name != name {
		t.Fatalf("foreign volume not preserved: %v", err)
	}
}

func TestRejectedSCRAMPasswordDoesNotAllocate(t *testing.T) {
	d := nativeRuntime(t)
	spec := Specification{ID: rand.Text(), Username: "master", Password: "prohibited\n"}
	if _, err := d.Ensure(t.Context(), spec); err == nil {
		t.Fatal("accepted password rejected by native SCRAM-SHA-256")
	}
	if _, err := d.inspect(t.Context(), d.name(spec.ID, "database")); !dockerStatus(err, http.StatusNotFound) {
		t.Fatalf("invalid password allocated a native container: %v", err)
	}
	if _, err := d.volume(t.Context(), spec.ID, "data", nil, false); !dockerStatus(err, http.StatusNotFound) {
		t.Fatalf("invalid password allocated a native volume: %v", err)
	}
}
