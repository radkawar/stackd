package kafka

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"stackd/compute/docker"

	msk "stackd/internal/services/kafka"
)

// These are deterministic persistence/effect failure schedules, not native
// protocol consumer proof. The retained real Kafka replay supplies that proof.
func TestUserConfirmationRepairsEffectBeforeMarkerFailureAndRestoredPreviousIntent(t *testing.T) {
	original := statusTestSpec()
	rotated := statusTestSpec()
	rotated.Users[0].Password = "rotated"
	originalHashes, rotatedHashes := userHashes(original), userHashes(rotated)
	for _, failurePhase := range []string{"alter-response", "restart-proof", "confirmation-write"} {
		t.Run(failurePhase, func(t *testing.T) {
			m := &material{UserHashes: maps.Clone(originalHashes), UsersConfirmed: true}
			var durable []byte
			native := maps.Clone(originalHashes)
			failure := errors.New(failurePhase)
			writes := 0
			persist := func() error {
				writes++
				if writes == 2 && failurePhase == "confirmation-write" {
					return failure
				}
				encoded, err := json.Marshal(m)
				durable = encoded
				return err
			}
			alter := func() error {
				var saved material
				if err := json.Unmarshal(durable, &saved); err != nil {
					t.Fatal(err)
				}
				if saved.UsersConfirmed {
					t.Fatal("native effect preceded durable uncertainty")
				}
				native = maps.Clone(rotatedHashes)
				if failurePhase == "alter-response" {
					return failure
				}
				return nil
			}
			prove := func() error {
				if failurePhase == "restart-proof" {
					return failure
				}
				return nil
			}
			if err := confirmUserIntent(m, rotatedHashes, persist, alter, prove); !errors.Is(err, failure) {
				t.Fatalf("injected failure=%v", err)
			}
			if m.UsersConfirmed || !maps.Equal(native, rotatedHashes) {
				t.Fatal("effect interruption was not modeled as uncertain")
			}
			var reopened material
			if err := json.Unmarshal(durable, &reopened); err != nil {
				t.Fatal(err)
			}
			if usersApplied(&reopened, originalHashes) {
				t.Fatal("restored original AWSCURRENT hash skipped native recovery")
			}
			// Reopening and restoring the previous model must run a real alteration
			// phase even when the retained previous hashes equal the restored intent.
			writes = 0
			repairEffects, proofs := 0, 0
			repairPersist := func() error { encoded, err := json.Marshal(&reopened); durable = encoded; return err }
			if err := confirmUserIntent(&reopened, originalHashes, repairPersist, func() error { repairEffects++; native = maps.Clone(originalHashes); return nil }, func() error { proofs++; return nil }); err != nil {
				t.Fatal(err)
			}
			var committed material
			if err := json.Unmarshal(durable, &committed); err != nil {
				t.Fatal(err)
			}
			if repairEffects != 1 || proofs != 1 || !usersApplied(&committed, originalHashes) || !maps.Equal(native, originalHashes) {
				t.Fatal("restored intent was not confirmed after actual effect/proof phases")
			}
		})
	}
}

func TestLegacyAndEmptyDesiredCredentialStateMustReconcile(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-same-hashes", true: "empty-desired-removal"}[empty], func(t *testing.T) {
			spec := statusTestSpec()
			if empty {
				spec.Users = nil
			}
			hashes := userHashes(spec)
			legacy, err := json.Marshal(struct{ UserHashes map[string]string }{hashes})
			if err != nil {
				t.Fatal(err)
			}
			var m material
			if err = json.Unmarshal(legacy, &m); err != nil {
				t.Fatal(err)
			}
			if usersApplied(&m, hashes) {
				t.Fatal("legacy missing confirmation bit manufactured native proof")
			}
			effects := 0
			if err = confirmUserIntent(&m, hashes, func() error { return nil }, func() error { effects++; return nil }, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if effects != 1 || !usersApplied(&m, hashes) {
				t.Fatal("legacy/empty desired did not reconcile and prove")
			}
		})
	}
}

func TestUserConfirmationPersistenceFencePrecedesNativeEffect(t *testing.T) {
	m := &material{UserHashes: userHashes(statusTestSpec()), UsersConfirmed: true}
	denied := errors.New("exact helper immutable owner mismatch")
	effects := 0
	if err := confirmUserIntent(m, m.UserHashes, func() error { return denied }, func() error { effects++; return nil }, func() error { effects++; return nil }); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if effects != 0 || m.UsersConfirmed {
		t.Fatal("stale owner/persistence failure reached native credential effect")
	}
}

func TestUserConfirmationDoesNotPromoteChangedDesiredIntent(t *testing.T) {
	first := statusTestSpec()
	later := statusTestSpec()
	later.Users[0].Password = "next-intent"
	firstHashes, laterHashes := userHashes(first), userHashes(later)
	m := &material{UserHashes: firstHashes, UsersConfirmed: true}
	currentDesired := firstHashes
	if err := confirmUserIntent(m, firstHashes, func() error { return nil }, func() error { currentDesired = laterHashes; return nil }, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if usersApplied(m, currentDesired) {
		t.Fatal("older in-flight proof promoted newer desired credentials")
	}
	if !usersApplied(m, firstHashes) {
		t.Fatal("proof did not retain the exact captured desired intent")
	}
}

func TestUnknownAndMismatchingCredentialsCannotSupplyReadyMarker(t *testing.T) {
	spec := statusTestSpec()
	hashes := userHashes(spec)
	m := &material{UserHashes: hashes}
	if usersApplied(m, hashes) {
		t.Fatal("admin-only readiness exposed unknown customer credential state")
	}
	m.UsersConfirmed = true
	changed := msk.Specification{Users: []msk.SCRAMUser{{Username: spec.Users[0].Username, Password: "changed"}}}
	if usersApplied(m, userHashes(changed)) {
		t.Fatal("old confirmed credentials exposed changed customer intent")
	}
}

func TestStatusRejectsUnknownOrStaleSCRAMBeforeAdminReadiness(t *testing.T) {
	for _, unknown := range []bool{true, false} {
		t.Run(map[bool]string{true: "unknown", false: "stale-desired"}[unknown], func(t *testing.T) {
			runtime := &Docker{gate: make(chan struct{}, 1), imageID: "owned-image"}
			spec := statusTestSpec()
			properties, err := msk.ParseProperties(spec.ServerProperties)
			if err != nil {
				t.Fatal(err)
			}
			m := material{Nodes: []nodePorts{{Client: 19092, Admin: 19095}}, Configuration: configurationID(spec, properties), UserHashes: userHashes(spec), UsersConfirmed: !unknown}
			if !unknown {
				m.UserHashes = map[string]string{"consumer": "stale-native-hash"}
			}
			encoded, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var stopped, unexpectedEffect atomic.Int32
			var running atomic.Bool
			running.Store(true)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/v1.44")
				switch {
				case path == "/version":
					w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
				case path == "/info":
					w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
				case strings.HasPrefix(path, "/volumes/"):
					json.NewEncoder(w).Encode(volumeState{Name: resourceName(spec, "config"), Driver: "local", Labels: runtime.labels(spec, "config")})
				case path == "/containers/owned-broker/archive":
					archive := tar.NewWriter(w)
					archive.WriteHeader(&tar.Header{Name: "material.json", Mode: 0600, Size: int64(len(encoded))})
					archive.Write(encoded)
					archive.Close()
				case path == "/containers/owned-broker/stop":
					running.Store(false)
					stopped.Add(1)
					w.WriteHeader(http.StatusNoContent)
				case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
					config := runtime.containerConfig(spec, "broker-1", nil)
					json.NewEncoder(w).Encode(map[string]any{"Id": "owned-broker", "Image": runtime.imageID, "Config": config, "HostConfig": config.HostConfig, "State": map[string]any{"Running": running.Load()}, "NetworkSettings": map[string]any{"Networks": map[string]any{resourceName(spec, "network"): map[string]any{"Aliases": []string{resourceName(spec, "internal-1")}, "GwPriority": 100}}}})
				default:
					unexpectedEffect.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()
			client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			runtime.client = client
			endpoint, err := runtime.Status(t.Context(), spec)
			if err == nil || !strings.Contains(err.Error(), "SCRAM credentials are not applied") || len(endpoint.Brokers) != 0 {
				t.Fatalf("unconfirmed native user state became admin-only ready: brokers=%d err=%v", len(endpoint.Brokers), err)
			}
			if stopped.Load() != 1 || running.Load() || unexpectedEffect.Load() != 0 {
				t.Fatalf("stops=%d running=%t unproved protocol effects=%d", stopped.Load(), running.Load(), unexpectedEffect.Load())
			}
		})
	}
}
