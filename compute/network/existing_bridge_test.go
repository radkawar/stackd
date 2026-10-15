package network

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"stackd/compute/docker"
)

func existingBridgeSpec() Specification {
	return Specification{NetworkID: "arn:aws:ec2:us-east-1:111111111111:vpc/vpc-owned", Pool: netip.MustParsePrefix("10.8.0.0/16"), Gateway: netip.MustParseAddr("10.8.0.1"), Address: netip.MustParseAddr("10.8.0.4")}
}

func existingBridgeInfo(spec Specification) bridgeInfo {
	info := bridgeInfo{ID: "0123456789abcdef", Name: bridgeName(spec.NetworkID), Driver: "bridge", Labels: map[string]string{BridgeLabel: spec.NetworkID}}
	info.IPAM.Driver = "default"
	info.IPAM.Config = append(info.IPAM.Config, struct{ Subnet, Gateway string }{spec.Pool.String(), spec.Gateway.String()})
	return info
}

func existingBridgeClient(t *testing.T, serve func(http.ResponseWriter, *http.Request)) *docker.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/v1.44")
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
		case "/info":
			w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
		default:
			serve(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestExistingBridgeNeverCreatesOrAdoptsMissingForeignTopology(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*bridgeInfo)
		missing bool
	}{
		{name: "owned"},
		{name: "missing", missing: true},
		{name: "foreign-account", change: func(i *bridgeInfo) { i.Labels[BridgeLabel] = "arn:aws:ec2:us-east-1:222222222222:vpc/vpc-owned" }},
		{name: "wrong-driver", change: func(i *bridgeInfo) { i.Driver = "overlay" }},
		{name: "wrong-name", change: func(i *bridgeInfo) { i.Name = "foreign" }},
		{name: "wrong-ipam-driver", change: func(i *bridgeInfo) { i.IPAM.Driver = "foreign" }},
		{name: "wrong-pool", change: func(i *bridgeInfo) { i.IPAM.Config[0].Subnet = "10.9.0.0/16" }},
		{name: "wrong-gateway", change: func(i *bridgeInfo) { i.IPAM.Config[0].Gateway = "10.8.0.2" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := existingBridgeSpec()
			info := existingBridgeInfo(spec)
			if tc.change != nil {
				tc.change(&info)
			}
			var inspections, mutations atomic.Int32
			client := existingBridgeClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					mutations.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.URL.Path != "/networks/"+bridgeName(spec.NetworkID) {
					t.Errorf("unexpected native request %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				inspections.Add(1)
				if tc.missing {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				json.NewEncoder(w).Encode(info)
			})
			bridges, err := NewBridges(client)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			err = bridges.WithExistingBridge(t.Context(), spec, func(b Bridge) error {
				called = true
				if b.Name != info.Name || b.Device != "br-0123456789ab" {
					t.Errorf("wrong admitted bridge %+v", b)
				}
				return nil
			})
			if tc.name == "owned" {
				if err != nil || !called || inspections.Load() != 2 {
					t.Fatalf("owned inspection=%d called=%t err=%v", inspections.Load(), called, err)
				}
			} else if err == nil || called {
				t.Fatalf("foreign/missing native topology adopted: called=%t err=%v", called, err)
			}
			if mutations.Load() != 0 {
				t.Fatal("existing observation issued native create/mutation")
			}
		})
	}
}

func TestExistingBridgeRejectsExternalDeletionAndRecreationDuringObservation(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(map[bool]string{false: "recreated", true: "deleted"}[deleted], func(t *testing.T) {
			spec := existingBridgeSpec()
			var changed atomic.Bool
			client := existingBridgeClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("unexpected mutation %s", r.Method)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				info := existingBridgeInfo(spec)
				if changed.Load() {
					if deleted {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					info.ID = "fedcba9876543210"
				}
				json.NewEncoder(w).Encode(info)
			})
			bridges, err := NewBridges(client)
			if err != nil {
				t.Fatal(err)
			}
			if err = bridges.WithExistingBridge(t.Context(), spec, func(Bridge) error { changed.Store(true); return nil }); err == nil {
				t.Fatal("deleted/recreated bridge retained old observation authority")
			}
		})
	}
}

func TestExistingBridgeLifetimeExcludesConcurrentRemovalAndWaitIsCancellable(t *testing.T) {
	spec := existingBridgeSpec()
	var mutations atomic.Int32
	client := existingBridgeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(existingBridgeInfo(spec))
	})
	bridges, err := NewBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- bridges.WithExistingBridge(t.Context(), spec, func(Bridge) error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("observation did not acquire lifetime")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = bridges.Release(ctx, spec.NetworkID); !errors.Is(err, context.Canceled) {
		t.Fatalf("concurrent removal ignored canceled lifetime wait: %v", err)
	}
	if mutations.Load() != 0 {
		t.Fatal("removal crossed active observer lifetime")
	}
	close(release)
	select {
	case err = <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observation did not release lifetime")
	}
}
