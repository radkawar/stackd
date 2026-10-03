package eks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// nativeBridge is reachable only on this exact-owned Docker network's gateway.
// Public IAM-authenticated Kubernetes traffic never enters its capability routes.
type nativeBridge struct {
	server    *http.Server
	mux       *http.ServeMux
	url       string
	ca        []byte
	wake      chan struct{}
	audit     *auditSpool
	auditMu   sync.RWMutex
	auditSink AuditSink
}

func (b *nativeBridge) close() error {
	b.audit.close()
	return b.server.Close()
}

func (c *nativeCluster) bridgeURL() string { return c.bridge.url }
func (c *nativeCluster) bridgeCA() []byte  { return c.bridge.ca }
func bridgeCapability(token, purpose string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("stackd-eks-bridge/" + purpose))
	return hex.EncodeToString(mac.Sum(nil))
}
func (c *nativeCluster) bridgeCapability(purpose string) string {
	return bridgeCapability(c.state.Token, purpose)
}

// Capture DeleteOptions and admitted binding responses. Other resource bodies
// (including secrets) stay metadata-only.
const nativeAuditPolicy = "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [RequestReceived]\nrules:\n- level: RequestResponse\n  verbs: [create]\n  resources:\n  - group: rbac.authorization.k8s.io\n    resources: [rolebindings, clusterrolebindings]\n- level: Request\n  verbs: [delete, deletecollection]\n- level: Metadata\n"

func (k *K3d) startBridge(ctx context.Context, state *diskState, dir string, sink AuditSink) (*nativeBridge, error) {
	out, err := k.command(ctx, "docker", "network", "inspect", state.Name)
	if err != nil {
		return nil, err
	}
	var networks []struct {
		IPAM struct{ Config []struct{ Gateway string } }
	}
	if err = json.Unmarshal(out, &networks); err != nil {
		return nil, err
	}
	if len(networks) != 1 || len(networks[0].IPAM.Config) == 0 || net.ParseIP(networks[0].IPAM.Config[0].Gateway) == nil {
		return nil, errors.New("eks: native bridge gateway unavailable")
	}
	gateway := networks[0].IPAM.Config[0].Gateway
	if state.BridgeHost != "" && state.BridgeHost != gateway {
		return nil, errors.New("eks: native bridge gateway changed")
	}
	state.BridgeHost = gateway
	if state.BridgePort == 0 {
		state.BridgePort, err = freePort(gateway)
		if err != nil {
			return nil, err
		}
		if err = saveState(dir, *state); err != nil {
			return nil, err
		}
	}
	ca, err := readPrivate(filepath.Join(dir, "bridge-ca.crt"))
	if errors.Is(err, os.ErrNotExist) {
		var cert, key []byte
		ca, cert, key, err = newProxyIdentity(gateway)
		if err != nil {
			return nil, err
		}
		for _, file := range []struct {
			name string
			data []byte
		}{{"bridge-ca.crt", ca}, {"bridge.crt", cert}, {"bridge.key", key}} {
			if err = writePrivate(dir, file.name, file.data); err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}
	cert, err := readPrivate(filepath.Join(dir, "bridge.crt"))
	if err != nil {
		return nil, err
	}
	key, err := readPrivate(filepath.Join(dir, "bridge.key"))
	if err != nil {
		return nil, err
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	source, err := prepareAuditSpool(dir)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(gateway, fmt.Sprint(state.BridgePort)))
	if err != nil {
		source.close()
		return nil, err
	}
	bridge := &nativeBridge{mux: http.NewServeMux(), url: "https://" + listener.Addr().String(), ca: ca, wake: make(chan struct{}, 1), audit: source}
	bridge.auditSink = sink
	token := bridgeCapability(state.Token, "audit")
	bridge.mux.HandleFunc("/audit/"+token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, auditBatchLimit))
		if err != nil {
			http.Error(w, "Invalid audit EventList", http.StatusBadRequest)
			return
		}
		var events struct {
			APIVersion string            `json:"apiVersion"`
			Kind       string            `json:"kind"`
			Items      []json.RawMessage `json:"items"`
		}
		if err = json.Unmarshal(body, &events); err != nil || events.APIVersion != "audit.k8s.io/v1" || events.Kind != "EventList" {
			http.Error(w, "Invalid audit EventList", http.StatusBadRequest)
			return
		}
		records, err := decodeKubernetesAudit(events.Items)
		if err != nil {
			http.Error(w, "Invalid native audit event", http.StatusBadRequest)
			return
		}
		bridge.auditMu.RLock()
		observer := bridge.auditSink
		bridge.auditMu.RUnlock()
		if observer != nil {
			// Commit source admission before acknowledgement. The observer
			// deduplicates retries even when the following spool fsync fails.
			if err := observer.PutKubernetesAudit(r.Context(), state.ID, records); err != nil {
				http.Error(w, "Audit observer unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if err = source.append(body); err != nil {
			http.Error(w, "Audit source unavailable", http.StatusServiceUnavailable)
			return
		}
		select {
		case bridge.wake <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})
	bridge.server = &http.Server{Handler: bridge.mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 16384}
	go bridge.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}))
	policy := []byte(nativeAuditPolicy)
	webhook := map[string]any{"apiVersion": "v1", "kind": "Config", "clusters": []any{map[string]any{"name": "audit", "cluster": map[string]any{"server": bridge.url + "/audit/" + token, "certificate-authority-data": base64.StdEncoding.EncodeToString(ca)}}}, "users": []any{map[string]any{"name": "audit", "user": map[string]string{"token": token}}}, "contexts": []any{map[string]any{"name": "audit", "context": map[string]string{"cluster": "audit", "user": "audit"}}}, "current-context": "audit"}
	encoded, err := json.Marshal(webhook)
	if err == nil {
		err = writePrivate(dir, "audit-policy.yaml", policy)
	}
	if err == nil {
		err = writePrivate(dir, "audit-webhook.kubeconfig", encoded)
	}
	if err != nil {
		bridge.close()
		return nil, err
	}
	return bridge, nil
}

func auditArguments() []string {
	return []string{"--kube-apiserver-arg=audit-policy-file=/etc/stackd/audit-policy.yaml", "--kube-apiserver-arg=audit-webhook-config-file=/etc/stackd/audit-webhook.kubeconfig", "--kube-apiserver-arg=audit-webhook-batch-max-wait=1s", "--v=2"}
}

func (k *K3d) installNativeLogging(ctx context.Context, state diskState, dir string) error {
	server := "k3d-" + state.Name + "-server-0"
	if _, err := k.command(ctx, "docker", "exec", server, "mkdir", "-p", "/etc/stackd", "/etc/rancher/k3s/config.yaml.d"); err != nil {
		return err
	}
	for _, name := range []string{"audit-policy.yaml", "audit-webhook.kubeconfig"} {
		if _, err := k.command(ctx, "docker", "cp", filepath.Join(dir, name), server+":/etc/stackd/"+name); err != nil {
			return err
		}
	}
	config := []byte("v: 2\nkube-apiserver-arg+:\n- audit-policy-file=/etc/stackd/audit-policy.yaml\n- audit-webhook-config-file=/etc/stackd/audit-webhook.kubeconfig\n- audit-webhook-batch-max-wait=1s\n")
	if err := writePrivate(dir, "native-logging.yaml", config); err != nil {
		return err
	}
	if _, err := k.command(ctx, "docker", "cp", filepath.Join(dir, "native-logging.yaml"), server+":/etc/rancher/k3s/config.yaml.d/98-stackd-logging.yaml"); err != nil {
		return err
	}
	_, err := k.command(ctx, "docker", "restart", "--time", "30", server)
	return err
}
