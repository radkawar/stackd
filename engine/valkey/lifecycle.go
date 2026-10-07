package valkey

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"stackd/compute/docker"
	"stackd/compute/ports"
)

type nativeNode struct{ Port, BusPort int32 }
type manifest struct {
	ID, Secret              string
	Shards, Replicas        int32
	ClusterMode, TLSEnabled bool
	MemoryBytes             int64
	Nodes                   []nativeNode
}
type containerState struct {
	ID, Image string
	Config    struct {
		Labels          map[string]string
		Entrypoint, Cmd []string
	}
	HostConfig struct {
		NetworkMode string
		Privileged  bool
		Binds       []string
		Memory      int64
	}
	Mounts []struct {
		Type, Name, Destination string
		RW                      bool
	}
	State struct {
		Running bool
		Status  string
	}
}
type volumeState struct {
	Name, Driver    string
	Labels, Options map[string]string
}

func (d *Docker) inspect(ctx context.Context, id string) (containerState, error) {
	var s containerState
	err := d.client.JSON(ctx, "GET", "/containers/"+d.name(id, "engine")+"/json", nil, &s)
	return s, err
}
func (d *Docker) volume(ctx context.Context, id, role string, create bool) (volumeState, error) {
	name := d.name(id, role)
	var v volumeState
	err := d.client.JSON(ctx, "GET", "/volumes/"+name, nil, &v)
	if dockerStatus(err, 404) && create {
		err = d.client.JSON(ctx, "POST", "/volumes/create", docker.VolumeConfig{Name: name, Driver: "local", Labels: d.labels(id, role)}, &v)
	}
	if err != nil {
		return v, err
	}
	if err = d.checkOwner(v.Labels, id, role); err != nil {
		return v, err
	}
	if v.Name != name || v.Driver != "local" || len(v.Options) != 0 {
		return v, errors.New("conflicting Valkey storage configuration")
	}
	return v, nil
}
func (d *Docker) checkContainer(s containerState, id string) error {
	if err := d.checkOwner(s.Config.Labels, id, "engine"); err != nil {
		return err
	}
	if s.Image != d.image || s.HostConfig.NetworkMode != "host" || s.HostConfig.Privileged || len(s.HostConfig.Binds) != 0 || !slices.Equal(s.Config.Entrypoint, []string{"/bin/sh", "/data/start.sh"}) {
		return errors.New("conflicting Valkey native process configuration")
	}
	if len(s.Mounts) != 1 || s.Mounts[0].Type != "volume" || s.Mounts[0].Name != d.name(id, "data") || s.Mounts[0].Destination != "/data" || !s.Mounts[0].RW {
		return errors.New("conflicting Valkey native data mount")
	}
	return nil
}
func (d *Docker) containerConfig(spec Specification) docker.ContainerConfig {
	config := docker.ContainerConfig{Image: d.image, Entrypoint: []string{"/bin/sh", "/data/start.sh"}, Labels: d.labels(spec.ID, "engine"), User: "999:1000"}
	config.HostConfig.NetworkMode = "host"
	config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: d.name(spec.ID, "data"), Target: "/data", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "none"}
	config.HostConfig.CapDrop = []string{"ALL"}
	config.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	config.HostConfig.ReadonlyRootfs = true
	config.HostConfig.PidsLimit = 512
	memory := spec.MemoryBytes
	if memory == 0 {
		memory = 512 << 20
	}
	config.HostConfig.Memory = (memory + (128 << 20)) * int64(spec.Shards*(spec.Replicas+1))
	config.HostConfig.MemorySwap = config.HostConfig.Memory
	config.HostConfig.CPUPeriod = 100000
	config.HostConfig.CPUQuota = 200000
	return config
}
func (d *Docker) newManifest(ctx context.Context, spec Specification) (manifest, []net.Listener, error) {
	m := manifest{ID: spec.ID, Secret: rand.Text(), Shards: spec.Shards, Replicas: spec.Replicas, ClusterMode: spec.ClusterMode, TLSEnabled: spec.TLSEnabled, MemoryBytes: spec.MemoryBytes}
	m.Nodes = make([]nativeNode, int(spec.Shards*(spec.Replicas+1)))
	held := make([]net.Listener, 0, len(m.Nodes)*2)
	fail := func(err error) (manifest, []net.Listener, error) {
		for _, listener := range held {
			listener.Close()
		}
		return m, nil, err
	}
	for node := range m.Nodes {
		listener, err := d.portRange.Listen(ctx, "127.0.0.1", 0)
		if err != nil {
			return fail(err)
		}
		held = append(held, listener)
		m.Nodes[node].Port = int32(listener.Addr().(*net.TCPAddr).Port)
	}
	if spec.ClusterMode {
		for node := range m.Nodes {
			// The private cluster bus is not a customer endpoint. Keep its
			// distinct exact ephemeral port in the same retained manifest.
			listener, err := (ports.Range{}).Listen(ctx, "127.0.0.1", 0)
			if err != nil {
				return fail(err)
			}
			held = append(held, listener)
			m.Nodes[node].BusPort = int32(listener.Addr().(*net.TCPAddr).Port)
		}
	}
	return m, held, nil
}

type archiveFile struct {
	name string
	body []byte
	mode int64
}

func (d *Docker) putFiles(ctx context.Context, container string, files []archiveFile) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0600
		}
		h := &tar.Header{Name: f.name, Mode: mode, Size: int64(len(f.body)), Uid: 999, Gid: 1000}
		if strings.HasSuffix(f.name, "/") {
			h.Typeflag = tar.TypeDir
			h.Mode = 0700
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err := tw.Write(f.body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	res, err := d.client.Request(ctx, "PUT", "/containers/"+url.PathEscape(container)+"/archive?path=/data", &buf, "application/x-tar")
	if err != nil {
		return err
	}
	return res.Body.Close()
}
func (d *Docker) readFile(ctx context.Context, container, path string) ([]byte, error) {
	res, err := d.client.Request(ctx, "GET", "/containers/"+url.PathEscape(container)+"/archive?path="+url.QueryEscape(path), nil, "")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	tr := tar.NewReader(res.Body)
	h, err := tr.Next()
	if err != nil {
		return nil, err
	}
	if h.Size > 1<<20 || h.Typeflag != tar.TypeReg {
		return nil, errors.New("invalid native Valkey metadata file")
	}
	return io.ReadAll(io.LimitReader(tr, 1<<20))
}
func (d *Docker) readManifest(ctx context.Context, s containerState, spec Specification) (manifest, error) {
	var m manifest
	data, err := d.readFile(ctx, s.ID, "/data/manifest.json")
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	if m.ID != spec.ID || m.Shards != spec.Shards || m.Replicas != spec.Replicas || m.ClusterMode != spec.ClusterMode || m.TLSEnabled != spec.TLSEnabled || m.MemoryBytes != spec.MemoryBytes || m.Secret == "" || len(m.Nodes) != int(m.Shards*(m.Replicas+1)) {
		return m, errors.New("native Valkey topology or identity differs from retained intent")
	}
	if err := m.validatePorts(); err != nil {
		return m, err
	}
	return m, nil
}
func (d *Docker) initialize(ctx context.Context, s containerState, spec Specification, m manifest) error {
	files := []archiveFile{{name: "users.acl", body: []byte(aclFile(spec.Users, m.Secret))}}
	if m.TLSEnabled {
		files = append(files, archiveFile{name: "server.crt", body: d.certificate}, archiveFile{name: "server.key", body: d.key})
	}
	var start strings.Builder
	start.WriteString("#!/bin/sh\nset -eu\npids=''\ntrap 'kill -TERM $pids 2>/dev/null || true; wait; exit 0' TERM INT\n")
	params := effectiveParameters(spec)
	for i, n := range m.Nodes {
		dir := fmt.Sprintf("node-%d", i)
		files = append(files, archiveFile{name: dir + "/"})
		var cfg strings.Builder
		fmt.Fprintf(&cfg, "bind 127.0.0.1\nprotected-mode yes\ndir /data/%s\nappendonly yes\nappendfsync always\nsave \"\"\naclfile /data/users.acl\nmasteruser %s\nmasterauth %s\nlogfile \"\"\n", dir, controllerUser, m.Secret)
		if m.TLSEnabled {
			fmt.Fprintf(&cfg, "port 0\ntls-port %d\ntls-cert-file /data/server.crt\ntls-key-file /data/server.key\ntls-ca-cert-file /data/server.crt\ntls-auth-clients no\ntls-replication yes\n", n.Port)
		} else {
			fmt.Fprintf(&cfg, "port %d\n", n.Port)
		}
		if m.ClusterMode {
			fmt.Fprintf(&cfg, "cluster-enabled yes\ncluster-config-file nodes.conf\ncluster-node-timeout 5000\ncluster-port %d\ncluster-announce-ip 127.0.0.1\ncluster-announce-port %d\ncluster-announce-bus-port %d\n", n.BusPort, n.Port, n.BusPort)
			if m.TLSEnabled {
				fmt.Fprintf(&cfg, "tls-cluster yes\ncluster-announce-tls-port %d\n", n.Port)
			}
		}
		for _, k := range sortedParameters(params) {
			fmt.Fprintf(&cfg, "%s %q\n", k, params[k])
		}
		files = append(files, archiveFile{name: dir + "/valkey.conf", body: []byte(cfg.String())})
		fmt.Fprintf(&start, "valkey-server /data/%s/valkey.conf &\npids=\"$pids $!\"\n", dir)
	}
	start.WriteString("wait -n\nstatus=$?\nkill -TERM $pids 2>/dev/null || true\nwait\nexit $status\n")
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	files = append(files, archiveFile{name: "start.sh", body: []byte(start.String()), mode: 0700}, archiveFile{name: "manifest.json", body: data})
	return d.putFiles(ctx, s.ID, files)
}
func (d *Docker) clientFor(m manifest, index int) *redis.Client {
	options := &redis.Options{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(m.Nodes[index].Port))), Username: controllerUser, Password: m.Secret, Protocol: 2, DisableIdentity: true, MaxRetries: -1, DialTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, ContextTimeoutEnabled: true}
	if m.TLSEnabled {
		options.TLSConfig = d.tlsConfig.Clone()
	}
	return redis.NewClient(options)
}
func (d *Docker) Ensure(ctx context.Context, spec Specification) (Deployment, error) {
	if err := d.lock(ctx); err != nil {
		return Deployment{}, err
	}
	defer d.unlock()
	return d.ensure(ctx, spec)
}
func (d *Docker) ensure(ctx context.Context, spec Specification) (Deployment, error) {
	if err := validateSpecification(spec); err != nil {
		return Deployment{}, err
	}
	if spec.TLSEnabled && d.tlsConfig == nil {
		return Deployment{}, errors.New("native TLS requires an explicitly configured Valkey server certificate/key")
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if _, err := d.volume(ctx, spec.ID, "data", true); err != nil {
		return Deployment{}, err
	}
	s, err := d.inspect(ctx, spec.ID)
	if dockerStatus(err, 404) {
		err = d.client.JSON(ctx, "POST", "/containers/create?name="+d.name(spec.ID, "engine"), d.containerConfig(spec), nil)
		if err != nil {
			return Deployment{}, err
		}
		s, err = d.inspect(ctx, spec.ID)
	}
	if err != nil {
		return Deployment{}, err
	}
	if err = d.checkContainer(s, spec.ID); err != nil {
		return Deployment{}, err
	}
	m, err := d.readManifest(ctx, s, spec)
	if dockerStatus(err, 404) && s.State.Status == "created" {
		var held []net.Listener
		m, held, err = d.newManifest(ctx, spec)
		if err != nil {
			return Deployment{}, err
		}
		err = d.initialize(ctx, s, spec, m)
		for _, l := range held {
			l.Close()
		}
		if err != nil {
			return Deployment{}, err
		}
	} else if err != nil {
		return Deployment{}, err
	}
	if !s.State.Running {
		if err = d.client.JSON(ctx, "POST", "/containers/"+s.ID+"/start", nil, nil); err != nil {
			return Deployment{}, err
		}
	}
	if err = d.waitNative(ctx, m); err != nil {
		return Deployment{}, err
	}
	if err = d.applySettings(ctx, s, spec, m); err != nil {
		return Deployment{}, err
	}
	if err = d.topology(ctx, m); err != nil {
		return Deployment{}, err
	}
	return d.currentDeployment(ctx, m)
}
func deployment(m manifest) Deployment {
	out := Deployment{}
	for i, n := range m.Nodes {
		ep := Endpoint{Address: "127.0.0.1", Port: n.Port}
		out.Nodes = append(out.Nodes, Node{ID: fmt.Sprintf("%04d", i+1), Shard: int32(i) / (m.Replicas + 1), Replica: int32(i) % (m.Replicas + 1), Endpoint: ep})
	}
	out.Endpoint = out.Nodes[0].Endpoint
	return out
}
func (d *Docker) waitNative(ctx context.Context, m manifest) error {
	for i := range m.Nodes {
		c := d.clientFor(m, i)
		err := waitCondition(ctx, func() (bool, error) {
			if e := c.Ping(ctx).Err(); e != nil {
				return false, nil
			}
			info, e := c.Info(ctx, "server").Result()
			if e != nil {
				return false, e
			}
			if !strings.Contains(info, "valkey_version:"+Version+"\r\n") {
				return false, errors.New("native server is not the pinned Valkey version")
			}
			return true, nil
		})
		c.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
func waitCondition(ctx context.Context, fn func() (bool, error)) error {
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	for {
		ready, err := fn()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (d *Docker) applySettings(ctx context.Context, s containerState, spec Specification, m manifest) error {
	if err := d.putFiles(ctx, s.ID, []archiveFile{{name: "users.acl", body: []byte(aclFile(spec.Users, m.Secret))}}); err != nil {
		return err
	}
	params := effectiveParameters(spec)
	for i := range m.Nodes {
		c := d.clientFor(m, i)
		err := c.Do(ctx, "ACL", "LOAD").Err()
		if err == nil {
			for _, k := range sortedParameters(params) {
				if err = c.ConfigSet(ctx, k, params[k]).Err(); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = c.ConfigRewrite(ctx).Err()
		}
		c.Close()
		if err != nil {
			return fmt.Errorf("apply native ACL/parameters: %w", err)
		}
	}
	return nil
}
func (d *Docker) Restart(ctx context.Context, spec Specification) (Deployment, error) {
	if err := d.lock(ctx); err != nil {
		return Deployment{}, err
	}
	defer d.unlock()
	s, err := d.inspect(ctx, spec.ID)
	if err != nil {
		return Deployment{}, err
	}
	if err = d.checkContainer(s, spec.ID); err != nil {
		return Deployment{}, err
	}
	if _, err = d.readManifest(ctx, s, spec); err != nil {
		return Deployment{}, err
	}
	if s.State.Running {
		if err = d.client.JSON(ctx, "POST", "/containers/"+s.ID+"/stop?t=30", nil, nil); err != nil {
			return Deployment{}, err
		}
	}
	return d.ensure(ctx, spec)
}
func (d *Docker) Delete(ctx context.Context, id string) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	s, err := d.inspect(ctx, id)
	if err == nil {
		if err = d.checkContainer(s, id); err != nil {
			return err
		}
		if err = d.client.RemoveContainer(ctx, s.ID); err != nil {
			return err
		}
	} else if !dockerStatus(err, http.StatusNotFound) {
		return err
	}
	return d.deleteVolume(ctx, id, "data")
}
func (d *Docker) deleteVolume(ctx context.Context, id, role string) error {
	v, err := d.volume(ctx, id, role, false)
	if dockerStatus(err, 404) {
		return nil
	}
	if err != nil {
		return err
	}
	return d.client.JSON(ctx, "DELETE", "/volumes/"+v.Name, nil, nil)
}
