package valkey

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
)

func (d *Docker) copyHelper(ctx context.Context, sourceID, sourceRole, targetID, targetRole, script string) ([]byte, error) {
	if _, err := d.volume(ctx, sourceID, sourceRole, false); err != nil {
		return nil, err
	}
	if _, err := d.volume(ctx, targetID, targetRole, true); err != nil {
		return nil, err
	}
	c := docker.ContainerConfig{Image: d.image, Entrypoint: []string{"/bin/sh", "-eu", "-c"}, Cmd: []string{script}, Labels: d.labels(targetID, "copy-helper"), NetworkDisabled: true}
	c.HostConfig.NetworkMode = "none"
	c.HostConfig.ReadonlyRootfs = true
	c.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	c.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "json-file"}
	c.HostConfig.PidsLimit = 32
	c.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: d.name(sourceID, sourceRole), Target: "/source", ReadOnly: true, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}, {Type: "volume", Source: d.name(targetID, targetRole), Target: "/target", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
	return docker.RunHelper(ctx, d.client, "valkey-copy", c)
}

// Snapshot pauses native writes across primaries, executes real SAVE, then copies
// independent RDBs. It does not copy metadata and call that a snapshot. TTLs
// remain the engine's absolute wall-clock expirations, including during restore.
func (d *Docker) Snapshot(ctx context.Context, spec Specification, id string) error {
	if id == "" || id == spec.ID {
		return errors.New("independent snapshot incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	s, err := d.inspect(ctx, spec.ID)
	if err != nil {
		return err
	}
	if err = d.checkContainer(s, spec.ID); err != nil {
		return err
	}
	m, err := d.readManifest(ctx, s, spec)
	if err != nil {
		return err
	}
	deployment, err := d.currentDeployment(ctx, m)
	if err != nil {
		return err
	}
	var primaries []int
	for i, n := range deployment.Nodes {
		if n.Replica == 0 {
			primaries = append(primaries, i)
		}
	}
	// Resume even if collection/copy fails or the command context is cancelled.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, i := range primaries {
			c := d.clientFor(m, i)
			_ = c.Do(cleanup, "CLIENT", "UNPAUSE").Err()
			c.Close()
		}
	}()
	for _, i := range primaries {
		c := d.clientFor(m, i)
		err = c.Do(ctx, "CLIENT", "PAUSE", 30000, "WRITE").Err()
		c.Close()
		if err != nil {
			return err
		}
	}
	for _, i := range primaries {
		c := d.clientFor(m, i)
		err = c.Save(ctx).Err()
		c.Close()
		if err != nil {
			return err
		}
	}
	var script strings.Builder
	fmt.Fprintf(&script, "if [ -f /target/complete ]; then test \"$(cat /target/shards)\" = '%d'; exit 0; fi\n", m.Shards)
	for _, i := range primaries {
		shard := deployment.Nodes[i].Shard
		fmt.Fprintf(&script, "cp /source/node-%d/dump.rdb /target/shard-%d.rdb\n", i, shard)
	}
	fmt.Fprintf(&script, "printf '%%s' '%d' > /target/shards\nchmod 600 /target/*\nsync\ntouch /target/complete\nsync\n", m.Shards)
	_, err = d.copyHelper(ctx, spec.ID, "data", id, "snapshot", script.String())
	return err
}
func (d *Docker) CopySnapshot(ctx context.Context, sourceID, targetID string) error {
	if sourceID == "" || targetID == "" || sourceID == targetID {
		return errors.New("independent source and destination snapshot incarnations are required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	_, err := d.copyHelper(ctx, sourceID, "snapshot", targetID, "snapshot", "test -f /source/complete\nif [ -f /target/complete ]; then cmp /source/shards /target/shards; exit 0; fi\ncp /source/shards /source/shard-*.rdb /target/\nsync\ntouch /target/complete\nsync\n")
	return err
}
func (d *Docker) Restore(ctx context.Context, spec Specification, snapshotID string) (Deployment, error) {
	if err := validateSpecification(spec); err != nil {
		return Deployment{}, err
	}
	if err := d.lock(ctx); err != nil {
		return Deployment{}, err
	}
	defer d.unlock()
	existing, err := d.inspect(ctx, spec.ID)
	if err == nil {
		if err = d.checkContainer(existing, spec.ID); err != nil {
			return Deployment{}, err
		}
		return d.ensure(ctx, spec)
	}
	if !dockerStatus(err, 404) {
		return Deployment{}, err
	}
	var script strings.Builder
	fmt.Fprintf(&script, "test -f /source/complete\ntest \"$(cat /source/shards)\" = '%d'\n", spec.Shards)
	for shard := int32(0); shard < spec.Shards; shard++ {
		node := shard * (spec.Replicas + 1)
		// With AOF enabled, a bare dump.rdb is not authoritative at startup.
		// Seed Valkey's documented multipart-AOF RDB base and manifest instead.
		fmt.Fprintf(&script, "mkdir -p /target/node-%d/appendonlydir\ncp /source/shard-%d.rdb /target/node-%d/appendonlydir/appendonly.aof.1.base.rdb\nprintf 'file appendonly.aof.1.base.rdb seq 1 type b\\n' > /target/node-%d/appendonlydir/appendonly.aof.manifest\nchown -R 999:1000 /target/node-%d\n", node, shard, node, node, node)
	}
	script.WriteString("sync\n")
	if _, err = d.copyHelper(ctx, snapshotID, "snapshot", spec.ID, "data", script.String()); err != nil {
		return Deployment{}, fmt.Errorf("restore native snapshot with %s shards: %w", strconv.Itoa(int(spec.Shards)), err)
	}
	return d.ensure(ctx, spec)
}
func (d *Docker) DeleteSnapshot(ctx context.Context, id string) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	return d.deleteVolume(ctx, id, "snapshot")
}
