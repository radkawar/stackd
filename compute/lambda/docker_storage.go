package lambda

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stackd/compute/docker"
)

// StorageImage is installed explicitly, never pulled by the executor. Its
// util-linux and e2fsprogs run on the Docker host, independently of the runtime's
// architecture. Only storage helpers receive host-device privileges.
const StorageImage = "ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"

const namespaceLabel = "io.stackd.lambda.instance"
const diskLabel = "io.stackd.lambda.disk"
const controllerLabel = "io.stackd.lambda.controller"

func immutableImage(image string) bool {
	parts := strings.Split(image, "@sha256:")
	return len(parts) == 2 && parts[0] != "" && len(parts[1]) == 64 && strings.Trim(parts[1], "0123456789abcdef") == ""
}

func (d *DockerExecutor) labels(identity, function string) map[string]string {
	return map[string]string{namespaceLabel: d.config.Namespace, controllerLabel: d.owner, "io.stackd.owner": identity, "io.stackd.kind": "lambda-runtime", "io.stackd.function": function}
}

// openOwner obtains a kernel flock inside the daemon, not on the API client.
// Docker closes the helper's stdin when the attached controller connection is
// lost. The helper then exits and releases flock, including after SIGKILL. No
// timestamp, lease expiry or client-visible host path participates in ownership.
func (d *DockerExecutor) openOwner(ctx context.Context) (err error) {
	var image struct {
		ID string `json:"Id"`
	}
	if err := d.engine.JSON(ctx, "GET", "/images/"+url.PathEscape(d.config.StorageImage)+"/json", nil, &image); err != nil {
		return fmt.Errorf("lambda disk storage helper is unavailable locally (automatic pull is disabled): %w", err)
	}
	sum := sha256.Sum256([]byte(d.config.Namespace))
	volume := fmt.Sprintf("stackd-lambda-owner-%x", sum[:16])
	labels := map[string]string{namespaceLabel: d.config.Namespace, "io.stackd.kind": "lambda-owner"}
	var ownerVolume struct{ Labels map[string]string }
	if err := d.engine.JSON(ctx, "POST", "/volumes/create", docker.VolumeConfig{Name: volume, Labels: labels}, &ownerVolume); err != nil {
		return err
	}
	if ownerVolume.Labels[namespaceLabel] != d.config.Namespace || ownerVolume.Labels["io.stackd.kind"] != "lambda-owner" {
		return fmt.Errorf("lambda instance owner volume belongs to another resource")
	}
	d.owner = volume + "-" + rand.Text()
	d.ownerVolume = volume
	d.lifetime, d.stop = context.WithCancel(context.Background())
	stopStartup := context.AfterFunc(ctx, d.stop)
	defer stopStartup()
	defer func() {
		if err != nil {
			d.stop()
			if d.guard != nil {
				d.guard.Close()
			}
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			err = errors.Join(err, d.engine.RemoveContainer(cleanup, d.owner))
			err = errors.Join(err, d.removeOwnerVolume(cleanup))
		}
	}()
	config := docker.ContainerConfig{Image: image.ID, Entrypoint: []string{"/bin/sh", "-ec"}, Cmd: []string{`exec 9>/owner/lock
if ! flock -n 9; then printf 'busy\n'; exit 73; fi
printf 'locked\n'
cat >/dev/null`}, OpenStdin: true, StdinOnce: true, Labels: labels,
		HostConfig: docker.ContainerHostConfig{NetworkMode: "none", ReadonlyRootfs: true, Memory: 32 << 20, MemorySwap: 32 << 20, PidsLimit: 32, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, LogConfig: docker.ContainerLogConfig{Type: "none"}, Mounts: []docker.ContainerMount{{Type: "volume", Source: volume, Target: "/owner", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true, Labels: labels}}}}}
	if err := d.engine.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(d.owner), config, nil); err != nil {
		return err
	}
	// Attach before start so the readiness write cannot be missed. The connection
	// has executor lifetime, while the startup read is bounded separately below.
	response, err := d.engine.RequestHeaders(d.lifetime, "POST", "/containers/"+d.owner+"/attach?stream=true&stdin=true&stdout=true&stderr=true", nil, "", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"tcp"}})
	if err != nil {
		return fmt.Errorf("attaching Lambda instance owner: %w", err)
	}
	var ok bool
	d.guard, ok = response.Body.(io.ReadWriteCloser)
	if !ok {
		response.Body.Close()
		return fmt.Errorf("docker attach did not provide a duplex connection")
	}
	if err := d.engine.JSON(ctx, "POST", "/containers/"+d.owner+"/start", nil, nil); err != nil {
		return err
	}
	guard := d.guard
	ready := make(chan error, 1)
	go func() {
		var header [8]byte
		_, err := io.ReadFull(guard, header[:])
		if err == nil {
			size := binary.BigEndian.Uint32(header[4:])
			if size == 0 || size > 1024 {
				err = fmt.Errorf("invalid Docker owner readiness frame")
			} else {
				data := make([]byte, size)
				_, err = io.ReadFull(guard, data)
				if err == nil && string(data) != "locked\n" {
					err = fmt.Errorf("lambda instance namespace %q is already active: %s", d.config.Namespace, data)
				}
			}
		}
		ready <- err
		if err == nil {
			_, _ = io.Copy(io.Discard, guard)
		}
		d.stop()
	}()
	select {
	case err := <-ready:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := d.recover(ctx, false); err != nil {
		return fmt.Errorf("recovering Lambda instance resources: %w", err)
	}
	// Old owner containers have released flock before this point. Remove their
	// native references while the current guard keeps the owner volume in use.
	owners, err := d.containers(ctx, "lambda-owner")
	if err != nil {
		return err
	}
	for _, item := range owners {
		if item.ID != d.owner && !containsName(item.Names, d.owner) {
			if err := d.engine.RemoveContainer(ctx, item.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsName(names []string, name string) bool {
	for _, value := range names {
		if value == "/"+name {
			return true
		}
	}
	return false
}

type nativeContainer struct {
	ID     string `json:"Id"`
	Names  []string
	Labels map[string]string
}

func (d *DockerExecutor) filters(kind string) string {
	filters, _ := json.Marshal(map[string][]string{"label": {namespaceLabel + "=" + d.config.Namespace, "io.stackd.kind=" + kind}})
	return url.QueryEscape(string(filters))
}

func (d *DockerExecutor) containers(ctx context.Context, kind string) ([]nativeContainer, error) {
	var found []nativeContainer
	err := d.engine.JSON(ctx, "GET", "/containers/json?all=true&filters="+d.filters(kind), nil, &found)
	if err != nil {
		return nil, err
	}
	for _, item := range found {
		if item.Labels[namespaceLabel] != d.config.Namespace || item.Labels["io.stackd.kind"] != kind {
			return nil, fmt.Errorf("docker returned a container outside the Lambda instance")
		}
	}
	return found, nil
}

// recover runs only with the instance flock held, before Prepare is exposed.
// Containers (including partial storage helpers) go first, then dependent
// filesystem volumes, loop devices, and finally their backing volumes. Networks
// are Docker's container-owned endpoints; removing containers releases them.
func (d *DockerExecutor) recover(ctx context.Context, current bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopOwnership := context.AfterFunc(d.lifetime, cancel)
	defer stopOwnership()
	if d.lifetime.Err() != nil {
		return fmt.Errorf("lambda instance ownership was lost")
	}
	containers, err := d.containers(ctx, "lambda-runtime")
	if err != nil {
		return err
	}
	// Snapshot both inventories while ownership is held; never discover new
	// resources after teardown has begun.
	var inventory struct {
		Volumes []struct {
			Name   string
			Labels map[string]string
		}
	}
	if err := d.engine.JSON(ctx, "GET", "/volumes?filters="+d.filters("lambda-runtime"), nil, &inventory); err != nil {
		return err
	}
	for _, volume := range inventory.Volumes {
		if volume.Labels[namespaceLabel] != d.config.Namespace || volume.Labels["io.stackd.kind"] != "lambda-runtime" {
			return fmt.Errorf("docker returned a volume outside the Lambda instance")
		}
	}
	// Customer containers share their keeper's network namespace. Remove
	// customers first; never dismantle their keeper after a failed removal.
	for _, runtime := range []bool{true, false} {
		for _, item := range containers {
			if !current && item.Labels[controllerLabel] == d.owner {
				continue
			}
			if containsName(item.Names, item.Labels["io.stackd.owner"]) != runtime {
				continue
			}
			if err := d.engine.RemoveContainer(ctx, item.ID); err != nil {
				return err
			}
		}
	}
	for _, volume := range inventory.Volumes {
		if !current && volume.Labels[controllerLabel] == d.owner {
			continue
		}
		if volume.Labels[diskLabel] == "true" {
			continue
		}
		if err := removeVolume(ctx, d.engine, volume.Name); err != nil {
			return err
		}
	}
	for _, volume := range inventory.Volumes {
		if !current && volume.Labels[controllerLabel] == d.owner {
			continue
		}
		if volume.Labels[diskLabel] != "true" {
			continue
		}
		if err := d.removeDisk(ctx, volume.Name, volume.Labels); err != nil {
			return err
		}
	}
	return nil
}

// An accepted Engine create can complete after its HTTP caller disappears.
// Keep reconciling older controller generations, never current environments, so
// even effects appearing after the initial inventory snapshot are reclaimed.
func (d *DockerExecutor) recoverLateCreates(lifetime context.Context) {
	defer close(d.reaperDone)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-lifetime.Done():
			return
		case <-ticker.C:
		}
		d.mu.Lock()
		if lifetime.Err() != nil {
			d.mu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(lifetime, 30*time.Second)
		d.recoveryErr = d.recover(ctx, false)
		if err := d.reconcileImagePins(ctx); err != nil {
			slog.Error("Lambda image retention reconciliation failed", "namespace", d.config.Namespace, "error", err)
		}
		cancel()
		d.mu.Unlock()
	}
}

// Close must follow service shutdown. It is retryable after cleanup errors and
// releases ownership only after native teardown has completed.
func (d *DockerExecutor) Close(ctx context.Context) error {
	d.reaperStop()
	select {
	case <-d.reaperDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.guard == nil {
		return d.removeOwnerVolume(ctx)
	}
	if d.lifetime.Err() != nil {
		err := d.engine.RemoveContainer(ctx, d.owner)
		d.guard.Close()
		d.guard = nil
		return errors.Join(fmt.Errorf("lambda instance ownership was lost; refusing to sweep a successor's resources"), err, d.removeOwnerVolume(ctx))
	}
	if err := d.recover(ctx, true); err != nil {
		return err
	}
	if err := d.reconcileImagePins(ctx); err != nil {
		return err
	}
	if err := d.engine.RemoveContainer(ctx, d.owner); err != nil {
		return err
	}
	d.guard.Close()
	d.guard = nil
	d.stop()
	return d.removeOwnerVolume(ctx)
}

// Docker refuses to unlink a volume referenced even by a created, unstarted
// container. Consequently every open flock inode remains protected during a
// concurrent owner handoff. An unreferenced ephemeral instance needs no retained
// lock volume; 409 means ownership infrastructure is in use and must survive.
func (d *DockerExecutor) removeOwnerVolume(ctx context.Context) error {
	if d.ownerVolume == "" {
		return nil
	}
	err := removeVolume(ctx, d.engine, d.ownerVolume)
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusConflict {
		err = nil
	}
	if err == nil {
		d.ownerVolume = ""
	}
	return err
}

func removeVolume(ctx context.Context, engine *docker.Client, name string) error {
	err := engine.JSON(ctx, "DELETE", "/volumes/"+url.PathEscape(name), nil, nil)
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}

func (d *DockerExecutor) diskHelper(ctx context.Context, volume string, labels map[string]string, script string, args ...string) ([]byte, error) {
	command := append([]string{script, "stackd-disk"}, args...)
	return docker.RunHelper(ctx, d.engine, "lambda-disk", docker.ContainerConfig{
		Image: d.config.StorageImage, Entrypoint: []string{"/bin/sh", "-ec"}, Cmd: command, Labels: labels,
		HostConfig: docker.ContainerHostConfig{Privileged: true, NetworkMode: "none", ReadonlyRootfs: true, Memory: 128 << 20, MemorySwap: 128 << 20, PidsLimit: 64, LogConfig: docker.ContainerLogConfig{Type: "json-file"}, Mounts: []docker.ContainerMount{
			{Type: "volume", Source: volume, Target: "/storage", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true, Labels: labels}},
			// Docker's ordinary privileged /dev is a creation-time snapshot; the
			// daemon's device namespace must expose newly allocated loop nodes.
			{Type: "bind", Source: "/dev", Target: "/dev"},
		}},
	})
}

const prepareDiskScript = `test ! -e /storage/disk.img
# Ext4 metadata is outside the public data capacity, not charged against it.
# Reserve a bounded metadata workspace; unused blocks become root-only below.
fallocate -l "$(($1 + $1 / 32 + 32 * 1024 * 1024))" /storage/disk.img
mkfs.ext4 -q -F -m 0 -b 4096 -O ^has_journal -E nodiscard,lazy_itable_init=0 /storage/disk.img
# Direct backing IO avoids a second page cache charged to the function cgroup.
loop=$(losetup --find --show --nooverlap --direct-io=on /storage/disk.img)
test "$(losetup -l -n --raw -O DIO "$loop")" = 1
mount -t ext4 -o nosuid,nodev "$loop" /mnt
chmod 1777 /mnt
# A public Size is usable storage, not a raw device size. Native AWS has small
# geometry-dependent headroom; keep one MiB for directory/extent/control-file
# bookkeeping so writing Size MiB does not fail solely on filesystem metadata.
# Measure native allocation rather than guessing mkfs or kernel-reserved blocks.
fallocate -l "$(($1 + 1024 * 1024))" /mnt/.stackd-capacity
reserved=$(stat -f -c '%a' /mnt)
umount /mnt
tune2fs -r "$reserved" "$loop" >/dev/null
mount -t ext4 -o nosuid,nodev "$loop" /mnt
rm /mnt/.stackd-capacity
test "$(stat -f -c '%S' /mnt)" = 4096
test "$(stat -f -c '%a' /mnt)" -ge "$(($1 / 4096))"
umount /mnt
printf '%s\n' "$loop"`

func (d *DockerExecutor) prepareDisk(ctx context.Context, e *dockerEnvironment, labels map[string]string) error {
	e.diskVolume = e.identity + "-disk"
	e.diskOwner = d
	diskLabels := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		diskLabels[key] = value
	}
	diskLabels[diskLabel] = "true"
	if err := d.engine.JSON(ctx, "POST", "/volumes/create", docker.VolumeConfig{Name: e.diskVolume, Labels: diskLabels}, nil); err != nil {
		return err
	}
	output, err := d.diskHelper(ctx, e.diskVolume, diskLabels, prepareDiskScript, fmt.Sprint(int64(e.spec.EphemeralMB)<<20))
	if err != nil {
		return fmt.Errorf("preparing quota-limited Lambda ext4 disk (requires rootful privileged Docker, loop devices, ext4, direct-IO-capable backing storage, and allocated disk space): %w", err)
	}
	device := strings.TrimSpace(string(output))
	if !strings.HasPrefix(device, "/dev/loop") || strings.Trim(strings.TrimPrefix(device, "/dev/loop"), "0123456789") != "" || device == "/dev/loop" {
		return fmt.Errorf("invalid Lambda loop device %q", device)
	}
	return d.engine.JSON(ctx, "POST", "/volumes/create", docker.VolumeConfig{Name: e.tmpVolume, Driver: "local", Labels: labels, DriverOpts: map[string]string{"type": "ext4", "device": device, "o": "rw,nosuid,nodev"}}, nil)
}

const removeDiskScript = `if test -e /storage/disk.img; then
# -j matches the backing inode, not the path reported by another mount namespace.
loops=$(losetup -j /storage/disk.img -O NAME --noheadings)
for loop in $loops; do
 losetup -d "$loop"
done
# An open device must not survive deletion of its backing file.
loops=$(losetup -j /storage/disk.img -O NAME --noheadings)
test -z "$loops"
fi`

func (d *DockerExecutor) removeDisk(ctx context.Context, volume string, labels map[string]string) error {
	var existing struct {
		Name   string
		Labels map[string]string
	}
	err := d.engine.JSON(ctx, "GET", "/volumes/"+url.PathEscape(volume), nil, &existing)
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if existing.Labels[namespaceLabel] != d.config.Namespace || existing.Labels["io.stackd.kind"] != "lambda-runtime" || existing.Labels[diskLabel] != "true" || existing.Labels["io.stackd.owner"] != labels["io.stackd.owner"] {
		return fmt.Errorf("lambda disk volume ownership mismatch")
	}
	helpers, err := d.containers(ctx, "lambda-runtime")
	if err != nil {
		return err
	}
	for _, helper := range helpers {
		if helper.Labels["io.stackd.owner"] == labels["io.stackd.owner"] {
			if err := d.engine.RemoveContainer(ctx, helper.ID); err != nil {
				return err
			}
		}
	}
	output, err := d.diskHelper(ctx, volume, existing.Labels, removeDiskScript)
	if err != nil {
		return fmt.Errorf("detaching Lambda disk %s: %w (%s)", volume, err, bytes.TrimSpace(output))
	}
	return removeVolume(ctx, d.engine, volume)
}
