package rds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"stackd/compute/docker"
)

// Snapshot takes a complete cold physical backup after a clean native shutdown.
// It intentionally interrupts connections; it is not an online Aurora snapshot.
// PostgreSQL: https://www.postgresql.org/docs/17/backup-file.html
// MySQL: https://dev.mysql.com/doc/refman/8.4/en/innodb-backup.html
// The whole native data directory, including WAL/redo, roles and every database,
// is copied to another named volume. Atomic directory publication separates a
// completed backup from an interrupted copy. No live directory is ever copied.
func (d *Docker) Snapshot(ctx context.Context, spec Specification, snapshot string) (result error) {
	if err := validateSpecification(spec); err != nil {
		return err
	}
	if snapshot == "" {
		return errors.New("native snapshot incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	if err := d.finishBackup(ctx, spec.ID); err != nil {
		return err
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		return err
	}
	if err := d.checkDatabase(state, spec); err != nil {
		return err
	}
	if state.State.Running {
		kind, _ := family(spec.Engine)
		if kind == "mysql" {
			endpoint, err := state.endpoint(d.endpointHost, spec.Engine)
			if err != nil {
				return err
			}
			db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
			if err != nil {
				return err
			}
			// SQL clients can change the global value after startup. Enforce
			// the documented slow-shutdown prerequisite immediately before
			// taking a cold InnoDB backup, not only in initial configuration.
			_, err = db.ExecContext(ctx, "SET GLOBAL innodb_fast_shutdown = 0")
			db.Close()
			if err != nil {
				return err
			}
		}
	}
	labels := d.labels(snapshot, "snapshot")
	labels[labelPrefix+"source"] = spec.ID
	labels[labelPrefix+"engine"] = spec.Engine
	labels[labelPrefix+"image"] = d.image(spec.Engine)
	labels[labelPrefix+"username"] = spec.Username
	labels[labelPrefix+"database"] = spec.Database
	volume, err := d.volume(ctx, snapshot, "snapshot", labels, true)
	if err != nil {
		return err
	}
	for key, expected := range labels {
		if volume.Labels[key] != expected {
			return errors.New("conflicting native snapshot source or configuration")
		}
	}
	wasRunning := state.State.Running
	if wasRunning {
		// Always restore source availability after a dispatched stop, even when
		// the caller cancels. A process crash is recovered by retained work.
		defer func() {
			recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.startupTimeout)
			defer cancel()
			_, err := d.ensure(recovery, spec)
			result = errors.Join(result, err)
		}()
	}
	if err := d.stop(ctx, state); err != nil {
		return err
	}
	state, err = d.inspect(ctx, state.ID)
	if err != nil {
		return err
	}
	if state.State.Running || state.State.Status != "exited" || state.State.ExitCode != 0 || state.State.OOMKilled {
		return errors.New("native snapshot requires a completed clean database shutdown")
	}
	// A source can have only one copying process. Ensure joins this same named
	// worker after controller loss before it restarts the database writer.
	previous, err := d.inspect(ctx, d.name(spec.ID, "backup"))
	if err == nil {
		if err := d.checkHelper(previous, spec.ID, "backup"); err != nil {
			return err
		}
		if previous.Config.Labels[labelPrefix+"snapshot"] != snapshot || previous.State.ExitCode != 0 {
			if err := d.removeContainer(ctx, previous.ID); err != nil {
				return err
			}
		}
	} else if !dockerStatus(err, http.StatusNotFound) {
		return err
	}
	helper, err := d.prepareHelper(ctx, spec.ID, "backup", snapshot, spec.Engine)
	if err != nil {
		return err
	}
	if err := d.waitHelper(ctx, helper); err != nil {
		return err
	}
	return nil
}

// Restore clones the full backup into a distinct incarnation and authenticates
// with the captured snapshot credentials. Retrying cannot overwrite a running
// restored database. Renaming databases/users or engine upgrades is not a restore.
func (d *Docker) Restore(ctx context.Context, spec Specification, snapshot string) (Endpoint, error) {
	if err := validateSpecification(spec); err != nil {
		return Endpoint{}, err
	}
	if snapshot == "" {
		return Endpoint{}, errors.New("native snapshot incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return Endpoint{}, err
	}
	defer d.unlock()
	// Native restoration may have committed before its controller transaction.
	// Recognize the atomically published destination even if the source snapshot
	// has subsequently been retired; never make a restored database depend on it.
	target, err := d.volume(ctx, spec.ID, "data", nil, false)
	if err == nil {
		if target.Labels[labelPrefix+"snapshot"] != snapshot || target.Labels[labelPrefix+"engine"] != spec.Engine || target.Labels[labelPrefix+"username"] != spec.Username || target.Labels[labelPrefix+"database"] != spec.Database {
			return Endpoint{}, errors.New("refusing to restore over a different native database")
		}
		state, err := d.createDatabase(ctx, spec)
		if err != nil {
			return Endpoint{}, err
		}
		complete, err := d.dataDirectoryExists(ctx, state, spec)
		if err != nil {
			return Endpoint{}, err
		}
		if complete {
			startup, cancel := context.WithTimeout(ctx, d.startupTimeout)
			defer cancel()
			return d.ensure(startup, spec)
		}
	} else if !dockerStatus(err, http.StatusNotFound) {
		return Endpoint{}, err
	}
	backup, err := d.volume(ctx, snapshot, "snapshot", nil, false)
	if err != nil {
		return Endpoint{}, err
	}
	if backup.Labels[labelPrefix+"engine"] != spec.Engine || backup.Labels[labelPrefix+"image"] != d.image(spec.Engine) || backup.Labels[labelPrefix+"username"] != spec.Username || backup.Labels[labelPrefix+"database"] != spec.Database {
		return Endpoint{}, errors.New("snapshot engine, image, database and username must match restore specification")
	}
	if backup.Labels[labelPrefix+"source"] == spec.ID {
		return Endpoint{}, errors.New("snapshot restoration requires a different database incarnation")
	}
	labels := d.labels(spec.ID, "data")
	labels[labelPrefix+"engine"] = spec.Engine
	labels[labelPrefix+"snapshot"] = snapshot
	labels[labelPrefix+"username"] = spec.Username
	labels[labelPrefix+"database"] = spec.Database
	volume, err := d.volume(ctx, spec.ID, "data", labels, true)
	if err != nil {
		return Endpoint{}, err
	}
	if volume.Labels[labelPrefix+"snapshot"] != snapshot || volume.Labels[labelPrefix+"engine"] != spec.Engine {
		return Endpoint{}, errors.New("refusing to restore over a different native database")
	}
	if err := d.finishRestore(ctx, spec, snapshot); err != nil {
		return Endpoint{}, err
	}
	startup, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	return d.ensure(startup, spec)
}

func (d *Docker) helperConfig(id, role, snapshot, engine string) containerConfig {
	_, mount, subdir := nativeLayout(engine)
	var config containerConfig
	config.Image = d.image(engine)
	config.Entrypoint = []string{"/bin/sh", "-ec"}
	config.Labels = d.labels(id, role)
	config.Labels[labelPrefix+"snapshot"] = snapshot
	config.Labels[labelPrefix+"engine"] = engine
	config.HostConfig.NetworkMode = "none"
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "none"}
	config.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	config.HostConfig.PidsLimit = 32
	if role == "backup" {
		config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: d.name(id, "data"), Target: mount, ReadOnly: true, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}, {Type: "volume", Source: d.name(snapshot, "snapshot"), Target: "/stackd-backup", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
		config.Cmd = []string{`test -d "$1"; if test -d "$2/database"; then exit 0; fi; test -z "$(find "$1" -type l -print -quit)"; rm -rf "$2/staging"; cp -a "$1" "$2/staging"; sync; mv "$2/staging" "$2/database"; sync`, "stackd-backup", subdir, "/stackd-backup"}
	} else {
		config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: d.name(snapshot, "snapshot"), Target: "/stackd-backup", ReadOnly: true, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}, {Type: "volume", Source: d.name(id, "data"), Target: mount, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
		config.Cmd = []string{`if test -d "$2/database"; then exit 0; fi; test -d "$1/database"; rm -rf "$2/staging"; cp -a "$1/database" "$2/staging"; rm -f "$2/staging/auto.cnf"; sync; mv "$2/staging" "$2/database"; sync`, "stackd-restore", "/stackd-backup", mount}
	}
	return config
}
func (d *Docker) checkHelper(state containerState, id, role string) error {
	if err := d.checkOwner(state.Config.Labels, id, role); err != nil {
		return err
	}
	snapshot, engine := state.Config.Labels[labelPrefix+"snapshot"], state.Config.Labels[labelPrefix+"engine"]
	if snapshot == "" {
		return errors.New("native backup worker has no snapshot incarnation")
	}
	if _, err := family(engine); err != nil {
		return err
	}
	expected := d.helperConfig(id, role, snapshot, engine)
	if state.Image != expected.Image || !slices.Equal(state.Config.Cmd, expected.Cmd) || !slices.Equal(state.Config.Entrypoint, expected.Entrypoint) || state.HostConfig.Privileged || state.HostConfig.NetworkMode != "none" || len(state.HostConfig.Binds) != 0 || len(state.HostConfig.PortBindings) != 0 || len(state.Mounts) != len(expected.HostConfig.Mounts) {
		return errors.New("conflicting native backup worker configuration")
	}
	for _, wanted := range expected.HostConfig.Mounts {
		found := false
		for _, actual := range state.Mounts {
			if actual.Type == wanted.Type && actual.Name == wanted.Source && actual.Destination == wanted.Target && actual.RW != wanted.ReadOnly {
				found = true
				break
			}
		}
		if !found {
			return errors.New("conflicting native backup worker volume mounts")
		}
	}
	return nil
}
func (d *Docker) prepareHelper(ctx context.Context, id, role, snapshot, engine string) (containerState, error) {
	name := d.name(id, role)
	state, err := d.inspect(ctx, name)
	if dockerStatus(err, http.StatusNotFound) {
		var created struct {
			ID string `json:"Id"`
		}
		err = d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), d.helperConfig(id, role, snapshot, engine), &created)
		if err != nil && !dockerStatus(err, http.StatusConflict) {
			return state, err
		}
		state, err = d.inspect(ctx, name)
	}
	if err != nil {
		return state, err
	}
	if err := d.checkHelper(state, id, role); err != nil {
		return state, err
	}
	if state.Config.Labels[labelPrefix+"snapshot"] != snapshot || state.Config.Labels[labelPrefix+"engine"] != engine {
		return state, errors.New("conflicting native backup worker operation")
	}
	return state, nil
}
func (d *Docker) waitHelper(ctx context.Context, state containerState) error {
	if state.State.Status == "created" {
		if err := d.start(ctx, state); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var err error
		state, err = d.inspect(ctx, state.ID)
		if err != nil {
			return err
		}
		if state.State.Status == "exited" {
			if state.State.ExitCode != 0 {
				return fmt.Errorf("native physical backup worker failed (exit %d); incomplete bytes are not a snapshot", state.State.ExitCode)
			}
			return nil
		}
		if state.State.Dead || state.State.OOMKilled {
			return errors.New("native physical backup worker failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (d *Docker) finishBackup(ctx context.Context, id string) error {
	state, err := d.inspect(ctx, d.name(id, "backup"))
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := d.checkHelper(state, id, "backup"); err != nil {
		return err
	}
	err = d.waitHelper(ctx, state)
	if err == nil {
		return nil
	}
	// A failed copy must not permanently prevent the original writer from
	// reopening. Interrupted running workers remain joined until they finish.
	state, inspectErr := d.inspect(ctx, state.ID)
	if inspectErr == nil && state.State.Status == "exited" {
		return d.removeContainer(ctx, state.ID)
	}
	return err
}
func (d *Docker) finishRestore(ctx context.Context, spec Specification, snapshot string) error {
	state, err := d.prepareHelper(ctx, spec.ID, "restore", snapshot, spec.Engine)
	if err != nil {
		return err
	}
	if state.State.Status == "exited" && state.State.ExitCode != 0 {
		if err := d.removeContainer(ctx, state.ID); err != nil {
			return err
		}
		state, err = d.prepareHelper(ctx, spec.ID, "restore", snapshot, spec.Engine)
		if err != nil {
			return err
		}
	}
	if err := d.waitHelper(ctx, state); err != nil {
		return err
	}
	return d.removeContainer(ctx, state.ID)
}
func (d *Docker) DeleteSnapshot(ctx context.Context, snapshot string) error {
	if snapshot == "" {
		return errors.New("native snapshot incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	volume, err := d.volume(ctx, snapshot, "snapshot", nil, false)
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	source := volume.Labels[labelPrefix+"source"]
	if source == "" {
		return errors.New("native snapshot has no source ownership")
	}
	state, err := d.inspect(ctx, d.name(source, "backup"))
	if err == nil {
		if err := d.checkHelper(state, source, "backup"); err != nil {
			return err
		}
		if state.Config.Labels[labelPrefix+"snapshot"] == snapshot {
			if err := d.waitHelper(ctx, state); err != nil && ctx.Err() != nil {
				return err
			}
			if err := d.removeContainer(ctx, state.ID); err != nil {
				return err
			}
		}
	} else if !dockerStatus(err, http.StatusNotFound) {
		return err
	}
	// A restore worker still mounting this snapshot makes Docker reject removal;
	// callers can retry after retiring that worker, never force-remove its bytes.
	return d.removeVolume(ctx, snapshot, "snapshot")
}
