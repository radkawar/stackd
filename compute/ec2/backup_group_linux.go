package ec2

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackupDisks captures a common native point in time. Live disks must belong to
// one VMM: all full-backup jobs start in a single grouped QMP transaction. Offline
// sources are all exclusively locked before the first ciphertext copy begins.
func (q *QEMU) BackupDisks(ctx context.Context, sources, destinations []Disk) ([]BackupResult, error) {
	if len(sources) == 0 || len(sources) != len(destinations) {
		return nil, errors.New("group backup requires matching nonempty disk lists")
	}
	if len(sources) == 1 {
		result, err := q.Backup(ctx, sources[0], destinations[0])
		if err != nil {
			return nil, err
		}
		return []BackupResult{result}, nil
	}
	identities := map[string]bool{}
	paths := map[string]bool{}
	for _, disks := range [][]Disk{sources, destinations} {
		for _, disk := range disks {
			if err := validateDisk(disk); err != nil {
				return nil, err
			}
			path := filepath.Clean(disk.Path)
			if identities[disk.ID] || paths[path] {
				return nil, errors.New("group backup requires distinct source and destination identities")
			}
			identities[disk.ID] = true
			paths[path] = true
		}
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	var directory string
	for index, source := range sources {
		client, owner, err := q.diskOwner(ctx, source)
		if err != nil {
			return nil, err
		}
		if client != nil {
			client.close()
		}
		if index == 0 {
			directory = owner
		} else if directory != owner {
			return nil, &CapabilityError{Feature: "atomic snapshot across different live VMMs or mixed live/offline disks"}
		}
	}
	if directory == "" {
		return q.backupOfflineGroup(ctx, sources, destinations)
	}
	client, err := q.existing(ctx, directory)
	if err != nil {
		return nil, err
	}
	defer client.close()
	return q.backupLiveGroup(ctx, client, directory, sources, destinations)
}

func (q *QEMU) backupOfflineGroup(ctx context.Context, sources, destinations []Disk) (results []BackupResult, err error) {
	var locks []*os.File
	defer func() { closeFiles(locks) }()
	for index, source := range sources {
		destination := destinations[index]
		if source.Encrypted != destination.Encrypted || (source.Encrypted && len(destination.Key) > 0 && !bytes.Equal(source.Key, destination.Key)) {
			return nil, errors.New("offline native snapshot group preserves encryption and keys")
		}
		if _, err := q.info(ctx, source); err != nil {
			return nil, err
		}
		lock, err := exclusiveImage(source.Path)
		if err != nil {
			return nil, err
		}
		locks = append(locks, lock)
	}
	created := 0
	defer func() {
		if err != nil {
			for _, destination := range destinations[:created] {
				err = errors.Join(err, os.Remove(destination.Path))
			}
		}
	}()
	results = make([]BackupResult, len(sources))
	for index, source := range sources {
		destination := destinations[index]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := copyIndependent(source.Path, destination.Path); err != nil {
			return nil, err
		}
		created++
		if source.Encrypted && len(source.Key) == 0 {
			continue
		}
		destination.Key = source.Key
		if err := q.withOfflineExport(ctx, destination, true, func(socket, export string) error {
			var err error
			results[index].Extents, err = q.mapExport(ctx, socket, export)
			return err
		}); err != nil {
			return nil, err
		}
		results[index].ExtentsKnown = true
	}
	return results, nil
}

func (q *QEMU) backupLiveGroup(ctx context.Context, client *qmpClient, directory string, sources, destinations []Disk) (results []BackupResult, err error) {
	var operation strings.Builder
	for index, source := range sources {
		fmt.Fprintf(&operation, "%s\x00%s\x00%s\x00%s\x00", source.ID, source.Path, destinations[index].ID, destinations[index].Path)
	}
	group := "group-" + identifier(operation.String())
	jobIDs := make([]string, len(destinations))
	for index, destination := range destinations {
		jobIDs[index] = group + "-" + identifier(destination.ID)
	}
	resumeCount := 0
	for index, destination := range destinations {
		job, err := queryJob(ctx, client, jobIDs[index])
		if err != nil {
			return nil, err
		}
		if job != nil {
			target, err := findBlock(ctx, client, destination)
			if err != nil {
				return nil, err
			}
			if target == nil {
				return nil, errors.New("surviving native backup group lacks a target")
			}
			resumeCount++
		}
	}
	if resumeCount != 0 && resumeCount != len(destinations) {
		return nil, errors.New("incomplete surviving native backup group requires owner reconciliation")
	}
	owned := make([]bool, len(destinations))
	defer func() {
		_ = client.close()
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		connection, e := q.existing(cleanup, directory)
		if e != nil && !errors.Is(e, ErrNotFound) {
			err = errors.Join(err, e)
			return
		}
		if connection != nil {
			defer connection.close()
		}
		for index, destination := range destinations {
			if !owned[index] {
				continue
			}
			if connection != nil {
				if e := releaseDiskNodes(cleanup, connection, destination); e != nil {
					err = errors.Join(err, e)
					continue
				}
			}
			if err != nil {
				err = errors.Join(err, os.Remove(destination.Path))
			}
		}
	}()
	if resumeCount == 0 {
		for index, source := range sources {
			destination := destinations[index]
			if err := reserveFile(destination.Path); err != nil {
				return nil, err
			}
			owned[index] = true
			if err := prepareBackupTarget(ctx, client, source, destination); err != nil {
				return nil, err
			}
		}
		actions := make([]map[string]any, len(sources))
		for index, source := range sources {
			actions[index] = map[string]any{"type": "blockdev-backup", "data": map[string]any{"job-id": jobIDs[index], "device": diskNode(source), "target": diskNode(destinations[index]), "sync": "full", "auto-dismiss": false}}
		}
		if err := client.execute(ctx, "transaction", map[string]any{"actions": actions, "properties": map[string]any{"completion-mode": "grouped"}}, nil); err != nil {
			return nil, err
		}
	} else {
		for index := range owned {
			owned[index] = true
		}
	}
	if err := waitBackupGroup(ctx, client, jobIDs); err != nil {
		return nil, err
	}
	results = make([]BackupResult, len(destinations))
	for index, destination := range destinations {
		if err := q.withExport(ctx, client, directory, diskNode(destination), func(socket, export string) error {
			var err error
			results[index].Extents, err = q.mapExport(ctx, socket, export)
			return err
		}); err != nil {
			return nil, err
		}
		results[index].ExtentsKnown = true
	}
	return results, nil
}

func prepareBackupTarget(ctx context.Context, client *qmpClient, source, destination Disk) error {
	sourceNode, err := findBlock(ctx, client, source)
	if err != nil {
		return err
	}
	if sourceNode == nil {
		return errors.New("native backup source disappeared")
	}
	key := secretNode(source)
	if destination.Encrypted {
		if len(destination.Key) > 0 {
			key = secretNode(destination)
			if err := client.execute(ctx, "object-add", map[string]any{"qom-type": "secret", "id": key, "data": base64.StdEncoding.EncodeToString(destination.Key)}, nil); err != nil {
				return err
			}
		} else if !source.Encrypted {
			return errors.New("encrypted native target requires actual KMS material")
		}
	}
	file := fileNode(destination)
	if err := client.execute(ctx, "blockdev-add", map[string]any{"driver": "file", "node-name": file, "filename": destination.Path}, nil); err != nil {
		return err
	}
	options := map[string]any{"driver": "qcow2", "file": file, "size": sourceNode.Image.VirtualSize}
	if destination.Encrypted {
		options["encrypt"] = map[string]any{"format": "luks", "key-secret": key}
	}
	job := "create-" + identifier(destination.ID)
	if err := client.execute(ctx, "blockdev-create", map[string]any{"job-id": job, "options": options}, nil); err != nil {
		return err
	}
	if err := waitJob(ctx, client, job); err != nil {
		return err
	}
	options = map[string]any{"driver": "qcow2", "node-name": diskNode(destination), "file": file}
	if destination.Encrypted {
		options["encrypt"] = map[string]any{"format": "luks", "key-secret": key}
	}
	return client.execute(ctx, "blockdev-add", options, nil)
}

func waitBackupGroup(ctx context.Context, client *qmpClient, jobIDs []string) error {
	for {
		var jobs []nativeJob
		if err := client.execute(ctx, "query-jobs", nil, &jobs); err != nil {
			return err
		}
		concluded := 0
		for _, id := range jobIDs {
			found := false
			for _, job := range jobs {
				if job.ID != id {
					continue
				}
				found = true
				if job.Status == "concluded" {
					if job.Error != "" {
						return fmt.Errorf("native grouped backup %s: %s", id, job.Error)
					}
					concluded++
				}
			}
			if !found {
				return errors.New("native grouped backup disappeared before observed conclusion")
			}
		}
		if concluded == len(jobIDs) {
			return nil
		}
		if err := waitTick(ctx); err != nil {
			return err
		}
	}
}
