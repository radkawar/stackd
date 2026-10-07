package ec2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

func (q *QEMU) Backup(ctx context.Context, source, destination Disk) (result BackupResult, err error) {
	if err := validateDisk(source); err != nil {
		return result, err
	}
	if err := validateDisk(destination); err != nil {
		return result, err
	}
	if source.Path == destination.Path || source.ID == destination.ID {
		return result, errors.New("backup requires an independent destination")
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return result, err
	}
	defer unlock()
	client, directory, err := q.diskOwner(ctx, source)
	if err != nil {
		return result, err
	}
	if client != nil {
		defer client.close()
		return q.backupLive(ctx, client, directory, source, destination)
	}
	if source.Encrypted != destination.Encrypted {
		return result, errors.New("offline native backup preserves encryption; import is required to change encryption")
	}
	if source.Encrypted && len(destination.Key) > 0 && (len(source.Key) == 0 || !bytes.Equal(source.Key, destination.Key)) {
		return result, errors.New("offline ciphertext backup cannot change keys")
	}
	if _, err := q.info(ctx, source); err != nil {
		return result, err
	}
	file, err := exclusiveImage(source.Path)
	if err != nil {
		return result, err
	}
	err = copyIndependent(source.Path, destination.Path)
	_ = file.Close()
	if err != nil {
		return result, err
	}
	if source.Encrypted && len(source.Key) == 0 {
		return BackupResult{ExtentsKnown: false}, nil
	}
	destination.Key = source.Key
	err = q.withOfflineExport(ctx, destination, true, func(socket, export string) error {
		var err error
		result.Extents, err = q.mapExport(ctx, socket, export)
		return err
	})
	if err != nil {
		_ = os.Remove(destination.Path)
		return BackupResult{}, err
	}
	result.ExtentsKnown = true
	return result, nil
}

type nativeJob struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

func queryJob(ctx context.Context, client *qmpClient, id string) (*nativeJob, error) {
	var jobs []nativeJob
	if err := client.execute(ctx, "query-jobs", nil, &jobs); err != nil {
		return nil, err
	}
	for _, job := range jobs {
		if job.ID == id {
			return &job, nil
		}
	}
	return nil, nil
}

func waitJob(ctx context.Context, client *qmpClient, id string) error {
	for {
		job, err := queryJob(ctx, client, id)
		if err != nil {
			return err
		}
		if job == nil {
			return errors.New("native job disappeared before observed completion")
		}
		if job.Status == "concluded" {
			err := client.execute(ctx, "job-dismiss", map[string]any{"id": id}, nil)
			if job.Error != "" {
				return errors.Join(fmt.Errorf("native job %s: %s", id, job.Error), err)
			}
			return err
		}
		if job.Status == "pending" {
			if err := client.execute(ctx, "job-finalize", map[string]any{"id": id}, nil); err != nil {
				return err
			}
		}
		if err := waitTick(ctx); err != nil {
			return err
		}
	}
}

func (q *QEMU) backupLive(ctx context.Context, client *qmpClient, directory string, source, destination Disk) (result BackupResult, err error) {
	sourceBlock, err := findBlock(ctx, client, source)
	if err != nil {
		return result, err
	}
	if sourceBlock == nil {
		return result, errors.New("source block disappeared")
	}
	node := diskNode(destination)
	jobID := "backup-" + identifier(destination.ID)
	job, err := queryJob(ctx, client, jobID)
	if err != nil {
		return result, err
	}
	resuming := job != nil
	if resuming {
		target, err := findBlock(ctx, client, destination)
		if err != nil {
			return result, err
		}
		if target == nil {
			return result, errors.New("surviving backup job lacks its native target")
		}
		// The already-open target owns its retained secret. No upload or
		// replacement job is needed to observe this job's actual conclusion.
	} else {
		if destination.Encrypted && len(destination.Key) == 0 && !source.Encrypted {
			return result, errors.New("encrypted backup from plaintext requires actual KMS key material")
		}
		if err := reserveFile(destination.Path); err != nil {
			return result, err
		}
	}
	defer func() {
		// A cancelled QMP read may leave the old stream between responses.
		// Reconnect and inspect actual graph/job ownership before deleting bytes.
		_ = client.close()
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		connection, e := q.existing(cleanup, directory)
		if errors.Is(e, ErrNotFound) {
			if err != nil {
				err = errors.Join(err, os.Remove(destination.Path))
			}
			return
		}
		if e != nil {
			err = errors.Join(err, e)
			return
		}
		defer connection.close()
		if e := releaseDiskNodes(cleanup, connection, destination); e != nil {
			err = errors.Join(err, e)
			return
		}
		if err != nil {
			err = errors.Join(err, os.Remove(destination.Path))
		}
	}()
	if !resuming {
		if err := prepareBackupTarget(ctx, client, source, destination); err != nil {
			return result, err
		}
		if err := client.execute(ctx, "blockdev-backup", map[string]any{"job-id": jobID, "device": diskNode(source), "target": node, "sync": "full", "auto-dismiss": false}, nil); err != nil {
			return result, err
		}
	}
	if err := waitJob(ctx, client, jobID); err != nil {
		return result, err
	}
	if err := q.withExport(ctx, client, directory, node, func(socket, export string) error {
		var err error
		result.Extents, err = q.mapExport(ctx, socket, export)
		return err
	}); err != nil {
		return result, err
	}
	result.ExtentsKnown = true
	return result, nil
}

// cancelJob observes conclusion before releasing a partial job's file nodes.
// A concluded failure is expected during cancellation, not an active writer.
func cancelJob(ctx context.Context, client *qmpClient, id string) error {
	job, err := queryJob(ctx, client, id)
	if err != nil || job == nil {
		return err
	}
	if job.Status != "concluded" {
		if err := client.execute(ctx, "job-cancel", map[string]any{"id": id}, nil); err != nil {
			return err
		}
	}
	for {
		job, err = queryJob(ctx, client, id)
		if err != nil {
			return err
		}
		if job == nil {
			return nil
		}
		if job.Status == "concluded" {
			return client.execute(ctx, "job-dismiss", map[string]any{"id": id}, nil)
		}
		if err := waitTick(ctx); err != nil {
			return err
		}
	}
}
