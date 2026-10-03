package ec2

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type guestBlock struct {
	QDev     string `json:"qdev"`
	Inserted struct {
		NodeName string `json:"node-name"`
	} `json:"inserted"`
}

func guestDevice(ctx context.Context, client *qmpClient, disk Disk) (string, error) {
	var devices []guestBlock
	if err := client.execute(ctx, "query-block", nil, &devices); err != nil {
		return "", err
	}
	for _, device := range devices {
		if device.Inserted.NodeName == diskNode(disk) {
			if device.QDev == "" {
				return "", errors.New("native block backend lacks a guest device identity")
			}
			return filepath.Base(device.QDev), nil
		}
	}
	return "", nil
}

func peripherals(ctx context.Context, client *qmpClient) (map[string]bool, error) {
	var objects []struct {
		Name string `json:"name"`
	}
	if err := client.execute(ctx, "qom-list", map[string]any{"path": "/machine/peripheral"}, &objects); err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(objects))
	for _, object := range objects {
		names[object.Name] = true
	}
	return names, nil
}

func volumeSerial(disk Disk) (string, error) {
	// Native graph identity remains the fully scoped EBS ARN; hardware serials
	// expose only the terminal AWS volume ID.
	id := disk.ID
	if separator := strings.LastIndexByte(id, '/'); separator >= 0 {
		id = id[separator+1:]
	}
	serial := strings.ReplaceAll(id, "-", "")
	if len(serial) == 0 || len(serial) > 20 || strings.ContainsAny(serial, ",\x00\n") {
		return "", &CapabilityError{Feature: "NVMe volume serial " + disk.ID}
	}
	return serial, nil
}

// AttachDisk realizes a real NVMe controller on a pre-created hotplug port.
// It never changes EBS metadata or substitutes a second mutable disk authority.
func (i *nativeInstance) AttachDisk(ctx context.Context, disk Disk) (err error) {
	if err := validateDisk(disk); err != nil {
		return err
	}
	if disk.Root {
		return &CapabilityError{Feature: "root-volume hotplug"}
	}
	relative, err := filepath.Rel(i.directory, disk.Path)
	if err != nil {
		return err
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("EBS disk must be outside the instance runtime directory")
	}
	serial, err := volumeSerial(disk)
	if err != nil {
		return err
	}
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	owner, ownerDirectory, err := i.driver.diskOwner(ctx, disk)
	if err != nil {
		return err
	}
	if owner != nil {
		_ = owner.close()
		if ownerDirectory != i.directory {
			return errors.New("native disk belongs to another VMM")
		}
	}
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return err
	}
	defer client.close()
	if device, err := guestDevice(ctx, client, disk); err != nil {
		return err
	} else if device != "" {
		return nil
	}
	names, err := peripherals(ctx, client)
	if err != nil {
		return err
	}
	index := -1
	for candidate := range 28 {
		if names[fmt.Sprintf("port%d", candidate)] && !names[fmt.Sprintf("nvme%d", candidate)] {
			index = candidate
			break
		}
	}
	if index < 0 {
		return &CapabilityError{Feature: "available native PCIe hotplug port"}
	}
	// A retry may find a successfully opened disk whose device_add failed.
	// Retain its loaded secret and reuse that same graph, not a new writer.
	node, err := findBlock(ctx, client, disk)
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		_ = client.close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		connection, e := i.driver.existing(cleanup, i.directory)
		if e != nil {
			err = errors.Join(err, e)
			return
		}
		defer connection.close()
		device, e := guestDevice(cleanup, connection, disk)
		if e != nil {
			err = errors.Join(err, e)
			return
		}
		// A lost device_add response is not permission to unplug a realized
		// guest disk. Leave it owned so the caller can reconcile by retrying.
		if device == "" {
			err = errors.Join(err, releaseDiskNodes(cleanup, connection, disk))
		}
	}()
	if node == nil {
		if _, err := i.driver.info(ctx, disk); err != nil {
			return err
		}
		if disk.Encrypted {
			var objects []struct {
				Name string `json:"name"`
			}
			if err := client.execute(ctx, "qom-list", map[string]any{"path": "/objects"}, &objects); err != nil {
				return err
			}
			present := false
			for _, object := range objects {
				if object.Name == secretNode(disk) {
					present = true
				}
			}
			if !present {
				if len(disk.Key) == 0 {
					return errors.New("encrypted hotplug requires actual KMS key material")
				}
				if err := client.execute(ctx, "object-add", map[string]any{"qom-type": "secret", "id": secretNode(disk), "data": base64.StdEncoding.EncodeToString(disk.Key)}, nil); err != nil {
					return err
				}
			}
		}
		options := diskOptions(disk)
		options["node-name"] = diskNode(disk)
		if err := client.execute(ctx, "blockdev-add", options, nil); err != nil {
			return err
		}
	}
	device := fmt.Sprintf("nvme%d", index)
	if err := client.execute(ctx, "device_add", map[string]any{"driver": "nvme", "id": device, "bus": fmt.Sprintf("port%d", index), "drive": diskNode(disk), "serial": serial}, nil); err != nil {
		return err
	}
	observed, err := guestDevice(ctx, client, disk)
	if err != nil {
		return err
	}
	if observed != device {
		return errors.New("native NVMe device realization not observed")
	}
	return nil
}

// DetachDisk returns success only after both native block-device and QOM qdev
// disappearance. A guest which does not acknowledge PCIe eject causes the
// caller's deadline to expire with ownership intact; disk bytes are never erased.
func (i *nativeInstance) DetachDisk(ctx context.Context, disk Disk) error {
	if err := validateDisk(disk); err != nil {
		return err
	}
	if disk.Root {
		return &CapabilityError{Feature: "root-volume hot-unplug"}
	}
	for _, attached := range i.spec.Disks {
		if attached.ID == disk.ID && attached.Root {
			return &CapabilityError{Feature: "root-volume hot-unplug"}
		}
	}
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return err
	}
	defer client.close()
	if _, err := findBlock(ctx, client, disk); err != nil {
		return err
	}
	device, err := guestDevice(ctx, client, disk)
	if err != nil {
		return err
	}
	if device == "" {
		return releaseDiskNodes(ctx, client, disk)
	}
	if err := client.execute(ctx, "device_del", map[string]any{"id": device}, nil); err != nil {
		if !strings.Contains(err.Error(), "already in the process of unplug") {
			return err
		}
	}
	for {
		attached, err := guestDevice(ctx, client, disk)
		if err != nil {
			return err
		}
		names, err := peripherals(ctx, client)
		if err != nil {
			return err
		}
		if attached == "" && !names[device] {
			return releaseDiskNodes(ctx, client, disk)
		}
		if err := waitTick(ctx); err != nil {
			return err
		}
	}
}

// CheckResizeDisk is an admission-time capability check without a size change.
// QEMU NVMe currently denies shared resize permission (including upstream
// v11.1.1); changing a live filesystem by unplug/replug is not an online resize.
func (q *QEMU) CheckResizeDisk(ctx context.Context, disk Disk, size int64) error {
	if err := validateDisk(disk); err != nil {
		return err
	}
	if size <= 0 || size%512 != 0 {
		return errors.New("disk size must be positive and sector aligned")
	}
	unlock, err := q.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	client, _, err := q.diskOwner(ctx, disk)
	if err != nil {
		return err
	}
	if client == nil {
		info, err := q.info(ctx, disk)
		if err != nil {
			return err
		}
		if size < info.VirtualSize {
			return errors.New("native volume shrink is not supported")
		}
		return nil
	}
	defer client.close()
	node, err := findBlock(ctx, client, disk)
	if err != nil {
		return err
	}
	if size < node.Image.VirtualSize {
		return errors.New("native volume shrink is not supported")
	}
	if size == node.Image.VirtualSize {
		return nil
	}
	device, err := guestDevice(ctx, client, disk)
	if err != nil {
		return err
	}
	if device != "" {
		return &CapabilityError{Feature: "online NVMe namespace resize: native controller does not share resize permission"}
	}
	return nil
}

// AttachedDisks observes guest-visible NVMe disks, not firmware flash or
// unattached backup targets. Unknown NVMe devices are reported with their native
// identities, never removed during reattachment.
func (i *nativeInstance) AttachedDisks(ctx context.Context) ([]DiskStatus, error) {
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return nil, err
	}
	defer client.close()
	return i.attachedDisks(ctx, client)
}

func (i *nativeInstance) attachedDisks(ctx context.Context, client *qmpClient) ([]DiskStatus, error) {
	var devices []guestBlock
	if err := client.execute(ctx, "query-block", nil, &devices); err != nil {
		return nil, err
	}
	var nodes []nativeBlock
	if err := client.execute(ctx, "query-named-block-nodes", nil, &nodes); err != nil {
		return nil, err
	}
	byName := make(map[string]nativeBlock, len(nodes))
	for _, node := range nodes {
		byName[node.NodeName] = node
	}
	expected := make(map[string]Disk, len(i.spec.Disks))
	for _, disk := range i.spec.Disks {
		expected[diskNode(disk)] = disk
	}
	result := make([]DiskStatus, 0, len(devices))
	for _, device := range devices {
		if device.QDev == "" {
			return nil, errors.New("native block backend lacks a guest device identity")
		}
		// query-block returns an explicit qdev ID or an absolute QOM path.
		qomPath := device.QDev
		if !strings.HasPrefix(qomPath, "/") {
			qomPath = "/machine/peripheral/" + qomPath
		}
		var deviceType string
		if err := client.execute(ctx, "qom-get", map[string]any{"path": qomPath, "property": "type"}, &deviceType); err != nil {
			return nil, err
		}
		if deviceType != "nvme" {
			continue
		}
		node, ok := byName[device.Inserted.NodeName]
		if !ok {
			return nil, errors.New("native guest device lacks its block node")
		}
		path, err := blockPath(node)
		if err != nil {
			return nil, err
		}
		status := DiskStatus{Device: filepath.Base(device.QDev), NodeName: node.NodeName, Path: path, Encrypted: node.Image.Encrypted}
		if err := client.execute(ctx, "qom-get", map[string]any{"path": qomPath, "property": "serial"}, &status.Serial); err != nil {
			return nil, err
		}
		var bootindex int
		if err := client.execute(ctx, "qom-get", map[string]any{"path": qomPath, "property": "bootindex"}, &bootindex); err != nil {
			return nil, err
		}
		status.Root = bootindex == 1
		if disk, ok := expected[node.NodeName]; ok {
			serial, err := volumeSerial(disk)
			if err != nil {
				return nil, err
			}
			if status.Path != filepath.Clean(disk.Path) || status.Encrypted != disk.Encrypted || status.Serial != serial || status.Root != disk.Root {
				return nil, fmt.Errorf("native volume %s does not match its resolved identity", disk.ID)
			}
			status.ID = disk.ID
		}
		result = append(result, status)
	}
	return result, nil
}
