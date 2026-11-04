package eks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const providerPendingName = "ecr-provider.pending"

// providerArtifact is an inode receipt, not a path to a controller build. The
// preparation receipt is durable before publishing the immutable final name.
// Neither recovery nor reattachment replaces a file or adopts an unknown inode.
type providerArtifact struct {
	SHA256    string
	Size      int64
	Device    uint64
	Inode     uint64
	UID       uint32
	GID       uint32
	Preparing bool `json:",omitempty"`
}

func providerDirectory(dir string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := privateDirectory(dir); err != nil {
		return stat, err
	}
	if err := unix.Lstat(dir, &stat); err != nil {
		return stat, err
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return stat, errors.New("eks: provider state directory belongs to a different OS owner")
	}
	return stat, nil
}

func validateProviderFile(dir, name string, artifact *providerArtifact) error {
	owner, err := providerDirectory(dir)
	if err != nil {
		return err
	}
	if artifact == nil || artifact.Size <= 0 || artifact.Inode == 0 || artifact.UID != owner.Uid || artifact.GID != owner.Gid {
		return errors.New("eks: invalid retained ECR provider ownership identity")
	}
	digest, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != artifact.SHA256 {
		return errors.New("eks: invalid retained ECR provider digest")
	}
	fd, err := unix.Open(filepath.Join(dir, name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("eks: retained ECR provider artifact is unavailable: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	maxLinks := uint64(1)
	if artifact.Preparing {
		maxLinks = 2
	}
	if stat.Mode != unix.S_IFREG|0500 || stat.Size != artifact.Size || uint64(stat.Dev) != artifact.Device || stat.Ino != artifact.Inode || stat.Uid != artifact.UID || stat.Gid != artifact.GID || uint64(stat.Nlink) < 1 || uint64(stat.Nlink) > maxLinks {
		return errors.New("eks: retained ECR provider mode or file ownership identity changed; refusing replacement or adoption")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return errors.New("eks: retained ECR provider digest changed; refusing replacement")
	}
	return nil
}

func validateProvider(dir string, artifact *providerArtifact) error {
	if artifact == nil || artifact.Preparing {
		return errors.New("eks: ECR provider preparation is incomplete; refusing worker attachment")
	}
	return validateProviderFile(dir, ecrProviderName, artifact)
}

func syncProviderDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (k *K3d) prepareProvider(state *diskState, dir string, creating bool) error {
	if state.ECRProvider != nil {
		if !state.ECRProvider.Preparing {
			return validateProvider(dir, state.ECRProvider)
		}
		if !creating || state.Ready {
			return errors.New("eks: incomplete ECR provider preparation cannot modify retained workers")
		}
		return finishProviderPreparation(state, dir)
	}
	if !creating || state.Ready {
		return errors.New("eks: enabling or upgrading a legacy ECR provider requires explicit cluster recreation")
	}
	owner, err := providerDirectory(dir)
	if err != nil {
		return err
	}
	// An unreceipted file may be an interrupted pre-checkpoint preparation, or
	// foreign content. Neither is adopted, removed, or replaced on retry.
	for _, name := range []string{ecrProviderName, providerPendingName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return err
			}
			return errors.New("eks: unreceipted ECR provider artifact; explicit owned cluster deletion is required before retrying")
		}
	}
	if k.config.ECRCredentialProvider == "" {
		return errors.New("eks: an executable ECR credential provider is required to create a native cluster")
	}
	sourceFD, err := unix.Open(k.config.ECRCredentialProvider, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(sourceFD), k.config.ECRCredentialProvider)
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 {
		return errors.New("eks: ECR credential provider must be a nonempty executable regular file")
	}
	file, err := os.OpenFile(filepath.Join(dir, providerPendingName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), source)
	if err != nil {
		return err
	}
	if size != info.Size() {
		return errors.New("eks: ECR credential provider changed during staging")
	}
	if err = file.Chmod(0500); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Uid != owner.Uid || stat.Gid != owner.Gid {
		return errors.New("eks: staged ECR provider differs from the state directory OS owner")
	}
	if err = syncProviderDirectory(dir); err != nil {
		return err
	}
	state.ECRProvider = &providerArtifact{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size, Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid, Preparing: true}
	if err = saveState(dir, *state); err != nil {
		return err
	}
	return finishProviderPreparation(state, dir)
}

func finishProviderPreparation(state *diskState, dir string) error {
	artifact := state.ECRProvider
	// Either name may survive a crash. A second name is acceptable only when
	// it names the same receipted inode; link never overwrites a final artifact.
	finalErr := validateProviderFile(dir, ecrProviderName, artifact)
	pendingErr := validateProviderFile(dir, providerPendingName, artifact)
	if finalErr != nil && !errors.Is(finalErr, os.ErrNotExist) {
		return finalErr
	}
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) {
		return pendingErr
	}
	if finalErr != nil {
		if pendingErr != nil {
			return errors.New("eks: retained ECR provider preparation lost its artifact; refusing replacement")
		}
		if err := os.Link(filepath.Join(dir, providerPendingName), filepath.Join(dir, ecrProviderName)); err != nil {
			return err
		}
	}
	if pendingErr == nil {
		if err := os.Remove(filepath.Join(dir, providerPendingName)); err != nil {
			return err
		}
	}
	if err := syncProviderDirectory(dir); err != nil {
		return err
	}
	ready := *artifact
	ready.Preparing = false
	if err := validateProvider(dir, &ready); err != nil {
		return err
	}
	updated := *state
	updated.ECRProvider = &ready
	if err := saveState(dir, updated); err != nil {
		return err
	}
	*state = updated
	return nil
}
