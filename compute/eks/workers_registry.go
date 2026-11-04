package eks

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"stackd/compute/eks/ecrcredentials"
)

const ecrNodeDirectory = "/etc/stackd/ecr"
const ecrProviderName = "stackd-ecr-credential-provider"

func configureECR(config *Config) error {
	enabled := config.ECRCredentialProvider != "" || config.ECRCredentialsFile != "" || len(config.ECRCA) != 0
	if !enabled {
		return nil
	}
	if config.ECRCredentialsFile == "" || len(config.ECRCA) == 0 {
		return errors.New("eks: ECR credentials file and CA are required together; a provider executable is also required for new clusters")
	}
	var err error
	if config.ECRCredentialProvider != "" {
		config.ECRCredentialProvider, err = filepath.Abs(config.ECRCredentialProvider)
		if err != nil {
			return err
		}
	}
	config.ECRCredentialsFile, err = filepath.Abs(config.ECRCredentialsFile)
	if err != nil {
		return err
	}
	// Terraform may create the least-privilege node identity and this file
	// before CreateCluster. Read it at native creation, not daemon startup.
	if !x509.NewCertPool().AppendCertsFromPEM(config.ECRCA) {
		return errors.New("eks: invalid ECR CA certificate")
	}
	return nil
}

// prepareECR preserves retained trust and credentials rotation independently
// from the executable. Only a worker-free preparation may create these files.
func (k *K3d) prepareECR(state *diskState, dir string, creating bool) error {
	if k.config.ECRCredentialsFile == "" {
		if state.ECRProvider != nil {
			return errors.New("eks: retained worker requires its explicit ECR credentials and CA")
		}
		return nil
	}
	if state.ECRProvider == nil && (!creating || state.Ready) {
		return errors.New("eks: legacy ECR worker has no retained provider identity; explicit cluster recreation is required")
	}
	if state.ECRProvider != nil && state.ECRProvider.Preparing && (!creating || state.Ready) {
		return errors.New("eks: incomplete ECR provider preparation cannot modify retained workers")
	}
	credentials, err := ecrcredentials.Load(k.config.ECRCredentialsFile)
	if err != nil {
		return err
	}
	registry, err := credentials.Registry()
	if err != nil {
		return err
	}
	provider, err := json.Marshal(map[string]any{
		"apiVersion": "kubelet.config.k8s.io/v1", "kind": "CredentialProviderConfig",
		"providers": []any{map[string]any{"name": ecrProviderName, "matchImages": []string{registry}, "defaultCacheDuration": "0s", "apiVersion": ecrcredentials.APIVersion, "args": []string{"--config", ecrNodeDirectory + "/credentials.json", "--ca", ecrNodeDirectory + "/ca.pem"}}},
	})
	if err != nil {
		return err
	}
	registries, err := json.Marshal(map[string]any{"configs": map[string]any{registry: map[string]any{"tls": map[string]string{"ca_file": ecrNodeDirectory + "/ca.pem"}}}})
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"ecr-ca.pem": k.config.ECRCA, "ecr-provider.json": provider, "ecr-registries.yaml": registries} {
		// A bind mount retains the inode. Never replace a retained mounted file;
		// changing trust or registry authority requires explicit cluster recreation.
		existing, err := readPrivate(filepath.Join(dir, name))
		if err == nil {
			if !bytes.Equal(existing, data) {
				return fmt.Errorf("eks: retained %s differs; recreate the native cluster to change registry trust or authority", name)
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !creating || state.ECRProvider != nil && !state.ECRProvider.Preparing {
			return fmt.Errorf("eks: retained %s is missing; refusing to replace mounted registry state", name)
		}
		if err = writePrivate(dir, name, data); err != nil {
			return err
		}
	}
	return k.prepareProvider(state, dir, creating)
}

// ecrWorkerArguments mounts only the durably identified provider, never the
// current controller checkout. Kubelet obtains fresh authentication per pull.
func (k *K3d) ecrWorkerArguments(state diskState, dir string) ([]string, error) {
	if k.config.ECRCredentialsFile == "" {
		if state.ECRProvider != nil {
			return nil, errors.New("eks: retained worker requires its explicit ECR credentials and CA")
		}
		return nil, nil
	}
	if err := validateProvider(dir, state.ECRProvider); err != nil {
		return nil, err
	}
	args := []string{}
	for _, mount := range k.ecrMounts(dir) {
		args = append(args, "--volume", mount.Source+":"+mount.Destination+":ro@agent:0")
	}
	return append(args,
		"--k3s-arg", "--kubelet-arg=image-credential-provider-config="+ecrNodeDirectory+"/provider.json@agent:0",
		"--k3s-arg", "--kubelet-arg=image-credential-provider-bin-dir=/opt/stackd/bin@agent:0"), nil
}

type ecrMount struct{ Source, Destination string }

func (k *K3d) ecrMounts(dir string) []ecrMount {
	return []ecrMount{
		{filepath.Join(dir, ecrProviderName), "/opt/stackd/bin/" + ecrProviderName},
		{k.config.ECRCredentialsFile, ecrNodeDirectory + "/credentials.json"},
		{filepath.Join(dir, "ecr-ca.pem"), ecrNodeDirectory + "/ca.pem"},
		{filepath.Join(dir, "ecr-provider.json"), ecrNodeDirectory + "/provider.json"},
		{filepath.Join(dir, "ecr-registries.yaml"), "/etc/rancher/k3s/registries.yaml"},
	}
}

func (k *K3d) validateWorkerECR(state diskState, container dockerContainer) error {
	dir := k.resourceDir(state.ID)
	if state.ECRProvider == nil {
		for _, mount := range container.Mounts {
			if mount.Destination == "/opt/stackd/bin/"+ecrProviderName || strings.HasPrefix(mount.Destination, ecrNodeDirectory+"/") || mount.Destination == "/etc/rancher/k3s/registries.yaml" {
				return errors.New("eks: legacy worker uses an externally mounted ECR provider; explicit cluster recreation is required, not live mount replacement")
			}
		}
		if k.config.ECRCredentialsFile != "" {
			return errors.New("eks: retained worker has no staged ECR provider; recreate the cluster to enable it")
		}
		return nil
	}
	if err := validateProvider(dir, state.ECRProvider); err != nil {
		return err
	}
	if k.config.ECRCredentialsFile == "" {
		return errors.New("eks: retained worker requires its explicit ECR credentials and CA")
	}
	for _, want := range k.ecrMounts(dir) {
		found := 0
		for _, mount := range container.Mounts {
			if mount.Destination == want.Destination {
				if mount.Source != want.Source || mount.Type != "bind" || mount.RW {
					return errors.New("eks: retained worker ECR mount differs from its immutable read-only ownership")
				}
				found++
			}
		}
		if found != 1 {
			return errors.New("eks: retained worker lacks the configured ECR provider/trust mount; recreate the native cluster to enable or change registry configuration")
		}
	}
	return nil
}
