package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

// Networking is an explicit customer-container DNS and AWS SDK trust selection.
// The zero value preserves each runtime's existing DNS and trust behavior.
//
// DNS lists daemon-reachable unicast IPv4 resolvers without ports; Docker
// queries port 53. Resolver traffic from VPC-attached containers remains subject
// to that attachment's routes, security groups and network ACLs. Host and daemon
// DNS defaults are never changed.
//
// CAFile names public PEM CA certificates on the controller. They travel through
// the Engine archive API into a container-owned volume, never through a host bind
// mount, so remote Engines need no matching path. The resulting bundle starts
// with the image's own public roots when present, so public AWS endpoints still
// verify. Only AWS_CA_BUNDLE is set; it is honored by botocore/boto3, AWS CLI and
// AWS SDK for Go v2's config loader. SDKs with independent TLS configuration,
// including the JavaScript and Java SDKs, must load the bundle explicitly.
// Certificate verification is never disabled, and customer or image trust
// settings (AWS_CA_BUNDLE, SSL_CERT_FILE, SSL_CERT_DIR) suppress injection.
//
// Container trust and DNS are immutable for a native container lifetime. Changed
// selections apply to newly created containers; reattached containers keep the
// configuration that their native resources actually retain.
type Networking struct {
	DNS    []string
	CAFile string
}

const (
	// RuntimeTrustDirectory is the anonymous volume used when a runtime has no
	// existing writable owned volume for the bundle.
	RuntimeTrustDirectory = "/stackd-trust"
	// RuntimeCALabel records the SHA-256 of the selected CA PEM, not secrets.
	RuntimeCALabel   = "io.stackd.runtime.ca-sha256"
	runtimeCABundle  = "ca-bundle.pem"
	maximumCABytes   = 4 << 20
	maximumRootBytes = 4 << 20
)

// Validate rejects malformed resolver addresses and unusable CA files.
func (n Networking) Validate() error {
	if err := validateDNS(n.DNS); err != nil {
		return err
	}
	if n.CAFile != "" {
		_, err := n.caCertificates()
		return err
	}
	return nil
}

func validateDNS(servers []string) error {
	seen := make(map[netip.Addr]bool, len(servers))
	for _, value := range servers {
		address, err := netip.ParseAddr(value)
		if err != nil || address.String() != value || !address.Is4() || !address.IsGlobalUnicast() {
			return fmt.Errorf("runtime DNS %q must be an explicit reachable unicast IPv4 address without a port", value)
		}
		if seen[address] {
			return fmt.Errorf("runtime DNS %q is repeated", value)
		}
		seen[address] = true
	}
	return nil
}

// SelectedDNS renders an EC2 DHCP DNS selection for a VPC-attached container.
// Only an enabled AmazonProvidedDNS entry (provider) is adapted: to the
// configured resolvers, or, when none are configured, to amazon's result.
// Custom DHCP servers stay exact and ordered; a disabled provider is omitted.
// No remaining server yields an explicit unanswered loopback resolver rather
// than an implicit daemon or host fallback.
func (n Networking) SelectedDNS(selected []netip.Addr, provider netip.Addr, enabled bool, amazon func() ([]string, error)) ([]string, error) {
	if err := validateDNS(n.DNS); err != nil {
		return nil, err
	}
	var result []string
	for _, address := range selected {
		if address != provider {
			result = append(result, address.String())
			continue
		}
		if !enabled {
			continue
		}
		servers := n.DNS
		if len(servers) == 0 {
			if amazon == nil {
				return nil, errors.New("AmazonProvidedDNS has no configured runtime resolver")
			}
			var err error
			if servers, err = amazon(); err != nil {
				return nil, err
			}
		}
		result = append(result, servers...)
	}
	if len(result) == 0 {
		result = []string{"127.0.0.1"}
	}
	return result, nil
}

// Trust is a validated public CA snapshot for one container. It has no private
// key, started helper process, controller mount or lifetime beyond its volume.
type Trust struct {
	certificates  []byte
	directory     string
	managedVolume bool
}

// PrepareTrust adds a scoped AWS_CA_BUNDLE to config unless customer or image
// environment already selects trust. An empty directory adds a read-only
// anonymous volume at RuntimeTrustDirectory, removed with its container.
// Otherwise the caller supplies an existing owned volume target, mounted
// read-only in its customer containers. Call after Env and Mounts are final.
// A nil Trust means nothing is injected.
func (n Networking) PrepareTrust(config *ContainerConfig, imageEnvironment []string, directory string) (*Trust, error) {
	if n.CAFile == "" || userTrust(config.Env) || userTrust(imageEnvironment) {
		return nil, nil
	}
	certificates, err := n.caCertificates()
	if err != nil {
		return nil, err
	}
	managedVolume := directory == ""
	if directory == "" {
		directory = RuntimeTrustDirectory
		for _, mount := range config.HostConfig.Mounts {
			target := path.Clean(mount.Target)
			if target == "/" || target == directory || strings.HasPrefix(directory, target+"/") || strings.HasPrefix(target, directory+"/") {
				return nil, fmt.Errorf("container mount %q overlaps the runtime trust directory", mount.Target)
			}
		}
		config.HostConfig.Mounts = append(slices.Clip(config.HostConfig.Mounts), ContainerMount{Type: "volume", Target: directory, ReadOnly: true, VolumeOptions: ContainerVolumeOptions{NoCopy: true}})
	}
	if !path.IsAbs(directory) || path.Clean(directory) != directory || directory == "/" {
		return nil, errors.New("runtime trust directory must be a clean absolute non-root path")
	}
	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}
	sum := sha256.Sum256(certificates)
	config.Labels[RuntimeCALabel] = hex.EncodeToString(sum[:])
	// Clip so a caller-owned backing array, e.g. a retained spec, is never written.
	config.Env = append(slices.Clip(config.Env), "AWS_CA_BUNDLE="+path.Join(directory, runtimeCABundle))
	return &Trust{certificates: certificates, directory: directory, managedVolume: managedVolume}, nil
}

// Install writes the bundle into the created container's owned volume before
// customer code starts. The image's system trust store is not modified.
func (t *Trust) Install(ctx context.Context, client *Client, container string) (err error) {
	if t == nil {
		return nil
	}
	roots, err := imageRoots(ctx, client, container)
	if err != nil {
		return err
	}
	bundle := make([]byte, 0, len(roots)+1+len(t.certificates))
	bundle = append(bundle, roots...)
	if len(roots) != 0 && roots[len(roots)-1] != '\n' {
		bundle = append(bundle, '\n')
	}
	bundle = append(bundle, t.certificates...)
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: runtimeCABundle, Typeflag: tar.TypeReg, Mode: 0444, Size: int64(len(bundle))}); err != nil {
		return err
	}
	if _, err := writer.Write(bundle); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if t.managedVolume {
		var state struct {
			Image  string
			Mounts []struct{ Type, Name, Destination string }
		}
		if err := client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(container)+"/json", nil, &state); err != nil {
			return fmt.Errorf("inspect runtime trust volume: %w", err)
		}
		volume := ""
		for _, mount := range state.Mounts {
			if mount.Type == "volume" && mount.Destination == t.directory {
				volume = mount.Name
				break
			}
		}
		if volume == "" || state.Image == "" {
			return errors.New("runtime trust volume or installed image is absent")
		}
		// The customer mount is read-only from creation. An unstarted container
		// of the same installed image supplies the Engine archive write view;
		// customer image code is never executed to install trust.
		container = "stackd-trust-writer-" + rand.Text()
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			err = errors.Join(err, client.RemoveContainer(cleanup, container))
		}()
		config := ContainerConfig{Image: state.Image, NetworkDisabled: true, Labels: map[string]string{RuntimeCALabel: "writer"}, HostConfig: ContainerHostConfig{
			NetworkMode: "none", ReadonlyRootfs: true,
			Mounts: []ContainerMount{{Type: "volume", Source: volume, Target: t.directory, VolumeOptions: ContainerVolumeOptions{NoCopy: true}}},
		}}
		if err := client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(container), config, nil); err != nil {
			return fmt.Errorf("create unstarted runtime trust writer: %w", err)
		}
	}
	response, err := client.Request(ctx, http.MethodPut, "/containers/"+url.PathEscape(container)+"/archive?path="+url.QueryEscape(t.directory)+"&noOverwriteDirNonDir=true", &archive, "application/x-tar")
	if err != nil {
		return fmt.Errorf("install runtime CA bundle through Docker Engine: %w", err)
	}
	return response.Body.Close()
}

// TrustMissing reports whether a retained container was labeled for managed
// trust but its bundle was never installed, e.g. after a crash between create
// and Install. Such a never-started container must be recreated, not started.
func TrustMissing(ctx context.Context, client *Client, container string, labels map[string]string, environment []string) (bool, error) {
	if labels[RuntimeCALabel] == "" {
		return false, nil
	}
	bundle := ""
	for _, entry := range environment {
		if value, found := strings.CutPrefix(entry, "AWS_CA_BUNDLE="); found {
			bundle = value
		}
	}
	if bundle == "" || !path.IsAbs(bundle) {
		return true, nil
	}
	_, err := readArchiveFile(ctx, client, container, bundle, maximumRootBytes+maximumCABytes+1)
	var remote *Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
		return true, nil
	}
	return false, err
}

func userTrust(environment []string) bool {
	// Empty values are deliberate selections too.
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if slices.Contains([]string{"AWS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}, key) {
			return true
		}
	}
	return false
}

func (n Networking) caCertificates() ([]byte, error) {
	file, err := os.Open(n.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read runtime CA file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("runtime CA file must be a regular public PEM file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumCABytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximumCABytes {
		return nil, errors.New("runtime CA file exceeds 4 MiB")
	}
	remaining := bytes.TrimSpace(data)
	var out []byte
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("runtime CA file must contain only public PEM CERTIFICATE blocks")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || (certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0) {
			return nil, errors.New("runtime trust requires CA certificates, not leaf certificates")
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		remaining = bytes.TrimSpace(rest)
	}
	if len(out) == 0 {
		return nil, errors.New("runtime CA file contains no CA certificates")
	}
	return out, nil
}

// imageRoots reads the image's public root bundle from well-known regular files.
// Symlinked names are skipped; their distribution's canonical file is listed.
func imageRoots(ctx context.Context, client *Client, container string) ([]byte, error) {
	for _, filename := range []string{
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
	} {
		roots, err := readArchiveFile(ctx, client, container, filename, maximumRootBytes)
		var remote *Error
		if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read image public CA roots %s: %w", filename, err)
		}
		if len(roots) != 0 && x509.NewCertPool().AppendCertsFromPEM(roots) {
			return roots, nil
		}
	}
	return nil, nil
}

// readArchiveFile returns a regular file's contents, or nil for another type.
func readArchiveFile(ctx context.Context, client *Client, container, filename string, limit int64) ([]byte, error) {
	response, err := client.Request(ctx, http.MethodGet, "/containers/"+url.PathEscape(container)+"/archive?path="+url.QueryEscape(filename), nil, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	reader := tar.NewReader(io.LimitReader(response.Body, limit+64<<10))
	header, err := reader.Next()
	if err != nil {
		return nil, err
	}
	if header.Typeflag != tar.TypeReg {
		return nil, nil
	}
	if header.Size > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", filename, limit)
	}
	return io.ReadAll(reader)
}
