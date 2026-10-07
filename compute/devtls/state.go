package devtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	bundleFile        = "authority.pem"
	publicFile        = "ca.pem"
	lockFile          = "authority.lock"
	maximumStateBytes = 64 * 1024
)

func publicPath(directory string) string { return filepath.Join(directory, publicFile) }

func openState(ctx context.Context, path string) (string, *x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	directory, root, err := privateRoot(path)
	if err != nil {
		return "", nil, nil, nil, err
	}
	defer root.Close()
	unlock, err := lockState(ctx, root)
	if err != nil {
		return "", nil, nil, nil, err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return "", nil, nil, nil, fmt.Errorf("devtls: open: %w", err)
	}
	bundle, err := readStateFile(root, bundleFile, true)
	var ca *x509.Certificate
	var key *ecdsa.PrivateKey
	var publicPEM []byte
	switch {
	case err == nil:
		ca, key, publicPEM, err = parseAuthority(bundle)
		if err != nil {
			return "", nil, nil, nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		if _, err := root.Lstat(publicFile); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return "", nil, nil, nil, fmt.Errorf("devtls: inspect orphaned public CA: %w", err)
			}
			return "", nil, nil, nil, errors.New("devtls: public CA exists without its private authority; refusing to replace trust")
		}
		ca, key, publicPEM, bundle, err = generateAuthority(ctx)
		if err != nil {
			return "", nil, nil, nil, err
		}
		if err := atomicWrite(ctx, root, bundleFile, bundle, 0600); err != nil {
			return "", nil, nil, nil, fmt.Errorf("devtls: persist CA identity: %w", err)
		}
	default:
		return "", nil, nil, nil, fmt.Errorf("devtls: read private CA identity: %w", err)
	}
	if err := validAuthorityTime(ca, time.Now()); err != nil {
		return "", nil, nil, nil, err
	}
	public, err := readStateFile(root, publicFile, false)
	switch {
	case err == nil:
		if !bytes.Equal(public, publicPEM) {
			return "", nil, nil, nil, errors.New("devtls: public CA does not match persisted private authority")
		}
	case errors.Is(err, os.ErrNotExist):
		// A crash between the two atomic writes must retain the committed CA,
		// not generate another identity. Only the public copy is reconstructed.
		if err := atomicWrite(ctx, root, publicFile, publicPEM, 0644); err != nil {
			return "", nil, nil, nil, fmt.Errorf("devtls: persist public CA certificate: %w", err)
		}
	default:
		return "", nil, nil, nil, fmt.Errorf("devtls: read public CA certificate: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", nil, nil, nil, fmt.Errorf("devtls: open: %w", err)
	}
	return directory, ca, key, publicPEM, nil
}

func privateRoot(path string) (string, *os.Root, error) {
	directory, err := filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("devtls: resolve state directory: %w", err)
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", nil, fmt.Errorf("devtls: create private directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", nil, fmt.Errorf("devtls: inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", nil, errors.New("devtls: state directory must be a nonsymlink private directory (0700)")
	}
	if err := ownedFile(info, false); err != nil {
		return "", nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", nil, fmt.Errorf("devtls: open private directory: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		root.Close()
		return "", nil, errors.New("devtls: state directory changed while opening")
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		root.Close()
		return "", nil, fmt.Errorf("devtls: resolve private directory: %w", err)
	}
	return directory, root, nil
}

func readStateFile(root *os.Root, name string, private bool) ([]byte, error) {
	file, err := openNoFollow(root, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("devtls: %s is not a regular file", name)
	}
	if private && info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("devtls: %s must be private (0600)", name)
	}
	if !private && info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("devtls: %s must not be group- or world-writable", name)
	}
	if err := ownedFile(info, true); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximumStateBytes {
		return nil, fmt.Errorf("devtls: %s exceeds the maximum identity size", name)
	}
	return data, nil
}

func parseAuthority(bundle []byte) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	block, rest := pem.Decode(bundle)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || !bytes.HasPrefix(bundle, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, nil, nil, errors.New("devtls: invalid persisted CA certificate PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("devtls: parse persisted CA certificate: %w", err)
	}
	publicPEM := pem.EncodeToMemory(block)
	if !bytes.HasPrefix(bytes.TrimSpace(rest), []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, nil, nil, errors.New("devtls: invalid persisted CA private-key PEM")
	}
	block, rest = pem.Decode(rest)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, nil, errors.New("devtls: invalid persisted CA private-key PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("devtls: parse persisted CA key: %w", err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, nil, errors.New("devtls: persisted CA requires an ECDSA P-256 key")
	}
	publicKey, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return nil, nil, nil, errors.New("devtls: persisted CA certificate and private key do not match")
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		ca.Subject.CommonName != authorityName || !bytes.Equal(ca.RawIssuer, ca.RawSubject) ||
		!ca.MaxPathLenZero || ca.MaxPathLen != 0 || len(ca.ExtKeyUsage) != 0 || len(ca.UnhandledCriticalExtensions) != 0 {
		return nil, nil, nil, errors.New("devtls: persisted certificate is not a local development root CA")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		return nil, nil, nil, fmt.Errorf("devtls: verify persisted CA self-signature: %w", err)
	}
	return ca, key, publicPEM, nil
}

func atomicWrite(ctx context.Context, root *os.Root, name string, data []byte, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".pending-" + hex.EncodeToString(random[:])
	file, err := openNoFollow(root, temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	written, err := file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	parent, err := root.Open(".")
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func (a *Authority) export(path string) error {
	if path == "" {
		return errors.New("devtls: public CA export path is required")
	}
	destination, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("devtls: resolve public export path: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("devtls: resolve public export directory: %w", err)
	}
	name := filepath.Base(destination)
	if parent == a.directory && name != publicFile {
		return errors.New("devtls: public export must not overwrite private authority state")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return fmt.Errorf("devtls: open public export directory: %w", err)
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err == nil && !info.Mode().IsRegular() {
		return errors.New("devtls: public export destination must be a regular nonsymlink file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("devtls: inspect public export destination: %w", err)
	}
	if err := atomicWrite(context.Background(), root, name, a.publicPEM, 0644); err != nil {
		return fmt.Errorf("devtls: export public CA: %w", err)
	}
	return nil
}
