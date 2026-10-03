package ebs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"

	"stackd/internal/awswire"
)

// DataKeys joins in-process KMS work to the snapshot transaction. GenerateDataKey
// returns exactly 64 plaintext bytes. The adapter retains caller authority and
// uses ec2.<region>.amazonaws.com for kms:ViaService; EBS is the audit invoker.
// EC2 consumers use the distinct EC2DataKeys forwarded/grant-based boundary.
type DataKeys interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	ReEncrypt(context.Context, []byte, string, map[string]string, map[string]string) ([]byte, string, *awswire.Error)
	DescribeKey(context.Context, string) (string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
	IsAWSManagedKey(context.Context, string) (bool, error)
}

// EncryptionContextID preserves the volume data-key context on volume-derived
// snapshots. Direct snapshots and snapshot copies have their own context.
func (v SnapshotRecord) EncryptionContextID() string {
	if v.Volume != nil {
		return v.Volume.Source.ID
	}
	return v.Key.ID
}

func encryptionContext(v SnapshotRecord) map[string]string {
	return map[string]string{"aws:ebs:id": v.EncryptionContextID()}
}
func dependencyFailure(rejected *awswire.Error, reading bool) *awswire.Error {
	if reading && (rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" || rejected.Code == "NotFoundException") {
		return failure("ResourceNotFoundException", "KMS key not found.", "DEPENDENCY_RESOURCE_NOT_FOUND", 404)
	}
	return invalid("INVALID_DEPENDENCY_REQUEST", rejected.Error())
}
func (s *Service) defaultKey(ctx context.Context, configured string) (string, error) {
	if s.keys == nil {
		return "", failure("InternalServerException", "EBS encryption is not configured.", "", 500)
	}
	if configured != "" && configured != "alias/aws/ebs" {
		return configured, nil
	}
	key, rejected := s.keys.EnsureServiceKey(ctx, "ebs")
	if rejected != nil {
		return "", dependencyFailure(rejected, false)
	}
	return key, nil
}
func (s *Service) createKey(ctx context.Context, v *SnapshotRecord, parent *SnapshotRecord, keyID string) error {
	if s.keys == nil {
		return failure("InternalServerException", "EBS encryption is not configured.", "", 500)
	}
	var plain, wrapped []byte
	var arn string
	var rejected *awswire.Error
	if parent != nil {
		wrapped, arn, rejected = s.keys.ReEncrypt(ctx, parent.WrappedKey, parent.KMSKeyARN, encryptionContext(*parent), encryptionContext(*v))
		if rejected == nil {
			plain, _, rejected = s.keys.Decrypt(ctx, wrapped, encryptionContext(*v))
			if rejected != nil {
				return dependencyFailure(rejected, true)
			}
		}
	} else {
		plain, wrapped, arn, rejected = s.keys.GenerateDataKey(ctx, keyID, encryptionContext(*v))
	}
	defer clear(plain)
	if rejected != nil {
		return dependencyFailure(rejected, false)
	}
	if len(plain) != 64 {
		return errors.New("EBS KMS data key must contain 64 bytes")
	}
	v.KMSKeyARN = arn
	v.WrappedKey = wrapped
	return nil
}
func (s *Service) describeKey(ctx context.Context, v SnapshotRecord) error {
	if v.KMSKeyARN == "" {
		return nil
	}
	if s.keys == nil {
		return errors.New("EBS encryption is not configured")
	}
	_, rejected := s.keys.DescribeKey(ctx, v.KMSKeyARN)
	if rejected != nil {
		return dependencyFailure(rejected, true)
	}
	return nil
}
func (s *Service) authorizeListKey(ctx context.Context, v SnapshotRecord) error {
	if err := s.describeKey(ctx, v); err != nil {
		return err
	}
	if v.KMSKeyARN == "" || v.Key.AccountID == scopeFor(ctx).AccountID {
		return nil
	}
	plain, err := s.dataKey(ctx, v)
	clear(plain)
	return err
}
func (s *Service) dataKey(ctx context.Context, v SnapshotRecord) ([]byte, error) {
	if s.keys == nil {
		return nil, errors.New("EBS encryption is not configured")
	}
	// TODO: Comeback calibrate native data-key reuse and disabled-key propagation.
	plain, _, rejected := s.keys.Decrypt(ctx, v.WrappedKey, encryptionContext(v))
	if rejected != nil {
		clear(plain)
		return nil, dependencyFailure(rejected, true)
	}
	if len(plain) != 64 {
		clear(plain)
		return nil, errors.New("EBS KMS data key must contain 64 bytes")
	}
	return plain, nil
}

// AES-GCM protects each retained block with a fresh nonce and immutable resource/
// index associated data. Both halves of KMS's data key feed the local AES key.
func blockCipher(plain []byte) (cipher.AEAD, error) {
	key := sha256.Sum256(plain)
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func blockAAD(origin BlockEncryptionOrigin, index int32) []byte {
	resource := snapshotARN(SnapshotKey(origin))
	if strings.HasPrefix(origin.ID, "vol-") {
		resource = volumeARN(VolumeKey(origin))
	}
	return []byte(resource + ":" + origin.AccountID + ":" + strconv.FormatInt(int64(index), 10))
}
func (s *Service) sealBlock(ctx context.Context, v SnapshotRecord, k BlockKey, data []byte) ([]byte, error) {
	if v.KMSKeyARN == "" {
		return data, nil
	}
	plain, err := s.dataKey(ctx, v)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	aead, err := blockCipher(plain)
	if err != nil {
		return nil, err
	}
	return sealBlockData(aead, BlockEncryptionOrigin{Scope: k.Snapshot.Scope, ID: k.Snapshot.ID}, k.Index, data), nil
}
func (s *Service) openBlock(ctx context.Context, v SnapshotRecord, block BlockRecord) ([]byte, error) {
	if v.KMSKeyARN == "" {
		return block.Data, nil
	}
	plain, err := s.dataKey(ctx, v)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	aead, err := blockCipher(plain)
	if err != nil {
		return nil, err
	}
	return openBlockData(aead, block.EncryptionOrigin, block.Key.Index, block.Data)
}

func sealBlockData(aead cipher.AEAD, origin BlockEncryptionOrigin, index int32, data []byte) []byte {
	if aead == nil {
		return data
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, data, blockAAD(origin, index))
}

func openBlockData(aead cipher.AEAD, origin BlockEncryptionOrigin, index int32, data []byte) ([]byte, error) {
	if aead == nil {
		return data, nil
	}
	if len(data) < aead.NonceSize() {
		return nil, errors.New("truncated EBS block")
	}
	return aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], blockAAD(origin, index))
}
