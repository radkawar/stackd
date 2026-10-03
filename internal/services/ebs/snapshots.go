package ebs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	api "stackd/internal/awsapi/ebs"
)

func (s *Service) startSnapshot(tx Transaction, in *api.StartSnapshotRequest) (*api.StartSnapshotResponse, error) {
	ctx := tx.Context()
	scope := scopeFor(ctx)
	conditions := map[string][]string{}
	if in.Description != nil {
		conditions["ebs:Description"] = []string{value(in.Description)}
	}
	if in.VolumeSize != nil {
		conditions["ebs:VolumeSize"] = []string{strconv.FormatInt(number(in.VolumeSize), 10)}
	}
	tags := make(map[string]string, len(in.Tags))
	for _, t := range in.Tags {
		conditions["aws:RequestTag/"+value(t.Key)] = []string{value(t.Value)}
		tags[value(t.Key)] = value(t.Value)
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], value(t.Key))
	}
	// StartSnapshot authorizes the source when present, not snapshot/null in
	// the recipient account. Keep this admission ahead of idempotent replay.
	resource := SnapshotRecord{Key: SnapshotKey{scope, "null"}, Tags: tags}
	if in.ParentSnapshotId != nil {
		conditions["ebs:ParentSnapshot"] = []string{snapshotARN(SnapshotKey{scope, value(in.ParentSnapshotId)})}
		var err error
		resource, err = s.snapshotRecord(tx, value(in.ParentSnapshotId))
		if err != nil {
			return nil, err
		}
		if resource.Key.AccountID != scope.AccountID {
			resource.Tags, err = tx.SharedTags(SharedTagsKey{Snapshot: resource.Key, AccountID: scope.AccountID})
			if err != nil {
				return nil, err
			}
		}
	}
	if err := s.authorize(ctx, "ebs", "StartSnapshot", resource, conditions); err != nil {
		return nil, err
	}
	// Native dependent authorization rejects the tested StartSnapshot and
	// CreateSnapshot values; no other ec2:CreateAction value is established.
	if len(in.Tags) > 0 {
		if err := s.authorize(ctx, "ec2", "CreateTags", SnapshotRecord{Key: SnapshotKey{scope, "*"}, Tags: tags}, conditions); err != nil {
			return nil, err
		}
	}
	if token := value(in.ClientToken); token != "" {
		prior, err := tx.SnapshotByToken(scope, token)
		if err == nil {
			if !reflect.DeepEqual(prior.InitialInput, *in) {
				return nil, failure("ConflictException", "Current request does not match request stored with this token.", "", 409)
			}
			return startOutput(prior), nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	if in.VolumeSize == nil || *in.VolumeSize <= 0 || *in.VolumeSize > 65536 {
		return nil, invalid("INVALID_VOLUME_SIZE", "Volume size must be between 1 and 65536 GiB.")
	}
	if in.Timeout != nil && (*in.Timeout < 10 || *in.Timeout > 4320) {
		return nil, invalid("INVALID_PARAMETER_VALUE", "Timeout must be between 10 and 4320 minutes.")
	}
	if in.ParentSnapshotId != nil && in.KmsKeyArn != nil {
		return nil, invalid("INVALID_PARAMETER_VALUE", "ParentSnapshotId and KmsKeyArn cannot be specified together")
	}
	if in.ParentSnapshotId != nil && in.Encrypted != nil {
		return nil, invalid("INVALID_PARAMETER_VALUE", "ParentSnapshotId and Encrypt cannot be specified together")
	}
	if in.KmsKeyArn != nil && in.Encrypted != nil && !*in.Encrypted {
		return nil, invalid("INVALID_PARAMETER_VALUE", "Encrypt cannot be false when KmsKeyArn is specified")
	}
	for _, t := range in.Tags {
		k := value(t.Key)
		if k == "" || utf8.RuneCountInString(k) > 127 || utf8.RuneCountInString(value(t.Value)) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, invalid("INVALID_TAG", "Invalid snapshot tag.")
		}
	}
	if len(tags) != len(in.Tags) {
		return nil, invalid("INVALID_TAG", "Duplicate tag key.")
	}
	if len(tags) > 50 {
		return nil, invalid("INVALID_TAG", "The maximum number of tags has been reached.")
	}
	counts, err := tx.SnapshotCounts(scope)
	if err != nil {
		return nil, err
	}
	if counts.Pending >= 100 {
		return nil, failure("ConcurrentLimitExceededException", "The maximum number of pending snapshots has been reached.", "", 400)
	}
	if counts.Total >= 100000 {
		return nil, failure("ServiceQuotaExceededException", "The maximum number of snapshots has been reached.", "DEPENDENCY_SERVICE_QUOTA_EXCEEDED", 402)
	}
	defaults, err := s.encryptionDefault(tx)
	if err != nil {
		return nil, err
	}
	var parent *SnapshotRecord
	if in.ParentSnapshotId != nil {
		p := resource
		if p.Status == api.StatusERROR {
			return nil, missing(p.Key.ID)
		}
		// Source IAM takes precedence, but sharing never makes a foreign
		// snapshot eligible as a parent, including when reads are permitted.
		if p.Key.AccountID != scope.AccountID {
			return nil, missing(p.Key.ID)
		}
		if !p.Readable {
			return nil, invalid("INVALID_SNAPSHOT_ID", "Source snapshot ("+p.Key.ID+") is not complete.")
		}
		if number(in.VolumeSize) < p.VolumeSize {
			return nil, invalid("INVALID_VOLUME_SIZE", "Volume size cannot be smaller than the source snapshot.")
		}
		if defaults.Enabled && p.KMSKeyARN == "" {
			return nil, invalid("INVALID_PARAMETER_VALUE", "An unencrypted parent snapshot cannot be used when encryption by default is enabled.")
		}
		parent = &p
	}
	id, err := tx.NextID(scope)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	timeout := 60 * time.Minute
	if in.Timeout != nil {
		timeout = time.Duration(*in.Timeout) * time.Minute
	}
	v := SnapshotRecord{Key: SnapshotKey{scope, id}, LineageID: id, VolumeSize: number(in.VolumeSize), Description: value(in.Description), InitialInput: cloneInput(*in), Created: now, Status: api.StatusPENDING, TimeoutAt: now.Add(timeout), Tags: tags, TokenKey: make([]byte, 32)}
	_, _ = rand.Read(v.TokenKey)
	if parent != nil {
		v.ParentID = parent.Key.ID
		v.LineageID = parent.LineageID
		if parent.KMSKeyARN != "" {
			if err = s.createKey(ctx, &v, parent, ""); err != nil {
				return nil, err
			}
		}
	} else if defaults.Enabled || in.Encrypted != nil && bool(*in.Encrypted) || in.KmsKeyArn != nil {
		key := value(in.KmsKeyArn)
		if key == "" {
			key = defaults.KMSKeyID
		}
		key, err = s.defaultKey(ctx, key)
		if err != nil {
			return nil, err
		}
		if err = s.createKey(ctx, &v, nil, key); err != nil {
			return nil, err
		}
	}
	if err = tx.PutSnapshot(v); err != nil {
		return nil, err
	}
	return startOutput(v), nil
}
func startOutput(v SnapshotRecord) *api.StartSnapshotResponse {
	out := &api.StartSnapshotResponse{BlockSize: new(api.BlockSize(BlockSize)), Description: clonePointer(v.InitialInput.Description), OwnerId: new(api.OwnerId(v.Key.AccountID)), ParentSnapshotId: clonePointer(v.InitialInput.ParentSnapshotId), SnapshotId: new(api.SnapshotId(v.Key.ID)), StartTime: new(v.Created), Status: new(api.StatusPENDING), Tags: cloneTags(v.InitialInput.Tags), VolumeSize: clonePointer(v.InitialInput.VolumeSize)}
	if v.KMSKeyARN != "" {
		out.KmsKeyArn = new(api.KmsKeyArn(v.KMSKeyARN))
	}
	return out
}
func (s *Service) putSnapshotBlock(tx Transaction, in *api.PutSnapshotBlockRequest) (*api.PutSnapshotBlockResponse, error) {
	v, err := s.snapshot(tx, value(in.SnapshotId), false)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx.Context(), "ebs", "PutSnapshotBlock", v, nil); err != nil {
		return nil, err
	}
	if rejected := s.admitBlock(v.Key, "PutSnapshotBlock"); rejected != nil {
		return nil, rejected
	}
	if v.Status == api.StatusERROR {
		return nil, missing(v.Key.ID)
	}
	if v.Sealed || v.Status == api.StatusCOMPLETED {
		return nil, invalid("INVALID_SNAPSHOT_ID", "Snapshot is already completed")
	}
	if len(in.BlockData) != BlockSize {
		return nil, invalid("INVALID_PARAMETER_VALUE", "Failed to read block data")
	}
	if number(in.DataLength) != BlockSize {
		return nil, invalid("INVALID_BLOCK", fmt.Sprintf("Block data length %d is not valid, expected %d", number(in.DataLength), BlockSize))
	}
	index := number(in.BlockIndex)
	if index < 0 || index >= v.VolumeSize*2048 {
		return nil, invalid("INVALID_BLOCK", fmt.Sprintf("Block index %d is beyond the volume size extent", index))
	}
	if value(in.ChecksumAlgorithm) != "SHA256" {
		return nil, invalid("INVALID_PARAMETER_VALUE", "Unsupported Checksum Algorithm '"+value(in.ChecksumAlgorithm)+"', supported algorithms are SHA256")
	}
	digest := sha256.Sum256(in.BlockData)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	if checksum != value(in.Checksum) {
		return nil, failure("InvalidSignatureException", "The value passed in as x-amz-Checksum does not match the computed checksum. Computed checksum: "+checksum+" expected checksum: "+value(in.Checksum), "", 403)
	}
	k := BlockKey{v.Key, int32(index)}
	data, err := s.sealBlock(tx.Context(), v, k, in.BlockData)
	if err != nil {
		return nil, err
	}
	if err = tx.PutBlock(BlockRecord{BlockInfo: BlockInfo{Key: k, Checksum: digest, WrittenSnapshotID: v.Key.ID, EncryptionOrigin: BlockEncryptionOrigin{Scope: v.Key.Scope, ID: v.Key.ID}}, Data: data}); err != nil {
		return nil, err
	}
	timeout := 60 * time.Minute
	if v.InitialInput.Timeout != nil {
		timeout = time.Duration(*v.InitialInput.Timeout) * time.Minute
	}
	v.TimeoutAt = s.clock.Now().Add(timeout)
	if err = tx.PutSnapshot(v); err != nil {
		return nil, err
	}
	return &api.PutSnapshotBlockResponse{Checksum: new(api.Checksum(checksum)), ChecksumAlgorithm: new(api.ChecksumAlgorithmCHECKSUM_ALGORITHM_SHA256)}, nil
}
func (s *Service) completeSnapshot(tx Transaction, in *api.CompleteSnapshotRequest) (*api.CompleteSnapshotResponse, error) {
	v, err := s.snapshot(tx, value(in.SnapshotId), false)
	if err != nil {
		return nil, err
	}
	if v.Copy != nil || v.Volume != nil {
		return nil, missing(v.Key.ID)
	}
	if err = s.authorize(tx.Context(), "ebs", "CompleteSnapshot", v, nil); err != nil {
		return nil, err
	}
	if v.Sealed || v.Status == api.StatusERROR {
		return &api.CompleteSnapshotResponse{Status: new(v.Status)}, nil
	}
	if in.Checksum != nil || in.ChecksumAlgorithm != nil || in.ChecksumAggregationMethod != nil {
		if in.Checksum == nil {
			return nil, invalid("INVALID_PARAMETER_VALUE", "Invalid parameter combination. Snapshot checksum is missing.")
		}
		if in.ChecksumAlgorithm == nil {
			return nil, invalid("INVALID_PARAMETER_VALUE", "Invalid parameter combination. Checksum algorithm is missing.")
		}
		if in.ChecksumAggregationMethod == nil {
			return nil, invalid("INVALID_PARAMETER_VALUE", "Invalid parameter combination. Checksum aggregation method is missing.")
		}
		if value(in.ChecksumAlgorithm) != "SHA256" || value(in.ChecksumAggregationMethod) != "LINEAR" {
			return nil, invalid("INVALID_PARAMETER_VALUE", "Unsupported snapshot checksum algorithm or aggregation method.")
		}
	}
	if in.ChangedBlocksCount == nil || *in.ChangedBlocksCount < 0 {
		return nil, invalid("INVALID_PARAMETER_VALUE", "ChangedBlocksCount must be nonnegative.")
	}
	blocks, err := tx.Blocks(v.Key)
	if err != nil {
		return nil, err
	}
	if int64(len(blocks)) != number(in.ChangedBlocksCount) {
		v.StateMessage = "Changed blocks count mismatch for snapshot"
	}
	if in.Checksum != nil {
		slices.SortFunc(blocks, func(a, b BlockInfo) int {
			if a.Key.Index < b.Key.Index {
				return -1
			}
			if a.Key.Index > b.Key.Index {
				return 1
			}
			return 0
		})
		hash := sha256.New()
		for _, b := range blocks {
			_, _ = hash.Write(b.Checksum[:])
		}
		if base64.StdEncoding.EncodeToString(hash.Sum(nil)) != value(in.Checksum) {
			v.StateMessage = "Checksum mismatch for snapshot"
		}
	}
	v.Sealed = true
	v.CompleteAt = s.clock.Now().Add(CompletionDelay)
	v.ReadableAt = v.CompleteAt.Add(ReadinessDelay)
	if v.StateMessage == "Changed blocks count mismatch for snapshot" {
		v.CompleteAt = s.clock.Now().Add(CountValidationDelay)
		v.ReadableAt = v.CompleteAt.Add(ReadinessDelay)
	}
	if err = tx.PutSnapshot(v); err != nil {
		return nil, err
	}
	return &api.CompleteSnapshotResponse{Status: new(api.StatusPENDING)}, nil
}
func (s *Service) encryptionDefault(r Reader) (EncryptionDefault, error) {
	v, err := r.EncryptionDefault(scopeFor(r.Context()))
	if errors.Is(err, ErrNotFound) {
		return EncryptionDefault{Scope: scopeFor(r.Context()), KMSKeyID: "alias/aws/ebs"}, nil
	}
	return v, err
}
