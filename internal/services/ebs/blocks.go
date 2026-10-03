package ebs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	api "stackd/internal/awsapi/ebs"
)

type snapshotToken struct {
	Operation     string
	First, Second string
	Index         int32
	Expires       int64
}

// Tokens are compact enough for the generated 256-character wire constraint.
// The per-snapshot signing key binds account/region/resource; the MAC additionally
// binds operation and snapshot pair without repeating those strings in the token.
func tokenMAC(v SnapshotRecord, t snapshotToken, payload []byte) []byte {
	mac := hmac.New(sha256.New, v.TokenKey)
	_, _ = mac.Write(payload)
	_, _ = mac.Write([]byte(t.Operation + "\x00" + t.First + "\x00" + t.Second))
	return mac.Sum(nil)
}
func signToken(v SnapshotRecord, t snapshotToken) string {
	var body [13 + sha256.Size]byte
	body[0] = 1
	binary.BigEndian.PutUint32(body[1:5], uint32(t.Index))
	binary.BigEndian.PutUint64(body[5:13], uint64(t.Expires))
	copy(body[13:], tokenMAC(v, t, body[:13]))
	return base64.StdEncoding.EncodeToString(body[:])
}
func (s *Service) parseToken(v SnapshotRecord, raw, op, first, second string) (snapshotToken, error) {
	bad := func() (snapshotToken, error) {
		kind, reason := "pagination", "INVALID_PAGE_TOKEN"
		if op == "block" {
			kind, reason = "block", "INVALID_BLOCK_TOKEN"
		}
		return snapshotToken{}, invalid(reason, "The "+kind+" token "+raw+" is invalid.")
	}
	body, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(body) != 13+sha256.Size || body[0] != 1 {
		return bad()
	}
	token := snapshotToken{Operation: op, First: first, Second: second, Index: int32(binary.BigEndian.Uint32(body[1:5])), Expires: int64(binary.BigEndian.Uint64(body[5:13]))}
	if !hmac.Equal(tokenMAC(v, token, body[:13]), body[13:]) || token.Index < 0 || !s.clock.Now().Before(time.Unix(0, token.Expires)) {
		return bad()
	}
	return token, nil
}
func blockToken(v SnapshotRecord, index int32, expiry time.Time) *api.BlockToken {
	return new(api.BlockToken(signToken(v, snapshotToken{Operation: "block", Second: v.Key.ID, Index: index, Expires: expiry.UnixNano()})))
}
func (s *Service) listCursor(v SnapshotRecord, operation, first string, start *api.BlockIndex, next *api.PageToken) (int32, error) {
	if next != nil {
		token, err := s.parseToken(v, value(next), operation, first, v.Key.ID)
		return token.Index, err
	}
	if start != nil {
		return int32(*start), nil
	}
	return 0, nil
}
func pageLimit(max *api.MaxResults) (int, error) {
	if max == nil {
		return 10000, nil
	}
	if *max < 100 || *max > 10000 {
		return 0, invalid("INVALID_PARAMETER_VALUE", "MaxResults must be between 100 and 10000.")
	}
	return int(*max), nil
}
func nextPage(v SnapshotRecord, operation, first string, index int32, expiry time.Time) *api.PageToken {
	return new(api.PageToken(signToken(v, snapshotToken{Operation: operation, First: first, Second: v.Key.ID, Index: index, Expires: expiry.UnixNano()})))
}

// resolvedBlocks walks metadata only, keeping an explicit zero block just like
// any other written block. A child layer overrides the same parent index.
// StartSnapshot chooses an immutable, pre-existing parent, so lineage is acyclic.
func resolvedBlocks(r Reader, v SnapshotRecord) (map[int32]BlockInfo, error) {
	out := map[int32]BlockInfo{}
	for {
		blocks, err := r.Blocks(v.Key)
		if err != nil {
			return nil, err
		}
		for _, b := range blocks {
			if _, ok := out[b.Key.Index]; !ok {
				out[b.Key.Index] = b
			}
		}
		if v.ParentID == "" {
			return out, nil
		}
		v, err = r.Snapshot(SnapshotKey{v.Key.Scope, v.ParentID})
		if err != nil {
			return nil, err
		}
	}
}
func blockIndices(blocks map[int32]BlockInfo, start int32) []int32 {
	out := make([]int32, 0, len(blocks))
	for index := range blocks {
		if index >= start {
			out = append(out, index)
		}
	}
	slices.Sort(out)
	return out
}
func (s *Service) listSnapshotBlocks(tx Transaction, in *api.ListSnapshotBlocksRequest) (*api.ListSnapshotBlocksResponse, error) {
	v, err := s.snapshot(tx, value(in.SnapshotId), true)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx.Context(), "ebs", "ListSnapshotBlocks", v, nil); err != nil {
		return nil, err
	}
	if err = s.authorizeListKey(tx.Context(), v); err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults)
	if err != nil {
		return nil, err
	}
	start, err := s.listCursor(v, "ListSnapshotBlocks", "", in.StartingBlockIndex, in.NextToken)
	if err != nil {
		return nil, err
	}
	blocks, err := resolvedBlocks(tx, v)
	if err != nil {
		return nil, err
	}
	indices := blockIndices(blocks, start)
	expiry := s.clock.Now()
	if len(indices) != 0 {
		expiry = expiry.Add(BlockTokenLifetime)
	}
	out := &api.ListSnapshotBlocksResponse{BlockSize: new(api.BlockSize(BlockSize)), Blocks: api.Blocks{}, ExpiryTime: new(expiry), VolumeSize: new(api.VolumeSize(v.VolumeSize))}
	if len(indices) > limit {
		out.NextToken = nextPage(v, "ListSnapshotBlocks", "", indices[limit], expiry)
		indices = indices[:limit]
	}
	for _, index := range indices {
		out.Blocks = append(out.Blocks, api.Block{BlockIndex: new(api.BlockIndex(index)), BlockToken: blockToken(v, index, expiry)})
	}
	return out, nil
}
func (s *Service) listChangedBlocks(tx Transaction, in *api.ListChangedBlocksRequest) (*api.ListChangedBlocksResponse, error) {
	if value(in.FirstSnapshotId) == "" {
		return nil, invalid("INVALID_SNAPSHOT_ID", "First snapshot should not be empty or null")
	}
	first, err := s.snapshot(tx, value(in.FirstSnapshotId), true)
	if err != nil {
		return nil, err
	}
	second, err := s.snapshot(tx, value(in.SecondSnapshotId), true)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx.Context(), "ebs", "ListChangedBlocks", first, nil); err != nil {
		return nil, err
	}
	if err = s.authorize(tx.Context(), "ebs", "ListChangedBlocks", second, nil); err != nil {
		return nil, err
	}
	if first.LineageID != second.LineageID {
		return nil, invalid("UNRELATED_SNAPSHOTS", "The snapshots are not related.")
	}
	if err = s.authorizeListKey(tx.Context(), first); err != nil {
		return nil, err
	}
	if err = s.authorizeListKey(tx.Context(), second); err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults)
	if err != nil {
		return nil, err
	}
	start, err := s.listCursor(second, "ListChangedBlocks", first.Key.ID, in.StartingBlockIndex, in.NextToken)
	if err != nil {
		return nil, err
	}
	a, err := resolvedBlocks(tx, first)
	if err != nil {
		return nil, err
	}
	b, err := resolvedBlocks(tx, second)
	if err != nil {
		return nil, err
	}
	candidates := make(map[int32]BlockInfo, len(a)+len(b))
	for index, info := range a {
		candidates[index] = info
	}
	for index, info := range b {
		candidates[index] = info
	}
	indices := blockIndices(candidates, start)
	expiry := s.clock.Now().Add(BlockTokenLifetime)
	out := &api.ListChangedBlocksResponse{BlockSize: new(api.BlockSize(BlockSize)), ChangedBlocks: api.ChangedBlocks{}, ExpiryTime: new(expiry), VolumeSize: new(api.VolumeSize(second.VolumeSize))}
	// Page the candidate allocation set before comparison. Self-comparisons and
	// sparse differences can legitimately return an empty page with a next token.
	if len(indices) > limit {
		out.NextToken = nextPage(second, "ListChangedBlocks", first.Key.ID, indices[limit], expiry)
		indices = indices[:limit]
	}
	for _, index := range indices {
		left, lok := a[index]
		right, rok := b[index]
		if lok && rok && left.WrittenSnapshotID == right.WrittenSnapshotID {
			continue
		}
		row := api.ChangedBlock{BlockIndex: new(api.BlockIndex(index))}
		if lok {
			row.FirstBlockToken = blockToken(first, index, expiry)
		}
		if rok {
			row.SecondBlockToken = blockToken(second, index, expiry)
		}
		out.ChangedBlocks = append(out.ChangedBlocks, row)
	}
	if len(out.ChangedBlocks) == 0 && out.NextToken == nil {
		out.BlockSize = nil
		out.VolumeSize = nil
		out.ExpiryTime = nil
	}
	return out, nil
}
func (s *Service) getSnapshotBlock(tx Transaction, in *api.GetSnapshotBlockRequest) (*api.GetSnapshotBlockResponse, error) {
	v, err := s.snapshot(tx, value(in.SnapshotId), true)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx.Context(), "ebs", "GetSnapshotBlock", v, nil); err != nil {
		return nil, err
	}
	if rejected := s.admitBlock(v.Key, "GetSnapshotBlock"); rejected != nil {
		return nil, rejected
	}
	if err = s.describeKey(tx.Context(), v); err != nil {
		return nil, err
	}
	token, err := s.parseToken(v, value(in.BlockToken), "block", "", v.Key.ID)
	if err != nil {
		return nil, err
	}
	if in.BlockIndex == nil || token.Index != int32(*in.BlockIndex) {
		return nil, invalid("INVALID_BLOCK_TOKEN", "The block token "+value(in.BlockToken)+" is invalid.")
	}
	layer := v
	var block BlockRecord
	for {
		block, err = tx.Block(BlockKey{layer.Key, int32(*in.BlockIndex)})
		if err == nil {
			break
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if layer.ParentID == "" {
			return nil, invalid("INVALID_BLOCK_TOKEN", "The block token "+value(in.BlockToken)+" is invalid.")
		}
		layer, err = tx.Snapshot(SnapshotKey{layer.Key.Scope, layer.ParentID})
		if err != nil {
			return nil, err
		}
	}
	// ReEncrypt preserves the lineage's plaintext data key. Use the requested
	// snapshot's KMS context, while authenticating the retained layer's block AAD.
	data, err := s.openBlock(tx.Context(), v, block)
	if err != nil {
		return nil, err
	}
	return &api.GetSnapshotBlockResponse{BlockData: data, Checksum: new(api.Checksum(base64.StdEncoding.EncodeToString(block.Checksum[:]))), ChecksumAlgorithm: new(api.ChecksumAlgorithmCHECKSUM_ALGORITHM_SHA256), DataLength: new(api.DataLength(len(data)))}, nil
}
