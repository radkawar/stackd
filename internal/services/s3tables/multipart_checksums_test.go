package s3tables

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"hash/crc64"
	"testing"
	"time"

	"stackd/internal/awswire"
)

func independentMultipartChecksum(algorithm string, data []byte) []byte {
	switch algorithm {
	case "CRC32":
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], crc32.ChecksumIEEE(data))
		return out[:]
	case "CRC32C":
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
		return out[:]
	case "CRC64NVME":
		var out [8]byte
		binary.BigEndian.PutUint64(out[:], crc64.Checksum(data, crc64.MakeTable(0x9a6c9329ac4bc9b5)))
		return out[:]
	case "SHA1":
		sum := sha1.Sum(data)
		return sum[:]
	case "SHA256":
		sum := sha256.Sum256(data)
		return sum[:]
	default:
		panic("test checksum algorithm")
	}
}
func checksumErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}
func TestMultipartSupportedChecksumAlgorithmsAndBadDigests(t *testing.T) {
	for _, algorithm := range []string{"CRC32", "CRC32C", "SHA1", "SHA256"} {
		t.Run(algorithm, func(t *testing.T) {
			data := []byte("the exact decoded native part bytes")
			partHash := independentMultipartChecksum(algorithm, data)
			var checksums ObjectChecksums
			checksumSet(&checksums, algorithm, base64.StdEncoding.EncodeToString(partHash))
			attrs := ObjectAttributes{ChecksumAlgorithm: algorithm, Checksums: checksums}
			info, err := SingleObjectInfo("object", data, attrs, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			part := StoredMultipartPart{MultipartPart: MultipartPart{Number: 1, ETag: info.ETag, Size: int64(len(data)), Checksums: checksums}, Data: data}
			selected := []CompletedPart{{Number: 1, ETag: info.ETag, Checksums: checksums}}
			var expected ObjectChecksums
			composite := base64.StdEncoding.EncodeToString(independentMultipartChecksum(algorithm, partHash)) + "-1"
			checksumSet(&expected, algorithm, composite)
			upload := MultipartUpload{Key: "object", Attributes: ObjectAttributes{ChecksumAlgorithm: algorithm}}
			completed, err := MultipartObjectInfo(upload, map[int]StoredMultipartPart{1: part}, selected, time.Time{}, expected)
			if err != nil || completed.Size != int64(len(data)) || completed.Attributes.Checksums != expected {
				t.Fatalf("composite = %#v size=%d err=%v", completed.Attributes.Checksums, completed.Size, err)
			}
			bad := ObjectChecksums{}
			checksumSet(&bad, algorithm, base64.StdEncoding.EncodeToString(independentMultipartChecksum(algorithm, []byte("wrong"))))
			_, err = SingleObjectInfo("object", data, ObjectAttributes{ChecksumAlgorithm: algorithm, Checksums: bad}, time.Time{})
			checksumErrorCode(t, err, "BadDigest")
			_, err = MultipartObjectInfo(upload, map[int]StoredMultipartPart{1: part}, selected, time.Time{}, bad)
			checksumErrorCode(t, err, "BadDigest")
			selected[0].Checksums = bad
			_, err = MultipartObjectInfo(upload, map[int]StoredMultipartPart{1: part}, selected, time.Time{}, ObjectChecksums{})
			checksumErrorCode(t, err, "InvalidPart")
			selected[0].Checksums = checksums
			part.Data = []byte("corrupt stored bytes of same length")
			_, err = MultipartObjectInfo(upload, map[int]StoredMultipartPart{1: part}, selected, time.Time{}, ObjectChecksums{})
			checksumErrorCode(t, err, "InvalidPart")
		})
	}
}
func TestMultipartOrdinaryPartGapsAndChecksumInitiationSemantics(t *testing.T) {
	data := []byte("tiny final part")
	sum := md5.Sum(data)
	partETag := "\"" + hex.EncodeToString(sum[:]) + "\""
	part := StoredMultipartPart{MultipartPart: MultipartPart{Number: 10000, ETag: partETag, Size: int64(len(data))}, Data: data}
	selected := []CompletedPart{{Number: 10000, ETag: partETag}}
	info, err := MultipartObjectInfo(MultipartUpload{Key: "object"}, map[int]StoredMultipartPart{10000: part}, selected, time.Time{}, ObjectChecksums{})
	multipartSum := md5.Sum(sum[:])
	expectedETag := "\"" + hex.EncodeToString(multipartSum[:]) + "-1\""
	if err != nil || info.Size != int64(len(data)) || info.ETag != expectedETag || info.Attributes.ChecksumAlgorithm != "" || info.Attributes.Checksums != (ObjectChecksums{}) {
		t.Fatalf("ordinary gap completion: %#v %v", info, err)
	}
	checksum := sha256.Sum256(data)
	part.Checksums.SHA256 = base64.StdEncoding.EncodeToString(checksum[:])
	selected[0].Checksums = part.Checksums
	_, err = MultipartObjectInfo(MultipartUpload{Key: "object", Attributes: ObjectAttributes{ChecksumAlgorithm: "SHA256"}}, map[int]StoredMultipartPart{10000: part}, selected, time.Time{}, ObjectChecksums{})
	checksumErrorCode(t, err, "InvalidPartOrder")
	// The AWS documented completion-only checksum is accepted but neither
	// validated nor stored when no algorithm was chosen at initiation.
	info, err = MultipartObjectInfo(MultipartUpload{Key: "object"}, map[int]StoredMultipartPart{10000: part}, selected, time.Time{}, ObjectChecksums{SHA256: "ignored-without-initiation"})
	if err != nil || info.Attributes.Checksums != (ObjectChecksums{}) {
		t.Fatalf("completion-only checksum advertised as validated: %#v %v", info, err)
	}
	checksumErrorCode(t, ValidateMultipartCompletionParts(nil), "InvalidRequest")
	checksumErrorCode(t, ValidateMultipartCompletionParts([]CompletedPart{{Number: 10001}}), "InvalidPart")
	checksumErrorCode(t, ValidateMultipartCompletionParts([]CompletedPart{{Number: 1}, {Number: 1}}), "InvalidPartOrder")
	checksumErrorCode(t, ValidateMultipartCompletionParts(make([]CompletedPart, 10001)), "InvalidRequest")
}

func TestMultipartCRC64UsesSelectedPlaintextFullObject(t *testing.T) {
	first := bytes.Repeat([]byte("a"), int(MultipartMinimumPartSize))
	last := []byte("the final native part")
	all := append(bytes.Clone(first), last...)
	expected := ObjectChecksums{CRC64NVME: base64.StdEncoding.EncodeToString(independentMultipartChecksum("CRC64NVME", all))}
	stored := make(map[int]StoredMultipartPart, 2)
	selected := make([]CompletedPart, 2)
	for i, data := range [][]byte{first, last} {
		checksums := ObjectChecksums{CRC64NVME: base64.StdEncoding.EncodeToString(independentMultipartChecksum("CRC64NVME", data))}
		info, err := SingleObjectInfo("object", data, ObjectAttributes{ChecksumAlgorithm: "CRC64NVME", Checksums: checksums}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		stored[i+1] = StoredMultipartPart{MultipartPart: MultipartPart{Number: i + 1, ETag: info.ETag, Size: info.Size, Checksums: checksums}, Data: data}
		selected[i] = CompletedPart{Number: i + 1, ETag: info.ETag}
	}
	// CRC64 in completion part XML is optional, unlike the older composites.
	selected[0].Checksums = stored[1].Checksums
	for _, algorithm := range []string{"", "CRC64NVME"} {
		t.Run("init="+algorithm, func(t *testing.T) {
			upload := MultipartUpload{Key: "object", Attributes: ObjectAttributes{ChecksumAlgorithm: algorithm}}
			for _, supplied := range []ObjectChecksums{{}, expected} {
				info, err := MultipartObjectInfo(upload, stored, selected, time.Time{}, supplied)
				if err != nil || info.Size != int64(len(all)) || info.Attributes.ChecksumAlgorithm != "CRC64NVME" || info.Attributes.Checksums != expected {
					t.Fatalf("full object = %#v, %v", info, err)
				}
			}
			_, err := MultipartObjectInfo(upload, stored, selected, time.Time{}, ObjectChecksums{CRC64NVME: expected.CRC64NVME + "-2"})
			checksumErrorCode(t, err, "BadDigest")
			badSelection := append([]CompletedPart(nil), selected...)
			badSelection[1].Checksums.CRC64NVME = stored[1].Checksums.CRC64NVME
			_, err = MultipartObjectInfo(upload, stored, badSelection, time.Time{}, ObjectChecksums{})
			checksumErrorCode(t, err, "InvalidPart")
		})
	}
	part := stored[2]
	part.Checksums.CRC64NVME = stored[1].Checksums.CRC64NVME
	stored[2] = part
	_, err := MultipartObjectInfo(MultipartUpload{Key: "object"}, stored, selected, time.Time{}, expected)
	checksumErrorCode(t, err, "BadDigest")
	_, err = SingleObjectInfo("object", last, ObjectAttributes{Checksums: part.Checksums}, time.Time{})
	checksumErrorCode(t, err, "BadDigest")
}

func TestMultipartCRC64CompletionOnlyInferenceAndConditions(t *testing.T) {
	data := []byte("completion-only full object")
	sum := md5.Sum(data)
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""
	part := StoredMultipartPart{MultipartPart: MultipartPart{Number: 8, ETag: etag, Size: int64(len(data))}, Data: data}
	expected := ObjectChecksums{CRC64NVME: base64.StdEncoding.EncodeToString(independentMultipartChecksum("CRC64NVME", data))}
	for _, tc := range []struct{ requested, supplied ObjectChecksums }{
		{supplied: expected},
		{requested: expected},
		{requested: expected, supplied: expected},
	} {
		info, err := MultipartObjectInfo(MultipartUpload{Key: "object"}, map[int]StoredMultipartPart{8: part}, []CompletedPart{{Number: 8, ETag: etag, Checksums: tc.requested}}, time.Time{}, tc.supplied)
		if err != nil || info.Attributes.Checksums != expected || info.Attributes.ChecksumAlgorithm != "CRC64NVME" {
			t.Fatalf("completion inference = %#v, %v", info, err)
		}
		checksumErrorCode(t, CheckMultipartCompletionConditions(info, ObjectConditions{ChecksumType: "COMPOSITE"}), "InvalidRequest")
	}
}
