// Package awschecksum computes base64 AWS wire checksums over decoded bytes.
package awschecksum

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/crc64"

	"github.com/cespare/xxhash/v2"
	"github.com/zeebo/xxh3"
)

var nvmeTable = crc64.MakeTable(0x9a6c9329ac4bc9b5)
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// Sum uses network-byte-order CRC and zero-seed XXHash digests; XXHASH128 is
// canonical XXH3_128 with the high half first. CRC64NVME uses the reflected NVMe
// polynomial with the initial and final complements supplied by hash/crc64.
func Sum(algorithm string, data []byte) (string, error) {
	var digest []byte
	switch algorithm {
	case "CRC32":
		digest = binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(data))
	case "CRC32C":
		digest = binary.BigEndian.AppendUint32(nil, crc32.Checksum(data, castagnoliTable))
	case "CRC64NVME":
		digest = binary.BigEndian.AppendUint64(nil, crc64.Checksum(data, nvmeTable))
	case "MD5":
		sum := md5.Sum(data)
		digest = sum[:]
	case "SHA1":
		sum := sha1.Sum(data)
		digest = sum[:]
	case "SHA256":
		sum := sha256.Sum256(data)
		digest = sum[:]
	case "SHA512":
		sum := sha512.Sum512(data)
		digest = sum[:]
	case "XXHASH64":
		digest = binary.BigEndian.AppendUint64(nil, xxhash.Sum64(data))
	case "XXHASH3":
		digest = binary.BigEndian.AppendUint64(nil, xxh3.Hash(data))
	case "XXHASH128":
		sum := xxh3.Hash128(data).Bytes()
		digest = sum[:]
	default:
		return "", fmt.Errorf("unsupported checksum algorithm %q", algorithm)
	}
	return base64.StdEncoding.EncodeToString(digest), nil
}

// CombineCRC returns the checksum of left || right from their wire digests and
// the decoded byte length of right. Multipart completion can combine retained
// CRCs without decrypting, loading or concatenating the underlying object parts.
func CombineCRC(algorithm, left, right string, rightSize int64) (string, error) {
	var polynomial uint64
	var width int
	switch algorithm {
	case "CRC32":
		polynomial, width = crc32.IEEE, 32
	case "CRC32C":
		polynomial, width = crc32.Castagnoli, 32
	case "CRC64NVME":
		polynomial, width = 0x9a6c9329ac4bc9b5, 64
	default:
		return "", fmt.Errorf("unsupported full-object checksum algorithm %q", algorithm)
	}
	a, err := base64.StdEncoding.DecodeString(left)
	if err != nil || len(a) != width/8 {
		return "", fmt.Errorf("invalid %s left checksum", algorithm)
	}
	b, err := base64.StdEncoding.DecodeString(right)
	if err != nil || len(b) != width/8 || rightSize < 0 {
		return "", fmt.Errorf("invalid %s right checksum or size", algorithm)
	}
	if rightSize == 0 {
		return left, nil
	}
	var leftCRC, rightCRC uint64
	if width == 32 {
		leftCRC, rightCRC = uint64(binary.BigEndian.Uint32(a)), uint64(binary.BigEndian.Uint32(b))
	} else {
		leftCRC, rightCRC = binary.BigEndian.Uint64(a), binary.BigEndian.Uint64(b)
	}
	// odd initially advances one zero bit. Successive squares advance powers
	// of two bytes; CRC linearity then appends the right-hand checksum.
	var odd, even [64]uint64
	odd[0] = polynomial
	for bit := 1; bit < width; bit++ {
		odd[bit] = uint64(1) << (bit - 1)
	}
	squareCRC(&even, &odd, width)
	squareCRC(&odd, &even, width)
	for {
		squareCRC(&even, &odd, width)
		if rightSize&1 != 0 {
			leftCRC = applyCRC(&even, leftCRC)
		}
		rightSize >>= 1
		if rightSize == 0 {
			break
		}
		squareCRC(&odd, &even, width)
		if rightSize&1 != 0 {
			leftCRC = applyCRC(&odd, leftCRC)
		}
		rightSize >>= 1
		if rightSize == 0 {
			break
		}
	}
	var digest [8]byte
	binary.BigEndian.PutUint64(digest[:], leftCRC^rightCRC)
	return base64.StdEncoding.EncodeToString(digest[8-width/8:]), nil
}

func applyCRC(operator *[64]uint64, value uint64) uint64 {
	var result uint64
	for bit := 0; value != 0; bit++ {
		if value&1 != 0 {
			result ^= operator[bit]
		}
		value >>= 1
	}
	return result
}

func squareCRC(result, operator *[64]uint64, width int) {
	for bit := 0; bit < width; bit++ {
		result[bit] = applyCRC(operator, operator[bit])
	}
}
