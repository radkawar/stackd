package signature

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

const codeSignatureFile = "META_INF/aws_signer_signature_v1.0.SF"
const maxSignatureBytes = 1 << 20
const maxSignatureCodeBytes = 250 << 20

var (
	ErrMissing   = errors.New("lambda deployment has no AWS Signer signature")
	ErrIntegrity = errors.New("lambda deployment signature integrity check failed")
)

// Claims contains only cryptographically authenticated AWS Signer claims.
// Expiry, allowed-publisher matching and current revocation are admission policy,
// not integrity checks. CertificateHashes use GetRevocationStatus's composite
// SHA384(TBSCertificate)||SHA384(parent TBSCertificate) hexadecimal encoding.
// A successful integrity check does NOT assert that these claims are unrevoked.
type Claims struct {
	SigningProfileVersionARN string
	SigningJobARN            string
	Expires                  time.Time
	SigningTime              time.Time
	CertificateHashes        []string
}

// Verify authenticates the ZIP and CMS chain against the pinned native AWS root
// and DER roots supplied by the authoritative local Signer owner. Roots MUST NOT
// come from the deployment request or the untrusted signature envelope.
func Verify(ctx context.Context, code []byte, now time.Time, trustedRoots [][]byte) (Claims, error) {
	if err := ctx.Err(); err != nil {
		return Claims{}, err
	}
	archive, err := zip.NewReader(bytes.NewReader(code), int64(len(code)))
	if err != nil {
		return Claims{}, signatureIntegrity(err)
	}
	var signatureFile *zip.File
	for _, file := range archive.File {
		if file.Name == codeSignatureFile {
			if signatureFile != nil {
				return Claims{}, signatureIntegrity(errors.New("duplicate signature entry"))
			}
			signatureFile = file
		}
	}
	if signatureFile == nil {
		return Claims{}, ErrMissing
	}
	if signatureFile.UncompressedSize64 > maxSignatureBytes {
		return Claims{}, signatureIntegrity(errors.New("signature envelope exceeds limit"))
	}
	reader, err := signatureFile.Open()
	if err != nil {
		return Claims{}, signatureIntegrity(err)
	}
	envelope, err := io.ReadAll(io.LimitReader(reader, maxSignatureBytes+1))
	closeErr := reader.Close()
	if err != nil {
		return Claims{}, signatureIntegrity(err)
	}
	if closeErr != nil || len(envelope) > maxSignatureBytes {
		return Claims{}, signatureIntegrity(errors.New("invalid signature envelope size"))
	}
	cms, err := parseCodeSignature(envelope)
	if err != nil {
		return Claims{}, signatureIntegrity(err)
	}
	digest, err := codeSignatureDigest(ctx, archive, false)
	if err != nil {
		if ctx.Err() != nil {
			return Claims{}, ctx.Err()
		}
		return Claims{}, signatureIntegrity(err)
	}
	claims, err := cms.verify(digest, now, trustedRoots)
	if err != nil {
		return Claims{}, signatureIntegrity(err)
	}
	return claims, nil
}

func signatureIntegrity(err error) error {
	return fmt.Errorf("%w: %v", ErrIntegrity, err)
}

// Locally re-signed vectors in signature_canonical_local.json cover the observed
// native representation (they are not independent AWS signature evidence):
// SHA384(SHA384(name1 || body1 || name2 || body2 || ...)). The inner binary hash
// is CMS's detached content. Include directory names (notably META_INF/), omit
// only the signature file, and preserve archive entry order. Compression, times,
// permissions and ZIP headers are not signed. Names and bodies have no length
// framing; this native format cannot distinguish every name/body boundary shift.
func codeSignatureDigest(ctx context.Context, archive *zip.Reader, appendMetadataDirectory bool) ([sha512.Size384]byte, error) {
	var zero [sha512.Size384]byte
	if len(archive.File) > 100000 {
		return zero, errors.New("too many ZIP entries")
	}
	hash := sha512.New384()
	seen := make(map[string]struct{}, len(archive.File))
	var expanded uint64
	buffer := make([]byte, 32<<10)
	for _, file := range archive.File {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if !utf8.ValidString(file.Name) {
			return zero, errors.New("signature entry name is not UTF-8")
		}
		if _, exists := seen[file.Name]; exists {
			return zero, errors.New("duplicate ZIP entry")
		}
		seen[file.Name] = struct{}{}
		if file.UncompressedSize64 > maxSignatureCodeBytes || expanded > maxSignatureCodeBytes-file.UncompressedSize64 {
			return zero, errors.New("expanded ZIP exceeds Lambda package limit")
		}
		expanded += file.UncompressedSize64
		if file.Name == codeSignatureFile {
			continue
		}
		_, _ = io.WriteString(hash, file.Name)
		reader, err := file.Open()
		if err != nil {
			return zero, err
		}
		limited := &io.LimitedReader{R: signatureContextReader{ctx: ctx, reader: reader}, N: int64(file.UncompressedSize64) + 1}
		_, err = io.CopyBuffer(hash, limited, buffer)
		closeErr := reader.Close()
		if err != nil {
			return zero, err
		}
		if closeErr != nil {
			return zero, closeErr
		}
		if limited.N != 1 {
			return zero, errors.New("inconsistent expanded ZIP entry size")
		}
	}
	if appendMetadataDirectory {
		_, _ = io.WriteString(hash, "META_INF/")
	}
	var inner [sha512.Size384]byte
	return sha512.Sum384(hash.Sum(inner[:0])), nil
}

type signatureContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r signatureContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
