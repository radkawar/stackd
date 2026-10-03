package signature

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
	"time"
)

type localFixture struct {
	ProfileVersionARN string   `json:"profileVersionArn"`
	SignedZIP         string   `json:"signedZipBase64"`
	UnsignedZIP       string   `json:"unsignedZipBase64"`
	JobID             string   `json:"jobId"`
	TrustedRoot       string   `json:"trustedRootCertificateBase64"`
	CertificateHashes []string `json:"certificateHashes"`
	Vectors           []struct {
		Label     string `json:"label"`
		SignedZIP string `json:"signedZipBase64"`
	} `json:"vectors"`
}

func localSignatureFixture(t *testing.T, name string) localFixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/lambda/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var fixture localFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func fixtureBytes(t *testing.T, value string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLocallyResignedCodeSignatures(t *testing.T) {
	fixture := localSignatureFixture(t, "code_signing_local.json")
	roots := [][]byte{fixtureBytes(t, fixture.TrustedRoot)}
	// Deployment is years after the short-lived leaf certificate expires. Only
	// the signed expiry is a current admission policy check; the chain is checked
	// at the authenticated signing time, as required by real Signer artifacts.
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	claims, err := Verify(t.Context(), fixtureBytes(t, fixture.SignedZIP), now, roots)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SigningProfileVersionARN != fixture.ProfileVersionARN || claims.SigningJobARN != "arn:aws:signer:us-east-1:000000000000:/signing-jobs/"+fixture.JobID {
		t.Fatalf("unexpected authenticated publisher: %+v", claims)
	}
	if !claims.SigningTime.Equal(time.Date(2026, 9, 28, 9, 19, 26, 806000000, time.UTC)) || !claims.Expires.Equal(time.Date(2037, 12, 28, 9, 19, 26, 806000000, time.UTC)) {
		t.Fatalf("incorrect authenticated validity: %+v", claims)
	}
	// Independently generated SHA-384 TBSCertificate hashes use the same
	// GetRevocationStatus composition (the root is its own parent).
	if !slices.Equal(claims.CertificateHashes, fixture.CertificateHashes) {
		t.Fatalf("incorrect current-revocation identifiers: %v", claims.CertificateHashes)
	}
	if _, err := Verify(t.Context(), fixtureBytes(t, fixture.SignedZIP), now, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("local fixture must not establish its own trust: %v", err)
	}
	if _, err := Verify(t.Context(), fixtureBytes(t, fixture.UnsignedZIP), now, roots); !errors.Is(err, ErrMissing) {
		t.Fatalf("unsigned ZIP: %v", err)
	}
	expired, err := Verify(t.Context(), fixtureBytes(t, fixture.SignedZIP), claims.Expires.Add(time.Second), roots)
	if err != nil || !expired.Expires.Equal(claims.Expires) {
		t.Fatalf("expiry must remain an authenticated policy input: %+v, %v", expired, err)
	}
	if _, err := Verify(t.Context(), fixtureBytes(t, fixture.SignedZIP), claims.SigningTime.Add(-time.Second), roots); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("future signing time accepted: %v", err)
	}
	corpus := localSignatureFixture(t, "signature_canonical_local.json")
	for _, vector := range corpus.Vectors {
		t.Run(vector.Label, func(t *testing.T) {
			claims, err := Verify(t.Context(), fixtureBytes(t, vector.SignedZIP), now, [][]byte{fixtureBytes(t, corpus.TrustedRoot)})
			if err != nil {
				t.Fatal(err)
			}
			if claims.SigningProfileVersionARN != corpus.ProfileVersionARN {
				t.Fatalf("incorrect locally re-signed publisher: %+v", claims)
			}
		})
	}
}

func TestLocallyResignedZIPTransformations(t *testing.T) {
	fixture := localSignatureFixture(t, "code_signing_local.json")
	original := fixtureBytes(t, fixture.SignedZIP)
	roots := [][]byte{fixtureBytes(t, fixture.TrustedRoot)}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, label := range []string{"recompressed", "retimed", "renamed", "payload", "reordered", "added", "removed-directory", "duplicate-signature", "cms-signature", "signed-profile", "trailing-cms", "deep-ber"} {
		t.Run(label, func(t *testing.T) {
			modified := transformSignedZIP(t, original, label)
			_, err := Verify(t.Context(), modified, now, roots)
			if label == "recompressed" || label == "retimed" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("modified signed ZIP must fail integrity: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Verify(ctx, original, now, roots); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verification: %v", err)
	}
}

func transformSignedZIP(t *testing.T, original []byte, label string) []byte {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(original), int64(len(original)))
	if err != nil {
		t.Fatal(err)
	}
	entries := slices.Clone(archive.File)
	if label == "reordered" {
		slices.Reverse(entries)
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range entries {
		if label == "removed-directory" && file.Name == "META_INF/" {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		name := file.Name
		if name == "handler.py" {
			if label == "renamed" {
				name = "other.py"
			}
			if label == "payload" {
				body = append(body, []byte("# changed\n")...)
			}
		}
		if name == codeSignatureFile {
			block, _ := pem.Decode(body)
			switch label {
			case "cms-signature":
				cms, err := parseCodeSignature(body)
				if err != nil {
					t.Fatal(err)
				}
				sig := cms.data.Signers[0].Signature
				bad := bytes.Clone(sig)
				bad[len(bad)-1] ^= 1
				block.Bytes = bytes.Replace(block.Bytes, sig, bad, 1)
			case "signed-profile":
				block.Bytes = bytes.Replace(block.Bytes, []byte("UqFTRcZGNs"), []byte("UqFTRcZGNx"), 1)
			case "trailing-cms":
				block.Bytes = append(block.Bytes, 0)
			case "deep-ber":
				block.Bytes = append(bytes.Repeat([]byte{0x30, 0x80}, 70), block.Bytes...)
				block.Bytes = append(block.Bytes, make([]byte, 140)...)
			}
			body = pem.EncodeToMemory(block)
		}
		date := file.Modified
		if label == "retimed" {
			date = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		writeEntry := func() {
			entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Modified: date})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write(body); err != nil {
				t.Fatal(err)
			}
		}
		writeEntry()
		if label == "duplicate-signature" && name == codeSignatureFile {
			writeEntry()
		}
	}
	if label == "added" {
		entry, err := writer.Create("other.py")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("untrusted")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
