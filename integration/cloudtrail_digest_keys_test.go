package stackd_test

import (
	"bytes"
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"stackd"
	"stackd/clock"
)

func TestCloudTrailDigestNativePublicKeyContract(t *testing.T) {
	var native struct {
		Requests []cloudtrail.ListPublicKeysInput `json:"requests_returning_this_response"`
		Response cloudtrail.ListPublicKeysOutput  `json:"response"`
	}
	awsReadFixture(t, "cloudtrail/digest_public_keys.json", &native)
	reference := native.Response.PublicKeyList[0]
	public, err := x509.ParsePKCS1PublicKey(reference.Value)
	if err != nil {
		t.Fatal(err)
	}
	validity := reference.ValidityEndTime.Sub(*reference.ValidityStartTime)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			var original []byte
			for _, request := range native.Requests {
				out, err := trailNativeClient(c).ListPublicKeys(t.Context(), &request)
				if err != nil {
					t.Fatal(err)
				}
				if len(out.PublicKeyList) != len(native.Response.PublicKeyList) {
					t.Fatalf("current key discovery: %+v", out)
				}
				key := out.PublicKeyList[0]
				parsed, err := x509.ParsePKCS1PublicKey(key.Value)
				if err != nil || parsed.N.BitLen() != public.N.BitLen() {
					t.Fatalf("native usable DER key contract: %v", err)
				}
				fingerprint := md5.Sum(key.Value)
				if aws.ToString(key.Fingerprint) != hex.EncodeToString(fingerprint[:]) || key.ValidityEndTime.Sub(*key.ValidityStartTime) != validity {
					t.Fatalf("native key fingerprint/validity contract: %+v", key)
				}
				if original != nil && !bytes.Equal(original, key.Value) {
					t.Fatal("reserved token changed the discoverable signer")
				}
				original = key.Value
				c = reopen()
			}
		})
	}
}
