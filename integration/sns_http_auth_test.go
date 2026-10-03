package stackd_test

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"stackd/internal/integrations"
	snsservice "stackd/internal/services/sns"
)

// RFC 2617 challenges are served by an actual TLS consumer. Native Function URL
// captures establish challenge initiation, not a completed digest handshake.
func TestSNSHTTPHTTPSAuthentication(t *testing.T) {
	for _, scheme := range []string{"Basic", "Digest"} {
		t.Run(scheme, func(t *testing.T) {
			var calls atomic.Int32
			var accepted atomic.Bool
			consumer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if string(body) != "actual signed payload" {
					w.WriteHeader(400)
					return
				}
				authorization := r.Header.Get("Authorization")
				if authorization == "" {
					challenge := `Basic realm="sns-consumer"`
					if scheme == "Digest" {
						challenge = `Digest realm="sns-consumer", nonce="bounded-native-style-nonce", qop="auth", algorithm=MD5`
					}
					w.Header().Set("WWW-Authenticate", challenge)
					w.WriteHeader(401)
					return
				}
				valid := false
				if scheme == "Basic" {
					user, password, ok := r.BasicAuth()
					valid = ok && user == "subscriber" && password == "owned-secret"
				} else {
					fields := map[string]string{}
					for _, field := range regexp.MustCompile(`([a-z]+)=(?:"([^"]*)"|([^, ]+))`).FindAllStringSubmatch(authorization, -1) {
						v := field[2]
						if v == "" {
							v = field[3]
						}
						fields[field[1]] = v
					}
					hash := func(input string) string { sum := md5.Sum([]byte(input)); return hex.EncodeToString(sum[:]) }
					ha1 := hash("subscriber:sns-consumer:owned-secret")
					ha2 := hash("POST:" + r.URL.RequestURI())
					expected := hash(ha1 + ":bounded-native-style-nonce:" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + ha2)
					valid = fields["username"] == "subscriber" && fields["uri"] == r.URL.RequestURI() && fields["response"] == expected && fields["qop"] == "auth" && fields["nc"] == "00000001" && fields["cnonce"] != ""
				}
				if !valid {
					w.WriteHeader(403)
					return
				}
				accepted.Store(true)
				w.WriteHeader(204)
			}))
			defer consumer.Close()
			endpoint := strings.Replace(consumer.URL, "https://", "https://subscriber:owned-secret@", 1) + "/notify?value=encoded%20path"
			adapter := integrations.SNSHTTP{Client: consumer.Client()}
			result := adapter.Send(t.Context(), endpoint, snsservice.DeliveryMessage{Body: "actual signed payload", Type: "Notification", MessageID: "message", TopicARN: "topic", SubscriptionARN: "subscription", CaptureFeedback: true})
			if result.Error != nil || result.StatusCode != 204 || result.ProviderResponse != "No Content" || !accepted.Load() || calls.Load() != 2 {
				t.Fatalf("%s actual authenticated delivery: result=%v calls=%d accepted=%v", scheme, result, calls.Load(), accepted.Load())
			}
		})
	}
}

func TestSNSHTTPRejectsUntrustedTLSAndRedirects(t *testing.T) {
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(204) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	payload := snsservice.DeliveryMessage{Body: "private publication", Type: "Notification", CaptureFeedback: true}
	result := (integrations.SNSHTTP{}).Send(t.Context(), source.URL, payload)
	if result.Error == nil || result.Error.Code != "HTTPDeliveryFailed" || result.StatusCode != 307 || result.ProviderResponse != "Temporary Redirect" || forwarded.Load() != 0 {
		t.Fatalf("redirect forwarded private notification: %v %d", result, forwarded.Load())
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(200) }))
	defer tls.Close()
	result = (integrations.SNSHTTP{}).Send(t.Context(), tls.URL, payload)
	if result.Error == nil || forwarded.Load() != 0 {
		t.Fatal("untrusted TLS accepted", fmt.Sprint(result))
	}
}
