package stackd_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"stackd/clock"
	"stackd/storage"
)

func TestSNSPublicQueryAuthenticationBoundary(t *testing.T) {
	var authority struct {
		Cases []struct {
			Label, AuthenticateOnUnsubscribe string
			Result                           struct{ Code string }
		}
		DenyPropagation struct {
			Policy json.RawMessage
			Before struct {
				Output struct{ Attributes map[string]string }
			}
		}
	}
	awsReadFixture(t, "sns/http_confirmation_authority.json", &authority)
	type confirmation struct {
		Type, Token, SubscribeURL string
	}
	var mu sync.Mutex
	confirmations := map[string]confirmation{}
	notifications := map[string]int{}
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message confirmation
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			http.Error(w, "invalid notification", http.StatusBadRequest)
			return
		}
		if message.Type == "SubscriptionConfirmation" {
			mu.Lock()
			confirmations[r.URL.Path] = message
			mu.Unlock()
		}
		if message.Type == "Notification" {
			mu.Lock()
			notifications[r.URL.Path]++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)
	cloud, clients, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))
	// A single public instance origin must route its delivered links to the
	// actual resource region without inventing an authenticated resource owner.
	topics := admissionSNSClient(clients, "111122223333", "eu-west-2")
	topic, err := topics.CreateTopic(t.Context(), &sns.CreateTopicInput{Name: aws.String("public-query-boundary")})
	if err != nil {
		t.Fatal(err)
	}
	request := func(t *testing.T, method, address, form string, headers http.Header) int {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, address, strings.NewReader(form))
		if err != nil {
			t.Fatal(err)
		}
		r.Header = headers
		response, err := clients.server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode
	}
	for _, protected := range []bool{false, true} {
		name := "open"
		if protected {
			name = "protected"
		}
		t.Run(name, func(t *testing.T) {
			endpoint := receiver.URL + "/" + name
			sub, err := topics.Subscribe(t.Context(), &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("http"), Endpoint: &endpoint, ReturnSubscriptionArn: true})
			if err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, cloud)
			mu.Lock()
			message := confirmations["/"+name]
			mu.Unlock()
			if message.Token == "" || message.SubscribeURL == "" {
				t.Fatal("subscriber did not receive a usable confirmation")
			}
			if !strings.HasPrefix(message.SubscribeURL, clients.server.URL+"/") {
				t.Fatal("confirmation link escaped the configured instance origin")
			}
			pending := func(want bool) {
				t.Helper()
				out, err := topics.GetSubscriptionAttributes(t.Context(), &sns.GetSubscriptionAttributesInput{SubscriptionArn: sub.SubscriptionArn})
				if err != nil || (out.Attributes["PendingConfirmation"] == "true") != want {
					t.Fatalf("pending=%v: %+v: %v", want, out, err)
				}
			}
			pending(true)
			link, err := url.Parse(message.SubscribeURL)
			if err != nil {
				t.Fatal(err)
			}
			params := link.Query()
			params.Del("Version")
			link.RawQuery = params.Encode()
			if !protected {
				for _, surface := range []string{"header", "query", "body"} {
					address, method, form := link.String(), http.MethodGet, ""
					headers := http.Header{}
					switch surface {
					case "header":
						headers.Set("Authorization", "")
					case "query":
						address += "&X-Amz-Credential=partial"
					case "body":
						method, form = http.MethodPost, "Signature=legacy"
						headers.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					if status := request(t, method, address, form, headers); status < 400 || status >= 500 {
						t.Fatalf("%s signing material bypassed authentication: HTTP %d", surface, status)
					}
					pending(true)
				}
			}
			if protected {
				if status := request(t, http.MethodGet, link.String()+"&AuthenticateOnUnsubscribe=true", "", nil); status != http.StatusForbidden {
					t.Fatalf("anonymous protected confirmation: HTTP %d", status)
				}
				pending(true)
				for _, native := range authority.Cases {
					policy := ""
					if native.Label == "explicit-deny" {
						policy = strings.ReplaceAll(string(authority.DenyPropagation.Policy), authority.DenyPropagation.Before.Output.Attributes["TopicArn"], aws.ToString(topic.TopicArn))
					}
					caller := snsControlUser(t, clients, snsAdmissionFixture{Account: "111122223333", Region: "eu-west-2"}, "confirm-"+native.Label, policy)
					_, err := caller.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: &message.Token, AuthenticateOnUnsubscribe: &native.AuthenticateOnUnsubscribe})
					assertAPIError(t, err, native.Result.Code)
					pending(true)
				}
				_, err = topics.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: &message.Token, AuthenticateOnUnsubscribe: aws.String("true")})
				if err != nil {
					t.Fatal(err)
				}
				// Native protected confirmation cannot be replayed, even by its owner.
				_, err = topics.ConfirmSubscription(t.Context(), &sns.ConfirmSubscriptionInput{TopicArn: topic.TopicArn, Token: &message.Token, AuthenticateOnUnsubscribe: aws.String("true")})
				assertAPIError(t, err, "AuthorizationError")
			} else if status := request(t, http.MethodGet, link.String(), "", nil); status != http.StatusOK {
				t.Fatalf("anonymous delivered confirmation link: HTTP %d", status)
			}
			pending(false)
			publishAndCheck := func(want int) {
				t.Helper()
				if _, err := topics.Publish(t.Context(), &sns.PublishInput{TopicArn: topic.TopicArn, Message: aws.String("authentication boundary")}); err != nil {
					t.Fatal(err)
				}
				trailNativeDrain(t, cloud)
				mu.Lock()
				got := notifications["/"+name]
				mu.Unlock()
				if got != want {
					t.Fatalf("subscriber received %d notifications, want %d", got, want)
				}
			}
			publishAndCheck(1)
			cancel := clients.server.URL + "/?Action=Unsubscribe&SubscriptionArn=" + url.QueryEscape(aws.ToString(sub.SubscriptionArn))
			status := request(t, http.MethodGet, cancel, "", nil)
			if protected {
				if status != http.StatusForbidden {
					t.Fatalf("anonymous protected unsubscribe: HTTP %d", status)
				}
				pending(false)
				publishAndCheck(2)
				if _, err := topics.Unsubscribe(t.Context(), &sns.UnsubscribeInput{SubscriptionArn: sub.SubscriptionArn}); err != nil {
					t.Fatal(err)
				}
			} else if status != http.StatusOK {
				t.Fatalf("anonymous unprotected unsubscribe: HTTP %d", status)
			}
			want := 1
			if protected {
				want = 2
			}
			publishAndCheck(want)
		})
	}
}
