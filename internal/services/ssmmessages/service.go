package ssmmessages

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const (
	createAction  = "ssmmessages:CreateControlChannel"
	openAction    = "ssmmessages:OpenControlChannel"
	tokenLifetime = time.Minute
)

// Config separates public signature verification from live backend authority.
type Config struct {
	Backend      Backend
	Authenticate func(*http.Request, string, string) (*http.Request, *awswire.Error)
	Clock        clock.Clock
}

type nodeKey struct{ partition, account, region, node string }
type tokenOwner struct {
	nodeKey
	accessKey, principalARN, principalID string
}
type channelToken struct {
	owner   tokenOwner
	expires time.Time
}
type nodeSlot struct {
	mu      sync.Mutex // fences backend effects and deliveries against reconnect
	current *connection
	refs    int // protected by Service.mu
}

// Service owns only ephemeral channels and one-use native handshake tokens.
type Service struct {
	backend      Backend
	authenticate func(*http.Request, string, string) (*http.Request, *awswire.Error)
	clock        clock.Clock
	mu           sync.Mutex
	closed       bool
	tokens       map[[32]byte]channelToken
	slots        map[nodeKey]*nodeSlot
	connections  map[*connection]struct{}
	workers      sync.WaitGroup
}

func New(config Config) *Service {
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	return &Service{backend: config.Backend, authenticate: config.Authenticate, clock: config.Clock,
		tokens: make(map[[32]byte]channelToken), slots: make(map[nodeKey]*nodeSlot), connections: make(map[*connection]struct{})}
}

// Handles matches only the native control/data-channel namespace. Data channels
// are matched so unsupported Session Manager traffic gets an explicit error.
func Handles(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/v1/control-channel/") || strings.HasPrefix(r.URL.Path, "/v1/data-channel/")
}

var nodePattern = regexp.MustCompile(`^(i-[a-f0-9]{8}|i-[a-f0-9]{17}|mi-[a-f0-9]{17})$`)
var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !Handles(r) {
		http.NotFound(w, r)
		return
	}
	r = r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{RequestID: uuid.NewString()}))
	if s.authenticate == nil || s.backend == nil {
		writeError(w, r, unavailable())
		return
	}
	region, accessKey, err := signedScope(r)
	if err != nil {
		writeError(w, r, &awswire.Error{Code: "IncompleteSignature", Message: err.Error(), StatusCode: 400})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	authenticated, rejected := s.authenticate(r, "ssmmessages", region)
	if rejected != nil {
		writeError(w, r, rejected)
		return
	}
	r = authenticated
	metadata := awsctx.FromContext(r.Context())
	if metadata.Region != region || metadata.AccessKeyID != accessKey || metadata.PrincipalARN == "" || metadata.PrincipalID == "" || metadata.AccountID == "" || metadata.Partition == "" {
		writeError(w, r, &awswire.Error{Code: "AccessDeniedException", Message: "Authenticated channel identity is required", StatusCode: 403})
		return
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		writeError(w, r, unavailable())
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/data-channel/") {
		// TODO: Comeback implement native Session Manager data channels and sessions.
		writeError(w, r, &awswire.Error{Code: "UnsupportedOperationException", Message: "Session Manager data channels are not supported", StatusCode: 400})
		return
	}
	node := strings.TrimPrefix(r.URL.Path, "/v1/control-channel/")
	if !nodePattern.MatchString(node) || r.URL.RawPath != "" {
		writeError(w, r, &awswire.Error{Code: "ValidationException", Message: "Invalid control channel ID", StatusCode: 400})
		return
	}
	owner := tokenOwner{nodeKey: nodeKey{metadata.Partition, metadata.AccountID, region, node}, accessKey: accessKey, principalARN: metadata.PrincipalARN, principalID: metadata.PrincipalID}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, r, &awswire.Error{Code: "ValidationException", Message: "Invalid query", StatusCode: 400})
		return
	}
	switch r.Method {
	case http.MethodPost:
		if len(query) != 0 {
			writeError(w, r, &awswire.Error{Code: "ValidationException", Message: "Unexpected control channel query", StatusCode: 400})
			return
		}
		s.create(w, r, owner)
	case http.MethodGet:
		if len(query) != 2 || len(query["role"]) != 1 || query.Get("role") != "subscribe" || len(query["stream"]) != 1 || query.Get("stream") != "input" {
			writeError(w, r, &awswire.Error{Code: "ValidationException", Message: "Control channel requires role=subscribe and stream=input", StatusCode: 400})
			return
		}
		if err := s.backend.AuthorizeAgent(r.Context(), node, openAction); err != nil {
			writeError(w, r, err)
			return
		}
		s.open(w, r, owner)
	default:
		writeError(w, r, &awswire.Error{Code: "UnsupportedOperationException", Message: "Unsupported channel operation", StatusCode: 405})
	}
}

// signedScope extracts routing only. The gateway verifies the entire signature;
// caller-provided account/region/principal headers are never identity sources.
func signedScope(r *http.Request) (region, accessKey string, err error) {
	invalid := errors.New("a valid ssmmessages SigV4 credential scope is required")
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "AWS4-HMAC-SHA256 ") {
		return "", "", invalid
	}
	parameters := make(map[string]string, 3)
	for _, item := range strings.Split(strings.TrimPrefix(values[0], "AWS4-HMAC-SHA256 "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || v == "" || parameters[k] != "" {
			return "", "", invalid
		}
		parameters[k] = v
	}
	if len(parameters) != 3 || parameters["SignedHeaders"] == "" || parameters["Signature"] == "" {
		return "", "", invalid
	}
	parts := strings.Split(parameters["Credential"], "/")
	if len(parts) != 5 || parts[0] == "" || parts[3] != "ssmmessages" || parts[4] != "aws4_request" || !regionPattern.MatchString(parts[2]) {
		return "", "", invalid
	}
	if _, err := time.Parse("20060102", parts[1]); err != nil {
		return "", "", invalid
	}
	return parts[2], parts[0], nil
}

type channelInput struct {
	MessageSchemaVersion string `json:"MessageSchemaVersion"`
	RequestID            string `json:"RequestId"`
	TokenValue           string `json:"TokenValue"`
	AgentVersion         string `json:"AgentVersion"`
	PlatformType         string `json:"PlatformType"`
}

func (s *Service) create(w http.ResponseWriter, r *http.Request, owner tokenOwner) {
	if err := s.backend.AuthorizeAgent(r.Context(), owner.node, createAction); err != nil {
		writeError(w, r, err)
		return
	}
	var input channelInput
	if err := awswire.DecodeJSON(r, &input); err != nil {
		writeError(w, r, &awswire.Error{Code: "ValidationException", Message: err.Error(), StatusCode: 400})
		return
	}
	if input.MessageSchemaVersion != "1.0" || len(input.RequestID) < 16 {
		writeError(w, r, &awswire.Error{Code: "ValidationException", Message: "Invalid control channel schema or request ID", StatusCode: 400})
		return
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		writeError(w, r, err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	now := s.clock.Now()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		writeError(w, r, unavailable())
		return
	}
	for digest, entry := range s.tokens {
		if !now.Before(entry.expires) {
			delete(s.tokens, digest)
		}
	}
	s.tokens[sha256.Sum256([]byte(token))] = channelToken{owner: owner, expires: now.Add(tokenLifetime)}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(http.StatusCreated)
	_ = xml.NewEncoder(w).Encode(struct {
		XMLName              xml.Name `xml:"CreateControlChannelResponse"`
		MessageSchemaVersion string   `xml:"MessageSchemaVersion"`
		TokenValue           string   `xml:"TokenValue"`
	}{MessageSchemaVersion: "1.0", TokenValue: token})
}

func (s *Service) consumeToken(token string, owner tokenOwner) bool {
	digest := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.tokens[digest]
	if !ok || s.closed || entry.owner != owner || !s.clock.Now().Before(entry.expires) {
		return false
	}
	delete(s.tokens, digest)
	return true
}

// Close fences new connections, cancels backend work and joins every worker,
// including sockets still waiting for their post-dial token handshake.
func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	clear(s.tokens)
	for c := range s.connections {
		c.stop()
	}
	s.mu.Unlock()
	s.workers.Wait()
	return nil
}

func unavailable() *awswire.Error {
	return &awswire.Error{Code: "ServiceUnavailableException", Message: "Control channel service unavailable", StatusCode: 503}
}
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var wire *awswire.Error
	if !errors.As(err, &wire) {
		wire = &awswire.Error{Code: "InternalServerError", Message: err.Error(), StatusCode: 500}
	}
	awswire.JSONError(w, r, wire)
}

var _ http.Handler = (*Service)(nil)
