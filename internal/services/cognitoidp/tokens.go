package cognitoidp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awsctx"
)

func newSigningKey() (SigningKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return SigningKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return SigningKey{}, err
	}
	id, err := randomToken(32)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{ID: id, PKCS8DER: der}, nil
}

func signingPrivate(key SigningKey) (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(key.PKCS8DER)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.ID == "" {
		return nil, errors.New("invalid Cognito signing key")
	}
	return private, nil
}

func signToken(key SigningKey, claims map[string]any) (string, error) {
	private, err := signingPrivate(key)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}{"RS256", key.ID, "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func tokenUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (s *Service) newSession(tx Transaction, pool PoolRecord, client ClientRecord, user UserRecord) (*api.AuthenticationResultType, error) {
	event, err := tokenUUID()
	if err != nil {
		return nil, err
	}
	origin, err := tokenUUID()
	if err != nil {
		return nil, err
	}
	refresh, digest, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	session := SessionRecord{Key: SessionKey{PoolKey: pool.Key, ID: event}, ClientID: client.Key.ID, Username: user.Key.Username, OriginID: origin, RefreshOriginID: origin, AuthTime: now, RefreshExpires: now.Add(tokenDuration(client, "refresh")), RefreshDigest: digest}
	if err := tx.PutSession(session); err != nil {
		return nil, err
	}
	result, err := s.sessionTokens(tx, pool, client, user, session)
	if err != nil {
		return nil, err
	}
	result.RefreshToken = str[api.TokenModelType](refresh)
	return result, nil
}

func (s *Service) sessionTokens(r Reader, pool PoolRecord, client ClientRecord, user UserRecord, session SessionRecord) (*api.AuthenticationResultType, error) {
	keys, err := r.SigningKeys(pool.Key)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	accessID, err := tokenUUID()
	if err != nil {
		return nil, err
	}
	accessDuration, idDuration := tokenDuration(client, "access"), tokenDuration(client, "id")
	access := map[string]any{
		"sub": userAttribute(user, "sub"), "iss": pool.IssuerURL, "client_id": client.Key.ID,
		"event_id": session.Key.ID, "token_use": "access", "scope": "aws.cognito.signin.user.admin",
		"auth_time": session.AuthTime.Unix(), "exp": now.Add(accessDuration).Unix(), "iat": now.Unix(),
		"jti": accessID, "username": user.Key.Username,
	}
	id := map[string]any{
		"sub": userAttribute(user, "sub"), "iss": pool.IssuerURL, "aud": client.Key.ID,
		"event_id": session.Key.ID, "token_use": "id", "auth_time": session.AuthTime.Unix(),
		"exp": now.Add(idDuration).Unix(), "iat": now.Unix(), "cognito:username": user.Key.Username,
	}
	rotating := refreshRotationEnabled(client)
	revocable := client.Data.EnableTokenRevocation == nil || bool(*client.Data.EnableTokenRevocation)
	origin := session.OriginID
	if !rotating {
		origin = session.RefreshOriginID
	}
	// Rotation includes the ID-token origin at login; access tokens gain it
	// on refresh when ordinary token revocation is disabled.
	if revocable || rotating {
		idID, err := tokenUUID()
		if err != nil {
			return nil, err
		}
		id["jti"] = idID
		id["origin_jti"] = origin
	}
	if revocable || (rotating && len(session.PreviousRefreshDigest) != 0) {
		access["origin_jti"] = origin
	}
	for _, attribute := range readableAttributes(user, client) {
		name, v := value(attribute.Name), value(attribute.Value)
		if _, reserved := id[name]; reserved {
			continue
		}
		switch name {
		case "email_verified", "phone_number_verified":
			id[name] = v == "true"
		case "updated_at":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				id[name] = n
			}
		default:
			id[name] = v
		}
	}
	if err := addGroupClaims(r, user.Key, access, id); err != nil {
		return nil, err
	}
	accessJWT, err := signToken(keys.Access, access)
	if err != nil {
		return nil, err
	}
	idJWT, err := signToken(keys.ID, id)
	if err != nil {
		return nil, err
	}
	return &api.AuthenticationResultType{AccessToken: str[api.TokenModelType](accessJWT), IdToken: str[api.TokenModelType](idJWT), ExpiresIn: ptr(api.IntegerType(accessDuration / time.Second)), TokenType: str[api.StringType]("Bearer")}, nil
}

func readableAttributes(user UserRecord, client ClientRecord) api.AttributeListType {
	result := make(api.AttributeListType, 0, len(user.Data.Attributes))
	for _, attribute := range user.Data.Attributes {
		name := value(attribute.Name)
		if strings.HasPrefix(name, "dev:") {
			continue
		}
		if name == "sub" || len(client.Data.ReadAttributes) == 0 || slices.Contains(client.Data.ReadAttributes, api.ClientPermissionType(name)) {
			result = append(result, attribute)
		}
	}
	return result
}

func tokenDuration(client ClientRecord, kind string) time.Duration {
	var amount int64
	unit := "hours"
	var units *api.TimeUnitsType
	switch kind {
	case "access":
		if client.Data.AccessTokenValidity == nil {
			return time.Hour
		}
		amount = int64(*client.Data.AccessTokenValidity)
		if client.Data.TokenValidityUnits != nil {
			units = client.Data.TokenValidityUnits.AccessToken
		}
	case "id":
		if client.Data.IdTokenValidity == nil {
			return time.Hour
		}
		amount = int64(*client.Data.IdTokenValidity)
		if client.Data.TokenValidityUnits != nil {
			units = client.Data.TokenValidityUnits.IdToken
		}
	case "refresh":
		if client.Data.RefreshTokenValidity == nil || *client.Data.RefreshTokenValidity == 0 {
			return 30 * 24 * time.Hour
		}
		amount, unit = int64(*client.Data.RefreshTokenValidity), "days"
		if client.Data.TokenValidityUnits != nil {
			units = client.Data.TokenValidityUnits.RefreshToken
		}
	}
	if units != nil {
		unit = value(units)
	}
	multiplier := time.Hour
	switch unit {
	case "seconds":
		multiplier = time.Second
	case "minutes":
		multiplier = time.Minute
	case "days":
		multiplier = 24 * time.Hour
	}
	return time.Duration(amount) * multiplier
}

type accessClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	Username string `json:"username"`
	TokenUse string `json:"token_use"`
	Scope    string `json:"scope"`
	EventID  string `json:"event_id"`
	OriginID string `json:"origin_jti"`
	Expires  int64  `json:"exp"`
	Issued   int64  `json:"iat"`
	AuthTime int64  `json:"auth_time"`
}

func (s *Service) accessUser(r Reader, token string) (PoolRecord, ClientRecord, UserRecord, SessionRecord, error) {
	invalid := func(message string) (PoolRecord, ClientRecord, UserRecord, SessionRecord, error) {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, failure("NotAuthorizedException", message)
	}
	if len(token) > 131072 {
		return invalid("Invalid Access Token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return invalid("Invalid Access Token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return invalid("Invalid Access Token")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "RS256" {
		return invalid("Invalid Access Token")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return invalid("Invalid Access Token")
	}
	var claims accessClaims
	if json.Unmarshal(body, &claims) != nil || claims.TokenUse != "access" || claims.EventID == "" || claims.ClientID == "" || claims.Subject == "" || claims.Username == "" {
		return invalid("Invalid Access Token")
	}
	issuer, err := url.Parse(claims.Issuer)
	if err != nil {
		return invalid("Invalid Access Token")
	}
	_, poolID, _ := strings.Cut(strings.TrimRight(issuer.Path, "/"), "/")
	if i := strings.LastIndexByte(poolID, '/'); i >= 0 {
		poolID = poolID[i+1:]
	}
	metadata := awsctx.FromContext(r.Context())
	pool, err := r.PoolByID(metadata.Partition, metadata.Region, poolID)
	if errors.Is(err, ErrNotFound) {
		return invalid("Invalid Access Token")
	}
	if err != nil {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, err
	}
	if claims.Issuer != pool.IssuerURL {
		return invalid("Invalid Access Token")
	}
	keys, err := r.SigningKeys(pool.Key)
	if err != nil {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, err
	}
	if header.KeyID != keys.Access.ID {
		return invalid("Invalid Access Token")
	}
	key, err := signingPrivate(keys.Access)
	if err != nil {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		return invalid("Could not verify signature for Access Token")
	}
	notePool(r.Context(), pool.Key)
	now := s.clock.Now().Unix()
	if claims.Expires <= now {
		return invalid("Access Token has expired")
	}
	if claims.Issued > now || claims.AuthTime > now {
		return invalid("Invalid Access Token")
	}
	if !slices.Contains(strings.Fields(claims.Scope), "aws.cognito.signin.user.admin") {
		return invalid("Access Token does not have required scopes")
	}
	client, err := r.Client(ClientKey{PoolKey: pool.Key, ID: claims.ClientID})
	if errors.Is(err, ErrNotFound) {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, failure("ResourceNotFoundException", "User pool client "+claims.ClientID+" does not exist.")
	}
	if err != nil {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, err
	}
	user, err := r.User(UserKey{PoolKey: pool.Key, Username: claims.Username})
	if errors.Is(err, ErrNotFound) {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, failure("UserNotFoundException", "User does not exist.")
	}
	if err != nil {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, err
	}
	noteUser(r.Context(), user)
	if value(user.Data.UserStatus) == "UNCONFIRMED" {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, failure("UserNotConfirmedException", "User is not confirmed.")
	}
	if userAttribute(user, "sub") != claims.Subject {
		return invalid("Invalid Access Token")
	}
	if err := userEnabled(user); err != nil {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, err
	}
	session, err := r.Session(SessionKey{PoolKey: pool.Key, ID: claims.EventID})
	if errors.Is(err, ErrNotFound) {
		return invalid("Access Token has been revoked")
	}
	if err != nil {
		return PoolRecord{}, ClientRecord{}, UserRecord{}, SessionRecord{}, err
	}
	if session.GloballyRevoked || (session.Revoked && claims.OriginID == session.OriginID) {
		return invalid("Access Token has been revoked")
	}
	if session.ClientID != client.Key.ID || session.Username != user.Key.Username || session.AuthTime.Unix() != claims.AuthTime {
		return invalid("Invalid Access Token")
	}
	return pool, client, user, session, nil
}

// ServeDiscovery exposes only public signing material. Pool keys are independent
// of refresh-family retention, so revocation does not change offline JWT validity.
func (s *Service) ServeDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	const suffix = "/.well-known/jwks.json"
	if !strings.HasSuffix(r.URL.Path, suffix) {
		http.NotFound(w, r)
		return
	}
	poolID := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, suffix), "/")
	if poolID == "" || strings.Contains(poolID, "/") {
		http.NotFound(w, r)
		return
	}
	type publicKey struct {
		Algorithm string `json:"alg"`
		Exponent  string `json:"e"`
		ID        string `json:"kid"`
		Type      string `json:"kty"`
		Modulus   string `json:"n"`
		Use       string `json:"use"`
	}
	document := struct {
		Keys []publicKey `json:"keys"`
	}{Keys: make([]publicKey, 0, 2)}
	keys, _, err := s.PublicSigningKeys(r.Context(), poolID)
	for id, public := range keys.Keys {
		document.Keys = append(document.Keys, publicKey{Algorithm: "RS256", Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()), ID: id, Type: "RSA", Modulus: base64.RawURLEncoding.EncodeToString(public.N.Bytes()), Use: "sig"})
	}
	slices.SortFunc(document.Keys, func(a, b publicKey) int { return strings.Compare(a.ID, b.ID) })
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Unable to load signing keys", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = json.NewEncoder(w).Encode(document)
}
