package cognitoidp

import (
	"cmp"
	"context"
	"maps"
	"slices"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/storage/memory"
)

type regionalID struct{ partition, region, id string }
type attributeIndex struct {
	pool        PoolKey
	name, value string
}

type memoryState struct {
	pools      map[PoolKey]PoolRecord
	ownership  map[OwnershipKey]OwnershipRecord
	providers  map[ProviderKey]ProviderRecord
	poolIDs    map[regionalID]PoolKey
	keys       map[PoolKey]PoolSigningKeys
	clients    map[ClientKey]ClientRecord
	clientIDs  map[regionalID]ClientKey
	users      map[UserKey]UserRecord
	attributes map[attributeIndex]map[UserKey]struct{}
	groups     map[GroupKey]GroupRecord
	groupUsers map[GroupKey]map[string]struct{}
	userGroups map[UserKey]map[string]struct{}
	challenges map[ChallengeKey]ChallengeRecord
	sessions   map[SessionKey]SessionRecord
	emailCodes map[EmailCodeKey]EmailCodeRecord
	refreshes  map[ClientKey]map[string]SessionKey
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		ownership: map[OwnershipKey]OwnershipRecord{}, providers: map[ProviderKey]ProviderRecord{},
		pools: map[PoolKey]PoolRecord{}, poolIDs: map[regionalID]PoolKey{}, keys: map[PoolKey]PoolSigningKeys{},
		clients: map[ClientKey]ClientRecord{}, clientIDs: map[regionalID]ClientKey{}, users: map[UserKey]UserRecord{},
		attributes: map[attributeIndex]map[UserKey]struct{}{}, challenges: map[ChallengeKey]ChallengeRecord{},
		sessions: map[SessionKey]SessionRecord{}, refreshes: map[ClientKey]map[string]SessionKey{},
		groups: map[GroupKey]GroupRecord{}, groupUsers: map[GroupKey]map[string]struct{}{},
		userGroups: map[UserKey]map[string]struct{}{},
		emailCodes: map[EmailCodeKey]EmailCodeRecord{},
	}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.pools, s.poolIDs, s.keys = maps.Clone(s.pools), maps.Clone(s.poolIDs), maps.Clone(s.keys)
		s.ownership, s.providers = maps.Clone(s.ownership), maps.Clone(s.providers)
		s.clients, s.clientIDs, s.users = maps.Clone(s.clients), maps.Clone(s.clientIDs), maps.Clone(s.users)
		s.attributes, s.challenges = maps.Clone(s.attributes), maps.Clone(s.challenges)
		s.sessions, s.refreshes = maps.Clone(s.sessions), maps.Clone(s.refreshes)
		s.groups, s.groupUsers, s.userGroups = maps.Clone(s.groups), maps.Clone(s.groupUsers), maps.Clone(s.userGroups)
		s.emailCodes = maps.Clone(s.emailCodes)
		return s
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

// Stored records and index buckets remain immutable between writes.
func copyPoolRecord(v PoolRecord) PoolRecord { v.Data = api.CloneUserPoolType(v.Data); return v }
func copyClientRecord(v ClientRecord) ClientRecord {
	v.Data = api.CloneUserPoolClientType(v.Data)
	return v
}
func copyUserRecord(v UserRecord) UserRecord {
	v.Data = api.CloneUserType(v.Data)
	v.Password.Salt = slices.Clone(v.Password.Salt)
	v.Password.Verifier = slices.Clone(v.Password.Verifier)
	if v.PasswordExpires != nil {
		v.PasswordExpires = new(*v.PasswordExpires)
	}
	return v
}
func copySigningKeys(v PoolSigningKeys) PoolSigningKeys {
	v.Access.PKCS8DER = slices.Clone(v.Access.PKCS8DER)
	v.ID.PKCS8DER = slices.Clone(v.ID.PKCS8DER)
	return v
}
func copyChallenge(v ChallengeRecord) ChallengeRecord {
	v.SRPPrivate = slices.Clone(v.SRPPrivate)
	return v
}
func copySession(v SessionRecord) SessionRecord {
	v.RefreshDigest = slices.Clone(v.RefreshDigest)
	v.PreviousRefreshDigest = slices.Clone(v.PreviousRefreshDigest)
	return v
}

func memoryRow[K comparable, V any](tx *memory.Transaction, rows map[K]V, key K, detach func(V) V) (V, error) {
	var zero V
	if err := tx.Check(false); err != nil {
		return zero, err
	}
	row, ok := rows[key]
	if !ok {
		return zero, ErrNotFound
	}
	return detach(row), nil
}
func (r memoryReader) Pool(k PoolKey) (PoolRecord, error) {
	return memoryRow(r.tx, r.s.pools, k, copyPoolRecord)
}
func (r memoryReader) SigningKeys(k PoolKey) (PoolSigningKeys, error) {
	return memoryRow(r.tx, r.s.keys, k, copySigningKeys)
}
func (r memoryReader) Client(k ClientKey) (ClientRecord, error) {
	return memoryRow(r.tx, r.s.clients, k, copyClientRecord)
}
func (r memoryReader) User(k UserKey) (UserRecord, error) {
	return memoryRow(r.tx, r.s.users, k, copyUserRecord)
}
func (r memoryReader) Challenge(k ChallengeKey) (ChallengeRecord, error) {
	return memoryRow(r.tx, r.s.challenges, k, copyChallenge)
}
func (r memoryReader) Session(k SessionKey) (SessionRecord, error) {
	return memoryRow(r.tx, r.s.sessions, k, copySession)
}

func (r memoryReader) PoolByID(partition, region, id string) (PoolRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PoolRecord{}, err
	}
	key, ok := r.s.poolIDs[regionalID{partition, region, id}]
	if !ok {
		return PoolRecord{}, ErrNotFound
	}
	return copyPoolRecord(r.s.pools[key]), nil
}
func (r memoryReader) ClientByID(partition, region, id string) (ClientRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ClientRecord{}, err
	}
	key, ok := r.s.clientIDs[regionalID{partition, region, id}]
	if !ok {
		return ClientRecord{}, ErrNotFound
	}
	return copyClientRecord(r.s.clients[key]), nil
}
func (r memoryReader) SessionByRefresh(pool PoolKey, client string, digest []byte) (SessionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SessionRecord{}, err
	}
	key, ok := r.s.refreshes[ClientKey{PoolKey: pool, ID: client}][string(digest)]
	if !ok {
		return SessionRecord{}, ErrNotFound
	}
	session, ok := r.s.sessions[key]
	if !ok || session.ClientID != client {
		return SessionRecord{}, ErrNotFound
	}
	return copySession(session), nil
}
func (r memoryReader) Pools(scope Scope) ([]PoolRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]PoolRecord, 0)
	for key, row := range r.s.pools {
		if key.Scope == scope {
			rows = append(rows, copyPoolRecord(row))
		}
	}
	slices.SortFunc(rows, func(a, b PoolRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (r memoryReader) PoolsForAccount(partition, accountID string) ([]PoolRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []PoolRecord{}
	for key, pool := range r.s.pools {
		if key.Partition == partition && key.AccountID == accountID {
			out = append(out, copyPoolRecord(pool))
		}
	}
	slices.SortFunc(out, func(a, b PoolRecord) int { return cmp.Compare(a.Key.ARN(), b.Key.ARN()) })
	return out, nil
}
func (r memoryReader) Clients(pool PoolKey) ([]ClientRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]ClientRecord, 0)
	for key, row := range r.s.clients {
		if key.PoolKey == pool {
			rows = append(rows, copyClientRecord(row))
		}
	}
	slices.SortFunc(rows, func(a, b ClientRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (r memoryReader) Users(pool PoolKey) ([]UserRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]UserRecord, 0)
	for key, row := range r.s.users {
		if key.PoolKey == pool {
			rows = append(rows, copyUserRecord(row))
		}
	}
	slices.SortFunc(rows, func(a, b UserRecord) int { return cmp.Compare(a.Key.Username, b.Key.Username) })
	return rows, nil
}
func (r memoryReader) UsersByAttribute(pool PoolKey, name, value string) ([]UserRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	keys := r.s.attributes[attributeIndex{pool, name, value}]
	rows := make([]UserRecord, 0, len(keys))
	for key := range keys {
		rows = append(rows, copyUserRecord(r.s.users[key]))
	}
	slices.SortFunc(rows, func(a, b UserRecord) int { return cmp.Compare(a.Key.Username, b.Key.Username) })
	return rows, nil
}

func (w memoryWriter) PutPool(v PoolRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.pools[v.Key] = copyPoolRecord(v)
	w.s.poolIDs[regionalID{v.Key.Partition, v.Key.Region, v.Key.ID}] = v.Key
	return nil
}
func (w memoryWriter) PutSigningKeys(k PoolKey, v PoolSigningKeys) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.keys[k] = copySigningKeys(v)
	return nil
}
func (w memoryWriter) PutClient(v ClientRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.clients[v.Key] = copyClientRecord(v)
	w.s.clientIDs[regionalID{v.Key.Partition, v.Key.Region, v.Key.ID}] = v.Key
	return nil
}
func (w memoryWriter) PutUser(v UserRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	old := w.s.users[v.Key]
	if !slices.EqualFunc(old.Data.Attributes, v.Data.Attributes, func(a, b api.AttributeType) bool {
		return value(a.Name) == value(b.Name) && value(a.Value) == value(b.Value)
	}) {
		w.removeAttributes(old)
		for _, attribute := range v.Data.Attributes {
			index := attributeIndex{v.Key.PoolKey, value(attribute.Name), value(attribute.Value)}
			keys := maps.Clone(w.s.attributes[index])
			if keys == nil {
				keys = make(map[UserKey]struct{})
			}
			keys[v.Key] = struct{}{}
			w.s.attributes[index] = keys
		}
	}
	w.s.users[v.Key] = copyUserRecord(v)
	return nil
}
func (w memoryWriter) removeAttributes(v UserRecord) {
	for _, attribute := range v.Data.Attributes {
		index := attributeIndex{v.Key.PoolKey, value(attribute.Name), value(attribute.Value)}
		keys := maps.Clone(w.s.attributes[index])
		delete(keys, v.Key)
		if len(keys) == 0 {
			delete(w.s.attributes, index)
		} else {
			w.s.attributes[index] = keys
		}
	}
}
func (w memoryWriter) PutChallenge(v ChallengeRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.challenges[v.Key] = copyChallenge(v)
	return nil
}
func (w memoryWriter) PutSession(v SessionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	client := ClientKey{PoolKey: v.Key.PoolKey, ID: v.ClientID}
	if _, ok := w.s.refreshes[client][string(v.RefreshDigest)]; v.RefreshDigest != nil && !ok {
		refreshes := maps.Clone(w.s.refreshes[client])
		if refreshes == nil {
			refreshes = make(map[string]SessionKey)
		}
		refreshes[string(v.RefreshDigest)] = v.Key
		w.s.refreshes[client] = refreshes
	}
	w.s.sessions[v.Key] = copySession(v)
	return nil
}
func (w memoryWriter) DeleteChallenge(k ChallengeKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.challenges, k)
	return nil
}
func (w memoryWriter) RevokeUserSessions(k UserKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key, v := range w.s.sessions {
		if key.PoolKey == k.PoolKey && v.Username == k.Username {
			v.Revoked = true
			v.GloballyRevoked = true
			w.s.sessions[key] = v
		}
	}
	return nil
}
func (w memoryWriter) DeleteUser(k UserKey) error {
	if err := w.RevokeUserSessions(k); err != nil {
		return err
	}
	w.removeAttributes(w.s.users[k])
	w.removeUserGroups(k)
	delete(w.s.users, k)
	w.releaseOwners(k.PoolKey, func(v OwnershipRecord) bool {
		return v.Key.Kind == OwnerKindUser && v.PhysicalID == k.Username || v.Key.Kind == OwnerKindMembership && v.MemberUser == k.Username
	})
	for key, v := range w.s.challenges {
		if key.PoolKey == k.PoolKey && v.Username == k.Username {
			delete(w.s.challenges, key)
		}
	}
	for key := range w.s.emailCodes {
		if key.UserKey == k {
			delete(w.s.emailCodes, key)
		}
	}
	return nil
}
func (w memoryWriter) DeleteClient(k ClientKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.clients, k)
	delete(w.s.clientIDs, regionalID{k.Partition, k.Region, k.ID})
	delete(w.s.refreshes, k)
	w.releaseOwners(k.PoolKey, func(v OwnershipRecord) bool {
		return (v.Key.Kind == OwnerKindClient || v.Key.Kind == OwnerKindClientToken) && v.PhysicalID == k.ID
	})
	for key, v := range w.s.challenges {
		if key.PoolKey == k.PoolKey && v.ClientID == k.ID {
			delete(w.s.challenges, key)
		}
	}
	for key, v := range w.s.sessions {
		if key.PoolKey == k.PoolKey && v.ClientID == k.ID {
			delete(w.s.sessions, key)
		}
	}
	return nil
}
func (w memoryWriter) DeletePool(k PoolKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.pools, k)
	delete(w.s.poolIDs, regionalID{k.Partition, k.Region, k.ID})
	delete(w.s.keys, k)
	w.releaseOwners(k, func(OwnershipRecord) bool { return true })
	for key := range w.s.providers {
		if key.PoolKey == k {
			delete(w.s.providers, key)
		}
	}
	for key := range w.s.clients {
		if key.PoolKey == k {
			delete(w.s.clients, key)
			delete(w.s.clientIDs, regionalID{key.Partition, key.Region, key.ID})
		}
	}
	for key := range w.s.refreshes {
		if key.PoolKey == k {
			delete(w.s.refreshes, key)
		}
	}
	for key := range w.s.users {
		if key.PoolKey == k {
			delete(w.s.users, key)
		}
	}
	for index := range w.s.attributes {
		if index.pool == k {
			delete(w.s.attributes, index)
		}
	}
	for key := range w.s.groups {
		if key.PoolKey == k {
			delete(w.s.groups, key)
			delete(w.s.groupUsers, key)
		}
	}
	for key := range w.s.userGroups {
		if key.PoolKey == k {
			delete(w.s.userGroups, key)
		}
	}
	for key := range w.s.challenges {
		if key.PoolKey == k {
			delete(w.s.challenges, key)
		}
	}
	for key := range w.s.sessions {
		if key.PoolKey == k {
			delete(w.s.sessions, key)
		}
	}
	for key := range w.s.emailCodes {
		if key.PoolKey == k {
			delete(w.s.emailCodes, key)
		}
	}
	return nil
}

func (r memoryReader) EmailCode(k EmailCodeKey) (EmailCodeRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return EmailCodeRecord{}, e
	}
	v, ok := r.s.emailCodes[k]
	if !ok {
		return v, ErrNotFound
	}
	v.Digest = slices.Clone(v.Digest)
	return v, nil
}
func (w memoryWriter) PutEmailCode(v EmailCodeRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	v.Digest = slices.Clone(v.Digest)
	w.s.emailCodes[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteEmailCode(k EmailCodeKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.emailCodes, k)
	return nil
}
