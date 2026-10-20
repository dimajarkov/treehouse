package pool

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/kunchenguid/treehouse/v3/internal/vcs"
)

// AliasRequest describes one explicitly selected metadata-only repair. Hashes
// detect changes; neither they nor an inventory HMAC grant operator authority.
type AliasRequest struct {
	Pool       string    `json:"pool"`
	Target     string    `json:"target"`
	Name       string    `json:"name"`
	LeaseID    string    `json:"lease_id"`
	Holder     string    `json:"holder"`
	LeasedAt   time.Time `json:"leased_at"`
	StateHash  string    `json:"state_sha256"`
	KeeperHash string    `json:"keeper_sha256"`
	ShadowHash string    `json:"shadow_sha256"`
}

type AliasPreview struct {
	Implementation string    `json:"implementation"`
	MarkerIdentity string    `json:"marker_identity"`
	MarkerHash     string    `json:"marker_sha256"`
	RootIdentity   string    `json:"root_identity"`
	Root           string    `json:"root"`
	Version        string    `json:"version"`
	RequestHash    string    `json:"request_sha256"`
	Before         string    `json:"before_sha256"`
	After          string    `json:"after_sha256"`
	Siblings       string    `json:"siblings_sha256"`
	PoolIdentity   string    `json:"pool_identity"`
	TargetIdentity string    `json:"target_identity"`
	KeyIdentity    string    `json:"key_identity"`
	LockIdentity   string    `json:"lock_identity"`
	StateIdentity  string    `json:"state_identity"`
	KeyHash        string    `json:"key_sha256"`
	Expires        time.Time `json:"expires"`
	Nonce          string    `json:"nonce"`
	Token          string    `json:"token"`
}

type AliasResult struct {
	Outcome     string `json:"outcome"`
	Transaction string `json:"transaction,omitempty"`
	StateHash   string `json:"state_sha256"`
}

type aliasManifest struct {
	Implementation string       `json:"implementation"`
	Version        string       `json:"version"`
	Request        AliasRequest `json:"request"`
	Preview        AliasPreview `json:"preview"`
	MAC            string       `json:"mac"`
}

type aliasSession struct {
	writerCheck            func() error
	request                AliasRequest
	lock                   *os.File
	before, key, candidate []byte
	preview                AliasPreview
	stateMode              os.FileMode
}

func aliasHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func aliasJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func aliasMAC(key []byte, domain string, v any) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(domain + "\x00"))
	h.Write(aliasJSON(v))
	return hex.EncodeToString(h.Sum(nil))
}
func validAliasHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

// StrictAliasJSON rejects duplicate fields (including nested objects), unknown
// fields and trailing values. Never discard an unmodelled state field on write.
func StrictAliasJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		tok, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate JSON field")
				}
				seen[key] = true
				if e = walk(); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := walk(); e != nil {
					return e
				}
			}
		default:
			return fmt.Errorf("invalid JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func (s *aliasSession) close() { clear(s.key); unlockFile(s.lock); s.lock.Close() }
func aliasIdentity(path string) (string, error) {
	i, e := os.Lstat(path)
	if e != nil || i.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("unverifiable alias transaction path")
	}
	return aliasFileIdentity(i)
}
func openAliasSession(r AliasRequest) (*aliasSession, error) {
	if !filepath.IsAbs(r.Pool) || !filepath.IsAbs(r.Target) || r.Name == "" || filepath.Base(r.Name) != r.Name || r.Name == "." || r.LeasedAt.IsZero() || strings.TrimSpace(r.Holder) == "" || r.Holder == RecoveredLeaseHolder {
		return nil, fmt.Errorf("incomplete exact-target request")
	}
	id, e := hex.DecodeString(r.LeaseID)
	if e != nil || len(id) != 16 || !validAliasHash(r.StateHash) || !validAliasHash(r.KeeperHash) || !validAliasHash(r.ShadowHash) || r.KeeperHash == r.ShadowHash {
		return nil, fmt.Errorf("invalid identity/hash predicates")
	}
	pool, e := filepath.EvalSymlinks(r.Pool)
	if e != nil || pool != filepath.Clean(r.Pool) {
		return nil, fmt.Errorf("request requires canonical physical pool")
	}
	target, e := filepath.EvalSymlinks(r.Target)
	if e != nil || target != filepath.Clean(r.Target) || filepath.Dir(filepath.Dir(target)) != pool || filepath.Base(filepath.Dir(target)) != r.Name {
		return nil, fmt.Errorf("target outside exact canonical slot")
	}
	lock, e := openInspectionFile(lockFilePath(pool))
	if e != nil {
		return nil, e
	}
	if e = tryLockFile(lock); e != nil {
		lock.Close()
		return nil, fmt.Errorf("existing pool lock busy")
	}
	s := &aliasSession{request: r, lock: lock}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	if s.before, e = readInspectionFile(stateFilePath(pool), 16<<20); e != nil {
		return nil, e
	}
	if s.key, e = readInspectionFile(stateKeyPath(pool), 32); e != nil || len(s.key) != 32 {
		return nil, fmt.Errorf("existing key unavailable")
	}
	s.preview = AliasPreview{Implementation: aliasImplementation(), Version: "treehouse.alias-preview.v1", RequestHash: aliasHash(aliasJSON(r)), Before: aliasHash(s.before), KeyHash: aliasHash(s.key)}
	for path, dest := range map[string]*string{pool: &s.preview.PoolIdentity, target: &s.preview.TargetIdentity, stateKeyPath(pool): &s.preview.KeyIdentity, lockFilePath(pool): &s.preview.LockIdentity, stateFilePath(pool): &s.preview.StateIdentity} {
		v, err := aliasIdentity(path)
		if err != nil {
			return nil, err
		}
		*dest = v
	}
	st, e := os.Stat(stateFilePath(pool))
	if e != nil {
		return nil, e
	}
	s.stateMode = st.Mode().Perm()
	pi, e := os.Stat(pool)
	if e != nil {
		return nil, e
	}
	if e = aliasStateWritable(st, pi); e != nil {
		return nil, e
	}

	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("state is not regular")
	}

	// This bounded operation supports Git worktree marker files only. It never
	// repairs a marker or broadens to a main checkout/JJ workspace.
	marker := filepath.Join(target, ".git")
	markerData, err := readInspectionFile(marker, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("regular Git worktree marker required")
	}
	s.preview.MarkerHash = aliasHash(markerData)
	s.preview.MarkerIdentity, err = aliasIdentity(marker)
	if err != nil {
		return nil, err
	}
	root, err := vcs.FindMainRepoRootFrom(target)
	if err != nil {
		return nil, fmt.Errorf("VCS root unavailable")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	s.preview.Root = root
	s.preview.RootIdentity, err = aliasIdentity(root)
	if err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *aliasSession) plan() error {
	r := s.request
	if aliasHash(s.before) != r.StateHash {
		return fmt.Errorf("state predicate changed; obtain fresh preview")
	}
	var state State
	if e := StrictAliasJSON(s.before, &state); e != nil {
		return e
	}
	if state.Version != stateVersion {
		return fmt.Errorf("unsupported state version")
	}
	info, e := os.Stat(r.Target)
	if e != nil || !info.IsDir() {
		return fmt.Errorf("target unavailable")
	}
	if backend, e := vcs.WorktreeBackendNameChecked(r.Target); e != nil || backend == "" {
		return fmt.Errorf("target marker unavailable")
	}
	if _, e := vcs.FindMainRepoRootFrom(r.Target); e != nil {
		return fmt.Errorf("target VCS root unavailable")
	}
	keeper, shadow := -1, -1
	names, matches := 0, 0
	var siblings []WorktreeEntry
	for i, w := range state.Worktrees {
		if !w.SeedInventoryKnown || !validSeedInventory(w.SeededPaths) || !validSeedMetadata(w) || !validSeedInventoryDigest(s.key, w) {
			return fmt.Errorf("unauthenticated inventory; no healing permitted")
		}
		wi, e := os.Stat(w.Path)
		if e != nil || !wi.IsDir() || !filepath.IsAbs(w.Path) {
			return fmt.Errorf("unverifiable registered filesystem identity")
		}
		same := e == nil && os.SameFile(info, wi)
		if w.Name == r.Name {
			names++
		}
		if same {
			matches++
		}
		h := aliasHash(aliasJSON(w))
		switch h {
		case r.KeeperHash:
			if keeper >= 0 {
				return fmt.Errorf("duplicate keeper")
			}
			keeper = i
		case r.ShadowHash:
			if shadow >= 0 {
				return fmt.Errorf("duplicate shadow")
			}
			shadow = i
		default:
			siblings = append(siblings, w)
		}
		if (h == r.KeeperHash || h == r.ShadowHash) && (!same || w.Name != r.Name) {
			return fmt.Errorf("selected row identity mismatch")
		}
	}
	if names != 2 || matches != 2 || keeper < 0 || shadow < 0 {
		return fmt.Errorf("exactly two selected registrations required")
	}
	k, w := state.Worktrees[keeper], state.Worktrees[shadow]
	inert := func(x WorktreeEntry) bool {
		return !x.Destroying && x.OwnerPID == 0 && x.OwnerStartedAt == 0 && x.RecoveryError == "" && x.RecoveryReason == "" && len(x.SeededPaths) == 0 && x.SeedBackend == "" && x.SeedAuthIdentity == ""
	}
	if !inert(k) || !inert(w) || !k.Leased || k.LeaseID != r.LeaseID || k.LeaseHolder != r.Holder || !k.LeasedAt.Equal(r.LeasedAt) || w.Leased || w.LeaseID != "" || w.LeaseHolder != "" || !w.LeasedAt.IsZero() || k.Path == r.Target || w.Path != r.Target {
		return fmt.Errorf("keeper/shadow ownership predicate denied")
	}
	// Preserve every field and row order except keeper path/digest and one shadow.
	k.Path = r.Target
	k.SeedInventoryDigest = seedInventoryDigest(s.key, k)
	candidate := State{Version: state.Version}
	for i, entry := range state.Worktrees {
		if i == shadow {
			continue
		}
		if i == keeper {
			entry = k
		}
		candidate.Worktrees = append(candidate.Worktrees, entry)
	}
	s.candidate, e = json.MarshalIndent(candidate, "", "  ")
	if e != nil {
		return e
	}
	s.preview.After = aliasHash(s.candidate)
	s.preview.Siblings = aliasHash(aliasJSON(siblings))
	return s.fresh(s.before, true)
}
func (s *aliasSession) fresh(expected []byte, original bool) error {
	if s.writerCheck != nil {
		if e := s.writerCheck(); e != nil {
			return e
		}
	}
	p := s.preview
	r := s.request
	checks := map[string]string{r.Pool: p.PoolIdentity, r.Target: p.TargetIdentity, stateKeyPath(r.Pool): p.KeyIdentity, lockFilePath(r.Pool): p.LockIdentity}
	if original {
		checks[stateFilePath(r.Pool)] = p.StateIdentity
	}
	checks[filepath.Join(r.Target, ".git")] = p.MarkerIdentity
	checks[p.Root] = p.RootIdentity
	marker, e := readInspectionFile(filepath.Join(r.Target, ".git"), 1<<20)
	if e != nil || aliasHash(marker) != p.MarkerHash {
		return fmt.Errorf("target Git marker changed")
	}
	root, e := vcs.FindMainRepoRootFrom(r.Target)
	if e != nil {
		return fmt.Errorf("VCS root changed")
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil || root != p.Root {
		return fmt.Errorf("VCS root changed")
	}

	current, e := aliasIdentity(stateFilePath(r.Pool))
	if e != nil {
		return e
	}
	// Atomic replacement changes only inode identity, never owner/group/mode.
	wantParts, gotParts := strings.Split(p.StateIdentity, ":"), strings.Split(current, ":")
	if len(wantParts) != 5 || len(gotParts) != 5 || strings.Join(wantParts[2:], ":") != strings.Join(gotParts[2:], ":") {
		return fmt.Errorf("state owner or mode changed")
	}

	for path, want := range checks {
		got, e := aliasIdentity(path)
		if e != nil || got != want {
			return fmt.Errorf("transaction filesystem identity changed")
		}
	}
	held, e := s.lock.Stat()
	named, ne := os.Lstat(lockFilePath(r.Pool))
	if e != nil || ne != nil || !os.SameFile(held, named) {
		return fmt.Errorf("named lock replaced")
	}
	data, e := readInspectionFile(stateFilePath(r.Pool), 16<<20)
	if e != nil || !bytes.Equal(data, expected) {
		return fmt.Errorf("transaction state changed")
	}
	key, e := readInspectionFile(stateKeyPath(r.Pool), 32)
	defer clear(key)
	if e != nil || !bytes.Equal(key, s.key) {
		return fmt.Errorf("transaction key changed")
	}
	return nil
}

func PreviewAlias(r AliasRequest) (AliasPreview, error) {
	s, e := openAliasSession(r)
	if e != nil {
		return AliasPreview{}, e
	}
	defer s.close()
	if e = s.plan(); e != nil {
		return AliasPreview{}, e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return AliasPreview{}, e
	}
	s.preview.Nonce = hex.EncodeToString(nonce)
	s.preview.Expires = time.Now().UTC().Add(5 * time.Minute)
	s.preview.Token = aliasMAC(s.key, "treehouse.alias-preview.v1", s.preview)
	return s.preview, nil
}
func validAliasPreview(key []byte, p AliasPreview) bool {
	mac := p.Token
	p.Token = ""
	return hmac.Equal([]byte(mac), []byte(aliasMAC(key, "treehouse.alias-preview.v1", p)))
}
func aliasTransactionPath(r AliasRequest, p AliasPreview) string {
	return filepath.Join(filepath.Dir(r.Pool), "treehouse-alias-transaction-"+p.Nonce)
}
func syncAliasDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeAliasExclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}

// AliasWriterFence must establish prevention on every owned launch route and
// exclude existing/waiting legacy writers and new legacy launches until release.
// A process snapshot, user-supplied boolean, or the pool lock alone cannot do
// this. No production adapter is available yet: CLI mutations fail closed.
// The lifecycle owner must supply an independently reviewed adapter; fixture
// fences live only in test files and cannot be selected by a flag or env var.
type AliasWriterFence func(AliasRequest) (check func() error, release func(), err error)

func holdAliasWriterFence(r AliasRequest, f AliasWriterFence) (func() error, func(), error) {
	if f == nil {
		return nil, nil, fmt.Errorf("legacy writer exclusion unproven: establish reviewed prevention on all owned launch routes and hold a lifecycle-owner fence excluding existing, waiting and future legacy writers; no mutation permitted")
	}
	check, release, e := f(r)
	if e != nil {
		return nil, nil, e
	}
	if release == nil || check == nil {
		if release != nil {
			release()
		}
		return nil, nil, fmt.Errorf("writer fence did not supply a held verifiable lifetime")
	}
	if e = check(); e != nil {
		release()
		return nil, nil, e
	}
	return check, release, nil
}

// ApplyAlias is deliberately separate from PreviewAlias. The token only binds
// reviewed intent and freshness; callers still need explicit operator approval.
func ApplyAlias(r AliasRequest, p AliasPreview, fence AliasWriterFence) (AliasResult, error) {
	return applyAlias(r, p, nil, fence)
}

// fault is fixture-only dependency injection, never a CLI or environment flag.
func applyAlias(r AliasRequest, p AliasPreview, fault func(string) error, fence AliasWriterFence) (AliasResult, error) {
	check, release, e := holdAliasWriterFence(r, fence)
	if e != nil {
		return AliasResult{}, e
	}
	defer release()
	s, e := openAliasSession(r)
	if e != nil {
		return AliasResult{}, e
	}
	defer s.close()
	s.writerCheck = check
	if e = s.plan(); e != nil {
		return AliasResult{}, e
	}
	now := time.Now()
	if !validAliasPreview(s.key, p) || p.Version != s.preview.Version || !p.Expires.After(now) || p.Expires.After(now.Add(5*time.Minute)) || len(p.Nonce) != 32 {
		return AliasResult{}, fmt.Errorf("fresh authenticated preview required")
	}
	if b, e := hex.DecodeString(p.Nonce); e != nil || len(b) != 16 {
		return AliasResult{}, fmt.Errorf("invalid preview nonce")
	}
	planned := s.preview
	planned.Nonce = p.Nonce
	planned.Expires = p.Expires
	planned.Token = p.Token
	if !bytes.Equal(aliasJSON(planned), aliasJSON(p)) {
		return AliasResult{}, fmt.Errorf("preview predicates changed")
	}
	dir := aliasTransactionPath(r, p)
	if e = os.Mkdir(dir, 0700); e != nil {
		return AliasResult{}, fmt.Errorf("exclusive transaction backup unavailable")
	}
	result := AliasResult{Outcome: "not-applied", Transaction: dir, StateHash: p.Before}
	if e = os.Chmod(dir, 0700); e != nil {
		return result, e
	}
	m := aliasManifest{Version: "treehouse.alias-transaction.v1", Implementation: aliasImplementation(), Request: r, Preview: p}
	m.MAC = aliasMAC(s.key, "treehouse.alias-transaction.v1", m)
	for _, f := range []struct {
		name string
		data []byte
	}{{"before.json", s.before}, {"candidate.json", s.candidate}, {"manifest.json", aliasJSON(m)}} {
		if e = writeAliasExclusive(filepath.Join(dir, f.name), f.data); e != nil {
			return result, e
		}
	}
	if e = syncAliasDir(dir); e != nil {
		return result, e
	}
	if e = syncAliasDir(filepath.Dir(dir)); e != nil {
		return result, e
	}
	// Authenticate durable backup before any state mutation.
	if _, _, _, e = readAliasBackup(s, dir); e != nil {
		return result, e
	}
	if fault != nil {
		if e = fault("before-write"); e != nil {
			return result, e
		}
	}
	if e = s.fresh(s.before, true); e != nil {
		return result, e
	}
	// No prepareStateForWrite: it can create keys or normalize siblings. The
	// validated candidate changes only the exact selected path/digest and row.
	if e = atomicWriteFile(stateFilePath(r.Pool), s.candidate, s.stateMode); e != nil {
		result.Outcome = "accepted-but-unconfirmed"
		return result, e
	}
	if e = syncAliasDir(r.Pool); e != nil {
		result.Outcome = "accepted-but-unconfirmed"
		return result, e
	}
	if fault != nil {
		if e = fault("lost-receipt"); e != nil {
			result.Outcome = "accepted-but-unconfirmed"
			return result, e
		}
	}
	if e = s.verifyCandidate(); e == nil && fault != nil {
		e = fault("verify")
	}
	if e != nil {
		if re := rollbackAliasSession(s, dir); re != nil {
			result.Outcome = "inconclusive"
			return result, fmt.Errorf("verification failed; guarded rollback refused: %w", re)
		}
		result.Outcome = "rolled-back"
		return result, fmt.Errorf("verification failed; original metadata restored")
	}
	result.Outcome = "confirmed"
	result.StateHash = p.After
	return result, nil
}

func (s *aliasSession) verifyCandidate() error {
	if e := s.fresh(s.candidate, false); e != nil {
		return e
	}
	lease, e := inspectLeaseObservation(s.request.Pool, s.request.Target, s.candidate, s.key)
	if e != nil || lease.LeaseID != s.request.LeaseID || lease.LeaseHolder != s.request.Holder || !lease.LeasedAt.Equal(s.request.LeasedAt) {
		return fmt.Errorf("lock-held strict lease validation failed")
	}
	return s.fresh(s.candidate, false)
}

func readAliasBackup(s *aliasSession, dir string) (aliasManifest, []byte, []byte, error) {
	var m aliasManifest
	fi, e := os.Lstat(dir)
	if e != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 {
		return m, nil, nil, fmt.Errorf("private transaction directory required")
	}
	if _, e = aliasFileIdentity(fi); e != nil {
		return m, nil, nil, e
	}
	data, e := readInspectionFile(filepath.Join(dir, "manifest.json"), 1<<20)
	if e != nil {
		return m, nil, nil, e
	}
	if e = StrictAliasJSON(data, &m); e != nil {
		return m, nil, nil, e
	}
	mac := m.MAC
	m.MAC = ""
	valid := hmac.Equal([]byte(mac), []byte(aliasMAC(s.key, "treehouse.alias-transaction.v1", m)))
	m.MAC = mac
	if !valid || m.Implementation != aliasImplementation() || m.Preview.Implementation != m.Implementation || m.Version != "treehouse.alias-transaction.v1" || !validAliasPreview(s.key, m.Preview) || !bytes.Equal(aliasJSON(m.Request), aliasJSON(s.request)) || dir != aliasTransactionPath(m.Request, m.Preview) {
		return m, nil, nil, fmt.Errorf("transaction authentication failed")
	}
	for _, name := range []string{"before.json", "candidate.json", "manifest.json"} {
		f, e := os.Lstat(filepath.Join(dir, name))
		if e != nil || f.Mode().Perm() != 0600 {
			return m, nil, nil, fmt.Errorf("private backup file required")
		}
		if _, e = aliasFileIdentity(f); e != nil {
			return m, nil, nil, e
		}
	}
	before, e := readInspectionFile(filepath.Join(dir, "before.json"), 16<<20)
	if e != nil {
		return m, nil, nil, e
	}
	after, e := readInspectionFile(filepath.Join(dir, "candidate.json"), 16<<20)
	if e != nil {
		return m, nil, nil, e
	}
	if aliasHash(before) != m.Preview.Before || aliasHash(after) != m.Preview.After {
		return m, nil, nil, fmt.Errorf("backup hash mismatch")
	}
	return m, before, after, nil
}
func rollbackAliasSession(s *aliasSession, dir string) error {
	m, before, after, e := readAliasBackup(s, dir)
	if e != nil {
		return e
	}
	s.preview = m.Preview
	if e = s.fresh(after, false); e != nil {
		return e
	}
	if e = atomicWriteFile(stateFilePath(s.request.Pool), before, s.stateMode); e != nil {
		return e
	}
	if e = syncAliasDir(s.request.Pool); e != nil {
		return e
	}
	return s.fresh(before, false)
}

// RecoverAlias never reapplies a transaction. Hashes classify lost receipts;
// rollback is an explicit, separately selected operation with no stale restore.
func RecoverAlias(r AliasRequest, dir string, rollback bool, fence AliasWriterFence) (AliasResult, error) {
	var writerCheck func() error
	if rollback {
		check, release, e := holdAliasWriterFence(r, fence)
		if e != nil {
			return AliasResult{}, e
		}
		defer release()
		writerCheck = check
	}
	s, e := openAliasSession(r)
	if e != nil {
		return AliasResult{}, e
	}
	defer s.close()
	s.writerCheck = writerCheck
	m, before, after, e := readAliasBackup(s, dir)
	if e != nil {
		return AliasResult{}, e
	}
	// Match current key/lock/pool/target against the authenticated transaction.
	s.preview = m.Preview
	result := AliasResult{Transaction: dir, StateHash: aliasHash(s.before)}
	switch {
	case bytes.Equal(s.before, before):
		if e = s.fresh(before, false); e != nil {
			return result, e
		}
		result.Outcome = "not-applied-or-rolled-back"
		return result, nil
	case bytes.Equal(s.before, after):
		if e = s.fresh(after, false); e != nil {
			return result, e
		}
		if rollback {
			if e = rollbackAliasSession(s, dir); e != nil {
				return result, e
			}
			result.Outcome = "rolled-back"
			result.StateHash = m.Preview.Before
		} else {
			result.Outcome = "applied-receipt-unconfirmed"
		}
		return result, nil
	default:
		result.Outcome = "inconclusive"
		return result, fmt.Errorf("current state differs; stale restore refused")
	}
}

func aliasImplementation() string {
	result := "treehouse.alias-reconcile.v1"
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			if s.Key == "vcs.revision" || s.Key == "vcs.modified" {
				result += " " + s.Key + "=" + s.Value
			}
		}
	}
	return result
}
