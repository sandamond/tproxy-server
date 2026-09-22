package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Profile mirrors one entry of the relay's profiles file. The relay decodes
// that file with DisallowUnknownFields, so no field may be added here that it
// does not know. Limits stay raw so a hand-written per-profile block survives
// an edit made through the panel.
type Profile struct {
	Name        string          `json:"name"`
	Secret      string          `json:"secret"`
	Backend     string          `json:"backend"`
	CarrierMode string          `json:"carrier_mode,omitempty"`
	Limits      json.RawMessage `json:"limits,omitempty"`
}

type ProfileFile struct {
	Profiles []Profile `json:"profiles"`
}

// KeyMeta is panel-owned bookkeeping. It cannot live in the profiles file, so
// it is kept beside it and joined by profile name.
type KeyMeta struct {
	Label   string `json:"label,omitempty"`
	Group   string `json:"group,omitempty"`
	Note    string `json:"note,omitempty"`
	Created string `json:"created,omitempty"`
}

type Meta struct {
	Keys map[string]KeyMeta `json:"keys"`
}

type Paths struct {
	Profiles   string
	RelayConf  string
	RelayBin   string
	Meta       string
	MTProxyEnv string
	Backends   string
	Token      string
	ReadyURL   string
}

func DefaultPaths() Paths {
	return Paths{
		Profiles:   "/etc/tproxy-server/profiles.json",
		RelayConf:  "/etc/tproxy-server/config.json",
		RelayBin:   "/usr/local/bin/tproxy-server",
		Meta:       "/etc/tproxy-keys/meta.json",
		MTProxyEnv: "/etc/mtproxy/mtproxy-keys.env",
		Backends:   "/etc/tproxy-keys/backends.json",
		Token:      "/etc/tproxy-keys/panel.token",
		ReadyURL:   "http://127.0.0.1:8081/readyz",
	}
}

// maxSecretsPerBackend is official MTProxy's own hard ceiling, not ours to
// raise: net/net-tcp-rpc-ext-server.c asserts ext_secret_cnt < 16 and aborts
// the process past it. Confirmed live 2026-09-22 trying to load 60 secrets
// into one backend - MTProxy crash-looped and Apply's own rollback (below)
// is what caught it, not this constant, because this constant didn't exist
// yet. See deploy/provision-mtproxy-backend.sh for adding backend capacity.
const maxSecretsPerBackend = 16

// BackendInfo is one official-MTProxy process this deployment can assign
// client secrets to.
type BackendInfo struct {
	Address string `json:"address"`
	Unit    string `json:"unit"`
	EnvFile string `json:"env_file"`
}

type BackendRegistry struct {
	Backends []BackendInfo `json:"backends"`
}

// LoadBackends reads the backend registry, or - for a deployment from before
// multi-backend support existed, which has no registry file at all - returns
// the single backend the reference installer has always set up, using the
// env file tproxy-keys has always written. This keeps every existing
// deployment working with zero migration step.
func LoadBackends(p Paths) (*BackendRegistry, error) {
	raw, err := os.ReadFile(p.Backends)
	if err != nil {
		return &BackendRegistry{Backends: []BackendInfo{{
			Address: "127.0.0.1:2398",
			Unit:    "mtproxy.service",
			EnvFile: p.MTProxyEnv,
		}}}, nil
	}
	var registry BackendRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		return nil, fmt.Errorf("backends file: %w", err)
	}
	if len(registry.Backends) == 0 {
		return nil, errors.New("backends file lists no backends")
	}
	return &registry, nil
}

// backendUsage counts how many profiles already sit on each backend address.
func backendUsage(file *ProfileFile) map[string]int {
	usage := map[string]int{}
	for _, profile := range file.Profiles {
		usage[profile.Backend]++
	}
	return usage
}

// pickBackend returns the first registered backend with room for one more
// secret, given the counts already committed to `usage` (which the caller
// updates as it assigns each key in a batch, so a multi-key batch spreads
// correctly across backends instead of only ever considering the first one).
func pickBackend(registry *BackendRegistry, usage map[string]int) (string, error) {
	for _, backend := range registry.Backends {
		if usage[backend.Address] < maxSecretsPerBackend {
			return backend.Address, nil
		}
	}
	return "", fmt.Errorf(
		"every registered backend is at official MTProxy's %d-secret limit; run deploy/provision-mtproxy-backend.sh to add capacity",
		maxSecretsPerBackend)
}

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var secretRE = regexp.MustCompile(`^(dd)?[0-9a-f]{32}$`)

const carrierModes = "https, https-lanes, websocket, websocket-lanes"

func validCarrier(mode string) bool {
	switch mode {
	case "", "https", "https-lanes", "websocket", "websocket-lanes":
		return true
	}
	return false
}

func NewSecret() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// backendSecret drops the optional dd prefix the way the reference installer
// does: official MTProxy takes the bare 16-byte value.
func backendSecret(secret string) string {
	if len(secret) == 34 && strings.HasPrefix(secret, "dd") {
		return secret[2:]
	}
	return secret
}

func LoadProfiles(p Paths) (*ProfileFile, error) {
	raw, err := os.ReadFile(p.Profiles)
	if err != nil {
		return nil, err
	}
	var file ProfileFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("profiles file: %w", err)
	}
	return &file, nil
}

func LoadMeta(p Paths) *Meta {
	meta := &Meta{Keys: map[string]KeyMeta{}}
	raw, err := os.ReadFile(p.Meta)
	if err != nil {
		return meta
	}
	if err := json.Unmarshal(raw, meta); err != nil || meta.Keys == nil {
		return &Meta{Keys: map[string]KeyMeta{}}
	}
	return meta
}

func SaveMeta(p Paths, meta *Meta) error {
	if err := os.MkdirAll(filepath.Dir(p.Meta), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(p.Meta, append(raw, '\n'), 0600, "")
}

// writeFileAtomic writes through a temporary file in the destination directory
// so a reader never observes a half-written config. group, when set, becomes
// the file's group owner.
func writeFileAtomic(path string, content []byte, mode os.FileMode, group string) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() {
		temp.Close()
		os.Remove(name)
	}()
	if _, err := temp.Write(content); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if group != "" {
		gid, err := lookupGID(group)
		if err == nil {
			if err := temp.Chown(0, gid); err != nil {
				return err
			}
		}
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func lookupGID(group string) (int, error) {
	value, err := user.LookupGroup(group)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(value.Gid)
}

func marshalProfiles(file *ProfileFile) ([]byte, error) {
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// Apply validates a candidate profile set with the relay's own -check, installs
// it, syncs the MTProxy secret list, and restarts the stack. Any failure after
// the point of no return restores the previous file and restarts again, so the
// proxy is never left serving a configuration nobody chose.
func Apply(p Paths, file *ProfileFile) error {
	if len(file.Profiles) == 0 {
		return errors.New("at least one key must remain; the relay refuses an empty profile list")
	}
	if limit := maxProfiles(p); len(file.Profiles) > limit {
		return fmt.Errorf("the relay's configured limits.max_profiles is %d; this would exceed it", limit)
	}
	registry, err := LoadBackends(p)
	if err != nil {
		return err
	}
	registered := map[string]bool{}
	for _, backend := range registry.Backends {
		registered[backend.Address] = true
	}
	seenName := map[string]bool{}
	seenSecret := map[string]bool{}
	perBackend := map[string]int{}
	for _, profile := range file.Profiles {
		if !nameRE.MatchString(profile.Name) {
			return fmt.Errorf("name %q: use 1-64 characters from a-z A-Z 0-9 . _ -", profile.Name)
		}
		if !secretRE.MatchString(profile.Secret) {
			return fmt.Errorf("key %q: secret must be 32 lowercase hex characters, optionally dd-prefixed", profile.Name)
		}
		if !validCarrier(profile.CarrierMode) {
			return fmt.Errorf("key %q: carrier_mode must be one of %s", profile.Name, carrierModes)
		}
		if seenName[profile.Name] {
			return fmt.Errorf("duplicate name %q", profile.Name)
		}
		if seenSecret[profile.Secret] {
			return fmt.Errorf("duplicate secret on key %q", profile.Name)
		}
		if !registered[profile.Backend] {
			return fmt.Errorf("key %q: backend %q is not in the backend registry", profile.Name, profile.Backend)
		}
		seenName[profile.Name] = true
		seenSecret[profile.Secret] = true
		perBackend[profile.Backend]++
		// Belt and suspenders: pickBackend should already prevent this, but
		// official MTProxy crash-loops past 16 secrets with no graceful
		// error of its own, so this path must never rely solely on callers
		// having used pickBackend correctly.
		if perBackend[profile.Backend] > maxSecretsPerBackend {
			return fmt.Errorf("backend %q would carry %d secrets, over official MTProxy's %d-secret limit",
				profile.Backend, perBackend[profile.Backend], maxSecretsPerBackend)
		}
	}

	candidate, err := marshalProfiles(file)
	if err != nil {
		return err
	}
	previous, err := os.ReadFile(p.Profiles)
	if err != nil {
		return err
	}

	// Dry-run the candidate through the relay binary before it goes live.
	directory := filepath.Dir(p.Profiles)
	temp, err := os.CreateTemp(directory, "profiles.candidate*.json")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(candidate); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Chmod(0400); err != nil {
		temp.Close()
		return err
	}
	temp.Close()
	check := exec.Command(p.RelayBin, "-config", p.RelayConf, "-profiles-file", tempName, "-check")
	if output, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("relay rejected the configuration: %s", strings.TrimSpace(string(output)))
	}

	if err := writeFileAtomic(p.Profiles, candidate, 0400, "tproxy"); err != nil {
		return err
	}
	changedUnits, err := syncBackendSecrets(p, registry, file)
	if err != nil {
		restore(p, previous)
		return err
	}
	fmt.Fprintf(os.Stderr, "applying: restarting %s and the relay, live sessions on the affected backend(s) drop\n",
		strings.Join(changedUnits, ", "))
	if err := restartStack(p, changedUnits); err != nil {
		restore(p, previous)
		var restoreFile ProfileFile
		if json.Unmarshal(previous, &restoreFile) == nil {
			if restoreUnits, syncErr := syncBackendSecrets(p, registry, &restoreFile); syncErr == nil {
				changedUnits = restoreUnits
			}
		}
		if second := restartStack(p, changedUnits); second != nil {
			return fmt.Errorf("%w; rollback also failed: %v", err, second)
		}
		return fmt.Errorf("%w; the previous key set was restored", err)
	}
	return nil
}

func restore(p Paths, previous []byte) {
	_ = writeFileAtomic(p.Profiles, previous, 0400, "tproxy")
}

// syncBackendSecrets keeps every registered official-MTProxy backend aware of
// exactly the client secrets assigned to it. The stock unit passes a single
// -S through ${MTPROXY_SECRET}, which systemd always expands to exactly one
// argument; every backend's env file instead carries a splitting
// $MTPROXY_SECRET_ARGS (the name backend 0's already-deployed drop-in reads)
// and, redundantly, $MTPROXY_BACKEND_SECRET_ARGS (the name the mtproxy@.
// service template reads) - writing both into every file is simpler than
// tracking which name a given backend actually needs, and the unused one is
// just an unreferenced environment variable.
//
// It returns the systemd units whose secret list actually changed, so the
// caller restarts only those - not every backend on every edit, which would
// disconnect an unrelated backend's live users for no reason.
func syncBackendSecrets(p Paths, registry *BackendRegistry, file *ProfileFile) ([]string, error) {
	arguments := map[string][]string{}
	for _, backend := range registry.Backends {
		arguments[backend.Address] = nil // ensure every backend gets a (possibly empty) write below
	}
	for _, profile := range file.Profiles {
		arguments[profile.Backend] = append(arguments[profile.Backend], "-S "+backendSecret(profile.Secret))
	}

	var changed []string
	for _, backend := range registry.Backends {
		joined := strings.Join(arguments[backend.Address], " ")
		content, err := upsertSecretArgs(backend.EnvFile, joined)
		if err != nil {
			return nil, err
		}
		previous, _ := os.ReadFile(backend.EnvFile)
		if string(previous) == content {
			continue
		}
		if err := writeFileAtomic(backend.EnvFile, []byte(content), 0640, "mtproxy"); err != nil {
			return nil, err
		}
		changed = append(changed, backend.Unit)
	}
	return changed, nil
}

// upsertSecretArgs rewrites only the two secret-argument lines this package
// owns in a backend's env file, preserving every other line untouched.
//
// A freshly-provisioned backend's env file (deploy/provision-mtproxy-backend.sh)
// also carries MTPROXY_CLIENT_PORT and MTPROXY_ADMIN_PORT, which
// mtproxy@.service's ExecStart depends on and nothing else ever sets; the
// first version of this function overwrote the whole file with just the
// secret lines and blanked those out, so mtproxy@1.service failed with
// literal, unexpanded "${MTPROXY_ADMIN_PORT}" on its command line the moment
// a key was ever assigned to it - confirmed live, not hypothetical. Backend
// 0's env file has no such foreign lines, so for it this is equivalent to
// the old unconditional rewrite.
func upsertSecretArgs(path, joinedArgs string) (string, error) {
	const (
		header = "# Written by tproxy-keys. Do not edit by hand."
		plain  = "MTPROXY_SECRET_ARGS="
		spread = "MTPROXY_BACKEND_SECRET_ARGS="
	)
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	var kept []string
	for _, line := range strings.Split(string(existing), "\n") {
		if line == "" || line == header || strings.HasPrefix(line, plain) || strings.HasPrefix(line, spread) {
			continue
		}
		kept = append(kept, line)
	}
	kept = append(kept, header, plain+joinedArgs, spread+joinedArgs)
	return strings.Join(kept, "\n") + "\n", nil
}

// restartStack restarts every unit in units (each an MTProxy backend whose
// secrets actually changed) plus, always, the relay itself - profiles.json
// changed regardless of which backend(s) did.
func restartStack(p Paths, units []string) error {
	for _, unit := range units {
		if err := systemctl("restart", unit); err != nil {
			return fmt.Errorf("%s restart failed: %w", unit, err)
		}
	}
	if err := systemctl("restart", "tproxy-server.service"); err != nil {
		return fmt.Errorf("relay restart failed: %w", err)
	}
	deadline := time.Now().Add(25 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		state, err := readyState(p)
		if err == nil && state == "ready" {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = state
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("the relay did not report ready within 25s (last: %s)", last)
}

func systemctl(arguments ...string) error {
	command := exec.Command("systemctl", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", strings.Join(arguments, " "), strings.TrimSpace(string(output)))
	}
	return nil
}

func readyState(p Paths) (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(p.ReadyURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body := make([]byte, 64)
	n, _ := response.Body.Read(body)
	text := strings.TrimSpace(string(body[:n]))
	if response.StatusCode != http.StatusOK {
		return text, nil
	}
	return "ready", nil
}

func unitActive(unit string) bool {
	output, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(output)) == "active"
}

// PublicHostname reads the one hostname this relay serves, which every client
// link must carry.
func PublicHostname(p Paths) string {
	raw, err := os.ReadFile(p.RelayConf)
	if err != nil {
		return ""
	}
	var config struct {
		PublicHostname string `json:"public_hostname"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return ""
	}
	return config.PublicHostname
}

// defaultMaxProfiles matches the relay's own Defaults() in
// internal/config/config.go. It's the fallback when config.json omits
// limits.max_profiles, which is itself valid — the relay applies this same
// default in that case.
const defaultMaxProfiles = 32

// maxProfiles reads limits.max_profiles from the relay's own config so this
// panel's admission check can never silently drift from what the relay
// actually enforces at -check time.
func maxProfiles(p Paths) int {
	raw, err := os.ReadFile(p.RelayConf)
	if err != nil {
		return defaultMaxProfiles
	}
	var config struct {
		Limits struct {
			MaxProfiles int `json:"max_profiles"`
		} `json:"limits"`
	}
	if json.Unmarshal(raw, &config) != nil || config.Limits.MaxProfiles <= 0 {
		return defaultMaxProfiles
	}
	return config.Limits.MaxProfiles
}

func ClientLink(host, secret string) string {
	if host == "" {
		return ""
	}
	return "https://t.me/webproxy?server=" + host + "&secret=" + secret
}

type KeyView struct {
	Profile      Profile
	Meta         KeyMeta
	Link         string
	CreatedShort string
}

func Keys(p Paths) ([]KeyView, string, error) {
	file, err := LoadProfiles(p)
	if err != nil {
		return nil, "", err
	}
	meta := LoadMeta(p)
	host := PublicHostname(p)
	views := make([]KeyView, 0, len(file.Profiles))
	for _, profile := range file.Profiles {
		entry := meta.Keys[profile.Name]
		views = append(views, KeyView{
			Profile:      profile,
			Meta:         entry,
			Link:         ClientLink(host, profile.Secret),
			CreatedShort: shortTime(entry.Created),
		})
	}
	// Group first so keys belonging to the same person sit together (the
	// stated point of the field), then by creation order within a group so a
	// person's own keys stay in the order they were issued.
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Meta.Group != views[j].Meta.Group {
			return views[i].Meta.Group < views[j].Meta.Group
		}
		return views[i].Meta.Created < views[j].Meta.Created
	})
	return views, host, nil
}

// DistinctGroups lists every group currently in use, for the web UI's
// autocomplete — free text stays free text, this just reduces accidental
// near-duplicates like "Глеб" vs "глеб".
func DistinctGroups(p Paths) []string {
	meta := LoadMeta(p)
	seen := map[string]bool{}
	var groups []string
	for _, entry := range meta.Keys {
		if entry.Group == "" || seen[entry.Group] {
			continue
		}
		seen[entry.Group] = true
		groups = append(groups, entry.Group)
	}
	sort.Strings(groups)
	return groups
}

// shortTime renders a stored RFC3339 stamp as a compact local-looking date; an
// unparsable or missing value degrades to an em dash at the template.
func shortTime(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return parsed.Format("2006-01-02 15:04") + " UTC"
}

// NewKeyRequest is one profile to create. Group is optional free text (see
// KeyMeta.Group) so a batch of keys handed to one person can be identified
// together without constraining what a name or label may contain.
type NewKeyRequest struct {
	Name  string
	Label string
	Group string
	Mode  string
}

func AddKey(p Paths, name, label, mode string) (Profile, error) {
	added, err := AddKeys(p, []NewKeyRequest{{Name: name, Label: label, Mode: mode}})
	if err != nil {
		return Profile{}, err
	}
	return added[0], nil
}

// AddKeys creates one or more profiles in a single Apply() — one relay and
// MTProxy restart for the whole batch, not one per key. This is what makes
// importing a large existing list (many names at once, e.g. migrating off a
// different proxy) practical: 57 individual `add` calls would mean 57
// restarts, each dropping every other family member's live session too.
func AddKeys(p Paths, requests []NewKeyRequest) ([]Profile, error) {
	if len(requests) == 0 {
		return nil, errors.New("no keys requested")
	}
	file, err := LoadProfiles(p)
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for _, profile := range file.Profiles {
		existing[profile.Name] = true
	}
	registry, err := LoadBackends(p)
	if err != nil {
		return nil, err
	}
	// Seeded from what's already committed, then incremented as this batch
	// assigns each key, so N keys in one import correctly spread across
	// backends instead of every one of them landing on whichever backend
	// looked free before the batch started.
	usage := backendUsage(file)

	seenInBatch := map[string]bool{}
	added := make([]Profile, 0, len(requests))
	for _, request := range requests {
		name := strings.TrimSpace(request.Name)
		if !nameRE.MatchString(name) {
			return nil, fmt.Errorf("name %q: use 1-64 characters from a-z A-Z 0-9 . _ -", name)
		}
		if existing[name] || seenInBatch[name] {
			return nil, fmt.Errorf("a key named %q already exists", name)
		}
		if !validCarrier(request.Mode) {
			return nil, fmt.Errorf("key %q: carrier mode must be one of %s", name, carrierModes)
		}
		backend, err := pickBackend(registry, usage)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", name, err)
		}
		seenInBatch[name] = true
		usage[backend]++
		secret, err := NewSecret()
		if err != nil {
			return nil, err
		}
		added = append(added, Profile{Name: name, Secret: secret, Backend: backend, CarrierMode: request.Mode})
	}

	file.Profiles = append(file.Profiles, added...)
	if err := Apply(p, file); err != nil {
		return nil, err
	}

	meta := LoadMeta(p)
	now := time.Now().UTC().Format(time.RFC3339)
	for i, request := range requests {
		meta.Keys[added[i].Name] = KeyMeta{
			Label:   strings.TrimSpace(request.Label),
			Group:   strings.TrimSpace(request.Group),
			Created: now,
		}
	}
	_ = SaveMeta(p, meta)
	return added, nil
}

// UpdateKeyMeta changes only a key's panel-owned bookkeeping (label, group).
// Unlike Add/Revoke/Rotate this never touches profiles.json, so it never
// restarts the relay or MTProxy and never affects a live connection - it's
// purely how this key is displayed and organized in the panel.
func UpdateKeyMeta(p Paths, name, label, group string) error {
	file, err := LoadProfiles(p)
	if err != nil {
		return err
	}
	found := false
	for _, profile := range file.Profiles {
		if profile.Name == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no key named %q", name)
	}
	meta := LoadMeta(p)
	entry := meta.Keys[name]
	entry.Label = strings.TrimSpace(label)
	entry.Group = strings.TrimSpace(group)
	if entry.Created == "" {
		entry.Created = time.Now().UTC().Format(time.RFC3339)
	}
	meta.Keys[name] = entry
	return SaveMeta(p, meta)
}

func RevokeKey(p Paths, name string) error {
	file, err := LoadProfiles(p)
	if err != nil {
		return err
	}
	kept := make([]Profile, 0, len(file.Profiles))
	found := false
	for _, profile := range file.Profiles {
		if profile.Name == name {
			found = true
			continue
		}
		kept = append(kept, profile)
	}
	if !found {
		return fmt.Errorf("no key named %q", name)
	}
	if len(kept) == 0 {
		return errors.New("this is the last key; the relay refuses to start without one")
	}
	file.Profiles = kept
	if err := Apply(p, file); err != nil {
		return err
	}
	meta := LoadMeta(p)
	delete(meta.Keys, name)
	_ = SaveMeta(p, meta)
	return nil
}

func RotateKey(p Paths, name string) (Profile, error) {
	file, err := LoadProfiles(p)
	if err != nil {
		return Profile{}, err
	}
	secret, err := NewSecret()
	if err != nil {
		return Profile{}, err
	}
	found := false
	for i := range file.Profiles {
		if file.Profiles[i].Name == name {
			file.Profiles[i].Secret = secret
			found = true
			break
		}
	}
	if !found {
		return Profile{}, fmt.Errorf("no key named %q", name)
	}
	if err := Apply(p, file); err != nil {
		return Profile{}, err
	}
	for _, profile := range file.Profiles {
		if profile.Name == name {
			return profile, nil
		}
	}
	return Profile{}, nil
}

// Sync rewrites every registered backend's MTProxy secret list from the
// current profiles and restarts the whole backend fleet plus the relay. It
// repairs the deployment after the reference installer has been re-run,
// which rewrites the shared /etc/mtproxy/mtproxy.env (workers, NAT args)
// that every backend instance reads alongside its own secret file - so this
// restarts every registered backend unconditionally, not just whichever
// one's secret list happens to have changed.
func Sync(p Paths) error {
	file, err := LoadProfiles(p)
	if err != nil {
		return err
	}
	registry, err := LoadBackends(p)
	if err != nil {
		return err
	}
	if _, err := syncBackendSecrets(p, registry, file); err != nil {
		return err
	}
	units := make([]string, len(registry.Backends))
	for i, backend := range registry.Backends {
		units[i] = backend.Unit
	}
	return restartStack(p, units)
}
