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
		Token:      "/etc/tproxy-keys/panel.token",
		ReadyURL:   "http://127.0.0.1:8081/readyz",
	}
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
	if len(file.Profiles) > 32 {
		return errors.New("the relay accepts at most 32 profiles")
	}
	seenName := map[string]bool{}
	seenSecret := map[string]bool{}
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
		seenName[profile.Name] = true
		seenSecret[profile.Secret] = true
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
	if err := syncBackendSecrets(p, file); err != nil {
		restore(p, previous)
		return err
	}
	fmt.Fprintln(os.Stderr, "applying: restarting mtproxy and the relay, live sessions drop")
	if err := restartStack(p); err != nil {
		restore(p, previous)
		var restoreFile ProfileFile
		if json.Unmarshal(previous, &restoreFile) == nil {
			_ = syncBackendSecrets(p, &restoreFile)
		}
		if second := restartStack(p); second != nil {
			return fmt.Errorf("%w; rollback also failed: %v", err, second)
		}
		return fmt.Errorf("%w; the previous key set was restored", err)
	}
	return nil
}

func restore(p Paths, previous []byte) {
	_ = writeFileAtomic(p.Profiles, previous, 0400, "tproxy")
}

// syncBackendSecrets keeps official MTProxy aware of every client secret. The
// stock unit passes a single -S through ${MTPROXY_SECRET}, which systemd always
// expands to exactly one argument; the panel's drop-in reads this file and uses
// the splitting $MTPROXY_SECRET_ARGS form instead.
func syncBackendSecrets(p Paths, file *ProfileFile) error {
	arguments := make([]string, 0, len(file.Profiles))
	for _, profile := range file.Profiles {
		arguments = append(arguments, "-S "+backendSecret(profile.Secret))
	}
	content := "# Written by tproxy-keys. Do not edit by hand.\n" +
		"MTPROXY_SECRET_ARGS=" + strings.Join(arguments, " ") + "\n"
	return writeFileAtomic(p.MTProxyEnv, []byte(content), 0640, "mtproxy")
}

func restartStack(p Paths) error {
	if err := systemctl("restart", "mtproxy.service"); err != nil {
		return fmt.Errorf("mtproxy restart failed: %w", err)
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
	sort.SliceStable(views, func(i, j int) bool {
		return views[i].Meta.Created < views[j].Meta.Created
	})
	return views, host, nil
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

func AddKey(p Paths, name, label, mode string) (Profile, error) {
	file, err := LoadProfiles(p)
	if err != nil {
		return Profile{}, err
	}
	if !nameRE.MatchString(name) {
		return Profile{}, fmt.Errorf("name %q: use 1-64 characters from a-z A-Z 0-9 . _ -", name)
	}
	for _, profile := range file.Profiles {
		if profile.Name == name {
			return Profile{}, fmt.Errorf("a key named %q already exists", name)
		}
	}
	if !validCarrier(mode) {
		return Profile{}, fmt.Errorf("carrier mode must be one of %s", carrierModes)
	}
	secret, err := NewSecret()
	if err != nil {
		return Profile{}, err
	}
	backend := "127.0.0.1:2398"
	if len(file.Profiles) > 0 {
		backend = file.Profiles[0].Backend
	}
	added := Profile{Name: name, Secret: secret, Backend: backend, CarrierMode: mode}
	file.Profiles = append(file.Profiles, added)
	if err := Apply(p, file); err != nil {
		return Profile{}, err
	}
	meta := LoadMeta(p)
	meta.Keys[name] = KeyMeta{Label: label, Created: time.Now().UTC().Format(time.RFC3339)}
	_ = SaveMeta(p, meta)
	return added, nil
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

// Sync rewrites the MTProxy secret list from the current profiles and restarts
// the stack. It repairs the deployment after the reference installer has been
// re-run, which rewrites mtproxy.env from scratch.
func Sync(p Paths) error {
	file, err := LoadProfiles(p)
	if err != nil {
		return err
	}
	if err := syncBackendSecrets(p, file); err != nil {
		return err
	}
	return restartStack(p)
}
