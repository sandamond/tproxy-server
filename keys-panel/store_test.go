package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolatedPaths(t *testing.T) Paths {
	dir := t.TempDir()
	conf := `{"public_hostname":"proxy.example.com","limits":{"max_profiles":5}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	profiles := `{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398"}]}`
	if err := os.WriteFile(filepath.Join(dir, "profiles.json"), []byte(profiles), 0400); err != nil {
		t.Fatal(err)
	}
	return Paths{
		Profiles:  filepath.Join(dir, "profiles.json"),
		RelayConf: filepath.Join(dir, "config.json"),
		Meta:      filepath.Join(dir, "meta.json"),
	}
}

func TestMaxProfilesReadsConfig(t *testing.T) {
	p := isolatedPaths(t)
	if got := maxProfiles(p); got != 5 {
		t.Fatalf("maxProfiles = %d, want 5", got)
	}
}

func TestMaxProfilesDefaultsWhenAbsent(t *testing.T) {
	p := isolatedPaths(t)
	if err := os.WriteFile(p.RelayConf, []byte(`{"public_hostname":"x"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if got := maxProfiles(p); got != defaultMaxProfiles {
		t.Fatalf("maxProfiles = %d, want default %d", got, defaultMaxProfiles)
	}
}

func TestUpdateKeyMetaChangesOnlyLabelAndGroup(t *testing.T) {
	p := isolatedPaths(t)
	if err := UpdateKeyMeta(p, "default", "Тестовая метка", "Тестовая группа"); err != nil {
		t.Fatal(err)
	}
	meta := LoadMeta(p)
	entry := meta.Keys["default"]
	if entry.Label != "Тестовая метка" || entry.Group != "Тестовая группа" {
		t.Fatalf("unexpected meta: %+v", entry)
	}
	if entry.Created == "" {
		t.Fatal("Created should be set on first edit")
	}

	// profiles.json must be byte-for-byte untouched - UpdateKeyMeta must never
	// touch it, which is the whole point (no restart).
	raw, err := os.ReadFile(p.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398"}]}`
	if string(raw) != want {
		t.Fatalf("profiles.json was modified: %s", raw)
	}
}

func TestUpdateKeyMetaRejectsUnknownName(t *testing.T) {
	p := isolatedPaths(t)
	if err := UpdateKeyMeta(p, "nope", "x", "y"); err == nil {
		t.Fatal("expected an error for an unknown key name")
	}
}

// --- Backend registry, selection, and the 16-secret ceiling ---
//
// This is the logic that didn't exist when a 60-key import crash-looped
// official MTProxy for real on 2026-09-22 (net-tcp-rpc-ext-server.c:
// assert(ext_secret_cnt < 16)). Apply()'s own rollback caught that live
// failure correctly, but nothing stopped the attempt in the first place -
// these tests are that stop.

func TestLoadBackendsFallsBackToSingleLegacyBackend(t *testing.T) {
	p := isolatedPaths(t)
	p.Backends = filepath.Join(t.TempDir(), "does-not-exist.json")
	p.MTProxyEnv = "/etc/mtproxy/mtproxy-keys.env"
	registry, err := LoadBackends(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Backends) != 1 {
		t.Fatalf("got %d backends, want the one legacy default", len(registry.Backends))
	}
	backend := registry.Backends[0]
	if backend.Address != "127.0.0.1:2398" || backend.Unit != "mtproxy.service" || backend.EnvFile != p.MTProxyEnv {
		t.Fatalf("unexpected legacy default: %+v", backend)
	}
}

func writeBackends(t *testing.T, p Paths, backends []BackendInfo) {
	t.Helper()
	raw, err := json.Marshal(BackendRegistry{Backends: backends})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Backends, raw, 0644); err != nil {
		t.Fatal(err)
	}
}

func twoBackendPaths(t *testing.T) (Paths, string, string) {
	p := isolatedPaths(t)
	dir := filepath.Dir(p.Profiles)
	p.Backends = filepath.Join(dir, "backends.json")
	envA := filepath.Join(dir, "backend-a.env")
	envB := filepath.Join(dir, "backend-b.env")
	writeBackends(t, p, []BackendInfo{
		{Address: "127.0.0.1:2398", Unit: "mtproxy.service", EnvFile: envA},
		{Address: "127.0.0.1:2399", Unit: "mtproxy@1.service", EnvFile: envB},
	})
	return p, envA, envB
}

func TestPickBackendFillsFirstRegisteredBeforeSecond(t *testing.T) {
	p, _, _ := twoBackendPaths(t)
	registry, err := LoadBackends(p)
	if err != nil {
		t.Fatal(err)
	}
	usage := map[string]int{"127.0.0.1:2398": maxSecretsPerBackend - 1}
	got, err := pickBackend(registry, usage)
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:2398" {
		t.Fatalf("pickBackend = %q, want the first backend while it still has room", got)
	}
	usage["127.0.0.1:2398"] = maxSecretsPerBackend
	got, err = pickBackend(registry, usage)
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:2399" {
		t.Fatalf("pickBackend = %q, want the second backend once the first is full", got)
	}
}

func TestPickBackendRejectsWhenEveryBackendIsFull(t *testing.T) {
	p, _, _ := twoBackendPaths(t)
	registry, err := LoadBackends(p)
	if err != nil {
		t.Fatal(err)
	}
	usage := map[string]int{"127.0.0.1:2398": maxSecretsPerBackend, "127.0.0.1:2399": maxSecretsPerBackend}
	if _, err := pickBackend(registry, usage); err == nil {
		t.Fatal("expected an error when every backend is at the 16-secret ceiling")
	}
}

func stubProvision(t *testing.T, fn func() error) *int {
	t.Helper()
	calls := 0
	original := provisionBackend
	provisionBackend = func() error {
		calls++
		return fn()
	}
	t.Cleanup(func() { provisionBackend = original })
	return &calls
}

func fullUsage() map[string]int {
	return map[string]int{"127.0.0.1:2398": maxSecretsPerBackend, "127.0.0.1:2399": maxSecretsPerBackend}
}

func TestChooseBackendDoesNotProvisionWhileThereIsRoom(t *testing.T) {
	p, _, _ := twoBackendPaths(t)
	registry, _ := LoadBackends(p)
	calls := stubProvision(t, func() error { return nil })
	got, err := chooseBackend(p, &registry, map[string]int{"127.0.0.1:2398": maxSecretsPerBackend})
	if err != nil || got != "127.0.0.1:2399" {
		t.Fatalf("chooseBackend = %q, %v", got, err)
	}
	if *calls != 0 {
		t.Fatalf("provisioned %d times although a backend had room", *calls)
	}
}

func TestChooseBackendProvisionsWhenEveryBackendIsFull(t *testing.T) {
	p, envA, envB := twoBackendPaths(t)
	registry, _ := LoadBackends(p)
	calls := stubProvision(t, func() error {
		writeBackends(t, p, []BackendInfo{
			{Address: "127.0.0.1:2398", Unit: "mtproxy.service", EnvFile: envA},
			{Address: "127.0.0.1:2399", Unit: "mtproxy@1.service", EnvFile: envB},
			{Address: "127.0.0.1:2400", Unit: "mtproxy@2.service", EnvFile: envB + "2"},
		})
		return nil
	})
	usage := fullUsage()
	for i := 0; i < 3; i++ {
		got, err := chooseBackend(p, &registry, usage)
		if err != nil || got != "127.0.0.1:2400" {
			t.Fatalf("pick %d: chooseBackend = %q, %v", i, got, err)
		}
		usage[got]++
	}
	if *calls != 1 {
		t.Fatalf("provisioned %d times, want exactly once for a batch that fits one new backend", *calls)
	}
}

func TestChooseBackendReportsFailedProvisioning(t *testing.T) {
	p, _, _ := twoBackendPaths(t)
	registry, _ := LoadBackends(p)
	stubProvision(t, func() error { return fmt.Errorf("unit not found") })
	_, err := chooseBackend(p, &registry, fullUsage())
	if err == nil || !errors.Is(err, errBackendsFull) ||
		!strings.Contains(err.Error(), "unit not found") ||
		!strings.Contains(err.Error(), "provision-mtproxy-backend.sh") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChooseBackendDoesNotLoopWhenProvisioningAddsNothing(t *testing.T) {
	p, _, _ := twoBackendPaths(t)
	registry, _ := LoadBackends(p)
	calls := stubProvision(t, func() error { return nil })
	if _, err := chooseBackend(p, &registry, fullUsage()); err == nil {
		t.Fatal("expected an error when provisioning left every backend full")
	}
	if *calls != 1 {
		t.Fatalf("provisioned %d times, want a single attempt", *calls)
	}
}

func TestAddKeysRejectsOverMaxProfilesBeforeProvisioning(t *testing.T) {
	p := isolatedPaths(t) // max_profiles 5, one existing key
	p.Backends = filepath.Join(filepath.Dir(p.Profiles), "does-not-exist.json")
	calls := stubProvision(t, func() error { return nil })
	requests := make([]NewKeyRequest, 5)
	for i := range requests {
		requests[i] = NewKeyRequest{Name: fmt.Sprintf("extra%d", i)}
	}
	if _, err := AddKeys(p, requests); err == nil || !strings.Contains(err.Error(), "max_profiles") {
		t.Fatalf("expected a max_profiles error, got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("provisioned %d times for a batch the relay would reject", *calls)
	}
}

func TestApplyRejectsExceedingBackendLimitBeforeTouchingAnything(t *testing.T) {
	p, envA, _ := twoBackendPaths(t)
	// A relay binary that would prove this test wrong if it were ever
	// invoked: the over-limit check must reject before any -check dry run.
	p.RelayBin = filepath.Join(t.TempDir(), "would-fail-if-called")
	if err := os.WriteFile(p.RelayBin, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	file := &ProfileFile{}
	for i := 0; i < maxSecretsPerBackend+1; i++ {
		file.Profiles = append(file.Profiles, Profile{
			Name:    fmt.Sprintf("user%02d", i),
			Secret:  fmt.Sprintf("%032x", i+1),
			Backend: "127.0.0.1:2398",
		})
	}

	beforeProfiles, err := os.ReadFile(p.Profiles)
	if err != nil {
		t.Fatal(err)
	}

	err = Apply(p, file)
	if err == nil {
		t.Fatal("expected Apply to reject 17 secrets on one backend")
	}

	afterProfiles, err := os.ReadFile(p.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	if string(beforeProfiles) != string(afterProfiles) {
		t.Fatal("profiles.json was modified despite the rejected candidate")
	}
	if _, err := os.Stat(envA); err == nil {
		t.Fatal("backend env file was written despite the rejected candidate")
	}
}

func TestSyncBackendSecretsReportsOnlyChangedUnits(t *testing.T) {
	p, envA, envB := twoBackendPaths(t)
	registry, err := LoadBackends(p)
	if err != nil {
		t.Fatal(err)
	}
	file := &ProfileFile{Profiles: []Profile{
		{Name: "on-a", Secret: "00000000000000000000000000000001", Backend: "127.0.0.1:2398"},
		{Name: "on-b", Secret: "00000000000000000000000000000002", Backend: "127.0.0.1:2399"},
	}}

	changed, err := syncBackendSecrets(p, registry, file)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 2 {
		t.Fatalf("first sync: got %v, want both backends written", changed)
	}
	for _, path := range []string{envA, envB} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	// Re-syncing the identical file must be a no-op: nothing to restart.
	changed, err = syncBackendSecrets(p, registry, file)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Fatalf("unchanged re-sync: got %v, want no units reported", changed)
	}

	// Changing only backend B's assignment must report only that unit.
	file.Profiles[1].Secret = "00000000000000000000000000000009"
	changed, err = syncBackendSecrets(p, registry, file)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != "mtproxy@1.service" {
		t.Fatalf("single-backend change: got %v, want only mtproxy@1.service", changed)
	}
}

// TestSyncBackendSecretsPreservesForeignLines guards the exact bug found live
// on 2026-09-22: a freshly-provisioned backend's env file also carries
// MTPROXY_CLIENT_PORT/MTPROXY_ADMIN_PORT (written once by
// provision-mtproxy-backend.sh; mtproxy@.service's ExecStart depends on
// them and nothing else sets them). The first version of syncBackendSecrets
// overwrote the whole file with just its own two lines, silently blanking
// those out - mtproxy@1.service then failed with a literal, unexpanded
// "${MTPROXY_ADMIN_PORT}" on its command line the moment a key was assigned
// to it. Confirmed by reproducing it against the real systemd unit before
// this test (and the upsertSecretArgs fix) existed.
func TestSyncBackendSecretsPreservesForeignLines(t *testing.T) {
	p, _, envB := twoBackendPaths(t)
	provisioned := "MTPROXY_CLIENT_PORT=2399\nMTPROXY_ADMIN_PORT=8889\nMTPROXY_BACKEND_SECRET_ARGS=\n"
	if err := os.WriteFile(envB, []byte(provisioned), 0640); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadBackends(p)
	if err != nil {
		t.Fatal(err)
	}
	file := &ProfileFile{Profiles: []Profile{
		{Name: "on-b", Secret: "00000000000000000000000000000002", Backend: "127.0.0.1:2399"},
	}}
	if _, err := syncBackendSecrets(p, registry, file); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(envB)
	if err != nil {
		t.Fatal(err)
	}
	got := string(after)
	if !strings.Contains(got, "MTPROXY_CLIENT_PORT=2399") || !strings.Contains(got, "MTPROXY_ADMIN_PORT=8889") {
		t.Fatalf("provisioning's port lines were lost:\n%s", got)
	}
	if !strings.Contains(got, "MTPROXY_BACKEND_SECRET_ARGS=-S 00000000000000000000000000000002") {
		t.Fatalf("secret args were not written:\n%s", got)
	}
}

func TestDistinctGroupsSortedAndDeduped(t *testing.T) {
	p := isolatedPaths(t)
	meta := &Meta{Keys: map[string]KeyMeta{
		"a": {Group: "Глеб"},
		"b": {Group: "Глеб"},
		"c": {Group: "Катя"},
		"d": {Group: ""},
	}}
	if err := SaveMeta(p, meta); err != nil {
		t.Fatal(err)
	}
	got := DistinctGroups(p)
	if len(got) != 2 || got[0] != "Глеб" || got[1] != "Катя" {
		t.Fatalf("DistinctGroups = %v", got)
	}
}
