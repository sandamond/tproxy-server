package main

import (
	"os"
	"path/filepath"
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
