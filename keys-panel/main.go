// tproxy-keys manages the client keys of a tproxy-server deployment: the relay
// profile list and the matching official MTProxy secret arguments, applied
// together and validated by the relay itself before anything goes live.
//
// It deliberately offers no network surface on the public hostname. The web UI
// binds a loopback address and is reached through an SSH tunnel.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fail("tproxy-keys must run as root: it reads and writes mode-0400 configuration and restarts services")
	}
	paths := DefaultPaths()
	command := os.Args[1]
	arguments := os.Args[2:]

	switch command {
	case "list":
		cmdList(paths)
	case "add":
		cmdAdd(paths, arguments)
	case "import":
		cmdImport(paths, arguments)
	case "edit":
		cmdEdit(paths, arguments)
	case "revoke":
		cmdRevoke(paths, arguments)
	case "rotate":
		cmdRotate(paths, arguments)
	case "link":
		cmdLink(paths, arguments)
	case "status":
		cmdStatus(paths)
	case "backends":
		cmdBackends(paths)
	case "sync":
		if err := Sync(paths); err != nil {
			fail(err.Error())
		}
		fmt.Println("backend secrets synced and services restarted")
	case "serve":
		cmdServe(paths, arguments)
	case "token":
		cmdToken(paths)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tproxy-keys — client keys for a tproxy-server deployment

  list                                   show every key with its client link
  add    -name N [-label L] [-group G] [-mode M]   create a key and apply it
  import -file PATH                      create many keys from a TSV file, one restart total
  edit   -name N [-label L] [-group G]   change a key's label/group only (no restart)
  revoke -name N                         delete a key and apply
  rotate -name N                         issue a new secret for an existing key
  link   -name N                         print the client link for one key
  status                                 service and readiness overview
  backends                               list registered MTProxy backends and how full each is
  sync                                   rebuild MTProxy secrets from the profiles file
  serve  [-listen 127.0.0.1:9000]        run the local web panel
  token                                  print the web panel access token

Carrier modes: https (default), https-lanes, websocket, websocket-lanes.
Adding, revoking or rotating a key restarts the relay: live carrier sessions
drop and clients reconnect on their own. edit only rewrites bookkeeping
(label, group) and never restarts anything.

import reads tab-separated lines "name<TAB>label<TAB>group<TAB>mode" (label,
group, mode may be empty; trailing columns may be omitted) and applies them
all as one batch - one restart instead of one per key.
`)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "error: "+message)
	os.Exit(1)
}

func cmdList(paths Paths) {
	views, host, err := Keys(paths)
	if err != nil {
		fail(err.Error())
	}
	if host == "" {
		fmt.Fprintln(os.Stderr, "warning: public_hostname is unset in the relay configuration")
	}
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tLABEL\tGROUP\tMODE\tSECRET\tCREATED")
	for _, view := range views {
		mode := view.Profile.CarrierMode
		if mode == "" {
			mode = "https"
		}
		created := view.Meta.Created
		if created == "" {
			created = "-"
		}
		label := view.Meta.Label
		if label == "" {
			label = "-"
		}
		group := view.Meta.Group
		if group == "" {
			group = "-"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n", view.Profile.Name, label, group, mode, view.Profile.Secret, created)
	}
	writer.Flush()
	fmt.Printf("\nHostname: %s\n", host)
}

func cmdAdd(paths Paths, arguments []string) {
	set := flag.NewFlagSet("add", flag.ExitOnError)
	name := set.String("name", "", "key name (a-z A-Z 0-9 . _ -)")
	label := set.String("label", "", "free-form label shown in the panel")
	group := set.String("group", "", "free-form group, e.g. the responsible person's name")
	mode := set.String("mode", "", "carrier mode: "+carrierModes)
	set.Parse(arguments)
	if *name == "" {
		fail("-name is required")
	}
	added, err := AddKeys(paths, []NewKeyRequest{{Name: *name, Label: *label, Group: *group, Mode: *mode}})
	if err != nil {
		fail(err.Error())
	}
	profile := added[0]
	host := PublicHostname(paths)
	fmt.Printf("added %s\n\nHostname: %s\nSecret:   %s\nLink:     %s\n",
		profile.Name, host, profile.Secret, ClientLink(host, profile.Secret))
}

// cmdImport bulk-creates keys from a TSV file: name, label, group, mode (the
// last three columns optional, may be omitted entirely on a line). Meant for
// migrating an existing list of users from another proxy in one shot - one
// restart for the whole file, not one per line.
func cmdImport(paths Paths, arguments []string) {
	set := flag.NewFlagSet("import", flag.ExitOnError)
	path := set.String("file", "", "path to a TSV file: name<TAB>label<TAB>group<TAB>mode")
	set.Parse(arguments)
	if *path == "" {
		fail("-file is required")
	}
	contents, err := os.ReadFile(*path)
	if err != nil {
		fail(err.Error())
	}
	var requests []NewKeyRequest
	for lineNumber, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		columns := strings.Split(line, "\t")
		request := NewKeyRequest{Name: strings.TrimSpace(columns[0])}
		if len(columns) > 1 {
			request.Label = strings.TrimSpace(columns[1])
		}
		if len(columns) > 2 {
			request.Group = strings.TrimSpace(columns[2])
		}
		if len(columns) > 3 {
			request.Mode = strings.TrimSpace(columns[3])
		}
		if request.Name == "" {
			fail(fmt.Sprintf("%s:%d: empty name", *path, lineNumber+1))
		}
		requests = append(requests, request)
	}
	if len(requests) == 0 {
		fail("no data rows found in " + *path)
	}
	fmt.Fprintf(os.Stderr, "importing %d keys in one batch (one restart)\n", len(requests))
	added, err := AddKeys(paths, requests)
	if err != nil {
		fail(err.Error())
	}
	host := PublicHostname(paths)
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tSECRET\tLINK")
	for _, profile := range added {
		fmt.Fprintf(writer, "%s\t%s\t%s\n", profile.Name, profile.Secret, ClientLink(host, profile.Secret))
	}
	writer.Flush()
}

func cmdEdit(paths Paths, arguments []string) {
	set := flag.NewFlagSet("edit", flag.ExitOnError)
	name := set.String("name", "", "key name")
	label := set.String("label", "", "new label (omit to leave unchanged)")
	group := set.String("group", "", "new group (omit to leave unchanged)")
	set.Parse(arguments)
	if *name == "" {
		fail("-name is required")
	}
	// An omitted -label/-group must leave that field alone, not blank it - so
	// track which flags were actually passed rather than trusting the string
	// being non-empty (clearing a label to "" on purpose is also valid).
	labelSet, groupSet := false, false
	set.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "label":
			labelSet = true
		case "group":
			groupSet = true
		}
	})
	views, _, err := Keys(paths)
	if err != nil {
		fail(err.Error())
	}
	current := KeyMeta{}
	found := false
	for _, view := range views {
		if view.Profile.Name == *name {
			current = view.Meta
			found = true
			break
		}
	}
	if !found {
		fail(fmt.Sprintf("no key named %q", *name))
	}
	newLabel, newGroup := current.Label, current.Group
	if labelSet {
		newLabel = *label
	}
	if groupSet {
		newGroup = *group
	}
	if err := UpdateKeyMeta(paths, *name, newLabel, newGroup); err != nil {
		fail(err.Error())
	}
	fmt.Printf("updated %s (no restart needed)\n", *name)
}

func cmdRevoke(paths Paths, arguments []string) {
	set := flag.NewFlagSet("revoke", flag.ExitOnError)
	name := set.String("name", "", "key name")
	set.Parse(arguments)
	if *name == "" {
		fail("-name is required")
	}
	if err := RevokeKey(paths, *name); err != nil {
		fail(err.Error())
	}
	fmt.Printf("revoked %s\n", *name)
}

func cmdRotate(paths Paths, arguments []string) {
	set := flag.NewFlagSet("rotate", flag.ExitOnError)
	name := set.String("name", "", "key name")
	set.Parse(arguments)
	if *name == "" {
		fail("-name is required")
	}
	profile, err := RotateKey(paths, *name)
	if err != nil {
		fail(err.Error())
	}
	host := PublicHostname(paths)
	fmt.Printf("rotated %s\n\nHostname: %s\nSecret:   %s\nLink:     %s\n",
		profile.Name, host, profile.Secret, ClientLink(host, profile.Secret))
}

func cmdLink(paths Paths, arguments []string) {
	set := flag.NewFlagSet("link", flag.ExitOnError)
	name := set.String("name", "", "key name")
	set.Parse(arguments)
	views, host, err := Keys(paths)
	if err != nil {
		fail(err.Error())
	}
	for _, view := range views {
		if view.Profile.Name == *name {
			fmt.Printf("Hostname: %s\nSecret:   %s\nLink:     %s\n", host, view.Profile.Secret, view.Link)
			return
		}
	}
	fail(fmt.Sprintf("no key named %q", *name))
}

func cmdStatus(paths Paths) {
	views, host, err := Keys(paths)
	keyCount := len(views)
	if err != nil {
		fmt.Printf("profiles:      unreadable (%v)\n", err)
		keyCount = 0
	}
	state, readyErr := readyState(paths)
	if readyErr != nil {
		state = "unreachable"
	}
	fmt.Printf("hostname:      %s\nkeys:          %d\nrelay ready:   %s\n", host, keyCount, state)
	for _, unit := range []string{"caddy.service", "mtproxy.service", "tproxy-server.service", "tproxy-keys.service"} {
		active := "inactive"
		if unitActive(unit) {
			active = "active"
		}
		fmt.Printf("%-14s %s\n", strings.TrimSuffix(unit, ".service")+":", active)
	}
}

func cmdBackends(paths Paths) {
	registry, err := LoadBackends(paths)
	if err != nil {
		fail(err.Error())
	}
	file, err := LoadProfiles(paths)
	if err != nil {
		fail(err.Error())
	}
	usage := backendUsage(file)
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "ADDRESS\tUNIT\tUSED\tROOM")
	for _, backend := range registry.Backends {
		used := usage[backend.Address]
		fmt.Fprintf(writer, "%s\t%s\t%d/%d\t%d\n", backend.Address, backend.Unit, used, maxSecretsPerBackend, maxSecretsPerBackend-used)
	}
	writer.Flush()
	full := true
	for _, backend := range registry.Backends {
		if usage[backend.Address] < maxSecretsPerBackend {
			full = false
			break
		}
	}
	if full {
		fmt.Println("\nEvery registered backend is full; run deploy/provision-mtproxy-backend.sh before adding another key.")
	}
}

// cmdToken prints the panel access token, creating it on first use.
func cmdToken(paths Paths) {
	token, err := ensureToken(paths)
	if err != nil {
		fail(err.Error())
	}
	fmt.Println(token)
}

func ensureToken(paths Paths) (string, error) {
	if raw, err := os.ReadFile(paths.Token); err == nil {
		if value := strings.TrimSpace(string(raw)); value != "" {
			return value, nil
		}
	}
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buffer)
	if err := os.MkdirAll("/etc/tproxy-keys", 0700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(paths.Token, []byte(token+"\n"), 0400, ""); err != nil {
		return "", err
	}
	return token, nil
}
