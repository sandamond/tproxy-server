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
	case "revoke":
		cmdRevoke(paths, arguments)
	case "rotate":
		cmdRotate(paths, arguments)
	case "link":
		cmdLink(paths, arguments)
	case "status":
		cmdStatus(paths)
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

  list                            show every key with its client link
  add    -name N [-label L] [-mode M]   create a key and apply it
  revoke -name N                  delete a key and apply
  rotate -name N                  issue a new secret for an existing key
  link   -name N                  print the client link for one key
  status                          service and readiness overview
  sync                            rebuild MTProxy secrets from the profiles file
  serve  [-listen 127.0.0.1:9000] run the local web panel
  token                           print the web panel access token

Carrier modes: https (default), https-lanes, websocket, websocket-lanes.
Adding, revoking or rotating a key restarts the relay: live carrier sessions
drop and clients reconnect on their own.
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
	fmt.Fprintln(writer, "NAME\tLABEL\tMODE\tSECRET\tCREATED")
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
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", view.Profile.Name, label, mode, view.Profile.Secret, created)
	}
	writer.Flush()
	fmt.Printf("\nHostname: %s\n", host)
}

func cmdAdd(paths Paths, arguments []string) {
	set := flag.NewFlagSet("add", flag.ExitOnError)
	name := set.String("name", "", "key name (a-z A-Z 0-9 . _ -)")
	label := set.String("label", "", "free-form label shown in the panel")
	mode := set.String("mode", "", "carrier mode: "+carrierModes)
	set.Parse(arguments)
	if *name == "" {
		fail("-name is required")
	}
	profile, err := AddKey(paths, *name, *label, *mode)
	if err != nil {
		fail(err.Error())
	}
	host := PublicHostname(paths)
	fmt.Printf("added %s\n\nHostname: %s\nSecret:   %s\nLink:     %s\n",
		profile.Name, host, profile.Secret, ClientLink(host, profile.Secret))
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
