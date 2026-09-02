#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "run this updater as root from the uploaded repository" >&2
	exit 1
fi

module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installed=/usr/local/bin/tproxy-keys
next=/usr/local/bin/tproxy-keys.next
previous=/usr/local/bin/tproxy-keys.previous
service=tproxy-keys.service
health=http://127.0.0.1:9000/
temporary="$(mktemp -d /tmp/tproxy-keys-update.XXXXXX)"
candidate="$temporary/tproxy-keys"
trap 'rm -rf -- "$temporary"' EXIT

if [[ ! -f "$installed" ]]; then
	echo "tproxy-keys is not installed; follow the manual install steps in keys-panel/README.md first" >&2
	exit 1
fi
for required_command in curl flock install systemctl; do
	if ! command -v "$required_command" >/dev/null 2>&1; then
		echo "$required_command is required" >&2
		exit 1
	fi
done
exec 9>/run/lock/tproxy-keys-update.lock
if ! flock -n 9; then
	echo "another tproxy-keys update is already running" >&2
	exit 1
fi

go_binary=
go_candidates=()
if command -v go >/dev/null 2>&1; then
	go_candidates+=("$(command -v go)")
fi
for found in /opt/go*/bin/go; do
	go_candidates+=("$found")
done
for found in "${go_candidates[@]}"; do
	if [[ ! -x "$found" ]]; then
		continue
	fi
	version="$("$found" env GOVERSION 2>/dev/null || true)"
	if [[ "$version" =~ ^go1\.([0-9]+) ]] && (( BASH_REMATCH[1] >= 24 )); then
		go_binary="$found"
		break
	fi
done
if [[ -z "$go_binary" ]]; then
	echo "Go 1.24 or newer was not found in PATH or /opt/go*/bin/go" >&2
	exit 1
fi

wait_for() {
	local url="$1"
	for ((attempt = 0; attempt != 20; ++attempt)); do
		if curl --fail --silent --output /dev/null "$url"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

rollback() {
	echo "New tproxy-keys failed verification; restoring $previous" >&2
	install -o root -g root -m 0755 "$previous" "$next"
	mv -f "$next" "$installed"
	if ! systemctl restart "$service" || ! wait_for "$health"; then
		echo "Rollback failed; inspect: journalctl -u $service -n 100 --no-pager" >&2
		return 1
	fi
	echo "Previous tproxy-keys restored and healthy" >&2
}

echo "Vetting tproxy-keys source"
(cd "$module_root" && "$go_binary" vet ./...)

echo "Building tproxy-keys candidate with $go_binary"
(cd "$module_root" && "$go_binary" build \
	-trimpath -ldflags='-s -w' -o "$candidate" .)

echo "Installing tproxy-keys candidate"
backup_next="$temporary/tproxy-keys.previous"
cp -a "$installed" "$backup_next"
install -o root -g root -m 0755 "$backup_next" "$previous"
install -o root -g root -m 0755 "$candidate" "$next"
mv -f "$next" "$installed"

echo "Restarting only $service"
if ! systemctl restart "$service" || ! wait_for "$health"; then
	rollback
	exit 1
fi

echo "tproxy-keys update complete"
echo "Existing panel sessions were invalidated; sign in again with the same token."
