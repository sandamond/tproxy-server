#!/usr/bin/env bash
set -euo pipefail

# Adds one more official-MTProxy backend instance, for when the existing
# backend(s) are at official MTProxy's own hard ceiling of 16 client secrets
# per process (net/net-tcp-rpc-ext-server.c: assert(ext_secret_cnt < 16) in
# https://github.com/TelegramMessenger/MTProxy - not configurable, not ours
# to raise). tproxy-keys fills a new backend automatically like any other
# registered one, and starts this script itself (through
# tproxy-provision-backend.service) when a new key finds every backend full,
# so running it by hand only adds capacity ahead of time.
#
# The very first backend (127.0.0.1:2398, mtproxy.service) is never managed
# by this script or the mtproxy@.service template - it predates both and is
# left exactly as the reference installer set it up.

registry=/etc/tproxy-keys/backends.json
# mtproxy@.service sits next to this script, both in the repository's deploy/
# and in the root-owned /usr/local/lib/tproxy-keys/ copy that
# tproxy-provision-backend.service runs.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
	echo "run as root" >&2
	exit 1
fi
for required in nft systemctl; do
	if ! command -v "$required" >/dev/null 2>&1; then
		echo "$required is required" >&2
		exit 1
	fi
done
if ! command -v jq >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends jq
fi
if [[ ! -x /opt/MTProxy/objs/bin/mtproto-proxy ]]; then
	echo "official MTProxy is not built yet; run deploy/install.sh first" >&2
	exit 1
fi

install -d -o root -g root -m 0700 /etc/tproxy-keys
if [[ ! -f "$registry" ]]; then
	cat > "$registry" <<'JSON'
{"backends":[{"address":"127.0.0.1:2398","unit":"mtproxy.service","env_file":"/etc/mtproxy/mtproxy-keys.env"}]}
JSON
	chmod 0644 "$registry"
fi

# Instance indices are 1, 2, 3, ... - index 0 is the untemplated original.
# The next one is one past the highest already-provisioned template instance
# recorded in the registry (not just present in /etc/mtproxy, so a half
# -finished previous run doesn't get silently reused).
highest=0
while IFS= read -r unit; do
	if [[ "$unit" =~ ^mtproxy@([0-9]+)\.service$ ]]; then
		index="${BASH_REMATCH[1]}"
		if (( index > highest )); then
			highest="$index"
		fi
	fi
done < <(jq -r '.backends[].unit' "$registry")
next=$((highest + 1))
if (( next > 9 )); then
	# Not a real technical ceiling (the arithmetic below works fine past
	# instance 9) - just a sanity bound. 9 extra backends is 144 more keys on
	# top of the first 16; if a deployment genuinely needs more than that,
	# look at this script deliberately rather than let it run unattended.
	echo "instance index $next is past this script's sanity bound of 9; inspect before extending it" >&2
	exit 1
fi
client_port=$((2398 + next))
admin_port=$((8888 + next))

env_file="/etc/mtproxy/mtproxy-backend-${next}.env"
if [[ -e "$env_file" ]]; then
	echo "$env_file already exists; refusing to overwrite a possibly-live instance" >&2
	exit 1
fi
cat > "$env_file" <<EOF
# Written by provision-mtproxy-backend.sh. MTPROXY_BACKEND_SECRET_ARGS is
# rewritten by tproxy-keys as keys are assigned to this backend; do not edit
# the other two.
MTPROXY_CLIENT_PORT=${client_port}
MTPROXY_ADMIN_PORT=${admin_port}
MTPROXY_BACKEND_SECRET_ARGS=
EOF
chown root:mtproxy "$env_file"
chmod 0640 "$env_file"

install -m 0644 "$here/mtproxy@.service" /etc/systemd/system/mtproxy@.service

# Regenerate the full port list from every known instance (the original
# 2398/8888 plus every mtproxy@N.service, including the one just added)
# rather than appending live to the running nft table: the table is
# re-applied from this file on every boot and on any nftables.service
# reload, so the file is what must stay authoritative.
all_ports="2398 8888 ${client_port} ${admin_port}"
while IFS= read -r existing_unit; do
	if [[ "$existing_unit" =~ ^mtproxy@([0-9]+)\.service$ ]]; then
		existing_index="${BASH_REMATCH[1]}"
		all_ports="$all_ports $((2398 + existing_index)) $((8888 + existing_index))"
	fi
done < <(jq -r '.backends[].unit' "$registry")
port_set="$(printf '%s\n' $all_ports | sort -un | paste -sd, -)"
firewall_temp="$(mktemp /etc/tproxy-server/firewall.nft.XXXXXX)"
cat > "$firewall_temp" <<EOF
table inet tproxy_backend {
	chain local_backend {
		type filter hook input priority -10; policy accept;
		iifname != "lo" tcp dport { ${port_set} } drop
	}
}
EOF
install -m 0644 "$firewall_temp" /etc/tproxy-server/firewall.nft
rm -f "$firewall_temp"
systemctl daemon-reload
# reload, not restart: tproxy-server.service Requires= this unit, so a restart
# here would restart the relay and drop every live session. The unit's
# ExecReload re-applies the same file.
systemctl reload-or-restart tproxy-firewall.service

systemctl enable --now "mtproxy@${next}.service"
for ((attempt = 0; attempt != 10; ++attempt)); do
	if systemctl is-active --quiet "mtproxy@${next}.service"; then
		break
	fi
	sleep 1
done
if ! systemctl is-active --quiet "mtproxy@${next}.service"; then
	echo "mtproxy@${next}.service did not become active; inspect: journalctl -u mtproxy@${next} -n 50" >&2
	exit 1
fi

address="127.0.0.1:${client_port}"
updated="$(jq --arg address "$address" --arg unit "mtproxy@${next}.service" --arg env "$env_file" \
	'.backends += [{"address": $address, "unit": $unit, "env_file": $env}]' "$registry")"
printf '%s\n' "$updated" > "${registry}.tmp"
mv "${registry}.tmp" "$registry"

echo "Provisioned backend $address (mtproxy@${next}.service, admin port ${admin_port})."
echo "tproxy-keys will start filling it once the existing backend(s) reach 16 keys."
