#!/usr/bin/env bash
# Start / stop the five token nodes and the shim forwarder on this host.
# usage: run.sh start|stop|status|stop-node NAME|start-node NAME      env: RDBI_HOME (default ~/.fabricx-token)
set -euo pipefail
H="${RDBI_HOME:-$HOME/.fabricx-token}"; BIN="$H/bin/rdbi-node"; L="$H/live"; PIDS="$L/pids"
nodes=(endorser-1 endorser-2 endorser-3 endorser-4 issuer bank2 bank3 bank4)
launch() { # NAME -> prints pid
  local n="$1"
  # BI (auditor) and the banks read their limits from policy.env; see patches/panurus-auditor-limits.patch
  if [ -f "$L/$n/policy.env" ]; then set -a; . "$L/$n/policy.env"; set +a; fi
  FSCNODE_CFG_PATH="$L/$n" RDBI_ROLE="$(cat "$L/$n/role")" RDBI_NETSHIM="$L/netshim-dns.json" \
    nohup "$BIN" node start > "$L/$n/node.log" 2>&1 & echo $!
}
start() {
  [ -s "$PIDS" ] && { echo "already started (see $PIDS); run stop first" >&2; exit 1; }
  : > "$PIDS"
  RDBI_ROLE=forward RDBI_NETSHIM="$L/netshim-forward.json" nohup "$BIN" > "$L/forward.log" 2>&1 & echo "forward $!" >> "$PIDS"
  sleep 1
  for n in "${nodes[@]}"; do echo "$n $(launch "$n")" >> "$PIDS"; done
  echo started; cat "$PIDS"
}
stop() { [ -s "$PIDS" ] || { echo "nothing to stop"; return; }
  while read -r n p; do kill "$p" 2>/dev/null && echo "stopped $n" || echo "$n not running"; done < "$PIDS"; : > "$PIDS"; }
status() { while read -r n p; do kill -0 "$p" 2>/dev/null && echo "up   $n ($p)" || echo "DOWN $n ($p)"; done < "$PIDS"; }
stop_node() { local n="$1" p; p=$(awk -v n="$n" '$1==n{print $2}' "$PIDS"); [ -n "$p" ] && kill "$p" 2>/dev/null && echo "stopped $n" || echo "$n not running"; }
start_node() { local n="$1" p; p=$(awk -v n="$n" '$1==n{print $2}' "$PIDS")
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then echo "$n already running" >&2; exit 1; fi
  p=$(launch "$n"); grep -v "^$n " "$PIDS" > "$PIDS.tmp" || true; echo "$n $p" >> "$PIDS.tmp"; mv "$PIDS.tmp" "$PIDS"; echo "started $n ($p)"; }
case "${1:?start|stop|status|stop-node NAME|start-node NAME}" in
  start) start ;; stop) stop ;; status) status ;;
  stop-node) stop_node "${2:?node name}" ;; start-node) start_node "${2:?node name}" ;;
esac
