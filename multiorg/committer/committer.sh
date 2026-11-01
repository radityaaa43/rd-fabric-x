#!/usr/bin/env bash
# One Fabric-X committer per bank on this host, next to BI's committer in the cluster.
# usage: committer.sh up|down|status [bank2|bank3|bank4 ...]   (default: all three)
# Needs: the bank's identity committer-<bank> (panurus-itest: make live-enroll), the forward shim for the
# assembler ports (panurus-itest: make live-assemble live-start), KUBECONFIG for the assembler NodePorts.
# Keys, config and data live in $RDBI_HOME/committer/<bank> (mode 0700), never in the repo.
set -euo pipefail
umask 077
here=$(cd "$(dirname "$0")" && pwd)
H="${RDBI_HOME:-$HOME/.fabricx-token}"
declare -A MSP=([bank2]=OrdererOrg2MSP [bank3]=OrdererOrg3MSP [bank4]=OrdererOrg4MSP)
declare -A CA=([bank2]=fca-orderer-org2 [bank3]=fca-orderer-org3 [bank4]=fca-orderer-org4)
declare -A PORT=([bank2]=25 [bank3]=35 [bank4]=45) # sidecar <PORT>130, query service <PORT>140

compose() {
  local b=$1 d="$H/committer/$1"
  shift
  BANK=$b MSP=${MSP[$b]} PORT=${PORT[$b]} CFG="$d/config" DATA="$d/data" UID_GID="$(id -u):$(id -g)" \
    DB_PASSWORD="$(cat "$d/db-password" 2>/dev/null || true)" docker compose -f "$here/compose.yaml" "$@"
}

up() {
  local b=$1 id="$H/ids/committer-$1" d="$H/committer/$1"
  [ -f "$id/tls/signcerts/cert.pem" ] || { echo "no identity $id: run make live-enroll first" >&2; exit 1; }
  mkdir -p "$d/config/tls" "$d/data"
  cp "$here"/config/*.yaml "$d/config/"
  rm -rf "$d/config/msp" && cp -r "$id/msp" "$d/config/msp"
  # the local MSP must classify identities by OU (the channel MSPs do the same); fabric-ca-client writes no config.yaml
  local ca; ca="cacerts/$(ls "$d/config/msp/cacerts" | head -1)"
  printf 'NodeOUs:\n  Enable: true\n' > "$d/config/msp/config.yaml"
  for ou in client peer admin orderer; do
    printf '  %sOUIdentifier: {Certificate: %s, OrganizationalUnitIdentifier: %s}\n' "${ou^}" "$ca" "$ou" >> "$d/config/msp/config.yaml"
  done
  cp "$id/tls/signcerts/cert.pem" "$d/config/tls/server.crt"
  cp "$id"/tls/keystore/* "$d/config/tls/server.key"
  cp "$H/${CA[$b]}-ca.pem" "$d/config/tls/ca.crt"
  cp "$H/multiorg/genesis-multiorg.block" "$d/config/config-block.pb.bin"
  [ -s "$d/db-password" ] || openssl rand -hex 24 > "$d/db-password"
  compose "$b" up -d
}

cmd=${1:?up|down|status}
shift
[ "$cmd" = up ] && kubectl apply -f "$here/assembler-nodeports.yaml" >/dev/null
for b in ${@:-bank2 bank3 bank4}; do
  case $cmd in
    up) up "$b" ;;
    down) compose "$b" down ;;
    status) compose "$b" ps --format '{{.Name}} {{.State}} {{.Status}}' ;;
  esac
done
