#!/usr/bin/env bash
# Deploy the hecate-sentinel — the threat brain — on the beam cluster.
#
# ONE instance for now. It hears every warden's facts off the mesh, so it does
# not need to be near any particular box; it just needs to be in the realm. It
# owns a reckon-db store (the evidence chain), so its data lands on /bulk0 like
# every other stateful thing on the cluster. It runs on the BEAM side, never on
# an attacked box — the evidence must live where the attacks do not.
#
# Host networking, for the same reason as the stations: the beam boxes reach the
# IPv6-only stations only with the host's public IPv6. No watchtower label: the
# fleet is rolled deliberately.
#
#   HECATE_REALM=<64-hex> ./scripts/deploy-sentinel.sh [host] [station-seed]
set -euo pipefail

IMAGE="${SENTINEL_IMAGE:-ghcr.io/hecate-services/hecate-sentinel:latest}"
REALM="${HECATE_REALM:?set HECATE_REALM to the 64-hex realm tag}"
HOST="${1:-beam02.lab}"
SEED="${2:-https://station-de-frankfurt.macula.io:4433}"

ssh -o BatchMode=yes "rl@${HOST}" \
    "IMAGE='${IMAGE}' REALM='${REALM}' SEED='${SEED}' bash -s" <<'REMOTE'
set -euo pipefail
docker pull "$IMAGE" >/dev/null
data="/bulk0/hecate/sentinel"
docker rm -f hecate-sentinel >/dev/null 2>&1 || true
docker run -d --name hecate-sentinel --restart unless-stopped --network host \
  -e HECATE_REALM="$REALM" \
  -e MACULA_STATION_SEEDS="$SEED" \
  -e HECATE_NODE_NAME=hecate_sentinel \
  -e HECATE_NODE_HOST=127.0.0.1 \
  -e HECATE_COOKIE=hecate_sentinel \
  -e HECATE_HEALTH_PORT=8450 \
  -e HECATE_DATA_DIR=/data \
  -e HECATE_SENTINEL_GEOIP=/geoip \
  -v "${data}:/data" \
  -v /bulk0/hecate/geoip:/geoip:ro \
  "$IMAGE" >/dev/null
echo "  hecate-sentinel up on $(hostname) -> ${SEED}"
REMOTE
