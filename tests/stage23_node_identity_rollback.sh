#!/usr/bin/env bash
# Stage23: actual Smite Node image, private read-only identity, durable replay,
# and fail-closed signed -> paused -> signed rollback. Disposable PR CI only.
# No published ports, network isolation, tunnels, host daemon configuration or VPS.
set -euo pipefail

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${GITHUB_EVENT_NAME:-}" != pull_request ]; then
  echo "HOLD: Stage23 destructive container trial requires disposable PR CI" >&2
  exit 2
fi

image="smite-node:stage15-local"
cid="smite-stage23-${GITHUB_RUN_ID:-0}-${GITHUB_RUN_ATTEMPT:-1}"
lab="$(mktemp -d)"
chmod 700 "$lab"
cleanup() {
  docker rm -f "$cid" >/dev/null 2>&1 || true
  sudo chown -R "$(id -u):$(id -g)" "$lab" 2>/dev/null || true
  rm -rf -- "$lab"
}
trap cleanup EXIT

mkdir -m 700 "$lab/identity" "$lab/replay"
# The Node identity never enters command-line flags, logs, Compose or images.
python3 - "$lab/identity/node-identity.json" <<'PY'
import json, os, secrets, sys
path = sys.argv[1]
with open(path, "x", encoding="ascii") as stream:
    json.dump({"version":1, "node_id":"stage23-kh-reserved-0001",
               "node_secret":secrets.token_hex(32)}, stream, separators=(",",":"))
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(path, 0o600)
PY
initial_id_sha="$(sha256sum "$lab/identity/node-identity.json" | awk '{print $1}')"
# Simulate the root-owned 0700 host credential volume from real KH.
# Never lower the permission requirements in Smite to fit a CI runner.
sudo chown -R 0:0 "$lab/identity" "$lab/replay"

# Boot command identical in all three modes. Underlying Node import needs
# writable ephemeral adapter config; identity is a separate readonly bind.
start_node() {
  local mode="$1" identity="$2"
  local args=(
    docker run -d --name "$cid" --network none --read-only
    --security-opt no-new-privileges --cap-drop ALL --pids-limit 128
    --tmpfs /tmp:rw,nosuid,nodev
    --tmpfs /etc/smite-node:rw,nosuid,nodev
    --tmpfs /var/lib/smite-node:rw,nosuid,nodev
    -e NODE_API_PORT=8888 -e NODE_ROLE=foreign
    -e PANEL_ADDRESS=panel.stage23.test:443
    -e PANEL_CA_PATH=/tmp/stage23-no-ca.pem
    -e SMITE_NODE_PANEL_AUTH_MODE="$mode"
    -e SMITE_AGENT_AUTH_MODE=strict
    -e SMITE_AGENT_IDENTITY_PATH=/run/smite-node-identity/node-identity.json
    -e SMITE_AGENT_REPLAY_DB=/var/lib/smite-node/auth/agent-replay.sqlite3
  )
  if [ "$identity" = yes ]; then
    args+=(
      --mount "type=bind,source=$lab/identity,target=/run/smite-node-identity,readonly"
      --mount "type=bind,source=$lab/replay,target=/var/lib/smite-node/auth"
    )
  fi
  args+=("$image")
  "${args[@]}" >/dev/null
  local ready=0
  for attempt in $(seq 1 50); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" != true ]; then
      echo "HOLD: Stage23 Node exited during $mode boot" >&2
      exit 1
    fi
    if docker exec "$cid" python3 -c         "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8888/',timeout=2)"         >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    echo "HOLD: Node never became locally ready in $mode mode" >&2
    exit 1
  fi
}
stop_node() { docker rm -f "$cid" >/dev/null; }

# Phase 1: Fresh paused KH; no identity is mounted. Even a valid-looking
# unsigned Agent request must fail closed, not fall back to legacy.
start_node paused no
docker exec -i "$cid" python3 - <<'PY'
import asyncio, urllib.error, urllib.request
from app.config import settings
from app.panel_client import PanelClient
assert settings.smite_node_panel_auth_mode == "paused"
assert settings.smite_agent_auth_mode == "strict"
client = PanelClient()
asyncio.run(client.start())
assert client.client is None
assert asyncio.run(client.register_with_panel()) is False
try:
    urllib.request.urlopen("http://127.0.0.1:8888/api/agent/status",timeout=3)
except urllib.error.HTTPError as exc:
    assert exc.code == 503, exc.code
else: raise AssertionError("Unpaired Node Agent accepted unauthenticated access")
PY
stop_node
echo "STAGE23_UNPAIRED_PAUSED=FAIL_CLOSED"

# Phase 2: A signed KH without a mounted key must likewise never downgrade.
start_node signed no
docker exec -i "$cid" python3 - <<'PY'
import asyncio, urllib.error, urllib.request
from app.config import settings
from app.panel_client import PanelClient
assert settings.smite_node_panel_auth_mode == "signed"
c = PanelClient()
asyncio.run(c.start())
assert c.client is None, "legacy verify=False client was constructed"
assert asyncio.run(c.register_with_panel()) is False
try: urllib.request.urlopen("http://127.0.0.1:8888/api/agent/status",timeout=4)
except urllib.error.HTTPError as ex: assert ex.code == 503, ex.code
else: raise AssertionError("No-identity signed Node accepted anonymous request")
PY
stop_node
echo "STAGE23_MISSING_IDENTITY_SIGNED=FAIL_CLOSED"

# Phase 3: Paired identity visible INSIDE Node, but mount is immutable.
start_node signed yes
docker exec -i "$cid" python3 - <<'PY'
import asyncio
import json
from pathlib import Path
import urllib.request
import urllib.error
from app.agent_auth import read_identity
from app.config import settings
from app.node_auth import sign_request
from app.panel_client import PanelClient

p = Path(settings.smite_agent_identity_path)
node_id, secret = read_identity(p)
assert node_id == "stage23-kh-reserved-0001"
assert len(secret) == 64
assert settings.smite_node_panel_auth_mode == "signed"
assert settings.smite_agent_auth_mode == "strict"
assert not p.is_symlink()
try:
    p.write_text("overwrite-attempt")
except OSError:
    pass
else: raise AssertionError("Container was able to alter read-only identity")
client = PanelClient()
asyncio.run(client.start())
assert client.client is None, "signed mode used legacy no-verify client"
assert asyncio.run(client.register_with_panel()) is False, "offline panel connected"
base = "http://127.0.0.1:8888/api/agent/status"
try:
    urllib.request.urlopen(base, timeout=3)
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
else: raise AssertionError("Signed Agent allowed anonymous access")
headers = sign_request(
    secret=secret, node_id=node_id, method="GET",
    target="/api/agent/status", body=b"", nonce="a"*32)
request = urllib.request.Request(base, headers=headers, method="GET")
with urllib.request.urlopen(request, timeout=5) as response:
    assert response.status == 200
    assert json.load(response)["status"] == "ok"
try:
    urllib.request.urlopen(request, timeout=5)
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
else: raise AssertionError("Replay was accepted inside actual Node")
try:
    urllib.request.urlopen(urllib.request.Request(
        "http://127.0.0.1:8888/api/agent/tunnels/apply",
        data=b"{}",headers={"Content-Type":"application/json"},method="POST"
    ),timeout=5)
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
else: raise AssertionError("Unsigned apply was not blocked")
PY
sudo test -s "$lab/replay/agent-replay.sqlite3"
test "$(sudo stat -c %a "$lab/replay/agent-replay.sqlite3")" = 600
test "$(sudo sha256sum "$lab/identity/node-identity.json" | awk '{print $1}')" = "$initial_id_sha"
stop_node
echo "STAGE23_SIGNED_IDENTITY_READONLY_AGENT=PASS"
echo "STAGE23_STRICT_NO_REPLAY_OR_UNSIGNED_APPLY=PASS"

# Phase 4: Roll back to paused without mounting identity. The generated key
# and replay DB survive unmodified on the host. No legacy auth is activated.
replay_before="$(sudo sha256sum "$lab/replay/agent-replay.sqlite3" | awk '{print $1}')"
start_node paused no
docker exec -i "$cid" python3 - <<'PY'
import urllib.request, urllib.error
from app.config import settings
assert settings.smite_node_panel_auth_mode == "paused"
assert settings.smite_agent_auth_mode == "strict"
try: urllib.request.urlopen("http://127.0.0.1:8888/api/agent/status",timeout=4)
except urllib.error.HTTPError as e: assert e.code == 503, e.code
else: raise AssertionError("Rolled-back Node allowed unsigned Agent request")
PY
stop_node
test "$(sudo sha256sum "$lab/identity/node-identity.json" | awk '{print $1}')" = "$initial_id_sha"
test "$(sudo sha256sum "$lab/replay/agent-replay.sqlite3" | awk '{print $1}')" = "$replay_before"
echo "STAGE23_PAUSED_ROLLBACK_PRIVATE_STATE_PRESERVED=PASS"

# Phase 5: Re-enable signed after paused mode. Replayed nonce from before
# the rollback must still be rejected across the fresh Node process.
start_node signed yes
docker exec -i "$cid" python3 - <<'PY'
import json, urllib.request, urllib.error
from app.config import settings
from app.agent_auth import read_identity
from app.node_auth import sign_request
node_id, secret = read_identity(settings.smite_agent_identity_path)
def fetch(nonce):
    headers = sign_request(secret=secret,node_id=node_id,method="GET",
                           target="/api/agent/status",body=b"",nonce=nonce)
    req = urllib.request.Request("http://127.0.0.1:8888/api/agent/status",
                                 headers=headers,method="GET")
    return urllib.request.urlopen(req,timeout=4)
try: fetch("a"*32)
except urllib.error.HTTPError as e: assert e.code == 401, e.code
else: raise AssertionError("Restart/rollback reopened replay window")
with fetch("b"*32) as response:
    assert response.status == 200
    assert json.load(response)["status"] == "ok"
PY
stop_node
test "$(sudo sha256sum "$lab/identity/node-identity.json" | awk '{print $1}')" = "$initial_id_sha"
echo "STAGE23_SIGNED_REENABLE_REPLAY_PERSISTENCE=PASS"
echo "STAGE23_VPS_PORTS_REGISTRY_PRODUCTION=UNTOUCHED"
