#!/usr/bin/env bash
# CI-only offline First Boot gate. No host ports, host paths, or VPS access.
set -euo pipefail

if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
  echo "HOLD: This disposable container test is restricted to GitHub Actions CI." >&2
  exit 2
fi

for role in panel node; do
  image="smite-${role}:stage15-local"
  container="smite-ci-firstboot-${role}-${GITHUB_RUN_ID:-0}-${GITHUB_RUN_ATTEMPT:-1}"
  # Container secrets exist only for this disposable CI boot.
  secret="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

  cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  if [ "$role" = panel ]; then
    docker run -d --name "$container" --network none --read-only \
      --security-opt no-new-privileges --cap-drop ALL --pids-limit 128 \
      --tmpfs /tmp:rw,nosuid,nodev --tmpfs /app/data:rw,nosuid,nodev \
      --tmpfs /app/certs:rw,nosuid,nodev \
      -e "SECRET_KEY=$secret" \
      -e DB_PATH=/app/data/smite.db \
      -e DOCS_ENABLED=false \
      -e PANEL_PORT=8000 -e PANEL_HOST=127.0.0.1 \
      -e NODE_CERT_PATH=/app/certs/ca.crt -e NODE_KEY_PATH=/app/certs/ca.key \
      -e NODE_SERVER_CERT_PATH=/app/certs/ca-server.crt \
      -e NODE_SERVER_KEY_PATH=/app/certs/ca-server.key \
      "$image" >/dev/null
    port=8000
  else
    # No panel is available in this isolated network. Node liveness
    # is tested, not signed registration or tunnel reachability.
    docker run -d --name "$container" --network none --read-only \
      --security-opt no-new-privileges --cap-drop ALL --pids-limit 128 \
      --tmpfs /tmp:rw,nosuid,nodev --tmpfs /var/lib/smite-node:rw,nosuid,nodev \
      --tmpfs /etc/smite-node:rw,nosuid,nodev \
      -e NODE_API_PORT=8888 -e PANEL_CA_PATH=/tmp/no-external-panel-ca.crt \
      -e PANEL_ADDRESS=127.0.0.1:8000 \
      "$image" >/dev/null
    port=8888
  fi

  ready=0
  for attempt in $(seq 1 45); do
    if ! [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = true ]; then
      echo "HOLD: $role container exited before becoming ready" >&2
      break
    fi
    if docker exec "$container" python3 -c \
      "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$port/', timeout=2).close()" \
      >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done

  if [ "$ready" -ne 1 ]; then
    # Do not print the generated secret or full container environment.
    docker logs --tail 35 "$container" >&2 || true
    echo "HOLD: $role first boot did not pass localhost readiness" >&2
    exit 1
  fi

  if [ "$role" = panel ]; then
    docker exec -i "$container" python3 - <<'PY'
import json
import sqlite3
import urllib.error
import urllib.request

base = "http://127.0.0.1:8000"
with urllib.request.urlopen(base + "/api/status", timeout=8) as response:
    status = json.load(response)
assert status["nodes"]["total"] == 0
assert status["tunnels"]["total"] == 0

with urllib.request.urlopen(base + "/api/status/version", timeout=8) as response:
    version = json.load(response)["version"]
assert version == "2.0.0-rc.0", version

with urllib.request.urlopen(base + "/login", timeout=8) as response:
    assert response.status == 200
    assert b"<html" in response.read(1024).lower()

db = sqlite3.connect("file:/app/data/smite.db?mode=ro", uri=True)
columns = {row[1] for row in db.execute("PRAGMA table_info(admins)")}
expected = {"username", "password_hash", "totp_secret", "totp_pending_secret",
            "recovery_codes", "totp_last_counter", "auth_version",
            "mfa_failures", "mfa_locked_until"}
assert expected <= columns, sorted(expected - columns)
db.close()

request = urllib.request.Request(
    base + "/api/auth/login",
    json.dumps({"username": "nonexistent", "password": "invalid"}).encode(),
    {"Content-Type": "application/json"},
    method="POST",
)
try:
    urllib.request.urlopen(request, timeout=8)
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
    assert b"access_token" not in error.read()
else:
    raise AssertionError("Anonymous login succeeded")

print("PANEL_FIRSTBOOT=PASSED")
print("PANEL_MFA_SCHEMA=PRESENT")
print("PANEL_ANONYMOUS_LOGIN=DENIED")
print("PANEL_API_AND_UI=HTTP_200")
PY
  else
    docker exec -i "$container" python3 - <<'PY'
import json
import urllib.request
with urllib.request.urlopen("http://127.0.0.1:8888/", timeout=8) as response:
    payload = json.load(response)
assert payload == {"status": "ok", "service": "smite-node"}, payload
print("NODE_FIRSTBOOT_LIVENESS=PASSED")
print("NODE_SIGNED_REGISTRATION=NOT_TESTED")
PY
  fi

  cleanup
  trap - EXIT
done
echo "ISOLATED_FIRSTBOOT_ONLY=PASSED"
echo "NETWORK_ACCESS=NONE"
echo "HOST_PORTS_PUBLISHED=NONE"
echo "VPS_DEPLOYMENT=NO"
