"""Inert trial foundation for administrator-authorized Foreign installation.

No HTTP route, startup migration or trusted-origin fallback imports this yet.
Callers must authenticate admin issuance and enforce verified TLS ingress.
The installer must durably save its random 256-bit Node secret BEFORE redeeming.
Redemption stores that secret encrypted, never returns a secret, and atomically
binds the exact approved origin. Lost replies can be retried with identical
credentials before grant expiry; expiry never revokes an established identity.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets

from cryptography.fernet import InvalidToken
from app import node_pairing_store as pairing

DEFAULT_TTL = 7200
MAX_TTL = 7200
PREFIX = "smi1_"
_DOMAIN = re.compile(r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}\Z")
_SECRET = re.compile(r"[0-9a-f]{64}\Z")
_CODE = re.compile(r"smi1_[A-Za-z0-9_-]{43}\Z")
_PATH = re.compile(r"/smite-node/[0-9a-f]{32}\Z")


@dataclass(frozen=True)
class Grant:
    node_id: str
    node_name: str
    origin: str
    control_url: str
    expires_at: int
    code: str = field(repr=False)


def _deny():
    raise pairing.PairingDenied("Foreign installation denied")


def normalize_domain(value: str) -> str:
    # Syntax validation only. Network adapters must also pin public DNS results,
    # deny private/link-local targets and redirects, and validate TLS certificates.
    if not isinstance(value, str):
        _deny()
    domain = value.lower()
    if not _DOMAIN.fullmatch(domain) or domain.endswith((".localhost", ".local", ".internal", ".home", ".lan", ".test", ".invalid", ".example", ".onion")):
        _deny()
    return domain


def _hash(code: str) -> str:
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        _deny()
    return hashlib.sha256(b"smite-foreign-install-v1\0" + code.encode("ascii")).hexdigest()


def _node(conn, node_id: str, name: str) -> bool:
    row = conn.execute("SELECT name,metadata FROM nodes WHERE id=?", (node_id,)).fetchone()
    if not row or row["name"] != name:
        return False
    try:
        meta = json.loads(row["metadata"] or "{}")
        return isinstance(meta, dict) and meta.get("role") == "foreign" and meta.get("provisioning") == "reserved_for_pairing"
    except (ValueError, TypeError):
        return False


def initialize_schema(database_path):
    """Explicit additive migration; requires the existing pairing schema first."""
    with closing(pairing._open_database(database_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("SELECT node_id FROM smite_node_identities LIMIT 0")
            conn.execute("SELECT code_hash FROM smite_node_pairing_codes LIMIT 0")
            conn.execute("""CREATE TABLE IF NOT EXISTS smite_foreign_install_grants (
                code_hash TEXT PRIMARY KEY, node_id TEXT NOT NULL,
                node_name TEXT NOT NULL, origin TEXT NOT NULL,
                control_url TEXT NOT NULL, issued_by TEXT NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                consumed_at INTEGER, revoked_at INTEGER)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS smite_foreign_install_origins (
                node_id TEXT PRIMARY KEY, node_name TEXT NOT NULL,
                origin TEXT NOT NULL, control_url TEXT NOT NULL,
                grant_hash TEXT NOT NULL UNIQUE, approved_at INTEGER NOT NULL)""")
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def issue(database_path, *, master_key, admin_id: str, node_id: str,
          node_name: str, domain: str, ttl_seconds: int = DEFAULT_TTL, now=None) -> Grant:
    """The API caller must authenticate admin_id; this is not an auth endpoint."""
    pairing._fernet(master_key)
    pairing._validate_node_id(node_id)
    if not isinstance(admin_id, str) or not admin_id or not isinstance(node_name, str) or not _NAME.fullmatch(node_name):
        _deny()
    if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= MAX_TTL:
        _deny()
    origin = "https://" + normalize_domain(domain) + ":443"
    code = PREFIX + secrets.token_urlsafe(32)
    hashed = _hash(code)
    current = pairing._now(now)
    with closing(pairing._open_database(database_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if not _node(conn, node_id, node_name) or conn.execute("SELECT 1 FROM smite_node_identities WHERE node_id=?", (node_id,)).fetchone():
                _deny()
            if conn.execute("SELECT 1 FROM smite_foreign_install_origins WHERE node_id=?", (node_id,)).fetchone():
                _deny()
            # Reissue preserves the pending grant's control path for the same
            # name/origin; do not force an installed Gateway to be rewritten.
            previous = conn.execute("SELECT control_url FROM smite_foreign_install_grants WHERE node_id=? AND node_name=? AND origin=? ORDER BY rowid DESC LIMIT 1", (node_id, node_name, origin)).fetchone()
            control = previous[0] if previous else origin + "/smite-node/" + secrets.token_hex(16)
            if not control.startswith(origin) or not _PATH.fullmatch(control[len(origin):]):
                _deny()
            conn.execute("UPDATE smite_foreign_install_grants SET revoked_at=? WHERE node_id=? AND revoked_at IS NULL", (current, node_id))
            conn.execute("UPDATE smite_node_pairing_codes SET consumed_at=? WHERE node_id=? AND consumed_at IS NULL", (current, node_id))
            conn.execute("INSERT INTO smite_foreign_install_grants VALUES (?,?,?,?,?,?,?,?,NULL,NULL)", (hashed, node_id, node_name, origin, control, admin_id, current, current + ttl_seconds))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return Grant(node_id, node_name, origin, control, current + ttl_seconds, code)


def redeem(database_path, *, master_key, code: str, node_id: str,
           node_name: str, control_url: str, node_secret: str, now=None) -> bool:
    """True for first commit or exact retry; no secret returned or rekey allowed."""
    cipher = pairing._fernet(master_key)
    hashed = _hash(code)
    pairing._validate_node_id(node_id)
    if not isinstance(node_secret, str) or not _SECRET.fullmatch(node_secret):
        _deny()
    current = pairing._now(now)
    with closing(pairing._open_database(database_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            grant = conn.execute("SELECT * FROM smite_foreign_install_grants WHERE code_hash=?", (hashed,)).fetchone()
            if not grant or grant["revoked_at"] is not None or current >= grant["expires_at"] or current < grant["issued_at"] or grant["node_id"] != node_id or grant["node_name"] != node_name or grant["control_url"] != control_url or not _node(conn, node_id, node_name):
                _deny()
            identity = conn.execute("SELECT * FROM smite_node_identities WHERE node_id=?", (node_id,)).fetchone()
            origin = conn.execute("SELECT * FROM smite_foreign_install_origins WHERE node_id=?", (node_id,)).fetchone()
            if grant["consumed_at"] is not None:
                if not identity or identity["revoked_at"] is not None or identity["node_role"] != "foreign" or not origin or origin["grant_hash"] != hashed or origin["control_url"] != control_url or origin["origin"] != grant["origin"] or origin["node_name"] != node_name:
                    _deny()
                try:
                    same = hmac.compare_digest(cipher.decrypt(identity["encrypted_secret"].encode()).decode(), node_secret)
                except (InvalidToken, ValueError, UnicodeError):
                    _deny()
                if not same:
                    _deny()
            else:
                if identity or origin:
                    _deny()
                encrypted = cipher.encrypt(node_secret.encode()).decode()
                conn.execute("INSERT INTO smite_node_identities (node_id,node_role,encrypted_secret,paired_at) VALUES (?,'foreign',?,?)", (node_id, encrypted, current))
                conn.execute("INSERT INTO smite_foreign_install_origins VALUES (?,?,?,?,?,?)", (node_id, node_name, grant["origin"], control_url, hashed, current))
                conn.execute("UPDATE smite_foreign_install_grants SET consumed_at=? WHERE code_hash=?", (current, hashed))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return True


def revoke_pending(database_path, *, node_id: str, now=None) -> bool:
    """Admin-only adapter operation. Does not revoke established Node identity."""
    pairing._validate_node_id(node_id)
    with closing(pairing._open_database(database_path)) as conn:
        result = conn.execute("UPDATE smite_foreign_install_grants SET revoked_at=? WHERE node_id=? AND consumed_at IS NULL AND revoked_at IS NULL", (pairing._now(now), node_id))
        return result.rowcount > 0
