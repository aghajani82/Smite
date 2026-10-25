"""Database models"""
from sqlalchemy import Column, String, Integer, DateTime, Float, JSON, Boolean, Text, UniqueConstraint
from sqlalchemy.dialects.sqlite import DATETIME as SQLiteDATETIME
from datetime import datetime
from app.database import Base
import uuid


def generate_uuid():
    return str(uuid.uuid4())


class Node(Base):
    __tablename__ = "nodes"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    fingerprint = Column(String, unique=True, nullable=False)
    status = Column(String, default="pending")
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    node_metadata = Column("metadata", JSON, default=dict)
    

class Tunnel(Base):
    __tablename__ = "tunnels"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    core = Column(String, nullable=False)
    type = Column(String, nullable=False)
    node_id = Column(String, nullable=False)
    foreign_node_id = Column(String, nullable=True)  # For reverse tunnels: foreign node (server side)
    iran_node_id = Column(String, nullable=True)  # For reverse tunnels: iran node (client side)
    spec = Column(JSON, nullable=False)
    quota_mb = Column(Float, default=0)
    used_mb = Column(Float, default=0)
    expires_at = Column(DateTime, nullable=True)
    status = Column(String, default="pending")
    error_message = Column(Text, nullable=True)
    revision = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Admin(Base):
    __tablename__ = "admins"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    # MFA secrets are Fernet-encrypted; recovery_codes holds HMAC hashes only.
    totp_secret = Column(Text, nullable=True)
    totp_pending_secret = Column(Text, nullable=True)
    recovery_codes = Column(JSON, nullable=True)
    totp_last_counter = Column(Integer, nullable=True)
    auth_version = Column(Integer, nullable=False, default=0, server_default="0")
    mfa_failures = Column(Integer, nullable=False, default=0, server_default="0")
    mfa_locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Usage(Base):
    __tablename__ = "usage"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    tunnel_id = Column(String, nullable=False)
    node_id = Column(String, nullable=False)
    bytes_used = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)


class CoreResetConfig(Base):
    __tablename__ = "core_reset_config"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    core = Column(String, nullable=False, unique=True)
    enabled = Column(Boolean, default=False)
    interval_minutes = Column(Integer, default=10)
    last_reset = Column(DateTime, nullable=True)
    next_reset = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Settings(Base):
    __tablename__ = "settings"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    key = Column(String, unique=True, nullable=False)
    value = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)



class FrpProxyLease(Base):
    """Persistent, unique IR Node+port allocation for a shared FRPS child.

    Only client proxies have leases. The pre-existing FRPS owner is verified
    from the signed Node and its established Tunnel DB row. A failed Apply
    retains its lease until an explicitly successful signed KH cleanup.
    """
    __tablename__ = "frp_proxy_leases"
    __table_args__ = (
        UniqueConstraint("iran_node_id", "remote_port", name="uq_frp_ir_remote_port"),
    )
    tunnel_id = Column(String, primary_key=True)
    iran_node_id = Column(String, nullable=False)
    foreign_node_id = Column(String, nullable=False)
    owner_tunnel_id = Column(String, nullable=False)
    remote_port = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
