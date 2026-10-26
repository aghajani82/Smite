"""Application configuration"""
from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Literal


class Settings(BaseSettings):
    node_api_port: int = 8888
    node_name: str = "node-1"
    node_role: str = "iran"  # "iran" or "foreign"
    
    panel_ca_path: str = "/etc/smite-node/ca.crt"
    panel_address: str = "panel.example.com:443"
    panel_api_port: int = 8000

    # Strict is an explicit staged opt-in; legacy preserves working tunnels.
    smite_agent_auth_mode: Literal["legacy", "strict"] = "legacy"
    smite_agent_identity_path: str = "/etc/smite-node/identity/node-identity.json"
    smite_agent_replay_db: str = "/var/lib/smite-node/auth/agent-replay.sqlite3"
    smite_node_panel_auth_mode: Literal["legacy", "signed", "paused"] = "legacy"

    # Explicit independent-engine enrollment. Legacy keeps its old behavior.
    # Managed mode does not treat binaries bundled in the Node image as ready.
    smite_engine_inventory_mode: Literal["legacy", "managed"] = "legacy"
    smite_engine_manifest_path: str = "/etc/smite-node/engine-state/engines.json"

    # KH-only, opt-in inventory. A separately approved read-only bind mount
    # is required; missing or untrusted SQLite must HOLD, never auto-install.
    smite_sanaei_inventory_enabled: bool = False
    smite_sanaei_db_path: str = "/run/smite-sanaei-ro/x-ui.db"

    # IR-only, explicit opt-in forwarding to the local U-OPTI route broker.
    smite_uopti_route_broker_enabled: bool = False
    smite_uopti_route_broker_socket: str = "/run/u-opti/smite/xhttp-broker.sock"
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


settings = Settings()

