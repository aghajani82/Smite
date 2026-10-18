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
    smite_node_panel_auth_mode: Literal["legacy", "signed"] = "legacy"
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


settings = Settings()

