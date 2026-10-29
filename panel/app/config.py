"""Application configuration"""
from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    panel_port: int = 8000
    panel_host: str = "0.0.0.0"
    panel_domain: str = ""
    https_enabled: bool = False
    https_cert_path: str = "./certs/server.crt"
    https_key_path: str = "./certs/server.key"
    docs_enabled: bool = True
    
    db_type: Literal["sqlite"] = "sqlite"
    db_path: str = "./data/smite.db"
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "smite"
    db_user: str = "smite"
    db_password: str = "changeme"
    
    node_port: int = 4443
    node_cert_path: str = "./certs/ca.crt"
    node_key_path: str = "./certs/ca.key"
    node_server_cert_path: str = "./certs/ca-server.crt"
    node_server_key_path: str = "./certs/ca-server.key"
    
    secret_key: str = "changeme-secret-key-change-in-production"

    # Default OFF. Requires separate encryption and trusted-proxy keys.
    smite_node_pairing_preview_enabled: bool = False
    smite_node_pairing_master_key: str = ""
    smite_node_pairing_ingress_token: str = ""

    # Signed Panel -> Node API calls remain OFF during the pairing migration.
    smite_panel_agent_auth_mode: Literal["legacy", "signed"] = "legacy"
    smite_node_registration_mode: Literal["legacy", "signed"] = "legacy"
    smite_engine_management_mode: Literal["legacy", "managed"] = "legacy"
    smite_frp_standard_wss: bool = False
    # Provisioned separately from the signed Agent identity; never source code.
    smite_uopti_route_broker_key_path: str = "/run/secrets/smite-uopti-xhttp-broker.key"
    # Manually approved, read-only per-node destination pins (not metadata).
    smite_signed_node_origins_path: str = "/etc/smite-panel/trusted-nodes/approved-origins.json"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()

