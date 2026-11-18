"""Authenticated Panel requests consumed by the local U-OPTI host worker."""
from time import time

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.dialects.sqlite import insert

from app.config import settings
from app.engine_admission import require_engine_ready_pair
from app.models import BackhaulPublishRequest, Node, Settings, generate_uuid
from app.uopti_backhaul_standard import RESERVED

HEARTBEAT_KEY = "uopti_backhaul_publish_heartbeat"
RESERVED_PORTS = RESERVED | {3080, 8444, 13080}


class BackhaulPublishInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    iran_node_id: str = Field(min_length=1, max_length=128)
    foreign_node_id: str = Field(min_length=1, max_length=128)
    port: int = Field(strict=True, ge=1024, le=65535)
    name: str = Field(min_length=1, max_length=100)

    @field_validator("name")
    @classmethod
    def clean_name(cls, name):
        name = name.strip()
        if not name or not name.isprintable():
            raise ValueError("Invalid tunnel name")
        return name


def result(row):
    return {"id": row.id, "port": row.port, "status": row.status,
            "path": row.path, "detail": row.detail}


async def enqueue(db, request, client):
    if (settings.smite_engine_management_mode != "managed"
            or settings.smite_panel_agent_auth_mode != "signed"):
        raise HTTPException(409, "SIGNED_MANAGED_BACKHAUL_REQUIRED")
    if request.port in RESERVED_PORTS:
        raise HTTPException(422, "DEDICATED_XHTTP_PORT_REQUIRED")

    heartbeat = await db.scalar(select(Settings.value).where(Settings.key == HEARTBEAT_KEY))
    if type(heartbeat) is not int or not 0 <= time() - heartbeat <= 90:
        raise HTTPException(409, "BACKHAUL_PANEL_PUBLISHER_UNAVAILABLE")

    nodes = (await db.execute(select(Node))).scalars().all()
    pair = {role: [node.id for node in nodes
                   if (node.node_metadata or {}).get("role") == role]
            for role in ("iran", "foreign")}
    if pair != {"iran": [request.iran_node_id], "foreign": [request.foreign_node_id]}:
        raise HTTPException(409, "BACKHAUL_PUBLISH_PAIR_MISMATCH")
    await require_engine_ready_pair("backhaul", request.iran_node_id, request.foreign_node_id, client)
    inventory = await client.get_signed_sanaei_xhttp_inbounds(request.foreign_node_id)
    if (not isinstance(inventory, dict) or inventory.get("status") != "success"
            or inventory.get("schema_version") != 1 or not isinstance(inventory.get("inbounds"), list)
            or len([item for item in inventory["inbounds"] if isinstance(item, dict)
                    and item.get("port") == request.port and item.get("enabled") is True
                    and item.get("listen") == "127.0.0.1" and item.get("network") == "xhttp"
                    and item.get("protocol") == "vless"]) != 1):
        raise HTTPException(409, "BACKHAUL_SIGNED_INBOUND_UNAVAILABLE")

    await db.execute(insert(BackhaulPublishRequest).values(
        id=generate_uuid(), name=request.name, port=request.port, iran_node_id=request.iran_node_id,
        foreign_node_id=request.foreign_node_id, status="queued",
    ).on_conflict_do_nothing(index_elements=["port"]))
    row = await db.scalar(select(BackhaulPublishRequest).where(BackhaulPublishRequest.port == request.port))
    if row.iran_node_id != request.iran_node_id or row.foreign_node_id != request.foreign_node_id:
        await db.rollback()
        raise HTTPException(409, "BACKHAUL_PUBLISH_PAIR_CHANGED")
    if row.status in ("hold", "applied"):
        await db.execute(update(BackhaulPublishRequest).where(
            BackhaulPublishRequest.id == row.id, BackhaulPublishRequest.status == row.status,
        ).values(status="queued", detail=None, path=None, name=request.name))
    await db.commit()
    await db.refresh(row)
    return result(row)
