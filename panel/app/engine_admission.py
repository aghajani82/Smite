"""Signed, read-only, two-Node independent engine admission."""
from fastapi import HTTPException

ENGINES = ("backhaul", "frp", "gost", "rathole", "chisel")


async def engine_pair_readiness(iran_node_id: str, foreign_node_id: str, client) -> dict:
    if not iran_node_id or not foreign_node_id or iran_node_id == foreign_node_id:
        return {name: "select-nodes" for name in ENGINES}
    values = []
    for node_id in (iran_node_id, foreign_node_id):
        try:
            inventory = await client.get_engine_inventory(node_id)
        except Exception:
            # A failed signed read is never evidence that an engine exists.
            return {name: "unavailable" for name in ENGINES}
        if (
            not isinstance(inventory, dict)
            or inventory.get("mode") != "managed"
            or not isinstance(inventory.get("engines"), dict)
            or set(inventory["engines"]) != set(ENGINES)
            or any(state not in {"ready", "not-installed", "unavailable"}
                   for state in inventory["engines"].values())
        ):
            return {name: "unavailable" for name in ENGINES}
        values.append(inventory["engines"])
    statuses = {}
    for engine in ENGINES:
        left, right = values[0].get(engine), values[1].get(engine)
        if left == right == "ready":
            statuses[engine] = "ready"
        elif "not-installed" in (left, right):
            statuses[engine] = "not-installed"
        else:
            statuses[engine] = "unavailable"
    return statuses


async def require_engine_ready_pair(core: str, iran_node_id: str, foreign_node_id: str, client) -> None:
    if core not in ENGINES:
        raise HTTPException(422, detail="Unknown tunnel engine")
    state = await engine_pair_readiness(iran_node_id, foreign_node_id, client)
    if state[core] != "ready":
        raise HTTPException(409, detail="Selected engine is not ready on both Nodes")
