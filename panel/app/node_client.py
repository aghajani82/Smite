"""Client for panel to communicate with nodes"""
import httpx
import ssl
import logging
import asyncio
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models import Node, Settings
from app.config import settings
from app.signed_agent_transport import signed_agent_call, SignedAgentUnavailable, SignedAgentHTTPFailure
from app.uopti_backhaul_dispatch import prepare_node_command
from app.uopti_backhaul_standard import StandardBackhaulSpecError
from app.signed_node_origins import approved_node, ApprovedOriginUnavailable


logger = logging.getLogger(__name__)


class NodeClient:
    """Client to send requests to nodes via HTTP/HTTPS or FRP"""
    
    def __init__(self):
        self.timeout = httpx.Timeout(30.0)
    
    async def _get_frp_settings(self) -> Optional[Dict[str, Any]]:
        """Get FRP communication settings"""
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Settings).where(Settings.key == "frp"))
            setting = result.scalar_one_or_none()
            if setting and setting.value and setting.value.get("enabled"):
                return setting.value
        return None
    
    async def _get_node_address(self, node: Node) -> Tuple[str, bool]:
        """
        Get node address (direct or via FRP)
        Returns: (address, using_frp)
        """
        frp_settings = await self._get_frp_settings()
        
        if frp_settings and frp_settings.get("enabled"):
            frp_remote_port = node.node_metadata.get("frp_remote_port") if node.node_metadata else None
            if frp_remote_port:
                # Verify FRP server is running before using FRP
                from app.frp_comm_manager import frp_comm_manager
                if not frp_comm_manager.is_running():
                    logger.warning(f"[HTTP] FRP enabled but FRP server not running, falling back to HTTP for node {node.id}")
                    # Fall through to HTTP
                else:
                    # Use FRP - the server is running, tunnel should be available
                    # Note: If connection fails, retry logic will handle it
                    logger.info(f"[FRP] Using FRP tunnel to communicate with node {node.id} (remote_port={frp_remote_port})")
                    return (f"http://127.0.0.1:{frp_remote_port}", True)
            else:
                # FRP is enabled but node hasn't reported its remote port yet (during initial setup)
                logger.warning(f"[HTTP] FRP enabled but node {node.id} has no frp_remote_port yet, temporarily using HTTP")
                logger.warning(f"[HTTP] This should only happen during node registration. After FRP setup, all communication will use FRP.")
        
        # FRP is not enabled or not available - use HTTP
        node_address = node.node_metadata.get("api_address", f"http://localhost:8888") if node.node_metadata else f"http://localhost:8888"
        if not node_address.startswith("http"):
            node_address = f"http://{node_address}"
        logger.info(f"[HTTP] Using direct HTTP to communicate with node {node.id} at {node_address}")
        return (node_address, False)
    
    async def _signed_agent_request(
        self, node_id: str, *, method: str, target: str,
        payload: Optional[Dict[str, Any]] = None, timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """Signed request with no legacy fallback and no automatic write retry."""
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Node).where(Node.id == node_id))
                node = result.scalar_one_or_none()
                if node is None:
                    return {"status": "error", "message": "Node not found"}
                # Pairing-code redemption creates a key, NOT permission
                # to send commands. Legacy active rows are also untrusted.
                metadata = node.node_metadata or {}
                if (node.status != "active"
                        or metadata.get("provisioning") != "signed_checkin"):
                    raise SignedAgentUnavailable("Signed Node not yet registered")
                # Never route HMAC credentials to historical, anonymous
                # Node.metadata.api_address / control_address / FRP ports.
                # The signed endpoint must be approved out of band.
                pin = approved_node(node_id)
                if (pin["role"] != metadata.get("role")
                        or pin["node_name"] != node.name
                        or pin["node_name"] != metadata.get("node_name")):
                    raise ApprovedOriginUnavailable(
                        "Node role or name differs from approved identity"
                    )
                address, using_frp = pin["origin"], False
                # Only the root-owned, approved Foreign gateway path is
                # permitted; a Node's self-reported API URL is never trusted.
                gateway_control_url = (
                    pin["control_url"] if pin["role"] == "foreign" else None
                )

            return await signed_agent_call(
                node_id=node_id, address=address, using_frp=using_frp,
                method=method, target=target, payload=payload, timeout=timeout,
                gateway_control_url=gateway_control_url,
            )
        except SignedAgentHTTPFailure as exc:
            # Only the integer response code from the authenticated, pinned
            # target is surfaced. Never expose a response body or URL.
            return {"status": "error", "message":
                    f"Signed Node rejected request (HTTP {exc.status_code})"}
        except (SignedAgentUnavailable, ApprovedOriginUnavailable, ValueError):
            # Never serialize tokens, raw authorization headers or TLS exceptions.
            return {"status": "error", "message": "Signed Node control unavailable"}
        except Exception:
            logger.warning("Signed Node communication failed for node %s", node_id)
            return {"status": "error", "message": "Signed Node control unavailable"}

    async def send_to_node(self, node_id: str, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to node via HTTPS or FRP
        """
        # Normalize persisted opt-in Backhaul BEFORE the signed/legacy split.
        # Never let the signed fast path skip the validated IR/KH spec.
        try:
            data = await prepare_node_command(node_id, endpoint, data)
        except StandardBackhaulSpecError:
            return {"status": "error", "message": "Standard Backhaul spec rejected"}
        except Exception:
            logger.warning("Backhaul dispatch precheck failed for node %s", node_id)
            return {"status": "error", "message": "Backhaul preparation unavailable"}
        if settings.smite_panel_agent_auth_mode == "signed":
            # No downgrade to legacy even if the Node rejects the signature.
            if endpoint not in (
                "/api/agent/tunnels/apply", "/api/agent/tunnels/remove"
            ):
                return {"status": "error", "message": "Unsigned command prohibited"}
            return await self._signed_agent_request(
                node_id, method="POST", target=endpoint, payload=data,
            )
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Node).where(Node.id == node_id))
            node = result.scalar_one_or_none()
            
            if not node:
                return {"status": "error", "message": f"Node {node_id} not found"}
            
            node_address, using_frp = await self._get_node_address(node)
            url = f"{node_address.rstrip('/')}{endpoint}"
            
            comm_type = "FRP" if using_frp else "HTTP"
            logger.debug(f"[{comm_type}] Sending request to node {node_id}: {endpoint}")
            
            try:
                # Retry logic for FRP connections which may need a moment to stabilize
                max_retries = 5 if using_frp else 1
                last_error = None
                
                for attempt in range(max_retries):
                    try:
                        # For FRP, use a new connection each time to avoid connection reuse issues
                        if using_frp and attempt > 0:
                            await asyncio.sleep(2.0)  # Longer delay for FRP retries
                            logger.info(f"[FRP] Retry {attempt + 1}/{max_retries} for node {node_id} via FRP tunnel")
                        
                        async with httpx.AsyncClient(
                            timeout=self.timeout, 
                            verify=False,
                            limits=httpx.Limits(max_keepalive_connections=0 if using_frp else 5)  # Disable keep-alive for FRP
                        ) as client:
                            response = await client.post(url, json=data)
                            response.raise_for_status()
                            return response.json()
                    except httpx.RequestError as e:
                        last_error = e
                        if attempt < max_retries - 1:
                            if not using_frp:
                                await asyncio.sleep(0.5)
                            continue
                        else:
                            error_msg = f"Network error: {str(e)}"
                            if using_frp:
                                remote_port = url.split(":")[-1].split("/")[0] if ":" in url else "unknown"
                                error_msg += f" (FRP tunnel connection failed after {max_retries} attempts. The panel may not be able to reach FRP server on 127.0.0.1:{remote_port}. Check if panel and FRP server are in the same network namespace, or check FRP server logs.)"
                            return {"status": "error", "message": error_msg}
                
                # Should not reach here, but just in case
                return {"status": "error", "message": f"Network error: {str(last_error)}"}
            except httpx.HTTPStatusError as e:
                try:
                    error_detail = e.response.json().get("detail", str(e))
                except:
                    error_detail = str(e)
                return {"status": "error", "message": f"Node error (HTTP {e.response.status_code}): {error_detail}"}
            except Exception as e:
                return {"status": "error", "message": f"Error: {str(e)}"}
    
    async def get_engine_inventory(self, node_id: str) -> Dict[str, Any]:
        """Explicit signed read-only inventory, with NO legacy fallback.

        The core-only install starts with no enrolled engines. Never infer
        readiness from the Node image containing bundled binaries.
        """
        if settings.smite_panel_agent_auth_mode != "signed":
            return {"status": "unavailable", "message": "Managed inventory requires signed Node control"}
        return await self._signed_agent_request(
            node_id, method="GET", target="/api/agent/engines", timeout=3.0,
        )

    async def get_verified_frps_owners(self, node_id: str) -> Dict[str, Any]:
        """Authenticated read-only evidence of the existing FRPS daemon.

        Strict Signed control only; no legacy fallback, no signed POST and
        no candidate token or other secret is exposed in the response.
        """
        if settings.smite_panel_agent_auth_mode != "signed":
            return {"status": "error", "message": "Signed FRPS owner evidence unavailable"}
        return await self._signed_agent_request(
            node_id, method="GET", target="/api/agent/frp/owners",
            timeout=3.0,
        )

    async def get_tunnel_status(self, node_id: str, tunnel_id: str = "") -> Dict[str, Any]:
        """Get tunnel status from node"""
        if settings.smite_panel_agent_auth_mode == "signed":
            target = "/api/agent/status"
            # Existing status caller intentionally uses aggregate status.
            # Do not change the response contract or assume tunnel-specific
            # format until all status polling consumers are migrated.
            return await self._signed_agent_request(
                node_id, method="GET", target=target, timeout=3.0,
            )
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Node).where(Node.id == node_id))
            node = result.scalar_one_or_none()
            
            if not node:
                return {"status": "error", "message": f"Node {node_id} not found"}
            
            node_address, using_frp = await self._get_node_address(node)
            url = f"{node_address.rstrip('/')}/api/agent/status"
            
            comm_type = "FRP" if using_frp else "HTTP"
            logger.debug(f"[{comm_type}] Getting tunnel status from node {node_id}")
            
            try:
                timeout = httpx.Timeout(3.0, connect=2.0)
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    response = await client.get(url)
                    response.raise_for_status()
                    return response.json()
            except httpx.RequestError as e:
                return {"status": "error", "message": f"Network error: {str(e)}"}
            except httpx.HTTPStatusError as e:
                try:
                    error_detail = e.response.json().get("detail", str(e))
                except:
                    error_detail = str(e)
                return {"status": "error", "message": f"Node error (HTTP {e.response.status_code}): {error_detail}"}
            except Exception as e:
                return {"status": "error", "message": f"Error: {str(e)}"}
    
    async def apply_tunnel(self, node_id: str, tunnel_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply tunnel to node"""
        return await self.send_to_node(node_id, "/api/agent/tunnels/apply", tunnel_data)
