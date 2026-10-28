"""FRP server management for panel"""
import os
import subprocess
import time
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class FrpServerManager:
    """Manages FRP server (frps) processes on the panel"""
    
    def __init__(self):
        self.config_dir = Path("/app/data/frp")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.active_servers: Dict[str, subprocess.Popen] = {}
        self.server_configs: Dict[str, dict] = {}
    
    def _resolve_binary_path(self) -> Path:
        """Resolve frps binary path"""
        env_path = os.environ.get("FRPS_BINARY")
        if env_path:
            resolved = Path(env_path)
            if resolved.exists() and resolved.is_file():
                return resolved
        
        common_paths = [
            Path("/usr/local/bin/frps"),
            Path("/usr/bin/frps"),
        ]
        
        for path in common_paths:
            if path.exists() and path.is_file():
                return path
        
        resolved = subprocess.run(["which", "frps"], capture_output=True, text=True)
        if resolved.returncode == 0 and resolved.stdout.strip():
            return Path(resolved.stdout.strip())
        
        raise FileNotFoundError(
            "frps binary not found. Expected at FRPS_BINARY, '/usr/local/bin/frps', or in PATH."
        )
    
    def start_server(self, tunnel_id: str, bind_port: int, token: Optional[str] = None) -> bool:
        """
        Start an FRP server for a tunnel
        
        Args:
            tunnel_id: Unique tunnel identifier
            bind_port: Port where server listens for client connections (default: 7000)
            token: Optional authentication token
        
        Returns:
            True if server started successfully, False otherwise
        """
        try:
            if tunnel_id in self.active_servers:
                logger.warning(f"FRP server for tunnel {tunnel_id} already exists, stopping it first")
                self.stop_server(tunnel_id)
            
            config_file = self.config_dir / f"frps_{tunnel_id}.yaml"
            config_content = f"""bindPort: {bind_port}
"""
            if token:
                config_content += f"""auth:
  method: token
  token: "{token}"
"""
            with os.fdopen(os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                                   | os.O_NOFOLLOW, 0o600), 'w') as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(config_content)
            
            logger.info("FRP server configuration prepared (port=%s, token=%s)",
                        bind_port, "set" if token else "none")
            
            binary_path = self._resolve_binary_path()
            cmd = [
                str(binary_path),
                "-c", str(config_file)
            ]
            
            self.server_configs[tunnel_id] = {
                "bind_port": bind_port,
                "token": token,
                "config_file": str(config_file)
            }
            
            log_file = self.config_dir / f"frps_{tunnel_id}.log"
            log_f = os.fdopen(os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                                     | os.O_NOFOLLOW, 0o600), 'w', buffering=1)
            os.fchmod(log_f.fileno(), 0o600)
            try:
                log_f.write(f"Starting FRP server for tunnel {tunnel_id}\n")
                log_f.write(f"Config: bind_port={bind_port}, token={'set' if token else 'none'}\n")
                log_f.write(f"Command: {' '.join(cmd)}\n")
                log_f.flush()
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_f,
                    stderr=subprocess.STDOUT,
                    cwd=str(self.config_dir),
                    start_new_session=True
                )
            except FileNotFoundError:
                log_f.write(f"Starting FRP server (system binary) for tunnel {tunnel_id}\n")
                log_f.flush()
                proc = subprocess.Popen(
                    ["frps"] + cmd[1:],
                    stdout=log_f,
                    stderr=subprocess.STDOUT,
                    cwd=str(self.config_dir),
                    start_new_session=True
                )
            
            self.active_servers[f"{tunnel_id}_log"] = log_f
            self.active_servers[tunnel_id] = proc
            
            time.sleep(1.0)
            if proc.poll() is not None:
                try:
                    # FRP parser output may echo secret-bearing configuration.
                    # Keep diagnostics in the private host log, never API logs.
                    error_msg = f"FRP server failed to start (exit code: {proc.poll()}); inspect private FRP log"
                    logger.error(error_msg)
                finally:
                    del self.active_servers[tunnel_id]
                    if f"{tunnel_id}_log" in self.active_servers:
                        try:
                            self.active_servers[f"{tunnel_id}_log"].close()
                        except:
                            pass
                        del self.active_servers[f"{tunnel_id}_log"]
                    if tunnel_id in self.server_configs:
                        del self.server_configs[tunnel_id]
                raise RuntimeError(error_msg)
            
            # Verify server is actually listening
            try:
                import socket
                max_retries = 3
                port_listening = False
                for attempt in range(max_retries):
                    time.sleep(0.5)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('127.0.0.1', bind_port))
                    sock.close()
                    if result == 0:
                        port_listening = True
                        break
                
                if not port_listening:
                    if proc.poll() is not None:
                        error_msg = f"FRP server process exited (code: {proc.poll()}) before port verification"
                        logger.error(error_msg)
                        raise RuntimeError(error_msg)
                    else:
                        logger.warning(f"FRP server port {bind_port} not listening after {max_retries} attempts, but process is running. PID: {proc.pid}")
                else:
                    logger.info(f"FRP server port {bind_port} verified as listening")
            except Exception as e:
                if proc.poll() is not None:
                    error_msg = f"FRP server process died during verification (code: {proc.poll()}): {e}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)
                logger.warning(f"Could not verify FRP server port is listening: {e}")
            
            logger.info(f"Started FRP server for tunnel {tunnel_id} on port {bind_port} (PID: {proc.pid})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start FRP server for tunnel {tunnel_id}: {e}")
            raise
    
    def stop_server(self, tunnel_id: str):
        """Stop FRP server for a tunnel"""
        if tunnel_id in self.active_servers:
            proc = self.active_servers[tunnel_id]
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            except Exception as e:
                logger.warning(f"Error stopping FRP server for tunnel {tunnel_id}: {e}")
            finally:
                del self.active_servers[tunnel_id]
                log_key = f"{tunnel_id}_log"
                if log_key in self.active_servers:
                    try:
                        self.active_servers[log_key].close()
                    except:
                        pass
                    del self.active_servers[log_key]
            
            logger.info(f"Stopped FRP server for tunnel {tunnel_id}")
        
        if tunnel_id in self.server_configs:
            config_file = Path(self.server_configs[tunnel_id].get("config_file", ""))
            if config_file.exists():
                try:
                    config_file.unlink()
                except:
                    pass
            del self.server_configs[tunnel_id]
        
        old_toml_config = self.config_dir / f"frps_{tunnel_id}.toml"
        if old_toml_config.exists():
            try:
                old_toml_config.unlink()
            except:
                pass
    
    def is_running(self, tunnel_id: str) -> bool:
        """Check if server is running for a tunnel"""
        if tunnel_id not in self.active_servers:
            return False
        proc = self.active_servers[tunnel_id]
        return proc.poll() is None
    
    def get_active_servers(self) -> list:
        """Get list of tunnel IDs with active servers"""
        active = []
        for tunnel_id, proc in list(self.active_servers.items()):
            if tunnel_id.endswith("_log"):
                continue
            if isinstance(proc, subprocess.Popen):
                if proc.poll() is None:
                    active.append(tunnel_id)
                else:
                    del self.active_servers[tunnel_id]
                    log_key = f"{tunnel_id}_log"
                    if log_key in self.active_servers:
                        try:
                            self.active_servers[log_key].close()
                        except:
                            pass
                        del self.active_servers[log_key]
                    if tunnel_id in self.server_configs:
                        del self.server_configs[tunnel_id]
        return active
    
    def cleanup_all(self):
        """Stop all FRP servers"""
        tunnel_ids = [tid for tid in self.active_servers.keys() if not tid.endswith("_log")]
        for tunnel_id in tunnel_ids:
            self.stop_server(tunnel_id)


frp_server_manager = FrpServerManager()

