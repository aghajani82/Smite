"""No daemon/network: failed FRPS startup must not publish its token."""
import importlib.util
import logging
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('frp_server_privacy', ROOT / 'panel/app/frp_server.py')
module = importlib.util.module_from_spec(spec)
# Import-time singleton must not create the production /app directory.
with patch.object(Path, "mkdir"):
    spec.loader.exec_module(module)

class FrpLogPrivacy(unittest.TestCase):
    def test_failed_start_never_logs_config_or_child_output_and_files_are_private(self):
        with tempfile.TemporaryDirectory() as temp:
            manager = module.FrpServerManager.__new__(module.FrpServerManager)
            manager.config_dir = Path(temp)
            manager.active_servers = {}
            manager.server_configs = {}
            token = 'SYNTHETIC_TEST_TOKEN_NO_REAL_CREDENTIAL'
            class Process:
                def poll(self): return 1
            def spawn(cmd, **kwargs):
                kwargs['stdout'].write('parser rejected token: ' + token + '\n')
                return Process()
            config = manager.config_dir / 'frps_test.yaml'
            config.write_text('previous')
            config.chmod(0o644)
            with patch.object(manager, '_resolve_binary_path', return_value=Path('/fake/frps')), \
                 patch.object(module.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(module.time, 'sleep'), \
                 self.assertLogs(module.logger, level=logging.INFO) as logs:
                with self.assertRaisesRegex(RuntimeError, 'exit code: 1') as error:
                    manager.start_server('test', 7000, token)
                self.assertNotIn(token, str(error.exception))
            self.assertNotIn(token, '\n'.join(logs.output))
            self.assertIn(token, config.read_text())
            for name in ('frps_test.yaml', 'frps_test.log'):
                self.assertEqual(os.stat(manager.config_dir / name).st_mode & 0o777, 0o600)
            for value in manager.active_servers.values():
                if hasattr(value, 'close'): value.close()

if __name__ == '__main__':
    unittest.main()
