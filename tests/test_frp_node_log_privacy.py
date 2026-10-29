import sys
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'node'))
from app import core_adapters as adapters

class NodePrivacy(unittest.TestCase):
    def test_failed_client_does_not_return_secret_and_writes_private_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter=adapters.FrpAdapter.__new__(adapters.FrpAdapter)
            adapter.config_dir=Path(tmp);adapter.processes={};adapter.log_handles={}
            secret='SYNTHETIC_SECRET_NOT_REAL'
            class Process:
                returncode=1
                def poll(self):return 1
            def spawn(*args,**kwargs):
                kwargs['stdout'].write(secret);kwargs['stdout'].flush();return Process()
            spec={'mode':'client','server_addr':'ir.example.test','server_port':7000,'token':secret,'local_port':12345,'remote_port':12345}
            with patch.dict(os.environ,{},clear=True),patch.object(adapter,'_resolve_binary_path',return_value=Path('/fake/frpc')),patch.object(adapters.subprocess,'Popen',side_effect=spawn),patch.object(adapters.time,'sleep'):
                with self.assertRaises(RuntimeError) as error:adapter.apply('fixture',spec)
                self.assertNotIn(secret,str(error.exception))
            for path in Path(tmp).iterdir():self.assertEqual(path.stat().st_mode&0o777,0o600)

if __name__=='__main__':unittest.main()
