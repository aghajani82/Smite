"""Reject reintroduction of the discarded independent approval runtime."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ConsoleOnly(unittest.TestCase):
 def test_no_attestation_runtime(self):
  self.assertFalse((ROOT/'node/app/approval_attestation.py').exists())
  self.assertFalse((ROOT/'node/app/approval_runtime_evidence.py').exists())
  agent=(ROOT/'node/app/routers/agent.py').read_text()
  self.assertNotIn('approval_attestation',agent)
  self.assertNotIn('approval_runtime_evidence',agent)
 def test_only_explicit_console_publication(self):
  ui=(ROOT/'frontend/src/pages/Tunnels.tsx').read_text()
  for marker in ('VITE_STAGE15_APPROVAL_ORIGIN','openIndependentRouteApproval','window.open','Passkey','postMessage'):
   self.assertNotIn(marker,ui)
  for marker in ('ROOT_GRANT_APPROVED','ثبت نهایی مسیر','HOLD / Requires Review','ROOT_OPERATOR_GRANT_REQUIRED'):
   self.assertIn(marker,ui)
if __name__=='__main__':unittest.main()
