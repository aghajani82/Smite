import hashlib
import io
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch
import stage15_frp_image_gate as gate

class ImageFrpGate(unittest.TestCase):
    def archive(self, symlink=False):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name in ('frpc', 'frps'):
                item = tarfile.TarInfo('frp_0.71.0_linux_amd64/' + name)
                if symlink:
                    item.type = tarfile.SYMTYPE
                    item.linkname = '/etc/passwd'
                else:
                    item.size = 4
                tar.addfile(item, None if symlink else io.BytesIO(b'ELF!'))
        return buf.getvalue()

    def test_unknown_arch_and_modified_archive_rejected(self):
        for arch in ('amd64', 'arm64', 'unknown'):
            with self.assertRaises(ValueError): gate.checked_archive(b'tampered', arch)

    def test_validated_bytes_and_symlink_rejection(self):
        for symlink in (False, True):
            raw = self.archive(symlink)
            with patch.dict(gate.HASHES, amd64=hashlib.sha256(raw).hexdigest()):
                if symlink:
                    with self.assertRaises(ValueError): gate.checked_archive(raw, 'amd64')
                else:
                    self.assertEqual(set(gate.checked_archive(raw, 'amd64')), {'frpc', 'frps'})

    def test_dockerfiles_verify_before_extract_and_fail_unknown_arch(self):
        root = Path(__file__).resolve().parents[1]
        for role in ('panel', 'node'):
            source = (root / role / 'Dockerfile').read_text()
            self.assertIn('FRP_VERSION="v0.71.0"', source)
            self.assertLess(source.index('sha256sum -c -'), source.index('tar -xzf "$FRP_TMP/frp.tar.gz"'))
            for digest in gate.HASHES.values(): self.assertIn(digest, source)
            self.assertIn('Unsupported architecture: $ARCH_RAW', source)

if __name__ == '__main__': unittest.main()
