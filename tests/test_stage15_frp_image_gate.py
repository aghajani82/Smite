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

    def test_official_api_fallback_requires_same_exact_archive_hash(self):
        import urllib.error
        raw = self.archive()
        source_error = urllib.error.HTTPError(
            'https://github.com/fatedier/frp/releases/download/v0.71.0/',
            504, 'Gateway Timeout', {}, None)
        with patch.dict(gate.HASHES, amd64=hashlib.sha256(raw).hexdigest()):
            with patch.object(gate.urllib.request, 'urlopen',
                              side_effect=[source_error, io.BytesIO(raw)]) as fetch:
                self.assertEqual(
                    set(gate.checked_archive(gate.official_archive('amd64'),
                                             'amd64')), {'frpc', 'frps'})
                self.assertEqual(fetch.call_count, 2)
                api = fetch.call_args.args[0]
                self.assertEqual(
                    api.full_url,
                    'https://api.github.com/repos/fatedier/frp/releases/assets/514042277')
                self.assertEqual(api.headers['Accept'], 'application/octet-stream')
        with patch.object(gate.urllib.request, 'urlopen',
                          side_effect=[source_error, io.BytesIO(b'{"id":514042277}')]):
            with self.assertRaisesRegex(ValueError, 'FRP_OFFICIAL_ARCHIVE_MISMATCH'):
                gate.checked_archive(gate.official_archive('amd64'), 'amd64')

    def test_unknown_arch_cannot_fetch_release_asset(self):
        with patch.object(gate.urllib.request, 'urlopen') as fetch:
            with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_FRP_ARCHITECTURE'):
                gate.official_archive('invalid')
            fetch.assert_not_called()

    def test_dockerfiles_verify_before_extract_and_fail_unknown_arch(self):
        root = Path(__file__).resolve().parents[1]
        for role in ('panel', 'node'):
            source = (root / role / 'Dockerfile').read_text()
            self.assertIn('FRP_VERSION="v0.71.0"', source)
            self.assertLess(source.index('sha256sum -c -'), source.index('tar -xzf "$FRP_TMP/frp.tar.gz"'))
            for digest in gate.HASHES.values(): self.assertIn(digest, source)
            self.assertIn('Unsupported architecture: $ARCH_RAW', source)

if __name__ == '__main__': unittest.main()
