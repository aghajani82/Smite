"""Strict offline FRP release candidate validation; never deploy or enroll."""
import hashlib
import io
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

import stage15_frp_image_gate as gate


class ImageFrpGate(unittest.TestCase):
    @staticmethod
    def elf(arch='amd64'):
        binary = bytearray(64)
        binary[:4] = bytes.fromhex('7f454c46')
        binary[18:20] = gate.EXPECTED_ELF_MACHINE[arch].to_bytes(2, 'little')
        return bytes(binary)

    def archive(self, version='0.71.0', arch='amd64', symlink=False, duplicate=False,
                machine='amd64', wrong_root=False):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name in ('frpc', 'frps'):
                raw = self.elf(machine)
                path = f'frp_{version}_linux_{arch}/{name}'
                if wrong_root:
                    path = 'wrong-directory/' + name
                for _ in range(2 if duplicate and name == 'frpc' else 1):
                    item = tarfile.TarInfo(path)
                    if symlink:
                        item.type = tarfile.SYMTYPE
                        item.linkname = '/etc/passwd'
                        tar.addfile(item)
                    else:
                        item.size = len(raw)
                        tar.addfile(item, io.BytesIO(raw))
        return buf.getvalue()

    def verified(self, raw, version='0.71.0', arch='amd64'):
        with patch.dict(gate.RELEASES[version], {arch: hashlib.sha256(raw).hexdigest()}):
            return gate.checked_archive(raw, arch, version)

    def test_both_pinned_versions_allow_only_exact_archive(self):
        for version in ('0.71.0', '0.71.1'):
            for arch in ('amd64', 'arm64'):
                with self.subTest(version=version, arch=arch):
                    raw = self.archive(version, arch, machine=arch)
                    # Pin the hash of the original clean fixture, then mutate
                    # the candidate WITHOUT updating that trusted expected hash.
                    with patch.dict(gate.RELEASES[version], {arch: hashlib.sha256(raw).hexdigest()}):
                        self.assertEqual(set(gate.checked_archive(raw, arch, version)), {'frpc', 'frps'})
                        with self.assertRaises(ValueError):
                            gate.checked_archive(raw+b'tampered', arch, version)
                        with self.assertRaises(ValueError):
                            gate.checked_archive(raw, arch, '9.9.9')
                        with self.assertRaises(ValueError):
                            gate.checked_archive(raw, 'unknown', version)
                        with self.assertRaises(ValueError):
                            gate.checked_archive(raw, arch, '0.71.1' if version == '0.71.0' else '0.71.0')

    def test_reject_symlink_duplicate_wrong_root_and_wrong_elf(self):
        for kwargs in (
            {'symlink': True}, {'duplicate': True}, {'wrong_root': True},
            {'machine': 'arm64'},
        ):
            with self.subTest(kwargs=kwargs):
                raw = self.archive('0.71.1', 'amd64', **kwargs)
                with self.assertRaises((ValueError, KeyError)):
                    self.verified(raw, '0.71.1')

    def test_dockerfiles_fail_closed_and_default_remains_0710(self):
        root = Path(__file__).resolve().parents[1]
        for role in ('panel', 'node'):
            source = (root / role / 'Dockerfile').read_text()
            self.assertIn('ARG SMITE_FRP_CANDIDATE_VERSION=v0.71.0', source)
            self.assertIn('FRP_VERSION="${SMITE_FRP_CANDIDATE_VERSION}"', source)
            self.assertIn('case "$FRP_VERSION:$ARCH" in', source)
            self.assertLess(source.index('case "$FRP_VERSION:$ARCH"'),
                            source.index('curl -fsSL "$FRP_URL"'))
            self.assertLess(source.index('sha256sum -c -'),
                            source.index('tar -xzf "$FRP_TMP/frp.tar.gz"'))
            for version, arches in gate.RELEASES.items():
                for arch, digest in arches.items():
                    self.assertIn(f'{version}:{arch})', source)
                    self.assertIn(digest, source)
            self.assertIn('HOLD: Unsupported FRP version or architecture', source)
            self.assertIn('Unsupported architecture: $ARCH_RAW', source)

    def test_image_audit_defaults_old_and_explicit_candidate_only(self):
        import inspect
        source = inspect.getsource(gate.main)
        self.assertIn("os.environ.get('SMITE_FRP_VERIFY_VERSION', '0.71.0')", source)
        self.assertIn("version not in RELEASES", source)
        self.assertIn("'--network', 'none'", source)
        self.assertIn("'--read-only'", source)
        self.assertIn("'--cap-drop', 'ALL'", source)
        self.assertIn("SIGNED_PUBLICATION_AUTHORIZED=NO", source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
