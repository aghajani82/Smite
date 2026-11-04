#!/usr/bin/env python3
"""Offline-only FRP image byte audit against pinned official release archives.

Both RC7 v0.71.0 and explicitly selected v0.71.1 candidates are supported.
This module cannot authorize publication, deployment, enrollment or mutation.
"""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

RELEASES = {
    '0.71.0': {
        'amd64': '84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716',
        'arm64': 'f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266',
    },
    '0.71.1': {
        'amd64': '1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803',
        'arm64': '8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019',
    },
}
# Preserve the pre-existing v0.71.0 test/RC7 import contract.
HASHES = RELEASES['0.71.0']
EXPECTED_ELF_MACHINE = {'amd64': 62, 'arm64': 183}
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 48 * 1024 * 1024


def checked_archive(raw, arch, version='0.71.0'):
    hashes = RELEASES.get(version)
    if (hashes is None or arch not in hashes or not isinstance(raw, bytes)
            or len(raw) > MAX_ARCHIVE
            or hashlib.sha256(raw).hexdigest() != hashes[arch]):
        raise ValueError('FRP_OFFICIAL_ARCHIVE_MISMATCH')
    result = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            members = archive.getmembers()
            for role in ('frpc', 'frps'):
                path = f'frp_{version}_linux_{arch}/{role}'
                hits = [item for item in members if item.name == path]
                if (len(hits) != 1 or not hits[0].isfile()
                        or not 20 <= hits[0].size < MAX_BINARY):
                    raise ValueError('FRP_ARCHIVE_MEMBER_INVALID')
                stream = archive.extractfile(hits[0])
                if stream is None:
                    raise ValueError('FRP_ARCHIVE_MEMBER_INVALID')
                binary = stream.read(MAX_BINARY)
                if (len(binary) != hits[0].size or binary[:4] != bytes.fromhex('7f454c46')
                        or int.from_bytes(binary[18:20], 'little') != EXPECTED_ELF_MACHINE[arch]):
                    raise ValueError('FRP_ARCHIVE_ELF_INVALID')
                result[role] = binary
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ValueError('FRP_ARCHIVE_INVALID') from exc
    return result


def run(*argv):
    return subprocess.check_output(argv, text=True, timeout=120).strip()


def main():
    version = os.environ.get('SMITE_FRP_VERIFY_VERSION', '0.71.0')
    if version not in RELEASES:
        raise ValueError('UNREVIEWED_FRP_VERSION')
    for role in ('panel', 'node'):
        image = f'smite-{role}:stage15-local'
        arch = run('docker', 'image', 'inspect', image, '--format', '{{.Architecture}}')
        if arch not in RELEASES[version]:
            raise ValueError('UNSUPPORTED_FRP_ARCHITECTURE')
        url = (f'https://github.com/fatedier/frp/releases/download/v{version}/'
               f'frp_{version}_linux_{arch}.tar.gz')
        with urllib.request.urlopen(url, timeout=60) as response:
            raw = response.read(MAX_ARCHIVE + 1)
        official = checked_archive(raw, arch, version)
        cid = run('docker', 'create', '--network', 'none', '--entrypoint', '/bin/true', image)
        try:
            with tempfile.TemporaryDirectory() as temp:
                for name in (('frps',) if role == 'panel' else ('frpc', 'frps')):
                    target = Path(temp) / name
                    run('docker', 'cp', f'{cid}:/usr/local/bin/{name}', str(target))
                    if target.read_bytes() != official[name]:
                        raise ValueError('IMAGE_FRP_BYTES_DIFFER_FROM_OFFICIAL')
                    if run('docker', 'run', '--rm', '--network', 'none', '--read-only',
                           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                           '--entrypoint', f'/usr/local/bin/{name}', image, '--version') != version:
                        raise ValueError('IMAGE_FRP_VERSION_MISMATCH')
                    print(f'{role}/{name}: OFFICIAL_{version}_BYTES_VERIFIED')
        finally:
            run('docker', 'rm', cid)
    print('NO_HOST_ACTIVATION=YES')
    print('SIGNED_PUBLICATION_AUTHORIZED=NO')


if __name__ == '__main__':
    main()
