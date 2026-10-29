#!/usr/bin/env python3
"""Verify built FRP binaries against the official release, before image export.

Run only on disposable CI workers. Never starts a service or reads a host token.
"""
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

HASHES = {
    'amd64': '84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716',
    'arm64': 'f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266',
}

def checked_archive(raw, arch):
    if arch not in HASHES or hashlib.sha256(raw).hexdigest() != HASHES[arch]:
        raise ValueError('FRP_OFFICIAL_ARCHIVE_MISMATCH')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        result = {}
        for name in ('frpc', 'frps'):
            member = archive.getmember(f'frp_0.71.0_linux_{arch}/{name}')
            if not member.isfile() or not 0 < member.size < 48 * 1024 * 1024:
                raise ValueError('FRP_ARCHIVE_MEMBER_INVALID')
            result[name] = archive.extractfile(member).read()
        return result

def run(*argv):
    return subprocess.check_output(argv, text=True, timeout=120).strip()

def main():
    for role in ('panel', 'node'):
        image = f'smite-{role}:stage15-local'
        arch = run('docker', 'image', 'inspect', image, '--format', '{{.Architecture}}')
        if arch not in HASHES:
            raise ValueError('UNSUPPORTED_FRP_ARCHITECTURE')
        url = f'https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_{arch}.tar.gz'
        with urllib.request.urlopen(url, timeout=60) as response:
            raw = response.read(64 * 1024 * 1024 + 1)
        official = checked_archive(raw, arch)
        cid = run('docker', 'create', '--network', 'none', '--entrypoint', '/bin/true', image)
        try:
            with tempfile.TemporaryDirectory() as temp:
                for name in (('frps',) if role == 'panel' else ('frpc', 'frps')):
                    target = Path(temp) / name
                    run('docker', 'cp', f'{cid}:/usr/local/bin/{name}', str(target))
                    if target.read_bytes() != official[name]:
                        raise ValueError('IMAGE_FRP_BYTES_DIFFER_FROM_OFFICIAL')
                    if run('docker', 'run', '--rm', '--network', 'none', '--entrypoint',
                           f'/usr/local/bin/{name}', image, '--version') != '0.71.0':
                        raise ValueError('IMAGE_FRP_VERSION_MISMATCH')
                    print(f'{role}/{name}: OFFICIAL_0.71.0_BYTES_VERIFIED')
        finally:
            run('docker', 'rm', cid)

if __name__ == '__main__':
    main()
