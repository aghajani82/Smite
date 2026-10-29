#!/usr/bin/env python3
"""Real FRP/Nginx TLS transport in an isolated Docker network; no host ports.

Synthetic CA/token only. This does not claim real-host Signed Pairing acceptance.
"""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wss', ROOT/'node/app/frp_gateway_config.py')
gateway = importlib.util.module_from_spec(spec); spec.loader.exec_module(gateway)

def run(*args, timeout=120, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        # Avoid forwarding raw subprocess output/configuration into CI logs.
        raise RuntimeError('ISOLATED_OPERATION_FAILED: ' + args[0])
    return p

def docker(*args, **kwargs): return run('docker', *args, **kwargs)

def main():
    name = 'smite-wss-' + secrets.token_hex(4)
    ir, kh, edge = name+'-ir', name+'-kh', name+'-edge'
    containers = []
    with tempfile.TemporaryDirectory() as temp:
        p = Path(temp); p.chmod(0o755)
        token = secrets.token_hex(24)
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(p/'key.pem'),'-out',str(p/'ca.pem'),'-subj','/CN=ir.example.test',
            '-addext','subjectAltName=DNS:ir.example.test')
        (p/'frps.toml').write_text('bindAddr="127.0.0.1"\nbindPort=7000\nproxyBindAddr="127.0.0.1"\n[auth]\nmethod="token"\ntoken='+json.dumps(token)+'\n')
        (p/'nginx.conf').write_text('''events {}
http {
 server {
  listen 443 ssl;
  ssl_certificate /fixture/ca.pem;
  ssl_certificate_key /fixture/key.pem;
  location = /~!frp {
   proxy_pass http://127.0.0.1:7000;
   proxy_http_version 1.1;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection "upgrade";
   proxy_read_timeout 60s;
  }
  location / { return 404; }
 }
}
''')
        docker('network','create','--internal',name)
        try:
            docker('run','-d','--name',ir,'--network',name,'--network-alias','ir.example.test',
                   '-v',f'{p}:/fixture:ro','--entrypoint','/usr/local/bin/frps',
                   'smite-node:stage15-local','-c','/fixture/frps.toml');containers.append(ir)
            docker('run','-d','--name',edge,'--network',f'container:{ir}',
                   '-v',f'{p}:/fixture:ro','--entrypoint','nginx','nginx:1.28-alpine',
                   '-c','/fixture/nginx.conf','-g','daemon off;');containers.append(edge)
            # The real adapter's WSS TLS output; only fixture CA path changes.
            os.environ.update(SMITE_FRP_STANDARD_WSS='1', PANEL_ADDRESS='ir.example.test:443')
            tls = gateway.frp_tls_transport_yaml({})
            base = 'serverAddr: "ir.example.test"\nserverPort: 443\nloginFailExit: true\n'
            proxy = '\nproxies:\n  - name: fixture\n    type: tcp\n    localIP: 127.0.0.1\n    localPort: 18081\n    remotePort: 19081\n'
            for case in ('untrusted-ca','wrong-host','wrong-token','valid'):
                current = tls if case=='untrusted-ca' else tls.replace('/etc/ssl/certs/ca-certificates.crt','/fixture/ca.pem')
                if case=='wrong-host': current=current.replace('serverName: "ir.example.test"','serverName: "wrong.example.test"')
                auth = 'auth:\n  method: token\n  token: '+json.dumps('wrong' if case=='wrong-token' else token)+'\n'
                (p/'frpc.yaml').write_text(base+auth+current+proxy)
                docker('run','-d','--name',kh,'--network',name,'-v',f'{p}:/fixture:ro',
                       '--entrypoint','sh','smite-node:stage15-local','-c',
                       'python -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 & exec /usr/local/bin/frpc -c /fixture/frpc.yaml')
                containers.append(kh)
                probe = 'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:19081",timeout=2); assert r.status==200'
                connected = False
                for _ in range(30):
                    got=docker('exec',ir,'python','-c',probe,check=False)
                    if got.returncode==0: connected=True;break
                    running=docker('inspect','-f','{{.State.Running}}',kh).stdout.strip()
                    if running=='false':break
                    time.sleep(1)
                if connected != (case=='valid'): raise RuntimeError('WSS_CASE_FAILED: '+case)
                if case=='valid':
                    docker('restart',kh)
                    for _ in range(30):
                        if docker('exec',ir,'python','-c',probe,check=False).returncode==0:break
                        time.sleep(1)
                    else:raise RuntimeError('WSS_RESTART_FAILED')
                else:
                    # A failed client must terminate; reject silent transient failures.
                    if docker('inspect','-f','{{.State.Running}}',kh).stdout.strip()!='false':
                        raise RuntimeError('NEGATIVE_CLIENT_DID_NOT_REJECT')
                print('WSS_'+case.upper().replace('-','_')+'=PASS')
                docker('rm','-f',kh);containers.remove(kh)
            # No control/proxy listener may bind a non-loopback address.
            code='import psutil; ports={7000,19081}; assert all(c.laddr.ip=="127.0.0.1" for c in psutil.net_connections("tcp") if c.status=="LISTEN" and c.laddr.port in ports)'
            docker('exec',ir,'python','-c',code)
            print('WSS_LOOPBACK_CONTROL_AND_PROXY=PASS')
        finally:
            for container in reversed(containers):docker('rm','-f',container,check=False)
            docker('network','rm',name,check=False)
if __name__=='__main__':main()
