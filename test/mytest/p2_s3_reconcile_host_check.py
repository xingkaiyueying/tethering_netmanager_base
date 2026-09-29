"""Run the production Network update/reconciliation and Netlink ACK path with fault-injectable boundaries."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
source = (repo / 'services/netconnmanager/src/network.cpp').read_text(encoding='utf-8')
helpers = source[source.index('static int32_t SetNetworkResolver('):source.index('bool Network::DelayStartDetection')]
resolver = source[source.index('static int32_t SetNetworkResolver(', source.index('void Network::BatchUpdateRoutes')):
                  source.index('void Network::UpdateDns(')]
with tempfile.TemporaryDirectory(prefix='p2-s3-reconcile-') as directory:
    out = Path(directory)
    test = Path(__file__).with_name('p2_s3_reconcile_test.cpp').read_text(encoding='utf-8')
    (out / 'production.inc').write_text(helpers + resolver, encoding='utf-8')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', f'-I{out}',
                    str(Path(__file__).with_name('p2_s3_reconcile_test.cpp')), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
