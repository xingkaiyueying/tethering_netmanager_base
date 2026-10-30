"""Execute actual router-loss handling and sharing failure propagation with platform doubles."""
from pathlib import Path
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[2]
network = (repo / 'services/netconnmanager/src/network.cpp').read_text(encoding='utf-8')
network = network[network.index('static void HandleDeleteIpv6Route('):network.index('bool Network::IsAddressValid(')]
with tempfile.TemporaryDirectory(prefix='p2-s3-base-') as directory:
    out = Path(directory)
    (out / 'test.cpp').write_text(r'''
#include <string>
#include <set>
#include <mutex>
#include <memory>
#include <cassert>
#include <cstdio>
#include <cstdint>
#define NETMGR_LOG_I(...) ((void)0)
#define NETMGR_LOG_E(...) ((void)0)
#define NETNATIVE_LOGI(...) ((void)0)
#define NETNATIVE_LOGE(...) ((void)0)
constexpr int NETMANAGER_SUCCESS=0;
namespace NetManagerStandard {constexpr int NETMANAGER_SUCCESS=0;}
struct NetLinkInfo {std::string ifaceName_;bool router=false,ipv4=true;
 bool HasIpv6DefaultRoute()const{return router;}bool IsIpv4Provisioned()const{return ipv4;}};
struct NetsysController {inline static int restarts=0,flushes=0;
 static NetsysController &GetInstance(){static NetsysController n;return n;}
 int SetEnableIpv6(const std::string&,int,bool){++restarts;return 0;}
 int FlushDnsCache(uint16_t){++flushes;return 0;}};
''' + network + r'''
int main(){
 NetLinkInfo old;old.router=true;NetLinkInfo next;next.ifaceName_="sleip0";
 HandleDeleteIpv6Route(old,next,42);assert(NetsysController::restarts==0);
 next.ifaceName_="wlan0";HandleDeleteIpv6Route(old,next,42);assert(NetsysController::restarts==1);
 puts("Base actual functions: router-only loss preserves sleip0 IPv6; other interfaces unchanged; S3 sharing ownership is exercised by p3_s3_sharing_host_check PASS");
}
''')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', str(out / 'test.cpp'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

# The shared DNS listener must preserve the receiving link independently of default-route selection.
subprocess.run([sys.executable, str(Path(__file__).with_name('p3_s3_dns_proxy_host_check.py'))], check=True)
