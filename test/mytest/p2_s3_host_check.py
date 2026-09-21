"""Execute actual router-loss handling and sharing failure propagation with platform doubles."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
network = (repo / 'services/netconnmanager/src/network.cpp').read_text(encoding='utf-8')
network = network[network.index('static void HandleDeleteIpv6Route('):network.index('bool Network::IsAddressValid(')]
sharing = (repo / 'services/netmanagernative/src/manager/sharing_manager.cpp').read_text(encoding='utf-8')
sharing = sharing[sharing.index('int32_t SharingManager::IpfwdAddInterfaceForward('):sharing.index('int32_t SharingManager::IpfwdRemoveInterfaceForward(')]
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
struct RouteManager {inline static int result=0;static constexpr int UNREACHABLE_NETWORK=99;
 static int EnableSharing(const std::string&,const std::string&){return result;}};
struct CommonUtils {static bool CheckIfaceName(const std::string&){return true;}};
constexpr int FILTER_TABLE=0,FORWARD_JUMP_TETHERCTRL_FORWARD=1,SET_TETHERCTRL_FORWARD_DROP=2,CMD_COMMIT=3,IPTYPE_IPV4V6=4;
constexpr const char *WLAN_IFACE_NAME="wlan",*P2P_IFACE_NAME="p2p";
struct Wrapper{int RunRestoreCommands(int,const std::string&){return 0;}};
class SharingManager {public:
int rollbacks=0;std::mutex interfaceForwardsMutex_,wifiShareInterfaceMutex_;
std::set<std::string> interfaceForwards_;std::string wifiShareInterface_;
std::shared_ptr<Wrapper> iptablesWrapper_=std::make_shared<Wrapper>();
int32_t IpfwdAddInterfaceForward(const std::string&,const std::string&);
void CheckInited(){}void IpfwdExecSaveBak(){}void Rollback(){++rollbacks;}
void CombineRestoreRules(int,std::string&){}void SetForwardRules(bool,int,std::string&){}
int SetTetherctrlForward1(const std::string&,const std::string&){return 0;}
int SetTetherctrlForward2(const std::string&,const std::string&){return 0;}
int SetTetherctrlForward3(const std::string&,const std::string&){return 0;}
int SetTetherctrlCounters1(const std::string&,const std::string&){return 0;}
int SetTetherctrlCounters2(const std::string&,const std::string&){return 0;}
void EnableShareUnreachableRoute(int){}void AddSharingSecurityRules(const std::string&,const std::string&){}
};
''' + sharing + r'''
int main(){
 NetLinkInfo old;old.router=true;NetLinkInfo next;next.ifaceName_="sleip0";
 HandleDeleteIpv6Route(old,next,42);assert(NetsysController::restarts==0);
 next.ifaceName_="wlan0";HandleDeleteIpv6Route(old,next,42);assert(NetsysController::restarts==1);
 SharingManager sharing;RouteManager::result=-55;
 assert(sharing.IpfwdAddInterfaceForward("sleip0","eth0")==-55 && sharing.rollbacks==1);
 assert(sharing.interfaceForwards_.empty());RouteManager::result=0;
 assert(sharing.IpfwdAddInterfaceForward("sleip0","eth0")==0 && sharing.interfaceForwards_.size()==1);
 puts("Base actual functions: router-only loss preserves sleip0 IPv6; other interfaces unchanged; forwarding route failure propagates/rolls back PASS");
}
''')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', str(out / 'test.cpp'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
