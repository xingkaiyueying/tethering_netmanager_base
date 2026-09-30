"""Execute production sharing ledger against atomic per-table iptables and route/sysctl doubles."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
source = repo / 'services/netmanagernative'
production = (source / 'src/manager/sharing_manager.cpp').read_text(encoding='utf-8')
constants = production[production.index('constexpr const char *IPV4_FORWARDING'):production.index('bool WriteToFile(')]
init_nat = production[production.index('void SharingManager::InitChildChains()'):production.index('int32_t SharingManager::SetIpv6PrivacyExtensions(')]
forward = production[production.index('int32_t SharingManager::ReconcileForwardPairs('):production.index('int32_t SharingManager::GetNetworkSharingTraffic(')]
sysctl = production[production.index('int32_t SharingManager::SetIpFwdEnable()'):production.index('void SharingManager::IpfwdExecSaveBak()')]
utility = production[production.index('void SharingManager::CheckInited()'):production.index('int32_t SharingManager::EnableShareUnreachableRoute(')]
with tempfile.TemporaryDirectory(prefix='p3-s3-sharing-') as directory:
    out = Path(directory)
    header = (source / 'include/manager/sharing_manager.h').read_text()
    for name in ['iptables_wrapper.h', 'network_sharing.h', 'route_manager.h']:
        header = header.replace(f'#include "{name}"', '')
    (out / 'sharing_manager.h').write_text(header, encoding='utf-8')
    (out / 'test.cpp').write_text(r'''
#include <map>
#include <vector>
#include <string>
#include <set>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <cassert>
#include <cerrno>
#include <cstdio>
#define NETNATIVE_LOGI(...) ((void)0)
#define NETNATIVE_LOG_D(...) ((void)0)
#define NETNATIVE_LOGE(...) ((void)0)
namespace OHOS::NetManagerStandard {constexpr int NETMANAGER_SUCCESS=0;}
namespace OHOS::nmd {
enum IpType {IPTYPE_IPV4=1,IPTYPE_IPV6=2,IPTYPE_IPV4V6=3};
struct NetworkSharingTraffic{};struct DpaWifiTrafficReport{};struct DpaWifiTrafficReportDummy{};
struct NetworkDpaTrafficReport{};
struct RouteManager {
 using TableType=int;static constexpr int UNREACHABLE_NETWORK=99;
 inline static int addError=0,delError=0;inline static std::set<std::string> pairs;
 static int EnableSharing(const std::string &d,const std::string &u){
  if(addError)return addError;pairs.insert(d+":"+u);return 0;}
 static int DisableSharing(const std::string &d,const std::string &u){
  if(delError)return delError;pairs.erase(d+":"+u);return 0;}
};
struct CommonUtils {static bool CheckIfaceName(const std::string &s){
 return !s.empty() && s.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-_")==std::string::npos;}};
// Restore applies one table atomically and rejects missing deletes/duplicate jumps.
class IptablesWrapper {public:
 using Chains=std::map<std::string,std::vector<std::string>>;
 inline static std::map<int,std::map<std::string,Chains>> tables;
 inline static int failFamily=0;inline static std::string failTable;
 inline static std::vector<std::pair<int,std::string>> commands;
 static std::shared_ptr<IptablesWrapper> &GetInstance(){static auto w=std::make_shared<IptablesWrapper>();return w;}
 int RunCheckedCommand(int family,const std::string &s,bool restore=false){
  commands.push_back({family,s});
  if(family==failFamily && (failTable.empty()||s.find("*"+failTable)!=std::string::npos)) return -77;
  if(!restore){
   std::istringstream in(s);std::string t,table,op,chain;in>>t>>table>>op>>chain;
   std::string rule;std::getline(in,rule);
   auto &rules=tables[family][table][chain];
   if(op=="-S" || op=="-N")return 0;
   auto i=std::find(rules.begin(),rules.end(),rule);
   if(op=="-C")return i==rules.end()?-1:0;
   if(op=="-I"){rules.insert(rules.begin(),rule);return 0;}
   if(op=="-D"){if(i==rules.end())return -2;rules.erase(i);return 0;}
   assert(false);
  }
  std::istringstream in(s);std::string line,table;std::getline(in,line);assert(line[0]=='*');table=line.substr(1);
  auto next=tables[family][table];
  while(std::getline(in,line)){
   if(line=="COMMIT"){tables[family][table]=next;return 0;}
   std::istringstream command(line);std::string op,chain;command>>op>>chain;
   auto &rules=next[chain];std::string rule;std::getline(command,rule);
   if(op=="-F"){rules.clear();continue;}
   auto i=std::find(rules.begin(),rules.end(),rule);
   if(op=="-D"){if(i==rules.end())return -3;rules.erase(i);}
   else if(op=="-A"){if(i!=rules.end())return -4;rules.push_back(rule);}
   else assert(false);
  }
  assert(false);return -5;
 }
};
}
#define private public
#include "sharing_manager.h"
#undef private
namespace OHOS::nmd {
using namespace OHOS::NetManagerStandard;
''' + constants + r'''
std::map<std::string,std::string> files;bool failFile=false;
bool WriteToFile(const char *p,const char *v){if(failFile)return false;files[p]=v;return true;}
SharingManager::SharingManager(){iptablesWrapper_=IptablesWrapper::GetInstance();}
''' + init_nat + sysctl + forward + utility + r'''
int SharingManager::EnableShareUnreachableRoute(int){return 0;}
int SharingManager::DisableShareUnreachableRoute(int){return 0;}
void SharingManager::ClearForbidIpRules(){}
void SharingManager::AddSharingSecurityRules(const std::string&,const std::string&){}
void SharingManager::RemoveSharingSecurityRules(const std::string&,const std::string&){}
}
using namespace OHOS::nmd;
bool ruleContains(int f,const std::string &t,const std::string &c,const std::string &needle){
 for(const auto &s:IptablesWrapper::tables[f][t][c])if(s.find(needle)!=std::string::npos)return true;
 return false;
}
int main(){
 SharingManager m;
 assert(m.IpEnableForwarding("NearlinkIpShare")==0);
 assert(ruleContains(1,"filter","FORWARD","-i sleip+ -o sleip+ -j DROP"));
 assert(ruleContains(2,"filter","FORWARD","-i sleip+ -o sleip+ -j DROP"));
 assert(m.IpEnableForwarding("NearlinkIpShare")==0);
 assert(IptablesWrapper::tables[1]["filter"]["FORWARD"].size()==1);
 assert(m.IpEnableForwarding("legacy")==0);
 assert(m.EnableNat("sleip0","wlan0")==0 && m.EnableNat("sleip1","wlan0")==0);
 assert(m.EnableNat("usb0","wlan0")==0);
 assert(m.natPairs_.size()==3 && IptablesWrapper::tables[1]["nat"]["tetherctrl_nat_POSTROUTING"].size()==1);
 assert(IptablesWrapper::tables[2]["nat"]["tetherctrl_nat_POSTROUTING"].empty());
 assert(m.DisableNat("sleip0","wlan0")==0 && m.natPairs_.size()==2);
 assert(ruleContains(1,"nat","tetherctrl_nat_POSTROUTING","-o wlan0 -j MASQUERADE"));
 assert(ruleContains(1,"mangle","FORWARD","tetherctrl_mangle_FORWARD"));
 // Different upstream holders and idempotence, including legacy Wi-Fi/USB/PAN pairs.
 assert(m.EnableNat("bt-pan","rmnet0")==0 && m.natPairs_.size()==3);
 assert(IptablesWrapper::tables[1]["nat"]["tetherctrl_nat_POSTROUTING"].size()==2);
 assert(m.DisableNat("sleip1","wlan0")==0 && m.DisableNat("usb0","wlan0")==0);
 assert(!ruleContains(1,"nat","tetherctrl_nat_POSTROUTING","wlan0"));
 assert(ruleContains(1,"nat","tetherctrl_nat_POSTROUTING","rmnet0"));
 IptablesWrapper::failFamily=1;IptablesWrapper::failTable="nat";
 assert(m.DisableNat("bt-pan","rmnet0")==-77 && m.natPairs_.size()==1);
 IptablesWrapper::failTable="mangle";
 assert(m.DisableNat("bt-pan","rmnet0")==-77 && m.natPairs_.empty() && m.natMangleOwned_);
 IptablesWrapper::failFamily=0;
 assert(m.DisableNat("bt-pan","rmnet0")==0 && !m.natMangleOwned_);
 assert(IptablesWrapper::tables[1]["nat"]["POSTROUTING"].empty());
 // Failed first NAT after successful MSS install is fully reclaimed by an idempotent delete.
 IptablesWrapper::failFamily=1;IptablesWrapper::failTable="nat";
 assert(m.EnableNat("sleip0","eth0")==-77 && m.natPairs_.empty() && m.natMangleOwned_);
 IptablesWrapper::failFamily=0;assert(m.DisableNat("sleip0","eth0")==0 && !m.natMangleOwned_);
 assert(m.EnableNat("sleip0;bad","eth0")!=0);
 RouteManager::addError=-55;assert(m.IpfwdAddInterfaceForward("sleip0","eth0")==-55);
 assert(m.interfaceForwards_.empty());RouteManager::addError=0;
 assert(m.IpfwdAddInterfaceForward("sleip0","eth0")==0);
 assert(m.IpfwdAddInterfaceForward("sleip1","eth0")==0);
 assert(m.IpfwdAddInterfaceForward("usb0","eth0")==0);
 assert(m.IpfwdAddInterfaceForward("sleip0","eth0")==0);
 assert(m.interfaceForwards_.size()==3 && m.forwarded4_.size()==3 && m.forwarded6_.size()==3);
 assert(ruleContains(1,"filter","tetherctrl_FORWARD","-i sleip0 -o eth0"));
 assert(ruleContains(1,"filter","tetherctrl_FORWARD","-i eth0 -o sleip0 -m state --state RELATED,ESTABLISHED"));
 assert(!ruleContains(1,"filter","tetherctrl_FORWARD","-i sleip0 -o sleip1"));
 assert(ruleContains(1,"filter","tetherctrl_FORWARD","-j DROP"));
 RouteManager::delError=-EBUSY;assert(m.IpfwdRemoveInterfaceForward("sleip0","eth0")==-EBUSY);
 assert(m.forwardingRoutes_.count("sleip0:eth0") && m.interfaceForwards_.size()==3);
 RouteManager::delError=0;IptablesWrapper::failFamily=2;IptablesWrapper::failTable="filter";
 assert(m.IpfwdRemoveInterfaceForward("sleip0","eth0")==-77);
 assert(!m.forwardingRoutes_.count("sleip0:eth0") && m.interfaceForwards_.size()==3);
 assert(m.forwarded4_.size()==2 && m.forwarded6_.size()==3);
 IptablesWrapper::failFamily=0;
 assert(m.IpfwdRemoveInterfaceForward("sleip0","eth0")==0);
 assert(m.interfaceForwards_.size()==2 && m.forwarded6_.size()==2);
 assert(ruleContains(1,"filter","tetherctrl_FORWARD","-i sleip1 -o eth0"));
 // Partial add stays owned and is removable before the controller reports success.
 IptablesWrapper::failFamily=2;
 assert(m.IpfwdAddInterfaceForward("sleip0","eth0")==-77);
 assert(m.interfaceForwards_.count("sleip0:eth0") && m.forwardingRoutes_.count("sleip0:eth0"));
 IptablesWrapper::failFamily=0;assert(m.IpfwdRemoveInterfaceForward("sleip0","eth0")==0);
 assert(m.IpfwdRemoveInterfaceForward("sleip1","eth0")==0);
 assert(m.IpfwdRemoveInterfaceForward("usb0","eth0")==0);
 assert(m.interfaceForwards_.empty() && m.forwarded4_.empty() && m.forwarded6_.empty());
 assert(RouteManager::pairs.empty());
 assert(m.IpDisableForwarding("NearlinkIpShare")==0);
 assert(files[IPV4_FORWARDING_PROC_FILE]=="1" && m.forwardingRequests_.count("legacy"));
 assert(!ruleContains(1,"filter","FORWARD","-i sleip+"));
 assert(m.IpDisableForwarding("legacy")==0 && files[IPV4_FORWARDING_PROC_FILE]=="0");
 puts("Base production: NAT holder sets, MSS partial cleanup, per-family forward commits, route failures, IPv4-only NAT, isolation, mixed legacy holders and zero residuals PASS");
}
''', encoding='utf-8')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', '-include', 'algorithm', f'-I{out}', str(out / 'test.cpp'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
