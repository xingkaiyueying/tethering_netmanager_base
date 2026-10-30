"""Execute production checked queue/wait/exit handling with explicit process and FFRT doubles."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
source = (repo / 'services/netmanagernative/src/netsys/iptables_wrapper.cpp').read_text()
child = source[source.index('int32_t ExecuteChecked('):source.index('} // namespace')]
checked = source[source.index('int32_t IptablesWrapper::RunCheckedCommand('):source.index('int32_t IptablesWrapper::RunRestoreCommands(')]
with tempfile.TemporaryDirectory(prefix='p3-s3-iptables-') as directory:
    out = Path(directory)
    (out / 'test.cpp').write_text(r'''
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <cassert>
#include <cerrno>
#include <functional>
#include <cstdlib>
#include <cstdio>
constexpr int NETMANAGER_ERROR=-1,NETMANAGER_SUCCESS=0;
constexpr const char *IPATBLES_CMD_PATH="iptables",*IP6TABLES_CMD_PATH="ip6tables";
constexpr const char *IPTABLES_RESTORE_CMD_PATH="iptables-restore",*IP6TABLES_RESTORE_CMD_PATH="ip6tables-restore";
constexpr const char *IPTABLES_RULE_PATH="rules";
enum IpType {IPTYPE_IPV4=1,IPTYPE_IPV6=2,IPTYPE_IPV4V6=3};
int mockFork=10,mockWait=10,mockExit=0,spawned=0,waited=0;
int fork(){++spawned;return mockFork;}
int execv(const char*,char *const*){return -1;}
void _exit(int){std::abort();}
int waitpid(int,int *s,int){++waited;*s=mockExit;return mockWait;}
#define WIFEXITED(s) ((s)>=0)
#define WEXITSTATUS(s) (s)
struct CommonUtils {
 inline static bool written=true;
 static std::vector<std::string> Split(const std::string &s,const std::string &){
  std::istringstream in(s);std::string word;std::vector<std::string> a;while(in>>word)a.push_back(word);return a;}
 static bool WriteFile(const char*,const std::string&){return written;}
};
struct Queue {int submitted=0,completed=0;std::function<void()> pending;
 template<class T>int submit_h(T t){++submitted;pending=t;return submitted;}
 void wait(int){pending();++completed;}
};
struct IptablesWrapper {
 std::shared_ptr<Queue> iptablesWrapperFfrtQueue_=std::make_shared<Queue>();
 bool isIptablesSystemAccess_=true,isIp6tablesSystemAccess_=true;
 int32_t RunCheckedCommand(const IpType&,const std::string&,bool=false);
};
''' + child + checked + r'''
int main(){
 IptablesWrapper w;
 assert(w.RunCheckedCommand(IPTYPE_IPV4,"-t filter -C FORWARD -j test")==0);
 assert(spawned==1 && waited==1 && w.iptablesWrapperFfrtQueue_->completed==1);
 mockExit=1;assert(w.RunCheckedCommand(IPTYPE_IPV6,"-t filter -C FORWARD -j test")!=0);
 mockExit=-9;assert(w.RunCheckedCommand(IPTYPE_IPV4,"rules",true)!=0);
 mockExit=0;mockFork=-1;assert(w.RunCheckedCommand(IPTYPE_IPV4,"rules",true)!=0);
 mockFork=10;mockWait=-1;errno=ECHILD;assert(w.RunCheckedCommand(IPTYPE_IPV4,"rules",true)!=0);
 mockWait=10;CommonUtils::written=false;int before=spawned;
 assert(w.RunCheckedCommand(IPTYPE_IPV4,"rules",true)!=0 && spawned==before);
 CommonUtils::written=true;assert(w.RunCheckedCommand(IPTYPE_IPV4,"rules",true)==0);
 assert(w.RunCheckedCommand(IPTYPE_IPV4V6,"rules",true)!=0);
 w.isIp6tablesSystemAccess_=false;assert(w.RunCheckedCommand(IPTYPE_IPV6,"rules",true)!=0);
 w.iptablesWrapperFfrtQueue_.reset();assert(w.RunCheckedCommand(IPTYPE_IPV4,"rules",true)!=0);
 puts("Base production checked iptables: queue completion, real exit/signal, fork/wait/write failures and missing family reject PASS");
}
''', encoding='utf-8')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', str(out / 'test.cpp'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
