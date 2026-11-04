"""Execute production DNS forwarding against adverse default-route and uplink-switch doubles."""
from pathlib import Path
import os
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
path = 'services/netmanagernative/src/netsys/dnsresolv/dns_proxy_listen.cpp'
ref = os.environ.get('P3_DNS_UPSTREAM_BEFORE_REF')
source = subprocess.check_output(['git', '-c', 'safe.directory=' + repo.as_posix(), '-C', str(repo),
                                  'show', ref + ':' + path]).decode() if ref else (repo / path).read_text()


def function(name):
    start = source.index(name)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


production = '\n'.join(function(name) for name in (
    'void DnsProxyListen::DnsParseBySocket(', 'bool DnsProxyListen::GetDnsProxyServers(',
    'bool DnsProxyListen::MakeAddrInfo(', 'void DnsProxyListen::SendRequest2Server('))
if ref:
    # Adapt only the old private signature so the same harness executes the old implementation.
    production = production.replace('size_t serverIdx)', 'size_t serverIdx, uint16_t netId)')
    production = production.replace('GetDnsProxyServers(servers, serverIdx)',
                                    'GetDnsProxyServers(servers, serverIdx, netId_)')

with tempfile.TemporaryDirectory(prefix='p3-dns-upstream-') as directory:
    out = Path(directory)
    test = out / 'test.cpp'
    test.write_text(r'''
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <chrono>
#include <cassert>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <cerrno>
constexpr int SOCK_CLOEXEC=0,SOCK_NONBLOCK=0,EPOLL_CTL_DEL=1,EPOLL_CTL_ADD=2;
constexpr uint16_t DNS_PROXY_PORT=53;
constexpr uint32_t EPOLL_LOOP_ADDR=16777343;
constexpr int EPOLL_TIMEOUT=3000;
union AlignedSockAddr {sockaddr sa;sockaddr_in sin;sockaddr_in6 sin6;};
struct RecvBuff {char questionsBuff[512]{};int questionLen=12,replyIfindex=48;
 AlignedSockAddr replyAddress{};uint16_t upstreamNetId=0;std::vector<std::string> upstreamServers;};
struct Request {std::unique_ptr<AlignedSockAddr> client;std::unique_ptr<RecvBuff> buffer;
 AlignedSockAddr server{};size_t index=0;std::chrono::system_clock::time_point endTime;
 Request(int,std::unique_ptr<AlignedSockAddr>&&c,std::unique_ptr<RecvBuff>&&b):client(std::move(c)),buffer(std::move(b)){}
 size_t GetIdx(){return index;}void IncreaseIdx(){++index;}
 AlignedSockAddr &GetAddr(){return server;}AlignedSockAddr &GetClientSock(){return *client;}
 RecvBuff &GetRecvBuff(){return *buffer;}void *GetEventPtr(){return nullptr;}};
struct DnsProxyListen {static inline std::atomic<uint16_t> netId_{101};
 int epollFd_=1;std::map<int,Request> serverIdxOfSocket;
 void DnsParseBySocket(std::unique_ptr<RecvBuff>&,std::unique_ptr<AlignedSockAddr>&);
 bool GetDnsProxyServers(std::vector<std::string>&,size_t,uint16_t);
 bool MakeAddrInfo(std::vector<std::string>&,size_t,AlignedSockAddr&,AlignedSockAddr&);
 void SendRequest2Server(int);};
inline int nextFd=10,bindError=0,configCalls=0,sendCalls=0,closes=0,wrongRouteSends=0;
inline bool emptyConfig=false,nonblock=true,switchDuringConfig=false;
inline int32_t defaultNetId=101;
inline std::map<int,uint16_t> marks;
inline std::vector<uint16_t> sentNetIds;
inline int Socket(int,int,int){return ++nextFd;}
inline int Close(int){++closes;return 0;}
struct FwmarkClient {int BindSocket(int fd,uint32_t id){if(bindError)return bindError;marks[fd]=id;return 0;}};
struct DnsParamCache {static DnsParamCache &GetInstance(){static DnsParamCache c;return c;}
 int32_t GetDefaultNetwork(){return defaultNetId;}
 void GetResolverConfig(uint16_t id,std::vector<std::string>&servers,std::vector<std::string>&,
 uint16_t&,uint8_t&){++configCalls;
 if(!emptyConfig)servers=id==101?std::vector<std::string>{"192.0.2.53","192.0.2.54","2001:db8::53","2001:db8::54"}:
 std::vector<std::string>{"198.51.100.53","2001:db8:1::53"};
 if(switchDuringConfig)DnsProxyListen::netId_=202;}};
struct PollUdpDataTransfer {static bool MakeUdpNonBlock(int){return nonblock;}
 static int PollUdpSendData(int fd,char*,int n,AlignedSockAddr &server,socklen_t&){++sendCalls;
 // The current default route deliberately belongs to another network.
 uint16_t selected=marks.count(fd)?marks[fd]:202;
 if(selected!=101){++wrongRouteSends;errno=ENETUNREACH;return -1;}
 assert(server.sa.sa_family==AF_INET||server.sa.sa_family==AF_INET6);
 sentNetIds.push_back(selected);return n;}};
inline int epoll_ctl(int,int,int,void*){return 0;}
#define socket Socket
#define close Close
#define NETNATIVE_LOGE(...) ((void)0)
''' + production + r'''
int main(){
 DnsProxyListen d;
 auto start=[&](int family){auto b=std::make_unique<RecvBuff>();auto c=std::make_unique<AlignedSockAddr>();
 c->sa.sa_family=family;d.DnsParseBySocket(b,c);};
 for(int family:{AF_INET,AF_INET6}){
  DnsProxyListen::netId_=101;switchDuringConfig=true;
  start(family);
  assert(wrongRouteSends==0 && "DNS upstream socket must use selected netId, not default route");
  assert(d.serverIdxOfSocket.size()==1);
  auto &request=d.serverIdxOfSocket.begin()->second;
  assert(request.GetRecvBuff().upstreamNetId==101&&DnsProxyListen::netId_==202);
  int calls=configCalls;int fd=d.serverIdxOfSocket.begin()->first;
  d.SendRequest2Server(fd);
  assert(configCalls==calls && "DNS retry must retain the request uplink configuration");
  assert(sentNetIds.back()==101);
  d.serverIdxOfSocket.clear();
 }
 DnsProxyListen::netId_=0;switchDuringConfig=true;start(AF_INET);
 assert(d.serverIdxOfSocket.size()==1 && "Default DNS requests must capture the actual default netId");
 assert(d.serverIdxOfSocket.begin()->second.GetRecvBuff().upstreamNetId==101);
 assert(sentNetIds.back()==101);d.serverIdxOfSocket.clear();
 switchDuringConfig=false;DnsProxyListen::netId_=0;defaultNetId=0;
 int allocatedZero=nextFd;start(AF_INET);assert(nextFd==allocatedZero&&d.serverIdxOfSocket.empty());
 defaultNetId=70000;start(AF_INET6);assert(nextFd==allocatedZero&&d.serverIdxOfSocket.empty());
 defaultNetId=101;
 switchDuringConfig=false;DnsProxyListen::netId_=101;
 bindError=-13;int sends=sendCalls,closed=closes;start(AF_INET);
 assert(sendCalls==sends&&closes==closed+1&&d.serverIdxOfSocket.empty());
 bindError=0;nonblock=false;closed=closes;start(AF_INET6);
 assert(sendCalls==sends&&closes==closed+1&&d.serverIdxOfSocket.empty());
 nonblock=true;emptyConfig=true;int allocated=nextFd;start(AF_INET);
 assert(nextFd==allocated&&d.serverIdxOfSocket.empty());
 puts("DNS production forwarding: selected/default netId capture, IPv4/IPv6 binding, concurrent uplink switch, retry snapshot, unavailable default, bind/setup failure without unbound fallback PASS");
}
''', encoding='utf-8')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', str(test), '-o', str(exe), '-lws2_32'], check=True)
    subprocess.run([str(exe)], check=True)
