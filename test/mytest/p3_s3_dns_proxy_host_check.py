"""Execute DNS receive/reply production functions with explicit socket and route-selection doubles.

This proves packet-info ownership, not kernel routing, device DNS or product compilation.
--source-ref runs the same scenario on an older source revision for regression evidence.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[2]
path = 'services/netmanagernative/src/netsys/dnsresolv/dns_proxy_listen.cpp'
if '--source-ref' in sys.argv:
    ref = sys.argv[sys.argv.index('--source-ref') + 1]
    source = subprocess.check_output(['git', '-c', 'safe.directory=' + repo.as_posix(), '-C', str(repo),
                                      'show', ref + ':' + path]).decode('utf-8')
else:
    source = (repo / path).read_text(encoding='utf-8')

def function(name):
    start = source.index(name)
    begin = source.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

helpers = ''
if 'int32_t ReceiveDnsRequest(' in source:
    helpers = function('int32_t ReceiveDnsRequest(') + '\n' + function('int32_t SendDnsReply(')
production = '\n'.join(function(name) for name in [
    'void DnsProxyListen::GetRequestAndTransmit(', 'void DnsProxyListen::SendDnsBack2Client(',
    'void DnsProxyListen::DnsSendRecvParseData(', 'bool DnsProxyListen::CheckDnsQuestion(',
    'bool DnsProxyListen::CheckDnsResponse('])
with tempfile.TemporaryDirectory(prefix='p3-s3-dns-reply-') as directory:
    out = Path(directory)
    test = out / 'test.cpp'
    test.write_text(r'''
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <map>
#include <memory>
#include <vector>
constexpr int AF_INET=2,AF_INET6=10,IPPROTO_IP=0,IPPROTO_IPV6=41,IP_PKTINFO=8,IPV6_PKTINFO=50;
constexpr int MSG_TRUNC=0x20,MSG_CTRUNC=8;
struct in_addr {uint32_t s_addr;};
struct in6_addr {unsigned char s6_addr[16];};
struct sockaddr {unsigned short sa_family;char pad[30];};
struct sockaddr_in {unsigned short sin_family,sin_port;in_addr sin_addr;};
struct sockaddr_in6 {unsigned short sin6_family,sin6_port;uint32_t flow;in6_addr sin6_addr;uint32_t sin6_scope_id;};
union AlignedSockAddr {sockaddr sa;sockaddr_in sin;sockaddr_in6 sin6;};
struct in_pktinfo {int ipi_ifindex;in_addr ipi_spec_dst,ipi_addr;};
struct in6_pktinfo {in6_addr ipi6_addr;unsigned ipi6_ifindex;};
using socklen_t=unsigned;
struct iovec {void *iov_base;size_t iov_len;};
struct msghdr {void *msg_name;size_t msg_namelen;iovec *msg_iov;size_t msg_iovlen;
 void *msg_control;size_t msg_controllen;int msg_flags;};
struct cmsghdr {size_t cmsg_len;int cmsg_level,cmsg_type;};
constexpr size_t alignSize(size_t n){return (n+sizeof(size_t)-1)&~(sizeof(size_t)-1);}
#define CMSG_SPACE(n) (alignSize(sizeof(cmsghdr))+alignSize(n))
#define CMSG_LEN(n) (alignSize(sizeof(cmsghdr))+(n))
#define CMSG_DATA(h) (reinterpret_cast<unsigned char*>(h)+alignSize(sizeof(cmsghdr)))
inline cmsghdr *first(msghdr*m){return m->msg_controllen>=sizeof(cmsghdr)?static_cast<cmsghdr*>(m->msg_control):nullptr;}
inline cmsghdr *next(msghdr*m,cmsghdr*h){auto p=reinterpret_cast<char*>(h)+alignSize(h->cmsg_len);
 return h->cmsg_len>=sizeof(cmsghdr)&&p+sizeof(cmsghdr)<=static_cast<char*>(m->msg_control)+m->msg_controllen?reinterpret_cast<cmsghdr*>(p):nullptr;}
#define CMSG_FIRSTHDR(m) first(m)
#define CMSG_NXTHDR(m,h) next(m,h)
constexpr size_t MAX_REQUESTDATA_LEN=512,DNS_HEAD_LENGTH=12,FLAG_BUFF_LEN=1,FLAG_BUFF_OFFSET=2;
constexpr uint8_t RESPONSE_FLAG=0x80,RESPONSE_FLAG_USED=80;
struct RecvBuff {char questionsBuff[512]{};int questionLen=0,replyIfindex=0;AlignedSockAddr replyAddress{};};
struct Pending {int family,index;uint32_t local;unsigned short port;};
inline Pending pending{};inline int flags=0,receiveLength=12;inline bool missing=false,shortInfo=false,interruptReceive=false,interruptSend=false,failSend=false;
inline int legacySends=0,markedSends=0;inline std::vector<Pending> replies;
inline void fillClient(void*value){auto &client=*static_cast<AlignedSockAddr*>(value);client={};
 if(pending.family==AF_INET){client.sin.sin_family=AF_INET;client.sin.sin_port=pending.port;client.sin.sin_addr.s_addr=123;}
 else {client.sin6.sin6_family=AF_INET6;client.sin6.sin6_port=pending.port;client.sin6.sin6_scope_id=pending.index;client.sin6.sin6_addr.s6_addr[15]=3;}}
inline int recvfrom(int,void*buf,size_t,int,sockaddr*client,socklen_t*){fillClient(client);memset(buf,0,12);return receiveLength;}
inline int recvmsg(int,msghdr*m,int){if(interruptReceive){interruptReceive=false;errno=EINTR;return -1;}
 fillClient(m->msg_name);memset(m->msg_iov->iov_base,0,12);m->msg_flags=flags;
 if(missing){m->msg_controllen=0;return receiveLength;}
 auto h=CMSG_FIRSTHDR(m);h->cmsg_level=pending.family==AF_INET?IPPROTO_IP:IPPROTO_IPV6;
 h->cmsg_type=pending.family==AF_INET?IP_PKTINFO:IPV6_PKTINFO;
 if(pending.family==AF_INET){in_pktinfo info{};info.ipi_ifindex=pending.index;info.ipi_addr.s_addr=pending.local;
  h->cmsg_len=CMSG_LEN(sizeof(info));memcpy(CMSG_DATA(h),&info,sizeof(info));}
 else{in6_pktinfo info{};info.ipi6_ifindex=pending.index;info.ipi6_addr.s6_addr[15]=pending.local;
  h->cmsg_len=CMSG_LEN(sizeof(info));memcpy(CMSG_DATA(h),&info,sizeof(info));}
 m->msg_controllen=CMSG_SPACE(pending.family==AF_INET?sizeof(in_pktinfo):sizeof(in6_pktinfo));
 if(shortInfo)h->cmsg_len=CMSG_LEN(1);return receiveLength;}
inline int sendmsg(int,const msghdr*m,int){if(interruptSend){interruptSend=false;errno=EINTR;return -1;}
 if(failSend){errno=ENODEV;return -1;}++markedSends;auto h=static_cast<cmsghdr*>(m->msg_control);
 auto &client=*static_cast<AlignedSockAddr*>(m->msg_name);Pending reply{};reply.family=client.sa.sa_family;
 if(reply.family==AF_INET){in_pktinfo info{};memcpy(&info,CMSG_DATA(h),sizeof(info));
  assert(h->cmsg_level==IPPROTO_IP&&h->cmsg_type==IP_PKTINFO);reply.index=info.ipi_ifindex;reply.local=info.ipi_spec_dst.s_addr;reply.port=client.sin.sin_port;}
 else{in6_pktinfo info{};memcpy(&info,CMSG_DATA(h),sizeof(info));assert(h->cmsg_level==IPPROTO_IPV6&&h->cmsg_type==IPV6_PKTINFO);
  reply.index=info.ipi6_ifindex;reply.local=info.ipi6_addr.s6_addr[15];reply.port=client.sin6.sin6_port;assert(client.sin6.sin6_scope_id==static_cast<unsigned>(reply.index));}
 replies.push_back(reply);return m->msg_iov->iov_len;}
struct PollUdpDataTransfer {
 static int PollUdpRecvData(int,char*b,size_t,AlignedSockAddr&,socklen_t&){memset(b,0,12);b[2]=char(0x80);return 12;}
 static int PollUdpSendData(int,char*,int n,AlignedSockAddr &client,socklen_t&){++legacySends;
  // Explicit adverse route fixture: wildcard send selects another local address/link.
  replies.push_back({client.sa.sa_family,1,99,client.sa.sa_family==AF_INET?client.sin.sin_port:client.sin6.sin6_port});return n;}};
inline int memset_s(void*p,size_t,int value,size_t n){memset(p,value,n);return 0;}
#define NETNATIVE_LOG_D(...) ((void)0)
#define NETNATIVE_LOGE(...) ((void)0)
#define NETNATIVE_LOGI(...) ((void)0)
struct Request {RecvBuff buffer{};AlignedSockAddr client{},server{};
 AlignedSockAddr &GetAddr(){return server;}AlignedSockAddr &GetClientSock(){return client;}RecvBuff &GetRecvBuff(){return buffer;}};
struct DnsProxyListen {int proxySockFd_=4,proxySockFd6_=6;std::map<int,Request> serverIdxOfSocket;int serial=10;
 void GetRequestAndTransmit(int);void SendDnsBack2Client(int);
 static void DnsSendRecvParseData(int,char*,int,AlignedSockAddr&);static bool CheckDnsQuestion(char*,size_t);static bool CheckDnsResponse(char*,size_t);
 void DnsParseBySocket(std::unique_ptr<RecvBuff>&buf,std::unique_ptr<AlignedSockAddr>&client){Request r;r.buffer=*buf;r.client=*client;serverIdxOfSocket.emplace(++serial,r);}
 void SendRequest2Server(int){assert(false);}};
''' + helpers + '\n' + production + r'''
int main(){
 DnsProxyListen d;
 for(int family:{AF_INET,AF_INET6}){
  pending={family,56,10,1001};interruptReceive=true;d.GetRequestAndTransmit(family);int firstId=d.serial;
  pending={family,57,11,1002};d.GetRequestAndTransmit(family);int secondId=d.serial;
  interruptSend=true;d.SendDnsBack2Client(secondId);d.SendDnsBack2Client(firstId);
  assert(replies.size()>=2);auto &b=replies[replies.size()-2];auto &a=replies.back();
  assert(b.index==57&&b.local==11&&b.port==1002);assert(a.index==56&&a.local==10&&a.port==1001);
  assert(d.serverIdxOfSocket.empty());
 }
 assert(markedSends==4&&legacySends==0);
 for(int mode=0;mode<5;++mode){auto count=d.serial;missing=mode==0;shortInfo=mode==1;flags=mode==2?MSG_CTRUNC:mode==3?MSG_TRUNC:0;receiveLength=mode==4?3:12;
  pending={AF_INET,57,11,1003};d.GetRequestAndTransmit(AF_INET);assert(d.serial==count);}
 flags=0;missing=shortInfo=false;receiveLength=12;pending={AF_INET,57,11,1004};d.GetRequestAndTransmit(AF_INET);
 failSend=true;d.SendDnsBack2Client(d.serial);assert(legacySends==0&&d.serverIdxOfSocket.empty());
 puts("DNS production functions: two IPv4/IPv6 peers, reverse replies, requested source/ifindex, IPv6 scope, EINTR, truncation/missing ancillary/short DNS rejection, failed old-link send without fallback PASS");
}
''', encoding='utf-8')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', str(test), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
