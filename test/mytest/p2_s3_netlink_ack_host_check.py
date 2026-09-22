"""Run the real ACK function against deterministic socket replies (not a live Linux kernel)."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
source = (repo / 'services/netmanagernative/src/netsys/netlink_socket.cpp').read_text(encoding='utf-8')
body = source[source.index('int32_t SendNetlinkMsgToKernelWithAck('):source.index('int32_t SendNetlinkMsgsToKernel(')]
with tempfile.TemporaryDirectory(prefix='p2-ack-') as directory:
    out = Path(directory)
    (out / 'test.cpp').write_text(r'''
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <cassert>
#include <cstdio>
using ssize_t = long long;
using socklen_t = unsigned;
struct timeval {long tv_sec, tv_usec;};
struct sockaddr {};
struct sockaddr_nl {uint16_t nl_family=0,pad=0;uint32_t nl_pid=0,nl_groups=0;};
struct nlmsghdr {uint32_t nlmsg_len=0;uint16_t nlmsg_type=0,nlmsg_flags=0;uint32_t nlmsg_seq=0,nlmsg_pid=0;};
struct nlmsgerr {int error=0;nlmsghdr msg;};
constexpr int AF_NETLINK=16,SOCK_RAW=3,SOCK_CLOEXEC=0,NETLINK_ROUTE=0;
constexpr int SOL_SOCKET=1,SO_RCVTIMEO=20,NLM_F_ACK=4,NLMSG_ERROR=2,KERNEL_BUFFER_SIZE=8192;
#define NLMSG_LENGTH(n) (sizeof(nlmsghdr)+(n))
#define NLMSG_DATA(p) (reinterpret_cast<char*>(p)+sizeof(nlmsghdr))
#define NLMSG_OK(p,n) ((n)>=int(sizeof(nlmsghdr))&&(p)->nlmsg_len>=sizeof(nlmsghdr)&&(p)->nlmsg_len<=unsigned(n))
#define NLMSG_NEXT(p,n) ((n)-=(p)->nlmsg_len,reinterpret_cast<nlmsghdr*>(reinterpret_cast<char*>(p)+(p)->nlmsg_len))
int kernelError=0,mode=0,closed=0;
int socket(int,int,int){if(mode==1){errno=EMFILE;return -1;}return 7;}
int setsockopt(int,int,int,const void*,unsigned){if(mode==2){errno=EPERM;return -1;}return 0;}
ssize_t SendMsgToKernel(nlmsghdr *msg,int&){assert(msg->nlmsg_flags&NLM_F_ACK);return mode==3?-1:msg->nlmsg_len;}
ssize_t recvfrom(int,void *buf,unsigned,int,sockaddr *from,socklen_t *size){
 if(mode==4){errno=EAGAIN;return -1;}
 sockaddr_nl sender{};sender.nl_pid=mode==5?42:0;std::memcpy(from,&sender,sizeof(sender));*size=sizeof(sender);
 nlmsghdr reply{};reply.nlmsg_len=NLMSG_LENGTH(sizeof(nlmsgerr));reply.nlmsg_type=NLMSG_ERROR;reply.nlmsg_seq=mode==6?9:1;
 if(mode==7)reply.nlmsg_len=sizeof(nlmsghdr);
 std::memcpy(buf,&reply,sizeof(reply));nlmsgerr error{};error.error=kernelError;
 std::memcpy(static_cast<char*>(buf)+sizeof(reply),&error,sizeof(error));return reply.nlmsg_len;
}
void close(int){++closed;}
''' + body + r'''
int main(){
 nlmsghdr request{};request.nlmsg_len=sizeof(request);request.nlmsg_seq=1;
 assert(SendNetlinkMsgToKernelWithAck(nullptr)==-EINVAL);
 for(int error : {0,-EACCES,-EEXIST,-ESRCH}){
  kernelError=error;assert(SendNetlinkMsgToKernelWithAck(&request)==error);
 }
 for(mode=1;mode<=7;++mode){int before=closed;assert(SendNetlinkMsgToKernelWithAck(&request)<0);assert(closed==before+(mode!=1));}
 puts("Netlink actual ACK function: success/kernel errno, timeout, malformed/foreign/sequence rejection, close ownership PASS");
}
'''.replace('for(int error : {0,-EACCES,-EEXIST,-ESRCH})', 'int errors[]={0,-EACCES,-EEXIST,-ESRCH};for(int error : errors)'), encoding='utf-8')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', str(out / 'test.cpp'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
