/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <array>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <thread>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "dns_config_client.h"
#include "dns_param_cache.h"
#include "netnative_log_wrapper.h"
#include "netsys_udp_transfer.h"
#include "singleton.h"
#include "ffrt.h"

#include "dns_proxy_listen.h"

namespace OHOS {
namespace nmd {
uint16_t DnsProxyListen::netId_ = 0;
std::atomic_bool DnsProxyListen::proxyListenSwitch_ = false;
std::mutex DnsProxyListen::listenerMutex_;
constexpr uint16_t DNS_PROXY_PORT = 53;
constexpr uint8_t RESPONSE_FLAG = 0x80;
constexpr uint8_t RESPONSE_FLAG_USED = 80;
constexpr size_t FLAG_BUFF_LEN = 1;
constexpr size_t FLAG_BUFF_OFFSET = 2;
constexpr size_t DNS_HEAD_LENGTH = 12;
constexpr int32_t EPOLL_TASK_NUMBER = 10;
constexpr int32_t EPOLL_LOOP_EXIT = 1;
constexpr uint32_t EPOLL_LOOP_ADDR = 16777343;

namespace {
int32_t ReceiveDnsRequest(int32_t fd, RecvBuff &buffer, AlignedSockAddr &client, int32_t family)
{
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(in6_pktinfo)) + CMSG_SPACE(sizeof(in_pktinfo))> control{};
    iovec data{buffer.questionsBuff, sizeof(buffer.questionsBuff)};
    msghdr message{};
    message.msg_name = &client;
    message.msg_namelen = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    buffer.replyIfindex = 0;
    buffer.replyAddress = {};
    int32_t length;
    do {
        length = recvmsg(fd, &message, 0);
    } while (length < 0 && errno == EINTR);
    if (length <= 0) {
        return length;
    }
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || client.sa.sa_family != family) {
        errno = EMSGSIZE;
        return -1;
    }
    for (auto header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (family == AF_INET && header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO &&
            header->cmsg_len >= CMSG_LEN(sizeof(in_pktinfo))) {
            in_pktinfo info{};
            memcpy(&info, CMSG_DATA(header), sizeof(info));
            buffer.replyIfindex = info.ipi_ifindex;
            buffer.replyAddress.sin.sin_family = AF_INET;
            buffer.replyAddress.sin.sin_addr = info.ipi_addr;
        } else if (family == AF_INET6 && header->cmsg_level == IPPROTO_IPV6 &&
                   header->cmsg_type == IPV6_PKTINFO && header->cmsg_len >= CMSG_LEN(sizeof(in6_pktinfo))) {
            in6_pktinfo info{};
            memcpy(&info, CMSG_DATA(header), sizeof(info));
            buffer.replyIfindex = info.ipi6_ifindex;
            buffer.replyAddress.sin6.sin6_family = AF_INET6;
            buffer.replyAddress.sin6.sin6_addr = info.ipi6_addr;
        }
    }
    // Never silently send a multi-interface reply through the current default route.
    if (buffer.replyIfindex <= 0) {
        errno = ENOMSG;
        return -1;
    }
    return length;
}

int32_t SendDnsReply(int32_t fd, char *response, int32_t length, AlignedSockAddr &client, const RecvBuff &request)
{
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(in6_pktinfo)) + CMSG_SPACE(sizeof(in_pktinfo))> control{};
    iovec data{response, static_cast<size_t>(length)};
    msghdr message{};
    message.msg_name = &client;
    message.msg_namelen = client.sa.sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = client.sa.sa_family == AF_INET ? CMSG_SPACE(sizeof(in_pktinfo))
                                                          : CMSG_SPACE(sizeof(in6_pktinfo));
    auto header = CMSG_FIRSTHDR(&message);
    if (client.sa.sa_family == AF_INET) {
        header->cmsg_level = IPPROTO_IP;
        header->cmsg_type = IP_PKTINFO;
        header->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
        in_pktinfo info{};
        info.ipi_ifindex = request.replyIfindex;
        info.ipi_spec_dst = request.replyAddress.sin.sin_addr;
        memcpy(CMSG_DATA(header), &info, sizeof(info));
    } else {
        header->cmsg_level = IPPROTO_IPV6;
        header->cmsg_type = IPV6_PKTINFO;
        header->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
        in6_pktinfo info{};
        info.ipi6_ifindex = request.replyIfindex;
        info.ipi6_addr = request.replyAddress.sin6.sin6_addr;
        memcpy(CMSG_DATA(header), &info, sizeof(info));
    }
    int32_t sent;
    do {
        sent = sendmsg(fd, &message, 0);
    } while (sent < 0 && errno == EINTR);
    return sent;
}
} // namespace

DnsProxyListen::DnsProxyListen() : proxySockFd_(-1), proxySockFd6_(-1) {}
DnsProxyListen::~DnsProxyListen()
{
    if (proxySockFd_ > 0) {
        close(proxySockFd_);
        proxySockFd_ = -1;
    }
    if (proxySockFd6_ > 0) {
        close(proxySockFd6_);
        proxySockFd6_ = -1;
    }
    if (epollFd_ > 0) {
        close(epollFd_);
        epollFd_ = -1;
    }
    if (exitFd_ > 0) {
        close(exitFd_);
        exitFd_ = -1;
    }
    serverIdxOfSocket.clear();
}

void DnsProxyListen::DnsParseBySocket(std::unique_ptr<RecvBuff> &recvBuff, std::unique_ptr<AlignedSockAddr> &clientSock)
{
    int32_t socketFd = -1;
    if (clientSock->sa.sa_family == AF_INET) {
        socketFd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
    } else if (clientSock->sa.sa_family == AF_INET6) {
        socketFd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
    }
    if (socketFd < 0) {
        NETNATIVE_LOGE("socketFd create socket failed %{public}d", errno);
        return;
    }
    if (!PollUdpDataTransfer::MakeUdpNonBlock(socketFd)) {
        NETNATIVE_LOGE("MakeNonBlock error %{public}d: %{public}s", errno, strerror(errno));
        close(socketFd);
        return;
    }
    serverIdxOfSocket.emplace(std::piecewise_construct, std::forward_as_tuple(socketFd),
                              std::forward_as_tuple(socketFd, std::move(clientSock), std::move(recvBuff)));
    SendRequest2Server(socketFd);
}

bool DnsProxyListen::GetDnsProxyServers(std::vector<std::string> &servers, size_t serverIdx)
{
    std::vector<std::string> domains;
    uint16_t baseTimeoutMsec;
    uint8_t retryCount;
    DnsParamCache::GetInstance().GetResolverConfig(DnsProxyListen::netId_, servers, domains, baseTimeoutMsec,
                                                   retryCount);
    if (serverIdx >= servers.size()) {
        NETNATIVE_LOGE("no server useful");
        return false;
    }
    return true;
}

bool DnsProxyListen::MakeAddrInfo(std::vector<std::string> &servers, size_t serverIdx, AlignedSockAddr &addrParse,
                                  AlignedSockAddr &clientSock)
{
    if (clientSock.sa.sa_family == AF_INET) {
        if (servers[serverIdx].find(".") == std::string::npos) {
            return false;
        }
        addrParse.sin.sin_family = AF_INET;
        addrParse.sin.sin_port = htons(DNS_PROXY_PORT);
        addrParse.sin.sin_addr.s_addr = inet_addr(servers[serverIdx].c_str());
        if (addrParse.sin.sin_addr.s_addr == INADDR_NONE) {
            NETNATIVE_LOGE("Input ipv4 dns server %{private}s is not correct!", servers[serverIdx].c_str());
            return false;
        }
    } else if (clientSock.sa.sa_family == AF_INET6) {
        if (servers[serverIdx].find(":") == std::string::npos) {
            return false;
        }
        addrParse.sin6.sin6_family = AF_INET6;
        addrParse.sin6.sin6_port = htons(DNS_PROXY_PORT);
        inet_pton(AF_INET6, servers[serverIdx].c_str(), &(addrParse.sin6.sin6_addr));
        // LCOV_EXCL_START
        if (IN6_IS_ADDR_UNSPECIFIED(&addrParse.sin6.sin6_addr)) {
            NETNATIVE_LOGE("Input ipv6 dns server %{private}s is not correct!", servers[serverIdx].c_str());
            return false;
        }
        // LCOV_EXCL_STOP
    } else {
        NETNATIVE_LOGE("current clientSock type is error!");
        return false;
    }
    return true;
}

void DnsProxyListen::SendRequest2Server(int32_t socketFd)
{
    auto iter = serverIdxOfSocket.find(socketFd);
    if (iter == serverIdxOfSocket.end()) {
        NETNATIVE_LOGE("no idx found");
        return;
    }
    auto serverIdx = iter->second.GetIdx();
    std::vector<std::string> servers;
    if (!GetDnsProxyServers(servers, serverIdx)) {
        serverIdxOfSocket.erase(iter);
        return;
    }
    iter->second.IncreaseIdx();
    epoll_ctl(epollFd_, EPOLL_CTL_DEL, socketFd, nullptr);
    socklen_t addrLen;
    AlignedSockAddr &addrParse = iter->second.GetAddr();
    AlignedSockAddr &clientSock = iter->second.GetClientSock();
    if (clientSock.sin.sin_addr.s_addr == EPOLL_LOOP_ADDR) {
        serverIdxOfSocket.erase(iter);
        return;
    }
    // LCOV_EXCL_START
    if (!MakeAddrInfo(servers, serverIdx, addrParse, clientSock)) {
        return SendRequest2Server(socketFd);
    }
    if (PollUdpDataTransfer::PollUdpSendData(socketFd, iter->second.GetRecvBuff().questionsBuff,
                                             iter->second.GetRecvBuff().questionLen, addrParse, addrLen) < 0) {
        NETNATIVE_LOGE("send failed %{public}d: %{public}s", errno, strerror(errno));
        return SendRequest2Server(socketFd);
    }
    iter->second.endTime = std::chrono::system_clock::now() + std::chrono::milliseconds(EPOLL_TIMEOUT);
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, socketFd, iter->second.GetEventPtr()) < 0) {
        NETNATIVE_LOGE("epoll add sock %{public}d failed, errno: %{public}d", socketFd, errno);
        serverIdxOfSocket.erase(iter);
    }
    // LCOV_EXCL_STOP
}

// LCOV_EXCL_START
void DnsProxyListen::SendDnsBack2Client(int32_t socketFd)
{
    NETNATIVE_LOG_D("epoll send back to client.");
    auto iter = serverIdxOfSocket.find(socketFd);
    if (iter == serverIdxOfSocket.end()) {
        NETNATIVE_LOGE("no idx found");
        return;
    }
    AlignedSockAddr &addrParse = iter->second.GetAddr();
    AlignedSockAddr &clientSock = iter->second.GetClientSock();
    int32_t proxySocket = proxySockFd_;
    socklen_t addrLen = 0;
    if (clientSock.sa.sa_family == AF_INET) {
        proxySocket = proxySockFd_;
        addrLen = sizeof(sockaddr_in);
    } else {
        proxySocket = proxySockFd6_;
        addrLen = sizeof(sockaddr_in6);
    }
    char requesData[MAX_REQUESTDATA_LEN] = {0};
    int32_t resLen =
        PollUdpDataTransfer::PollUdpRecvData(socketFd, requesData, MAX_REQUESTDATA_LEN, addrParse, addrLen);
    if (resLen > 0 && CheckDnsResponse(requesData, resLen)) {
        NETNATIVE_LOG_D("send %{public}d back to client.", socketFd);
        const auto &request = iter->second.GetRecvBuff();
        if (request.replyIfindex > 0) {
            int32_t sent = SendDnsReply(proxySocket, requesData, resLen, clientSock, request);
            NETNATIVE_LOGI("[NearlinkIpShare][DnsReply] family=%{public}d ifindex=%{public}d "
                           "bytes=%{public}d code=%{public}d", clientSock.sa.sa_family, request.replyIfindex,
                           sent, sent == resLen ? 0 : errno);
        } else {
            DnsSendRecvParseData(proxySocket, requesData, resLen, clientSock);
        }
        serverIdxOfSocket.erase(iter);
        return;
    }
    NETNATIVE_LOGE("response not correct, retry for next server.");
    SendRequest2Server(socketFd);
}

void DnsProxyListen::DnsSendRecvParseData(int32_t clientSocket, char *requesData, int32_t resLen,
                                          AlignedSockAddr &proxyAddr)
{
    socklen_t addrLen = 0;
    if (proxyAddr.sa.sa_family == AF_INET) {
        addrLen = sizeof(sockaddr_in);
    } else {
        addrLen = sizeof(sockaddr_in6);
    }
    if (PollUdpDataTransfer::PollUdpSendData(clientSocket, requesData, resLen, proxyAddr, addrLen) < 0) {
        NETNATIVE_LOGE("send failed %{public}d: %{public}s", errno, strerror(errno));
    }
}

void DnsProxyListen::StartListen()
{
    NETNATIVE_LOGI("StartListen proxySockFd_ : %{public}d, proxySockFd6_ : %{public}d", proxySockFd_, proxySockFd6_);
    epoll_event proxyEvent;
    epoll_event proxy6Event;
    if (!InitForListening(proxyEvent, proxy6Event)) {
        return;
    }
    epoll_event eventsReceived[EPOLL_TASK_NUMBER];
    while (true) {
        bool end = false;
        int32_t nfds =
            epoll_wait(epollFd_, eventsReceived, EPOLL_TASK_NUMBER, serverIdxOfSocket.empty() ? -1 : EPOLL_TIMEOUT);
        NETNATIVE_LOG_D("now socket num: %{public}zu", serverIdxOfSocket.size());
        if (nfds < 0) {
            NETNATIVE_LOG_D("epoll errno: %{public}d", errno);
            continue; // now ignore all errno.
        }
        if (nfds == 0) {
            // dns timeout
            EpollTimeout();
            continue;
        }
        for (int i = 0; i < nfds; ++i) {
            if (eventsReceived[i].data.fd == proxySockFd_ || eventsReceived[i].data.fd == proxySockFd6_) {
                int32_t family = (eventsReceived[i].data.fd == proxySockFd_) ? AF_INET : AF_INET6;
                GetRequestAndTransmit(family);
            } else if (eventsReceived[i].data.fd == exitFd_) {
                end = GetExitFlag();
                break;
            } else {
                SendDnsBack2Client(eventsReceived[i].data.fd);
            }
        }
        if (end) {
            break;
        }
        CollectSocks();
    }
    clearResource();
    NETNATIVE_LOGI("DnsProxyListen stop");
}
// LCOV_EXCL_STOP

void DnsProxyListen::GetRequestAndTransmit(int32_t family)
{
    NETNATIVE_LOG_D("epoll got request from client.");
    auto recvBuff = std::make_unique<RecvBuff>();
    if (recvBuff == nullptr) {
        NETNATIVE_LOGE("recvBuff mem failed");
        return;
    }
    (void)memset_s(recvBuff->questionsBuff, MAX_REQUESTDATA_LEN, 0, MAX_REQUESTDATA_LEN);

    auto clientAddr = std::make_unique<AlignedSockAddr>();
    if (clientAddr == nullptr) {
        NETNATIVE_LOGE("clientAddr mem failed");
        return;
    }

    recvBuff->questionLen = ReceiveDnsRequest(family == AF_INET ? proxySockFd_ : proxySockFd6_,
                                             *recvBuff, *clientAddr, family);
    if (recvBuff->questionLen <= 0) {
        NETNATIVE_LOGE("read errno %{public}d", errno);
        return;
    }
    if (!CheckDnsQuestion(recvBuff->questionsBuff, recvBuff->questionLen)) {
        NETNATIVE_LOGE("read buff is not dns question");
        return;
    }
    DnsParseBySocket(recvBuff, clientAddr);
}

// LCOV_EXCL_START
bool DnsProxyListen::GetExitFlag()
{
    uint64_t val;
    read(exitFd_, &val, sizeof(val));
    if (val == EPOLL_LOOP_EXIT) {
        return true;
    }
    return false;
}
// LCOV_EXCL_STOP

void DnsProxyListen::InitListenForIpv4()
{
    std::lock_guard<std::mutex> lock(listenerMutex_);
    if (proxySockFd_ < 0) {
        proxySockFd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (proxySockFd_ < 0) {
            NETNATIVE_LOGE("proxySockFd_ create socket failed %{public}d", errno);
            return;
        }
    }
    int on = 1;
    // LCOV_EXCL_START
    if (setsockopt(proxySockFd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        NETNATIVE_LOGE("setsockopt Ipv4 SO_REUSEADDR failed errno:%{public}d", errno);
        return;
    }
    // LCOV_EXCL_STOP
    sockaddr_in proxyAddr{};
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxyAddr.sin_port = htons(DNS_PROXY_PORT);
    if (setsockopt(proxySockFd_, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
        NETNATIVE_LOGE("setsockopt IP_PKTINFO failed errno:%{public}d", errno);
        close(proxySockFd_);
        proxySockFd_ = -1;
        return;
    }
    if (bind(proxySockFd_, (sockaddr *)&proxyAddr, sizeof(proxyAddr)) == -1) {
        NETNATIVE_LOGE("bind errno %{public}d: %{public}s", errno, strerror(errno));
        close(proxySockFd_);
        proxySockFd_ = -1;
        return;
    }
}

void DnsProxyListen::InitListenForIpv6()
{
    std::lock_guard<std::mutex> lock(listenerMutex_);
    if (proxySockFd6_ < 0) {
        proxySockFd6_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (proxySockFd6_ < 0) {
            NETNATIVE_LOGE("proxySockFd_ create socket failed %{public}d", errno);
            return;
        }
    }
    sockaddr_in6 proxyAddr6{};
    proxyAddr6.sin6_family = AF_INET6;
    proxyAddr6.sin6_addr = in6addr_any;
    proxyAddr6.sin6_port = htons(DNS_PROXY_PORT);
    int on = 1;
    // LCOV_EXCL_START
    if (setsockopt(proxySockFd6_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        NETNATIVE_LOGE("setsockopt Ipv6 SO_REUSEADDR failed errno:%{public}d", errno);
        return;
    }
    if (setsockopt(proxySockFd6_, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
        NETNATIVE_LOGE("setsockopt failed");
        close(proxySockFd6_);
        proxySockFd6_ = -1;
        return;
    }
    if (setsockopt(proxySockFd6_, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
        NETNATIVE_LOGE("setsockopt IPV6_RECVPKTINFO failed errno:%{public}d", errno);
        close(proxySockFd6_);
        proxySockFd6_ = -1;
        return;
    }
    // LCOV_EXCL_STOP
    if (bind(proxySockFd6_, (sockaddr *)&proxyAddr6, sizeof(proxyAddr6)) == -1) {
        NETNATIVE_LOGE("bind6 errno %{public}d: %{public}s", errno, strerror(errno));
        close(proxySockFd6_);
        proxySockFd6_ = -1;
        return;
    }
}

bool DnsProxyListen::InitExitFdforListening()
{
    // LCOV_EXCL_START
    if (exitFd_ >= 0) {
        close(exitFd_);
        exitFd_ = -1;
    }
    exitFd_ = eventfd(0, EFD_NONBLOCK);
    if (exitFd_ < 0) {
        NETNATIVE_LOGE("eventfd errno %{public}d: %{public}s", errno, strerror(errno));
        return false;
    } else {
        epoll_event exitEvent;
        exitEvent.data.fd = exitFd_;
        exitEvent.events = EPOLLIN;
        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, exitFd_, &exitEvent) < 0) {
            NETNATIVE_LOGE("EPOLL_CTL_ADD proxy errno %{public}d: %{public}s", errno, strerror(errno));
            return false;
        }
    }
    // LCOV_EXCL_STOP
    return true;
}

bool DnsProxyListen::InitForListening(epoll_event &proxyEvent, epoll_event &proxy6Event)
{
    InitListenForIpv4();
    InitListenForIpv6();
    // LCOV_EXCL_START
    if (epollFd_ >= 0) {
        close(epollFd_);
        epollFd_ = -1;
    }
    epollFd_ = epoll_create1(0);
    if (epollFd_ < 0) {
        NETNATIVE_LOGE("epoll_create1 errno %{public}d: %{public}s", errno, strerror(errno));
        clearResource();
        return false;
    }
    if (proxySockFd_ > 0) {
        proxyEvent.data.fd = proxySockFd_;
        proxyEvent.events = EPOLLIN;
        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, proxySockFd_, &proxyEvent) < 0) {
            NETNATIVE_LOGE("EPOLL_CTL_ADD proxy errno %{public}d: %{public}s", errno, strerror(errno));
            clearResource();
            return false;
        }
    }
    if (proxySockFd6_ > 0) {
        proxy6Event.data.fd = proxySockFd6_;
        proxy6Event.events = EPOLLIN;
        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, proxySockFd6_, &proxy6Event) < 0) {
            NETNATIVE_LOGE("EPOLL_CTL_ADD proxy6 errno %{public}d: %{public}s", errno, strerror(errno));
            clearResource();
            return false;
        }
    }
    if (proxySockFd_ < 0 && proxySockFd6_ < 0) {
        NETNATIVE_LOGE("InitForListening ipv4/ipv6 error!");
        clearResource();
        return false;
    }
    // LCOV_EXCL_STOP
    if (!InitExitFdforListening()) {
        clearResource();
        return false;
    }
    collectTime = std::chrono::system_clock::now() + std::chrono::milliseconds(EPOLL_TIMEOUT);
    return true;
}

// LCOV_EXCL_START
void DnsProxyListen::CollectSocks()
{
    if (std::chrono::system_clock::now() >= collectTime) {
        NETNATIVE_LOG_D("collect socks");
        std::list<int32_t> sockTemp;
        for (const auto &[sock, request] : serverIdxOfSocket) {
            if (std::chrono::system_clock::now() >= request.endTime) {
                sockTemp.push_back(sock);
            }
        }
        for (const auto sock : sockTemp) {
            SendRequest2Server(sock);
        }
        collectTime = std::chrono::system_clock::now() + std::chrono::milliseconds(EPOLL_TIMEOUT);
    }
}

void DnsProxyListen::EpollTimeout()
{
    NETNATIVE_LOGE("epoll timeout, try next server.");
    if (serverIdxOfSocket.size() > 0) {
        std::list<int32_t> sockTemp;
        std::transform(serverIdxOfSocket.cbegin(), serverIdxOfSocket.cend(), std::back_inserter(sockTemp),
                       [](auto &iter) { return iter.first; });
        for (const auto sock : sockTemp) {
            SendRequest2Server(sock);
        }
    }
    collectTime = std::chrono::system_clock::now() + std::chrono::milliseconds(EPOLL_TIMEOUT);
}
// LCOV_EXCL_STOP

bool DnsProxyListen::CheckDnsQuestion(char *recBuff, size_t recLen)
{
    if (recLen < DNS_HEAD_LENGTH) {
        return false;
    }
    char *recFlagBuff = recBuff + FLAG_BUFF_OFFSET;
    uint8_t flagBuff = static_cast<uint8_t>(*recFlagBuff);
    int reqFlag = (flagBuff & RESPONSE_FLAG) / RESPONSE_FLAG_USED;
    if (reqFlag) {
        return false; // answer
    } else {
        return true; // question
    }
}

bool DnsProxyListen::CheckDnsResponse(char *recBuff, size_t recLen)
{
    if (recLen < FLAG_BUFF_LEN + FLAG_BUFF_OFFSET) {
        return false;
    }
    char *recFlagBuff = recBuff + FLAG_BUFF_OFFSET;
    uint8_t flagBuff = static_cast<uint8_t>(*recFlagBuff);
    int reqFlag = (flagBuff & RESPONSE_FLAG) / RESPONSE_FLAG_USED;
    if (reqFlag) {
        return true; // answer
    } else {
        return false; // question
    }
}

void DnsProxyListen::OnListen()
{
    DnsProxyListen::proxyListenSwitch_ = true;
    NETNATIVE_LOGI("DnsProxy OnListen");
}

void DnsProxyListen::OffListen()
{
    DnsProxyListen::proxyListenSwitch_ = false;
    if (proxySockFd_ > 0) {
        close(proxySockFd_);
        proxySockFd_ = -1;
    }
    if (proxySockFd6_ > 0) {
        close(proxySockFd6_);
        proxySockFd6_ = -1;
    }
    uint64_t val = EPOLL_LOOP_EXIT;
    if (exitFd_ > 0) {
        write(exitFd_, &val, sizeof(val));
    }
    NETNATIVE_LOGI("DnsProxy OffListen");
}

void DnsProxyListen::SetParseNetId(uint16_t netId)
{
    DnsProxyListen::netId_ = netId;
    NETNATIVE_LOGI("SetParseNetId");
}

bool DnsProxyListen::IsListening() const
{
    return DnsProxyListen::proxyListenSwitch_.load();
}

void DnsProxyListen::clearResource()
{
    if (proxySockFd_ > 0) {
        close(proxySockFd_);
        proxySockFd_ = -1;
    }
    if (proxySockFd6_ > 0) {
        close(proxySockFd6_);
        proxySockFd6_ = -1;
    }
    if (epollFd_ > 0) {
        close(epollFd_);
        epollFd_ = -1;
    }
    if (exitFd_ > 0) {
        close(exitFd_);
        exitFd_ = -1;
    }
    serverIdxOfSocket.clear();
}

template<typename... Args>
auto DnsProxyListen::DnsSocketHolder::emplace(Args&&... args) ->
decltype(DnsSocketHolderBase::emplace(std::forward<Args>(args)...))
{
    if (size() >= MAX_SOCKET_CAPACITY) {
        NETNATIVE_LOG_D("Socket num over capacity, throw oldest socket.");
        DnsSocketHolderBase::erase(lruCache.front());
        lruCache.pop_front();
    }
    auto iter = DnsSocketHolderBase::emplace(std::forward<Args>(args)...);
    iter.first->second.SetLruIterator(lruCache.insert(lruCache.end(), iter.first));
    return iter;
}

auto DnsProxyListen::DnsSocketHolder::erase(iterator position) -> decltype(DnsSocketHolderBase::erase(position))
{
    lruCache.erase(position->second.GetLruIterator());
    return DnsSocketHolderBase::erase(position);
}

auto DnsProxyListen::DnsSocketHolder::clear() -> decltype(DnsSocketHolderBase::clear())
{
    lruCache.clear();
    return DnsSocketHolderBase::clear();
}
} // namespace nmd
} // namespace OHOS
