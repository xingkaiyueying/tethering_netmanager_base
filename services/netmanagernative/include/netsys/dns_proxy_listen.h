/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef INCLUDE_DNS_PROXY_LISTEN_H
#define INCLUDE_DNS_PROXY_LISTEN_H

#include <iostream>
#include <atomic>
#include <mutex>
#include <netinet/in.h>
#include <vector>
#include <map>
#include <sys/eventfd.h>

#include "dns_proxy_request_socket.h"

namespace OHOS {
namespace nmd {
class DnsProxyListen {
public:
    DnsProxyListen();
    ~DnsProxyListen();

    /**
     * Begin dns proxy listen
     *
     */
    void OnListen();

    /**
     * Close dns proxy listen
     */
    void OffListen();

    /**
     * Dns proxy listen obj
     *
     */
    void StartListen();

    /**
     * Set the Parse Net Id objectse
     *
     * @param netId network ID
     */
    void SetParseNetId(uint16_t netId);

    /**
     * Check whether dns proxy listen is active
     *
     * @return true if listening, false otherwise
     */
    bool IsListening() const;

    using DnsSocketHolderBase = std::map<int32_t, DnsProxyRequestSocket>;

private:
class DnsSocketHolder : private DnsSocketHolderBase {
public:
    auto find(const int32_t& x) { return DnsSocketHolderBase::find(x); }
    auto begin() { return DnsSocketHolderBase::begin(); }
    auto end() { return DnsSocketHolderBase::end(); }
    auto cbegin() { return DnsSocketHolderBase::cbegin(); }
    auto cend() { return DnsSocketHolderBase::cend(); }
    auto size() { return DnsSocketHolderBase::size(); }
    auto empty() { return DnsSocketHolderBase::empty(); }
    template<typename... Args>
    auto emplace(Args&&... args) -> decltype(DnsSocketHolderBase::emplace(std::forward<Args>(args)...));
    auto erase(iterator position) -> decltype(DnsSocketHolderBase::erase(position));
    auto clear() -> decltype(DnsSocketHolderBase::clear());
private:
    constexpr static uint32_t MAX_SOCKET_CAPACITY = 300;
    std::list<iterator> lruCache;
};

private:
    void DnsParseBySocket(std::unique_ptr<RecvBuff> &recvBuff, std::unique_ptr<AlignedSockAddr> &clientSock);
    static void DnsSendRecvParseData(int32_t clientSocket, char *requestData, int32_t resLen,
                                     AlignedSockAddr &proxyAddr);
    static bool CheckDnsResponse(char *recBuff, size_t recLen);
    static bool CheckDnsQuestion(char *recBuff, size_t recLen);
    void SendDnsBack2Client(int32_t socketFd);
    void clearResource();
    void SendRequest2Server(int32_t socketFd);
    bool GetDnsProxyServers(std::vector<std::string> &servers, size_t serverIdx, uint16_t netId);
    bool MakeAddrInfo(std::vector<std::string> &servers, size_t serverIdx, AlignedSockAddr &addrParse,
                      AlignedSockAddr &clientSock);
    int32_t proxySockFd_;
    int32_t proxySockFd6_;
    int32_t epollFd_ = -1;
    int32_t exitFd_ = -1;
    static std::atomic<uint16_t> netId_;
    static std::atomic_bool proxyListenSwitch_;
    static std::mutex listenerMutex_;
    DnsSocketHolder serverIdxOfSocket;
    std::chrono::system_clock::time_point collectTime;
    void EpollTimeout();
    void CollectSocks();
    void InitListenForIpv4();
    void InitListenForIpv6();
    bool InitForListening(epoll_event &proxyEvent, epoll_event &proxy6Event);
    bool InitExitFdforListening();
    void GetRequestAndTransmit(int32_t family);
    bool GetExitFlag();
};
} // namespace nmd
} // namespace OHOS
#endif // INCLUDE_DNS_PROXY_LISTEN_H
