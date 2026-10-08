/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NETSYS_DNS_PROXY_REQUEST_SOCKET_H
#define NETSYS_DNS_PROXY_REQUEST_SOCKET_H

#include "dns_config_client.h"
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <list>
#include <map>
#include <memory>
#include <netinet/ip.h>
#include <sys/epoll.h>

namespace OHOS::nmd {
static constexpr uint32_t MAX_REQUESTDATA_LEN = 512;
static constexpr int32_t EPOLL_TIMEOUT = 3000;

struct RecvBuff {
    char questionsBuff[MAX_REQUESTDATA_LEN];
    int32_t questionLen;
    // Reply on the link and local address that received this individual request.
    int32_t replyIfindex = 0;
    AlignedSockAddr replyAddress{};
};

class DnsProxyRequestSocket final {
public:
    DnsProxyRequestSocket(int32_t sock, std::unique_ptr<AlignedSockAddr> &&clientSock,
                          std::unique_ptr<RecvBuff> &&recvBuff);
    DnsProxyRequestSocket(const DnsProxyRequestSocket &) = delete;
    DnsProxyRequestSocket &operator=(const DnsProxyRequestSocket &) = delete;
    DnsProxyRequestSocket(DnsProxyRequestSocket &&other) = delete;
    DnsProxyRequestSocket &operator=(DnsProxyRequestSocket &&other) = delete;
    [[nodiscard]] int32_t GetSock() const;
    [[nodiscard]] size_t GetIdx() const;
    [[nodiscard]] AlignedSockAddr &GetAddr();
    void IncreaseIdx();
    void ResetIdx();
    epoll_event *GetEventPtr();
    AlignedSockAddr &GetClientSock();
    RecvBuff &GetRecvBuff();
    void SetLruIterator(std::list<std::map<int32_t, DnsProxyRequestSocket>::iterator>::iterator iterator);
    [[nodiscard]] std::list<std::map<int32_t, DnsProxyRequestSocket>::iterator>::iterator GetLruIterator() const;
    ~DnsProxyRequestSocket();
    std::chrono::system_clock::time_point endTime;

private:
    int32_t sock;
    size_t dnsServerIdx = 0;
    epoll_event event{};
    AlignedSockAddr addrParse{};
    std::unique_ptr<AlignedSockAddr> clientSock;
    std::unique_ptr<RecvBuff> recvBuff;
    std::list<std::map<int32_t, DnsProxyRequestSocket>::iterator>::iterator lruIterator;
};
} // namespace OHOS::nmd
#endif // NETSYS_DNS_PROXY_REQUEST_SOCKET_H
