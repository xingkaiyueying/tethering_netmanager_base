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

#include <gtest/gtest.h>
#include <unistd.h>
#include <sys/socket.h>

#define private public

#include "dns_proxy_request_socket.h"
#include "netnative_log_wrapper.h"
#include "dns_proxy_listen.h"

namespace OHOS::nmd {
    
using namespace testing;
using namespace testing::ext;

class DnsProxyRequestSocketTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DnsProxyRequestSocketTest::SetUpTestCase() {}
void DnsProxyRequestSocketTest::TearDownTestCase() {}
void DnsProxyRequestSocketTest::SetUp() {}
void DnsProxyRequestSocketTest::TearDown() {}

HWTEST_F(DnsProxyRequestSocketTest, Create_01, TestSize.Level0)
{
    int32_t sock = socket(10000, SOCK_CLOEXEC, 0);
    std::unique_ptr<AlignedSockAddr> clientSock = std::make_unique<AlignedSockAddr>();
    std::unique_ptr<RecvBuff> recvBuff = std::make_unique<RecvBuff>();
    DnsProxyRequestSocket dnsProxyRequestSocket(sock, std::move(clientSock), std::move(recvBuff));
    EXPECT_EQ(dnsProxyRequestSocket.sock, sock);
    EXPECT_EQ(dnsProxyRequestSocket.event.data.fd, sock);
    EXPECT_EQ(dnsProxyRequestSocket.event.events, EPOLLIN);
    EXPECT_NE(dnsProxyRequestSocket.clientSock, nullptr);
    EXPECT_NE(dnsProxyRequestSocket.recvBuff, nullptr);
}

HWTEST_F(DnsProxyRequestSocketTest, Release_01, TestSize.Level0)
{
    int32_t sock = -1;
    std::unique_ptr<AlignedSockAddr> clientSock = nullptr;
    std::unique_ptr<RecvBuff> recvBuff = nullptr;
    DnsProxyRequestSocket dnsProxyRequestSocket(sock, std::move(clientSock), std::move(recvBuff));
    dnsProxyRequestSocket.~DnsProxyRequestSocket();
    EXPECT_EQ(dnsProxyRequestSocket.sock, sock);
}

HWTEST_F(DnsProxyRequestSocketTest, Release_02, TestSize.Level0)
{
    int32_t sock = socket(10000, SOCK_CLOEXEC, 0);
    std::unique_ptr<AlignedSockAddr> clientSock = std::make_unique<AlignedSockAddr>();
    std::unique_ptr<RecvBuff> recvBuff = std::make_unique<RecvBuff>();
    DnsProxyRequestSocket dnsProxyRequestSocket(sock, std::move(clientSock), std::move(recvBuff));
    dnsProxyRequestSocket.~DnsProxyRequestSocket();
    EXPECT_EQ(dnsProxyRequestSocket.sock, sock);
}

HWTEST_F(DnsProxyRequestSocketTest, DnsParseBySocket001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::unique_ptr<RecvBuff> recvBuff = std::make_unique<RecvBuff>();
    std::unique_ptr<AlignedSockAddr> clientSock = std::make_unique<AlignedSockAddr>();
    clientSock->sa.sa_family = AF_INET;
    dnsproxylisten.DnsParseBySocket(recvBuff, clientSock);
    EXPECT_FALSE(dnsproxylisten.proxyListenSwitch_);
}

HWTEST_F(DnsProxyRequestSocketTest, DnsParseBySocket002, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::unique_ptr<RecvBuff> recvBuff = std::make_unique<RecvBuff>();
    std::unique_ptr<AlignedSockAddr> clientSock = std::make_unique<AlignedSockAddr>();
    clientSock->sa.sa_family = 10;
    dnsproxylisten.DnsParseBySocket(recvBuff, clientSock);
    EXPECT_FALSE(dnsproxylisten.proxyListenSwitch_);
}

HWTEST_F(DnsProxyRequestSocketTest, DnsParseBySocket003, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::unique_ptr<RecvBuff> recvBuff = std::make_unique<RecvBuff>();
    std::unique_ptr<AlignedSockAddr> clientSock = std::make_unique<AlignedSockAddr>();
    clientSock->sa.sa_family = 3;
    dnsproxylisten.DnsParseBySocket(recvBuff, clientSock);
    EXPECT_FALSE(dnsproxylisten.proxyListenSwitch_);
}

HWTEST_F(DnsProxyRequestSocketTest, GetDnsProxyServers001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::vector<std::string> servers = {"1", "2"};
    size_t serverIdx = 1;
    EXPECT_TRUE(dnsproxylisten.GetDnsProxyServers(servers, serverIdx, 0));
}

HWTEST_F(DnsProxyRequestSocketTest, GetDnsProxyServers002, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::vector<std::string> servers = {"1"};
    size_t serverIdx = 1;
    EXPECT_FALSE(dnsproxylisten.GetDnsProxyServers(servers, serverIdx, 0));
}

HWTEST_F(DnsProxyRequestSocketTest, MakeAddrInfo001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::vector<std::string> servers = {"1"};
    size_t serverIdx = 0;
    AlignedSockAddr addrParse;
    AlignedSockAddr clientSock;
    clientSock.sa.sa_family = AF_INET;
    EXPECT_FALSE(dnsproxylisten.MakeAddrInfo(servers, serverIdx, addrParse, clientSock));
    servers = {"1", ".", "2"};
    serverIdx = 1;
    EXPECT_FALSE(dnsproxylisten.MakeAddrInfo(servers, serverIdx, addrParse, clientSock));
    servers = {"1", "127.0.0.1", "2"};
    serverIdx = 1;
    EXPECT_TRUE(dnsproxylisten.MakeAddrInfo(servers, serverIdx, addrParse, clientSock));
}

HWTEST_F(DnsProxyRequestSocketTest, MakeAddrInfo002, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::vector<std::string> servers = {"1", ":", "2"};
    size_t serverIdx = 2;
    AlignedSockAddr addrParse;
    AlignedSockAddr clientSock;
    clientSock.sa.sa_family = AF_INET6;
    EXPECT_FALSE(dnsproxylisten.MakeAddrInfo(servers, serverIdx, addrParse, clientSock));
    servers = {"1"};
    serverIdx = 0;
    EXPECT_FALSE(dnsproxylisten.MakeAddrInfo(servers, serverIdx, addrParse, clientSock));
}

HWTEST_F(DnsProxyRequestSocketTest, MakeAddrInfo003, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    std::vector<std::string> servers = {"1"};
    size_t serverIdx = 0;
    AlignedSockAddr addrParse;
    AlignedSockAddr clientSock;
    clientSock.sa.sa_family = 3;
    EXPECT_FALSE(dnsproxylisten.MakeAddrInfo(servers, serverIdx, addrParse, clientSock));
}

HWTEST_F(DnsProxyRequestSocketTest, SendRequest2Server001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    int32_t socketFd = 300;
    dnsproxylisten.SendRequest2Server(socketFd);
    EXPECT_EQ(socketFd, 300);
}

HWTEST_F(DnsProxyRequestSocketTest, SendRequest2Server002, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    int32_t socketFd = 300;
    std::unique_ptr<AlignedSockAddr> clientSock = std::make_unique<AlignedSockAddr>();
    std::unique_ptr<RecvBuff> recvBuff = std::make_unique<RecvBuff>();
    clientSock->sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    dnsproxylisten.serverIdxOfSocket.emplace(std::piecewise_construct, std::forward_as_tuple(socketFd),
                              std::forward_as_tuple(socketFd, std::move(clientSock), std::move(recvBuff)));;
    dnsproxylisten.SendRequest2Server(socketFd);
    EXPECT_EQ(socketFd, 300);
}

HWTEST_F(DnsProxyRequestSocketTest, SendDnsBack2Client001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    int32_t socketFd = 300;
    dnsproxylisten.SendDnsBack2Client(socketFd);
    EXPECT_EQ(socketFd, 300);
}

HWTEST_F(DnsProxyRequestSocketTest, GetRequestAndTransmit001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    int32_t family = AF_INET;
    dnsproxylisten.GetRequestAndTransmit(family);
    family = AF_INET6;
    dnsproxylisten.GetRequestAndTransmit(family);
    EXPECT_EQ(family, 10);
}

HWTEST_F(DnsProxyRequestSocketTest, CollectSocks001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    dnsproxylisten.CollectSocks();
    EXPECT_FALSE(dnsproxylisten.proxyListenSwitch_);
}

HWTEST_F(DnsProxyRequestSocketTest, EpollTimeout001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    dnsproxylisten.EpollTimeout();
    EXPECT_FALSE(dnsproxylisten.proxyListenSwitch_);
}

HWTEST_F(DnsProxyRequestSocketTest, CheckDnsQuestion001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    char data[100];
    char *recBuff = data;
    size_t recLen = 10;
    dnsproxylisten.CheckDnsQuestion(recBuff, recLen);
    recLen = 12;
    EXPECT_TRUE(dnsproxylisten.CheckDnsQuestion(recBuff, recLen));
}

HWTEST_F(DnsProxyRequestSocketTest, CheckDnsResponse001, TestSize.Level0)
{
    DnsProxyListen dnsproxylisten;
    char data[100];
    char *recBuff = data;
    size_t recLen = 2;
    dnsproxylisten.CheckDnsResponse(recBuff, recLen);
    recLen = 3;
    EXPECT_FALSE(dnsproxylisten.CheckDnsResponse(recBuff, recLen));
}
}  // namespace OHOS::nmd
