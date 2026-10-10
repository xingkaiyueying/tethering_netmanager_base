/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <sys/socket.h>
#include <netinet/in.h>

#include <poll.h>
#include <fcntl.h>

#include "iservice_registry.h"

#include "net_conn_manager_test_util.h"
#include "netsys_native_service_proxy.h"
#include "system_ability_definition.h"
#include "securec.h"
#include "dns_config_client.h"
#include "netnative_log_wrapper.h"

#define private public
#include "dns_proxy_listen.h"

namespace OHOS {
namespace NetsysNative {
using namespace testing::ext;
using namespace OHOS::nmd;
using namespace NetManagerStandard::NetConnManagerTestUtil;
constexpr uint8_t RESPONSE_FLAG = 0x80;
static constexpr const int32_t CLIENT_SOCKET = 99999;
static constexpr const int32_t TEST_SOCKET = 123;
static constexpr const uint32_t MAX_REQUESTDATA_LEN = 512;
class DnsProxyListenTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<DnsProxyListen> instance_ = nullptr;
};

void DnsProxyListenTest::SetUpTestCase() {}

void DnsProxyListenTest::TearDownTestCase() {}

void DnsProxyListenTest::SetUp()
{
    instance_ = std::make_shared<DnsProxyListen>();
}

void DnsProxyListenTest::TearDown() {}

HWTEST_F(DnsProxyListenTest, StartListenTest, TestSize.Level1)
{
    NETNATIVE_LOGI("StartListenTest enter");
    DnsProxyListen listener;
    listener.OnListen();
    listener.OffListen();
    listener.clearResource();

    listener.SetParseNetId(0);
    EXPECT_EQ(listener.netId_, 0);
}

HWTEST_F(DnsProxyListenTest, OffListenTest, TestSize.Level1)
{
    DnsProxyListen listener;
    listener.proxySockFd_ = CLIENT_SOCKET;
    listener.exitFd_ = TEST_SOCKET;
    listener.OffListen();
    listener.clearResource();
    EXPECT_EQ(listener.proxySockFd_, -1);
    EXPECT_EQ(listener.exitFd_, -1);
}

HWTEST_F(DnsProxyListenTest, DnsProxyListenTest01, TestSize.Level1)
{
    instance_->proxySockFd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    instance_->proxySockFd6_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    instance_->epollFd_ = epoll_create1(0);
    instance_->~DnsProxyListen();
    EXPECT_EQ(instance_->proxySockFd_, -1);
    EXPECT_EQ(instance_->proxySockFd6_, -1);
    EXPECT_EQ(instance_->epollFd_, -1);
}

HWTEST_F(DnsProxyListenTest, GetDnsProxyServersTest01, TestSize.Level1)
{
    std::vector<std::string> servers = {"servers"};
    size_t serverIdx = 1;

    bool ret = instance_->GetDnsProxyServers(servers, serverIdx, 0);
    EXPECT_FALSE(ret);
    serverIdx = 0;
    ret = instance_->GetDnsProxyServers(servers, serverIdx, 0);
    EXPECT_TRUE(ret);
}

HWTEST_F(DnsProxyListenTest, MakeAddrInfoTest01, TestSize.Level1)
{
    std::vector<std::string> servers = {"servers"};
    size_t serverIdx = 0;
    struct sockaddr sa {};
    sa.sa_family = AF_INET;
    struct sockaddr_in sin {};
    AlignedSockAddr addrParse{};
    AlignedSockAddr clientSock{};
    addrParse.sin = sin;
    clientSock.sa = sa;

    bool ret = instance_->MakeAddrInfo(servers, serverIdx, addrParse, clientSock);
    EXPECT_FALSE(ret);
    servers[0] = "172.0.0.1";
    ret = instance_->MakeAddrInfo(servers, serverIdx, addrParse, clientSock);
    EXPECT_TRUE(ret);
    ret = instance_->MakeAddrInfo(servers, serverIdx, addrParse, clientSock);
    EXPECT_TRUE(ret);

    clientSock.sa.sa_family = AF_INET6;
    ret = instance_->MakeAddrInfo(servers, serverIdx, addrParse, clientSock);
    EXPECT_FALSE(ret);
    servers[0] = "INET6:172.0.0.1";
    ret = instance_->MakeAddrInfo(servers, serverIdx, addrParse, clientSock);
    EXPECT_FALSE(ret);

    clientSock.sa.sa_family = 0;
    ret = instance_->MakeAddrInfo(servers, serverIdx, addrParse, clientSock);
    EXPECT_FALSE(ret);
}

HWTEST_F(DnsProxyListenTest, InitForListeningTest01, TestSize.Level1)
{
    epoll_event proxyEvent;
    epoll_event proxy6Event;

    instance_->InitListenForIpv4();
    bool ret = instance_->InitForListening(proxyEvent, proxy6Event);
    EXPECT_TRUE(ret);

    instance_->InitListenForIpv6();
    instance_->InitForListening(proxyEvent, proxy6Event);

    instance_->OffListen();
    instance_->clearResource();
    instance_->InitForListening(proxyEvent, proxy6Event);
}

HWTEST_F(DnsProxyListenTest, CheckDnsQuestionTest01, TestSize.Level1)
{
    char recBuff[] = "10101010101012";
    size_t recLen = 1;
    bool ret = instance_->CheckDnsQuestion(recBuff, recLen);
    EXPECT_FALSE(ret);

    recLen = strlen(recBuff);
    ret = instance_->CheckDnsQuestion(recBuff, recLen);
    EXPECT_TRUE(ret);
}

HWTEST_F(DnsProxyListenTest, CheckDnsResponseTest01, TestSize.Level1)
{
    char recBuff[] = "120212";
    size_t recLen = 1;
    bool ret = instance_->CheckDnsResponse(recBuff, recLen);
    EXPECT_FALSE(ret);

    recLen = strlen(recBuff);
    ret = instance_->CheckDnsResponse(recBuff, recLen);
    EXPECT_FALSE(ret);
}

HWTEST_F(DnsProxyListenTest, OffListenTest01, TestSize.Level1)
{
    instance_->proxySockFd6_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    instance_->OffListen();
    instance_->clearResource();
    EXPECT_EQ(instance_->proxySockFd6_, -1);
}

HWTEST_F(DnsProxyListenTest, clearResourceTest01, TestSize.Level1)
{
    instance_->InitListenForIpv4();
    instance_->InitListenForIpv6();
    instance_->clearResource();
    EXPECT_EQ(instance_->proxySockFd_, -1);
    EXPECT_EQ(instance_->proxySockFd6_, -1);
}
} // namespace NetsysNative
} // namespace OHOS
