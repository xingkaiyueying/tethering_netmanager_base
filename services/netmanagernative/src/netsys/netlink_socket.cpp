/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <arpa/inet.h>
#include <asm/types.h>
#include <cstdlib>
#include <cerrno>
#include <sys/time.h>
#include <cstring>
#include <iostream>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <net/if.h>
#include "netnative_log_wrapper.h"
#include "securec.h"

#include "netlink_socket.h"
namespace OHOS {
namespace nmd {
#ifdef SUPPORT_SYSVPN
constexpr const char* XFRM_TYPE_NAME = "xfrm";
#endif

constexpr int32_t MAC_ADDRESS_STR_LEN = 18;
constexpr int32_t MAC_ADDRESS_INT_LEN = 6;
constexpr int32_t MAC_BYTE_HEX_SIZE = 4;
constexpr int32_t IF_NAME_SIZE = 16;
constexpr const uint32_t FAMILY_INVALID = 0;
constexpr const uint32_t FAMILY_V4 = 1;
constexpr const uint32_t FAMILY_V6 = 2;
constexpr const char* ANCO_IFNAME = "anco";
constexpr const char* RMNET_IFNAME = "rmnet";

static ssize_t SendMsgToKernel(struct nlmsghdr *msg, int32_t &kernelSocket)
{
    struct iovec ioVector;
    ioVector.iov_base = msg;
    ioVector.iov_len = msg->nlmsg_len;

    struct msghdr msgHeader;
    (void)memset_s(&msgHeader, sizeof(msgHeader), 0, sizeof(msgHeader));

    struct sockaddr_nl kernel;
    (void)memset_s(&kernel, sizeof(kernel), 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    kernel.nl_groups = 0;

    msgHeader.msg_name = &kernel;
    msgHeader.msg_namelen = sizeof(kernel);
    msgHeader.msg_iov = &ioVector;
    msgHeader.msg_iovlen = 1;

    ssize_t msgState = sendmsg(kernelSocket, &msgHeader, 0);
    if (msgState == -1) {
        NETNATIVE_LOGE("[NetlinkSocket] msg can not be null ");
        return -1;
    } else if (msgState == 0) {
        NETNATIVE_LOGE("[NetlinkSocket] 0 bytes send.");
        return -1;
    }
    NETNATIVE_LOG_D("[NetlinkSocket] msgState is %{public}zd", msgState);
    return msgState;
}

int32_t SendNetlinkMsgToKernel(struct nlmsghdr *msg, uint32_t table)
{
    if (msg == nullptr) {
        NETNATIVE_LOGE("[NetlinkSocket] msg can not be null ");
        return -1;
    }
    int32_t kernelSocket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (kernelSocket == -1) {
        NETNATIVE_LOGE("[NetlinkSocket] create socket failed: %{public}d", errno);
        return -1;
    }
    ssize_t msgState = SendMsgToKernel(msg, kernelSocket);
    if (msgState <= 0) {
        NETNATIVE_LOGE("[NetlinkSocket] send msg failed");
        close(kernelSocket);
        return -1;
    }
    if (msg->nlmsg_flags & NLM_F_DUMP) {
        msgState = GetInfoFromKernel(kernelSocket, msg->nlmsg_type, table);
    }
    if (msgState != 0) {
        NETNATIVE_LOGE("netlink read socket[%{public}d] failed, msgState=%{public}zd", kernelSocket, msgState);
    }
    close(kernelSocket);
    return msgState;
}

int32_t SendNetlinkMsgToKernelWithAck(nlmsghdr *msg)
{
    if (msg == nullptr || msg->nlmsg_len < sizeof(nlmsghdr)) {
        return -EINVAL;
    }
    int32_t fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -errno;
    }
    timeval timeout {1, 0};
    int32_t result = -EIO;
    msg->nlmsg_flags |= NLM_F_ACK;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        result = -errno;
    } else if (SendMsgToKernel(msg, fd) == static_cast<ssize_t>(msg->nlmsg_len)) {
        alignas(nlmsghdr) char buffer[KERNEL_BUFFER_SIZE] {};
        sockaddr_nl sender {};
        socklen_t senderLength = sizeof(sender);
        ssize_t size = recvfrom(fd, buffer, sizeof(buffer), 0,
            reinterpret_cast<sockaddr *>(&sender), &senderLength);
        if (size < 0) {
            result = -errno;
        } else if (senderLength == sizeof(sender) && sender.nl_pid == 0) {
            int32_t remaining = static_cast<int32_t>(size);
            for (auto *reply = reinterpret_cast<nlmsghdr *>(buffer); NLMSG_OK(reply, remaining);
                reply = NLMSG_NEXT(reply, remaining)) {
                if (reply->nlmsg_seq == msg->nlmsg_seq && reply->nlmsg_type == NLMSG_ERROR &&
                    reply->nlmsg_len >= NLMSG_LENGTH(sizeof(nlmsgerr))) {
                    result = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(reply))->error;
                    break;
                }
            }
        }
    }
    close(fd);
    return result;
}

int32_t SendNetlinkMsgsToKernel(std::vector<NetlinkMsg> &msgs)
{
    if (msgs.empty()) {
        NETNATIVE_LOGE("[SendNetlinkMsgsToKernel] buffer is empty");
        return -1;
    }
    int32_t kernelSocket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (kernelSocket == -1) {
        NETNATIVE_LOGE("[SendNetlinkMsgsToKernel] create socket failed: %{public}d", errno);
        return -1;
    }
    std::vector<struct iovec> ioVector;
    ioVector.reserve(msgs.size());
    for (auto &nl : msgs) {
        struct nlmsghdr* hdr = nl.GetNetLinkMessage();
        ioVector.emplace_back(iovec{
            .iov_base = hdr,
            .iov_len = hdr->nlmsg_len
        });
    }

    struct msghdr msgHeader;
    (void)memset_s(&msgHeader, sizeof(msgHeader), 0, sizeof(msgHeader));

    struct sockaddr_nl kernel;
    (void)memset_s(&kernel, sizeof(kernel), 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    kernel.nl_groups = 0;

    msgHeader.msg_name = &kernel;
    msgHeader.msg_namelen = sizeof(kernel);
    msgHeader.msg_iov = ioVector.data();
    msgHeader.msg_iovlen = static_cast<int>(ioVector.size());

    ssize_t msgState = sendmsg(kernelSocket, &msgHeader, 0);
    NETNATIVE_LOG_D("[NetlinkSocket] msgState is %{public}zd", msgState);
    if (msgState == -1) {
        NETNATIVE_LOGE("[NetlinkSocket] msg can not be null ");
        close(kernelSocket);
        return -1;
    } else if (msgState == 0) {
        NETNATIVE_LOGE("[NetlinkSocket] 0 bytes send.");
        close(kernelSocket);
        return -1;
    }

    close(kernelSocket);
    return msgState;
}

#ifdef SUPPORT_SYSVPN
static void AddAttribute(struct nlmsghdr *msghdr, int type, const void *data, size_t len)
{
    struct rtattr *attr = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<char*>(msghdr) + NLMSG_ALIGN(msghdr->nlmsg_len));
    attr->rta_type = type;
    attr->rta_len = RTA_LENGTH(len);
    if (memcpy_s(RTA_DATA(attr), NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN), data, len) != 0) {
        NETNATIVE_LOGE("[AddRoute]: string copy failed");
    }
    msghdr->nlmsg_len = NLMSG_ALIGN(msghdr->nlmsg_len) + RTA_ALIGN(attr->rta_len);
}

static struct rtattr *AddNestedStart(struct nlmsghdr *msghdr, int type)
{
    struct rtattr *nested = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<char*>(msghdr) + NLMSG_ALIGN(msghdr->nlmsg_len));
    nested->rta_type = type;
    nested->rta_len = RTA_LENGTH(0);
    msghdr->nlmsg_len = NLMSG_ALIGN(msghdr->nlmsg_len) + RTA_ALIGN(nested->rta_len);
    return nested;
}

static void AddNestedEnd(struct nlmsghdr *msghdr, struct rtattr *nested)
{
    nested->rta_len = reinterpret_cast<char*>(msghdr) + NLMSG_ALIGN(msghdr->nlmsg_len) -
                       reinterpret_cast<char*>(nested);
}

int32_t CreateVpnIfByNetlink(const char *name, uint32_t ifNameId, const char *phys, uint32_t mtu = 0)
{
    NETNATIVE_LOGI("CreateVpnIfByNetlink %{public}s, %{public}d, %{public}d", name, ifNameId, mtu);
    uint32_t ifindex = 0;
    if (phys) {
        ifindex = if_nametoindex(phys);
        if (!ifindex) {
            NETNATIVE_LOGE("physical interface '%{public}s' not found", phys);
            return -1;
        }
    }
    std::unique_ptr<char[]> msghdrBuf = std::make_unique<char[]>(NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN));
    struct nlmsghdr *msghdr = reinterpret_cast<struct nlmsghdr *>(msghdrBuf.get());
    errno_t result = memset_s(msghdr, NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN), 0, NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN));
    if (result != 0) {
        NETNATIVE_LOGE("[NetlinkMessage]: memset result %{public}d", result);
    }
    rtmsg msg;
    msg.rtm_family = AF_INET;
    int32_t copeResult = memcpy_s(NLMSG_DATA(msghdr), sizeof(struct rtmsg), &msg, sizeof(struct rtmsg));
    if (copeResult != 0) {
        NETNATIVE_LOGE("[AddRoute]: string copy failed result %{public}d", copeResult);
    }
    msghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    msghdr->nlmsg_type = RTM_NEWLINK;
    msghdr->nlmsg_len = static_cast<uint32_t>(NLMSG_LENGTH(sizeof(struct ifinfomsg)));

    AddAttribute(msghdr, IFLA_IFNAME, name, strlen(name) + 1);

    if (mtu > 0) {
        AddAttribute(msghdr, IFLA_MTU, &mtu, sizeof(mtu));
    }
    struct rtattr *linkinfo = AddNestedStart(msghdr, IFLA_LINKINFO);
    AddAttribute(msghdr, IFLA_INFO_KIND, XFRM_TYPE_NAME, strlen(XFRM_TYPE_NAME) + 1);
    struct rtattr *info_data = AddNestedStart(msghdr, IFLA_INFO_DATA);
    AddAttribute(msghdr, IFLA_XFRM_IF_ID, &ifNameId, sizeof(ifNameId));
    AddAttribute(msghdr, IFLA_XFRM_LINK, &ifindex, sizeof(ifindex));

    AddNestedEnd(msghdr, info_data);
    AddNestedEnd(msghdr, linkinfo);
    return SendNetlinkMsgToKernel(msghdr);
}

int32_t DeleteVpnIfByNetlink(const char *name)
{
    std::unique_ptr<char[]> msghdrBuf = std::make_unique<char[]>(NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN));
    struct nlmsghdr *msghdr = reinterpret_cast<struct nlmsghdr *>(msghdrBuf.get());
    errno_t result = memset_s(msghdr, NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN), 0, NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN));
    if (result != 0) {
        NETNATIVE_LOGE("[NetlinkMessage]: memset result %{public}d", result);
    }
    rtmsg msg;
    msg.rtm_family = AF_INET;
    int32_t copeResult = memcpy_s(NLMSG_DATA(msghdr), sizeof(struct rtmsg), &msg, sizeof(struct rtmsg));
    if (copeResult != 0) {
        NETNATIVE_LOGE("[AddRoute]: string copy failed result %{public}d", copeResult);
    }
    msghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msghdr->nlmsg_type = RTM_DELLINK;
    msghdr->nlmsg_len = static_cast<uint32_t>(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
    AddAttribute(msghdr, IFLA_IFNAME, name, strlen(name) + 1);
    return SendNetlinkMsgToKernel(msghdr);
}
#endif

int32_t ClearRouteInfo(uint16_t clearThing, uint32_t table)
{
    if (clearThing != RTM_GETROUTE && clearThing != RTM_GETRULE) {
        NETNATIVE_LOGE("ClearRouteInfo %{public}d type error", clearThing);
        return -1;
    }
    // Request the kernel to send a list of all routes or rules.
    std::unique_ptr<char[]> msghdrBuf = std::make_unique<char[]>(NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN));
    struct nlmsghdr *msghdr = reinterpret_cast<struct nlmsghdr *>(msghdrBuf.get());
    errno_t result = memset_s(msghdr, NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN), 0, NLMSG_SPACE(NETLINKMESSAGE_MAX_LEN));
    if (result != 0) {
        NETNATIVE_LOGE("[NetlinkMessage]: memset result %{public}d", result);
    }
    rtmsg msg;
    msg.rtm_family = AF_INET;
    int32_t copeResult = memcpy_s(
        NLMSG_DATA(msghdr), NETLINKMESSAGE_MAX_LEN - NLMSG_HDRLEN, &msg, sizeof(struct rtmsg));
    if (copeResult != 0) {
        NETNATIVE_LOGE("[AddRoute]: string copy failed result %{public}d", copeResult);
    }
    msghdr->nlmsg_len = static_cast<uint32_t>(NLMSG_LENGTH(sizeof(struct rtmsg)));
    msghdr->nlmsg_type = clearThing;
    msghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    return SendNetlinkMsgToKernel(msghdr);
}

int32_t GetInfoFromKernel(int32_t sock, uint16_t clearThing, uint32_t table)
{
    char readBuffer[KERNEL_BUFFER_SIZE] = {0};
    // Read the information returned by the kernel through the socket.
    ssize_t readedInfos = read(sock, readBuffer, sizeof(readBuffer));
    if (readedInfos < 0) {
        return -errno;
    }
    while (readedInfos > 0) {
        uint32_t readLength = static_cast<uint32_t>(readedInfos);
        // Traverse and read the information returned by the kernel for item by item processing.
        for (nlmsghdr *nlmsgHeader = reinterpret_cast<nlmsghdr *>(readBuffer); NLMSG_OK(nlmsgHeader, readLength);
             nlmsgHeader = NLMSG_NEXT(nlmsgHeader, readLength)) {
            if (nlmsgHeader->nlmsg_type == NLMSG_ERROR) {
                nlmsgerr *err = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(nlmsgHeader));
                NETNATIVE_LOG_D("netlink read socket[%{public}d] failed error = %{public}d", sock, err->error);
                return err->error;
            } else if (nlmsgHeader->nlmsg_type == NLMSG_DONE) {
                return 0;
            } else {
                DealInfoFromKernel(nlmsgHeader, clearThing, table);
            }
        }
        readedInfos = read(sock, readBuffer, sizeof(readBuffer));
        if (readedInfos < 0) {
            return -errno;
        }
    }
    return 0;
}

void DealInfoFromKernel(nlmsghdr *nlmsgHeader, uint16_t clearThing, uint32_t table)
{
    if (nlmsgHeader == nullptr) {
        NETNATIVE_LOGE("nlmsgHeader is nullptr");
        return;
    }
    struct nlmsghdr *msg = nlmsgHeader;
    msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (clearThing == RTM_GETRULE) {
        msg->nlmsg_type = RTM_DELRULE;
        if (GetRouteProperty(nlmsgHeader, FRA_PRIORITY) != static_cast<int32_t>(LOCAL_PRIORITY)) {
            return;
        }
    } else if (clearThing == RTM_GETROUTE) {
        msg->nlmsg_type = RTM_DELROUTE;
        if (GetRouteProperty(nlmsgHeader, RTA_TABLE) != static_cast<int32_t>(table)) {
            return;
        }
    }
    SendNetlinkMsgToKernel(msg);
}

std::string MacArrayToString(const uint8_t *mac)
{
    if (mac == nullptr) {
        NETNATIVE_LOGE("mac is nullptr");
        return "";
    }
    std::vector<uint8_t> macArray(mac, mac + MAC_ADDRESS_INT_LEN);
    std::string macString;
    char buf[MAC_BYTE_HEX_SIZE] {};
    for (const auto byte : macArray) {
        if (sprintf_s(buf, sizeof(buf), "%02x:", byte) < 0) {
            return "";
        }
        macString.append(buf);
    }
    macString.erase(macString.length() - 1);
    return macString;
}

int32_t GetRouteProperty(const nlmsghdr *nlmsgHeader, int32_t property)
{
    if (nlmsgHeader == nullptr) {
        NETNATIVE_LOGE("nlmsgHeader is nullptr");
        return -1;
    }
    uint32_t rtaLength = RTM_PAYLOAD(nlmsgHeader);
    rtmsg *infoMsg = reinterpret_cast<rtmsg *>(NLMSG_DATA(nlmsgHeader));
    for (rtattr *infoRta = reinterpret_cast<rtattr *> RTM_RTA(infoMsg); RTA_OK(infoRta, rtaLength);
         infoRta = RTA_NEXT(infoRta, rtaLength)) {
        if (infoRta->rta_type == property) {
            return *(reinterpret_cast<uint32_t *>(RTA_DATA(infoRta)));
        }
    }
    return 0;
}

int32_t ReceiveMsgFromKernel(struct nlmsghdr *msg, uint32_t table, void* rcvMsg)
{
    if (msg == nullptr || rcvMsg == nullptr) {
        NETNATIVE_LOGE("[NetlinkSocket] msg can not be null ");
        return -1;
    }
    int32_t kernelSocket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (kernelSocket == -1) {
        NETNATIVE_LOGE("[NetlinkSocket] create socket failed: %{public}d", errno);
        return -1;
    }
    ssize_t msgState = SendMsgToKernel(msg, kernelSocket);
    if (msgState <= 0) {
        NETNATIVE_LOGE("[NetlinkSocket] send msg failed");
        close(kernelSocket);
        return -1;
    }
    if (msg->nlmsg_flags & NLM_F_DUMP) {
        msgState = GetRcvMsgFromKernel(kernelSocket, msg->nlmsg_type, table, rcvMsg);
    }
    if (msgState != 0) {
        NETNATIVE_LOGE("ReceiveMsgFromKernel netlink read socket[%{public}d] failed, msgState=%{public}zd",
            kernelSocket, msgState);
    }
    close(kernelSocket);
    return msgState;
}

int32_t GetRcvMsgFromKernel(int32_t &sock, uint16_t msgType, uint32_t table, void* rcvMsg)
{
    if (rcvMsg == nullptr) {
        return -1;
    }
    char readBuffer[KERNEL_BUFFER_SIZE] = {0};
    // Read the information returned by the kernel through the socket.
    ssize_t readedInfos = read(sock, readBuffer, sizeof(readBuffer));
    if (readedInfos < 0) {
        return -errno;
    }
    while (readedInfos > 0) {
        int32_t readLength = static_cast<int32_t>(readedInfos);
        // Traverse and read the information returned by the kernel for item by item processing.
        for (nlmsghdr *nlmsgHeader = reinterpret_cast<nlmsghdr *>(readBuffer); NLMSG_OK(nlmsgHeader, readLength);
             nlmsgHeader = NLMSG_NEXT(nlmsgHeader, readLength)) {
            if (nlmsgHeader->nlmsg_type == NLMSG_ERROR) {
                nlmsgerr *err = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(nlmsgHeader));
                NETNATIVE_LOG_D("netlink read socket[%{public}d] failed error = %{public}d", sock, err->error);
                return err->error;
            } else if (nlmsgHeader->nlmsg_type == NLMSG_DONE) {
                return 0;
            } else {
                DealRcvMsgFromKernel(nlmsgHeader, msgType, table, rcvMsg);
            }
        }
        readedInfos = read(sock, readBuffer, sizeof(readBuffer));
        if (readedInfos < 0) {
            return -errno;
        }
    }
    return 0;
}

void DealRcvMsgFromKernel(nlmsghdr *nlmsgHeader, uint16_t msgType, uint32_t table, void* rcvMsg)
{
    if (nlmsgHeader == nullptr) {
        NETNATIVE_LOGE("nlmsgHeader is nullptr");
        return;
    }
    if (rcvMsg == nullptr) {
        NETNATIVE_LOGE("rcvMsg is nullptr");
        return;
    }
    if (msgType == RTM_GETNEIGH) {
        std::vector<NetManagerStandard::NetIpMacInfo>* ipMacInfoVec =
            reinterpret_cast<std::vector<NetManagerStandard::NetIpMacInfo>*>(rcvMsg);
        DealNeighInfo(nlmsgHeader, msgType, table, *ipMacInfoVec);
    }
}

void DealNeighInfo(nlmsghdr *nlmsgHeader, uint16_t msgType, uint32_t table,
    std::vector<NetManagerStandard::NetIpMacInfo>& ipMacInfoVec)
{
    if (nlmsgHeader == nullptr) {
        return;
    }
    char macStr[MAC_ADDRESS_STR_LEN] = {0};
    int32_t length = static_cast<int32_t>(RTM_PAYLOAD(nlmsgHeader));
    if (nlmsgHeader->nlmsg_type != RTM_NEWNEIGH && nlmsgHeader->nlmsg_type != RTM_DELNEIGH &&
        nlmsgHeader->nlmsg_type != RTM_GETNEIGH) {
        return;
    }
    ndmsg *ndm = reinterpret_cast<ndmsg *>(NLMSG_DATA(nlmsgHeader));
    if (ndm->ndm_type != RTN_UNICAST) {
        return;
    }
    NetManagerStandard::NetIpMacInfo info;
    char ifIndexName[IF_NAME_SIZE] = {0};
    if (if_indextoname(static_cast<unsigned>(ndm->ndm_ifindex), ifIndexName) == nullptr) {
        return;
    }
    if (strncmp(ifIndexName, ANCO_IFNAME, strlen(ANCO_IFNAME)) == 0 ||
        strncmp(ifIndexName, RMNET_IFNAME, strlen(RMNET_IFNAME)) == 0) {
        NETNATIVE_LOGE("need filter out ifname");
        return;
    }
    info.iface_ = ifIndexName;
    for (rtattr *infoRta = reinterpret_cast<rtattr *> RTM_RTA(ndm); RTA_OK(infoRta, length);
        infoRta = RTA_NEXT(infoRta, length)) {
        NETNATIVE_LOGI("info rtattr:%{public}d", static_cast<uint32_t>(infoRta->rta_type));
        if (infoRta->rta_type == NDA_DST) {
            void* ipAddr = RTA_DATA(infoRta);
            if (ndm->ndm_family == AF_INET) {
                char ipStr[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, ipAddr, ipStr, sizeof(ipStr));
                info.ipAddress_ = ipStr;
                info.family_ = FAMILY_V4;
            } else if (ndm->ndm_family == AF_INET6) {
                char ip6Str[INET6_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET6, ipAddr, ip6Str, sizeof(ip6Str));
                info.ipAddress_ = ip6Str;
                info.family_ = FAMILY_V6;
            } else {
                NETNATIVE_LOGE("get ipv4 and ipv6 failed");
            }
        } else if (infoRta->rta_type == NDA_LLADDR) {
            uint8_t* macAddr = reinterpret_cast<uint8_t *>(RTA_DATA(infoRta));
            info.macAddress_ = MacArrayToString(macAddr);
        }
    }
    ipMacInfoVec.push_back(info);
}
} // namespace nmd
} // namespace OHOS
