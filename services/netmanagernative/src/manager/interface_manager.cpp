/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "interface_manager.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <regex>

#include "netlink_manager.h"
#include "netlink_socket.h"
#include "netlink_socket_diag.h"
#include "net_manager_constants.h"
#include "netmanager_base_common_utils.h"
#include "netnative_log_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace nmd {
using namespace NetManagerStandard;
using namespace NetManagerStandard::CommonUtils;

namespace {
constexpr const char *SYS_NET_PATH = "/sys/class/net/";
constexpr const char *MTU_PATH = "/mtu";
constexpr int32_t FILE_PERMISSION = 0666;
constexpr uint32_t ARRAY_OFFSET_1_INDEX = 1;
constexpr uint32_t ARRAY_OFFSET_2_INDEX = 2;
constexpr uint32_t ARRAY_OFFSET_3_INDEX = 3;
constexpr uint32_t ARRAY_OFFSET_4_INDEX = 4;
constexpr uint32_t ARRAY_OFFSET_5_INDEX = 5;
constexpr uint32_t MOVE_BIT_LEFT31 = 31;
constexpr uint32_t BIT_MAX = 32;
constexpr uint32_t IPV6_PREFIX_MAX_LEN = 128;
constexpr uint32_t IOCTL_RETRY_TIME = 32;
constexpr int32_t MAX_MTU_LEN = 11;
constexpr int32_t MAC_ADDRESS_STR_LEN = 18;
constexpr int32_t MAC_SSCANF_SPACE = 3;
const std::regex REGEX_CMD_MAC_ADDRESS("^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$");
constexpr const char *IPV6_PROC_PATH = "/proc/sys/net/ipv6/conf/";
constexpr const char *DISABLE_IPV6_AUTO_CONF = "0";
constexpr const char *ENABLE_IPV6_AUTO_CONF = "1";
constexpr const char* VLAN_TYPE_NAME = "vlan";

bool CheckFilePath(const std::string &fileName, std::string &realPath)
{
    char tmpPath[PATH_MAX] = {0};
    if (!realpath(fileName.c_str(), tmpPath)) {
        NETNATIVE_LOGE("file name is illegal");
        return false;
    }
    realPath = tmpPath;
    return true;
}
} // namespace

int InterfaceManager::GetMtu(const char *interfaceName)
{
    if (interfaceName == nullptr) {
        NETNATIVE_LOGE("interfaceName is null");
        return -1;
    }

    if (!CheckIfaceName(interfaceName)) {
        NETNATIVE_LOGE("GetMtu isIfaceName fail %{public}d", errno);
        return -1;
    }
    std::string mtuPath = std::string(SYS_NET_PATH).append(interfaceName).append(MTU_PATH);
    std::string realPath;
    if (!CheckFilePath(mtuPath, realPath)) {
        NETNATIVE_LOGE("file does not exist! ");
        return -1;
    }
    int fd = open(realPath.c_str(), 0, FILE_PERMISSION);
    if (fd == -1) {
        NETNATIVE_LOGE("GetMtu open fail %{public}d", errno);
        return -1;
    }

    char originMtuValue[MAX_MTU_LEN] = {0};
    int nread = read(fd, originMtuValue, (sizeof(char) * (MAX_MTU_LEN - 1)));
    if (nread == -1 || nread == 0) {
        NETNATIVE_LOGE("GetMtu read fail %{public}d", errno);
        close(fd);
        return -1;
    }
    close(fd);

    int32_t mtu = -1;
    mtu = StrToInt(originMtuValue);
    return mtu;
}

int InterfaceManager::SetMtu(const char *interfaceName, const char *mtuValue)
{
    if (interfaceName == nullptr || mtuValue == nullptr) {
        NETNATIVE_LOGE("interfaceName or mtuValue is null");
        return -1;
    }

    if (!CheckIfaceName(interfaceName)) {
        NETNATIVE_LOGE("SetMtu isIfaceName fail %{public}d", errno);
        return -1;
    }
    int32_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        NETNATIVE_LOGE("SetMtu socket fail %{public}d", errno);
        return -1;
    }

    struct ifreq ifr;
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        close(sockfd);
        return -1;
    }
    if (strncpy_s(ifr.ifr_name, IFNAMSIZ, interfaceName, strlen(interfaceName)) != EOK) {
        close(sockfd);
        return -1;
    }

    int32_t mtu = StrToInt(mtuValue);
    ifr.ifr_mtu = mtu;

    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        NETNATIVE_LOGE("SetMtu ioctl fail %{public}d", errno);
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

std::vector<std::string> InterfaceManager::GetInterfaceNames()
{
    std::vector<std::string> ifaceNames;
    DIR *dir(nullptr);
    struct dirent *de(nullptr);

    dir = opendir(SYS_NET_PATH);
    if (dir == nullptr) {
        NETNATIVE_LOGE("GetInterfaceNames opendir fail %{public}d", errno);
        return ifaceNames;
    }

    de = readdir(dir);
    while (de != nullptr) {
        if ((de->d_name[0] != '.') && ((de->d_type == DT_DIR) || (de->d_type == DT_LNK))) {
            ifaceNames.push_back(std::string(de->d_name));
        }
        de = readdir(dir);
    }
    closedir(dir);

    return ifaceNames;
}

// LCOV_EXCL_START
bool InterfaceManager::CheckPrefix(int8_t family, int prefixLen)
{
    if (family == AF_INET) {
        if (prefixLen < 0 || prefixLen > static_cast<int>(BIT_MAX)) {
            NETNATIVE_LOGE("ModifyAddress, invalid ipv4 prefixLen %{public}d", prefixLen);
            return false;
        }
    } else {
        if (prefixLen < 0 || prefixLen > static_cast<int>(IPV6_PREFIX_MAX_LEN)) {
            NETNATIVE_LOGE("ModifyAddress, invalid ipv6 prefixLen %{public}d", prefixLen);
            return false;
        }
    }
    return true;
}
// LCOV_EXCL_STOP

int InterfaceManager::ModifyAddress(uint32_t action, const char *interfaceName, const char *addr, int prefixLen)
{
    if (interfaceName == nullptr || addr == nullptr) {
        return -1;
    }
    uint32_t index = if_nametoindex(interfaceName);
    if (index == 0) {
        NETNATIVE_LOGE("ModifyAddress, if_nametoindex error %{public}d", errno);
        return -errno;
    }
    auto family = CommonUtils::GetAddrFamily(addr);
    if (family != AF_INET && family != AF_INET6) {
        NETNATIVE_LOGE("Ivalid ip address: %{public}s", CommonUtils::ToAnonymousIp(addr).c_str());
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    // LCOV_EXCL_START
    if (!CheckPrefix(family, prefixLen)) {
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    // LCOV_EXCL_STOP
    ifaddrmsg ifm = {static_cast<uint8_t>(family), static_cast<uint8_t>(prefixLen), 0, 0, index};
    uint16_t flags = action == RTM_NEWADDR ? NLM_F_CREATE | NLM_F_EXCL : NLM_F_CREATE;
    nmd::NetlinkMsg nlmsg(flags, nmd::NETLINK_MAX_LEN, getpid());
    nlmsg.AddAddress(action, ifm);

    if (family == AF_INET6) {
        in6_addr in6Addr;
        // LCOV_EXCL_START
        if (inet_pton(AF_INET6, addr, &in6Addr) <= 0) {
            NETNATIVE_LOGE("Modify ipv6 address, inet_pton error %{public}d", errno);
            return NETMANAGER_ERR_INTERNAL;
        }
        // LCOV_EXCL_STOP
        nlmsg.AddAttr(IFA_LOCAL, &in6Addr, sizeof(in6Addr));
    } else {
        in_addr inAddr;
        if (inet_pton(AF_INET, addr, &inAddr) <= 0) {
            NETNATIVE_LOGE("Modify ipv4 address, inet_pton error %{public}d", errno);
            return NETMANAGER_ERR_INTERNAL;
        }
        nlmsg.AddAttr(IFA_LOCAL, &inAddr, sizeof(inAddr));
        if (action == RTM_NEWADDR) {
            // LCOV_EXCL_START
            uint32_t hostMask = (prefixLen == 0) ? 0xFFFFFFFFU : ((1U << (BIT_MAX - prefixLen)) - 1);
            inAddr.s_addr |= htonl(hostMask);
            nlmsg.AddAttr(IFA_BROADCAST, &inAddr, sizeof(inAddr));
            // LCOV_EXCL_STOP
        }
    }

    NETNATIVE_LOGI("ModifyAddress:%{public}u %{public}s %{public}s %{public}d", action, interfaceName,
                   ToAnonymousIp(addr).c_str(), prefixLen);

    if (std::strcmp(interfaceName, "sleip0") == 0) {
        return SendNetlinkMsgToKernelWithAck(nlmsg.GetNetLinkMessage());
    }
    return SendNetlinkMsgToKernel(nlmsg.GetNetLinkMessage());
}

int InterfaceManager::AddAddress(const char *interfaceName, const char *addr, int prefixLen)
{
    return ModifyAddress(RTM_NEWADDR, interfaceName, addr, prefixLen);
}

int InterfaceManager::DelAddress(const char *interfaceName, const char *addr, int prefixLen)
{
    NetLinkSocketDiag socketDiag;
    socketDiag.DestroyLiveSockets(addr, true);
    return ModifyAddress(RTM_DELADDR, interfaceName, addr, prefixLen);
}

int InterfaceManager::DelAddress(const char *interfaceName, const char *addr, int prefixLen,
                                 int socketType)
{
    // LCOV_EXCL_START
    if (interfaceName == nullptr || addr == nullptr) {
        return -1;
    }
    // LCOV_EXCL_STOP
    NetLinkSocketDiag socketDiag;
    if (socketDiag.SetSocketDestroyType(socketType) != 0) {
        NETNATIVE_LOGE("DelAddress SetSocketDestroyType failed %{public}d", socketType);
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    socketDiag.DestroyLiveSockets(addr, true);
    return 0;
}

int Ipv4NetmaskToPrefixLength(in_addr_t mask)
{
    int prefixLength = 0;
    uint32_t m = ntohl(mask);
    const uint32_t referenceValue = 1;
    while (m & (referenceValue << MOVE_BIT_LEFT31)) {
        prefixLength++;
        m = m << referenceValue;
    }
    return prefixLength;
}

std::string HwAddrToStr(char *hwaddr)
{
    char buf[64] = {'\0'};
    if (hwaddr != nullptr) {
        errno_t result =
            sprintf_s(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[ARRAY_OFFSET_1_INDEX],
                      hwaddr[ARRAY_OFFSET_2_INDEX], hwaddr[ARRAY_OFFSET_3_INDEX], hwaddr[ARRAY_OFFSET_4_INDEX],
                      hwaddr[ARRAY_OFFSET_5_INDEX]);
        if (result != 0) {
            NETNATIVE_LOGE("[hwAddrToStr]: result %{public}d", result);
        }
    }
    return std::string(buf);
}

void UpdateIfaceConfigFlags(unsigned flags, nmd::InterfaceConfigurationParcel &ifaceConfig)
{
    ifaceConfig.flags.emplace_back(flags & IFF_UP ? "up" : "down");
    if (flags & IFF_BROADCAST) {
        ifaceConfig.flags.emplace_back("broadcast");
    }
    if (flags & IFF_LOOPBACK) {
        ifaceConfig.flags.emplace_back("loopback");
    }
    if (flags & IFF_POINTOPOINT) {
        ifaceConfig.flags.emplace_back("point-to-point");
    }
    if (flags & IFF_RUNNING) {
        ifaceConfig.flags.emplace_back("running");
    }
    if (flags & IFF_MULTICAST) {
        ifaceConfig.flags.emplace_back("multicast");
    }
}

InterfaceConfigurationParcel InterfaceManager::GetIfaceConfig(const std::string &ifName)
{
    NETNATIVE_LOG_D("GetIfaceConfig in. ifName %{public}s", ifName.c_str());
    struct in_addr addr = {};
    nmd::InterfaceConfigurationParcel ifaceConfig;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    // LCOV_EXCL_START
    if (fd < 0) {
        NETNATIVE_LOGE("GetIfaceConfig socket fail %{public}d", errno);
        return ifaceConfig;
    }
    // LCOV_EXCL_STOP
    struct ifreq ifr = {};
    auto ret = strncpy_s(ifr.ifr_name, IFNAMSIZ, ifName.c_str(), ifName.length());
    if (ret != 0) {
        NETNATIVE_LOGW("IfName copy failed, no need to return.");
    }

    ifaceConfig.ifName = ifName;
    if (ioctl(fd, SIOCGIFADDR, &ifr) != -1) {
        addr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        // LCOV_EXCL_START
        char addrBuf[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &addr, addrBuf, sizeof(addrBuf)) != nullptr) {
            ifaceConfig.ipv4Addr = std::string(addrBuf);
        } else {
            NETNATIVE_LOGE("GetIfaceConfig inet_ntop fail %{public}d", errno);
        }
        // LCOV_EXCL_STOP
    }
    if (ioctl(fd, SIOCGIFNETMASK, &ifr) != -1) {
        ifaceConfig.prefixLength = Ipv4NetmaskToPrefixLength(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
    }
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != -1) {
        UpdateIfaceConfigFlags(ifr.ifr_flags, ifaceConfig);
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != -1) {
        ifaceConfig.hwAddr = HwAddrToStr(ifr.ifr_hwaddr.sa_data);
    }
    close(fd);
    return ifaceConfig;
}

int InterfaceManager::SetIfaceConfig(const nmd::InterfaceConfigurationParcel &ifaceConfig)
{
    struct ifreq ifr = {};
    if (strncpy_s(ifr.ifr_name, IFNAMSIZ, ifaceConfig.ifName.c_str(), ifaceConfig.ifName.length()) != 0) {
        NETNATIVE_LOGE("ifaceConfig strncpy_s error.");
        return -1;
    }

    if (ifaceConfig.flags.empty()) {
        NETNATIVE_LOGE("ifaceConfig flags is empty.");
        return -1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        NETNATIVE_LOGE("ifaceConfig socket error, errno[%{public}d]", errno);
        return -1;
    }
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        char errmsg[INTERFACE_ERR_MAX_LEN] = {0};
        strerror_r(errno, errmsg, INTERFACE_ERR_MAX_LEN);
        NETNATIVE_LOGE("fail to set interface config. strerror[%{public}s]", errmsg);
        close(fd);
        return -1;
    }
    short flags = ifr.ifr_flags;
    auto fit = std::find(ifaceConfig.flags.begin(), ifaceConfig.flags.end(), "up");
    if (fit != std::end(ifaceConfig.flags)) {
        uint16_t ifrFlags = static_cast<uint16_t>(ifr.ifr_flags);
        ifrFlags = ifrFlags | IFF_UP;
        ifr.ifr_flags = static_cast<short>(ifrFlags);
    }
    fit = std::find(ifaceConfig.flags.begin(), ifaceConfig.flags.end(), "down");
    if (fit != std::end(ifaceConfig.flags)) {
        ifr.ifr_flags = (short)((uint16_t)ifr.ifr_flags & (~IFF_UP));
    }
    if (ifr.ifr_flags == flags) {
        close(fd);
        return 1;
    }
    uint32_t retry = 0;
    do {
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) != -1) {
            break;
        }
        ++retry;
    } while (errno == ETIMEDOUT && retry < IOCTL_RETRY_TIME);
    NETNATIVE_LOGI("set ifr flags=[%{public}d] strerror=[%{public}s] retry=[%{public}u]", ifr.ifr_flags,
                   strerror(errno), retry);
    return 1;
}

int InterfaceManager::SetIpAddress(const std::string &ifaceName, const std::string &ipAddress)
{
    struct ifreq ifr;
    struct in_addr ipv4Addr = {INADDR_ANY};

    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        NETNATIVE_LOGE("memset is false");
        return -1;
    }
    if (strncpy_s(ifr.ifr_name, IFNAMSIZ, ifaceName.c_str(), strlen(ifaceName.c_str())) != EOK) {
        NETNATIVE_LOGE("strncpy is false");
        return -1;
    }
    if (inet_aton(ipAddress.c_str(), &ipv4Addr) == 0) {
        NETNATIVE_LOGE("set net ip is false");
        return -1;
    }
    sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr = ipv4Addr;
    int32_t inetSocket = socket(AF_INET, SOCK_DGRAM, 0);
    // LCOV_EXCL_START
    if (inetSocket < 0) {
        NETNATIVE_LOGE("set ip address socket fail %{public}d", errno);
        return -1;
    }
    // LCOV_EXCL_STOP
    if (ioctl(inetSocket, SIOCSIFADDR, &ifr) < 0) {
        NETNATIVE_LOGE("set ip address ioctl SIOCSIFADDR error: %{public}s", strerror(errno));
        close(inetSocket);
        return -1;
    }
    close(inetSocket);
    return 0;
}

int InterfaceManager::SetIffUp(const std::string &ifaceName)
{
    struct ifreq ifr;

    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        NETNATIVE_LOGE("memset is false");
        return -1;
    }
    if (strncpy_s(ifr.ifr_name, IFNAMSIZ, ifaceName.c_str(), strlen(ifaceName.c_str())) != EOK) {
        NETNATIVE_LOGE("strncpy is false");
        return -1;
    }
    uint32_t flagVal = (IFF_UP | IFF_MULTICAST);
    ifr.ifr_flags = static_cast<short int>(flagVal);

    int32_t inetSocket = socket(AF_INET, SOCK_DGRAM, 0);
    // LCOV_EXCL_START
    if (inetSocket < 0) {
        NETNATIVE_LOGE("set iface up socket fail %{public}d", errno);
        return -1;
    }
    // LCOV_EXCL_STOP
    if (ioctl(inetSocket, SIOCSIFFLAGS, &ifr) < 0) {
        char errmsg[INTERFACE_ERR_MAX_LEN] = {0};
        strerror_r(errno, errmsg, INTERFACE_ERR_MAX_LEN);
        NETNATIVE_LOGE("set iface up ioctl SIOCSIFFLAGS error: %{public}s", errmsg);
        close(inetSocket);
        return -1;
    }
    close(inetSocket);
    return 0;
}

int32_t InterfaceManager::AddStaticArp(const std::string &ipAddr, const std::string &macAddr,
                                       const std::string &ifName)
{
    arpreq req = {};
    req.arp_flags = ATF_PERM;
    int32_t res = AssembleArp(ipAddr, macAddr, ifName, req);
    if (res != NETMANAGER_SUCCESS) {
        NETNATIVE_LOGE("AssembleArp error");
        return res;
    }

    int32_t inetSocket = socket(AF_INET, SOCK_DGRAM, 0);
    // LCOV_EXCL_START
    if (inetSocket < 0) {
        NETNATIVE_LOGE("AddStaticArp socket fail %{public}d", errno);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    if (ioctl(inetSocket, SIOCSARP, &req) < 0) {
        char errmsg[INTERFACE_ERR_MAX_LEN] = {0};
        strerror_r(errno, errmsg, INTERFACE_ERR_MAX_LEN);
        NETNATIVE_LOGE("AddStaticArp ioctl SIOCSARP error: %{public}s", errmsg);
        close(inetSocket);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    // LCOV_EXCL_STOP
    close(inetSocket);
    return NETMANAGER_SUCCESS;
}

int32_t InterfaceManager::DelStaticArp(const std::string &ipAddr, const std::string &macAddr,
                                       const std::string &ifName)
{
    arpreq req = {};
    req.arp_flags = ATF_PERM;
    int32_t res = AssembleArp(ipAddr, macAddr, ifName, req);
    if (res != NETMANAGER_SUCCESS) {
        NETNATIVE_LOGE("AssembleArp error");
        return res;
    }

    int32_t inetSocket = socket(AF_INET, SOCK_DGRAM, 0);
    // LCOV_EXCL_START
    if (inetSocket < 0) {
        NETNATIVE_LOGE("DelStaticArp socket fail %{public}d", errno);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    if (ioctl(inetSocket, SIOCDARP, &req) < 0) {
        char errmsg[INTERFACE_ERR_MAX_LEN] = {0};
        strerror_r(errno, errmsg, INTERFACE_ERR_MAX_LEN);
        NETNATIVE_LOGE("DelStaticArp ioctl SIOCDARP error: %{public}s", errmsg);
        close(inetSocket);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    // LCOV_EXCL_STOP
    close(inetSocket);
    return NETMANAGER_SUCCESS;
}

int32_t InterfaceManager::SetIpv6AutoConf(const std::string &ipAddr, const uint32_t on)
{
    NETNATIVE_LOGI("SetIpv6AutoConf.");
    if (!CheckIfaceName(ipAddr)) {
        NETNATIVE_LOGE("SetIpv6AutoConf isIfaceName fail %{public}d", errno);
        return -1;
    }
    std::string option = IPV6_PROC_PATH + ipAddr + "/autoconf";
    std::string value = on ? ENABLE_IPV6_AUTO_CONF : DISABLE_IPV6_AUTO_CONF;
    bool ipv6Success = WriteFile(option, value);
    return ipv6Success ? 0 : -1;
}

int32_t InterfaceManager::AssembleArp(const std::string &ipAddr, const std::string &macAddr,
                                      const std::string &ifName, arpreq &req)
{
    if (!IsValidIPV4(ipAddr)) {
        NETNATIVE_LOGE("ipAddr error");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    if (!regex_match(macAddr, REGEX_CMD_MAC_ADDRESS)) {
        NETNATIVE_LOGE("macAddr error");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    sockaddr& ethAddrStruct = req.arp_ha;
    ethAddrStruct.sa_family = ARPHRD_ETHER;
    if (MacStringToArray(macAddr, ethAddrStruct) != 0) {
        NETNATIVE_LOGE("macStringToArray error");
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    in_addr ipv4Addr = {};
    if (inet_aton(ipAddr.c_str(), &ipv4Addr) == 0) {
        NETNATIVE_LOGE("addr inet_aton error");
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    auto sin = reinterpret_cast<sockaddr_in *>(&req.arp_pa);
    sin->sin_family = AF_INET;
    sin->sin_addr = ipv4Addr;

    if (strncpy_s(req.arp_dev, sizeof(req.arp_dev),
                  ifName.c_str(), ifName.size()) != 0) {
        NETNATIVE_LOGE("strncpy_s is false");
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    auto uFlags = static_cast<unsigned int>(req.arp_flags);
    uFlags |= ATF_COM;
    req.arp_flags = static_cast<int>(uFlags);

    return NETMANAGER_SUCCESS;
}

int32_t InterfaceManager::AddStaticIpv6Addr(const std::string &ipv6Addr, const std::string &macAddr,
    const std::string &ifName)
{
    NETNATIVE_LOGI("AddStaticIpv6Addr");
    nmd::NetlinkMsg nlmsg(NLM_F_CREATE | NLM_F_REPLACE, nmd::NETLINK_MAX_LEN, getpid());
    int32_t res = AssembleIPv6Neighbor(ipv6Addr, macAddr, ifName, nlmsg, RTM_NEWNEIGH);
    if (res != NETMANAGER_SUCCESS) {
        NETNATIVE_LOGE("AssembleIPv6Neighbor error");
        return res;
    }
    return SendNetlinkMsgToKernel(nlmsg.GetNetLinkMessage());
}

int32_t InterfaceManager::DelStaticIpv6Addr(const std::string &ipv6Addr, const std::string &macAddr,
    const std::string &ifName)
{
    NETNATIVE_LOGI("DelStaticIpv6Addr");
    nmd::NetlinkMsg nlmsg(0, nmd::NETLINK_MAX_LEN, getpid());
    int32_t res = AssembleIPv6Neighbor(ipv6Addr, macAddr, ifName, nlmsg, RTM_DELNEIGH);
    if (res != NETMANAGER_SUCCESS) {
        NETNATIVE_LOGE("AssembleIPv6Neighbor error");
        return res;
    }
    return SendNetlinkMsgToKernel(nlmsg.GetNetLinkMessage());
}

int32_t InterfaceManager::AssembleIPv6Neighbor(const std::string &ipv6Addr, const std::string &macAddr,
    const std::string &ifName, nmd::NetlinkMsg &nlmsg, uint16_t action)
{
    if (!IsValidIPV6(ipv6Addr)) {
        NETNATIVE_LOGE("ipv6Addr error");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    if (!regex_match(macAddr, REGEX_CMD_MAC_ADDRESS)) {
        NETNATIVE_LOGE("macAddr error");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    uint8_t macBin[MAC_ADDRESS_INT_LEN];
    if (MacStringToBinary(macAddr, macBin) != 0) {
        NETNATIVE_LOGE("MacStringToArray error");
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    uint32_t index = if_nametoindex(ifName.c_str());
    if (index == 0) {
        NETNATIVE_LOGE("AssembleIPv6Neighbor, ifName error %{public}d", errno);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    struct in6_addr in6Addr;
    if (inet_pton(AF_INET6, ipv6Addr.c_str(), reinterpret_cast<void *>(&in6Addr)) <= 0) {
        NETNATIVE_LOGE("addr inet_pton error %{public}d", errno);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    struct ndmsg ndm = {};
    ndm.ndm_family = AF_INET6;
    ndm.ndm_ifindex = static_cast<int32_t>(index);
    ndm.ndm_pad1 = 0;
    ndm.ndm_pad2 = 0;
    if (action == RTM_NEWNEIGH) {
        ndm.ndm_state = NUD_PERMANENT;
    }
    ndm.ndm_flags = 0;
    ndm.ndm_type = RTN_UNICAST;

    nlmsg.AddNeighbor(action, ndm);
    nlmsg.AddAttr(NDA_DST, &in6Addr, sizeof(in6Addr));
    nlmsg.AddAttr(NDA_LLADDR, macBin, sizeof(macBin));
    return NETMANAGER_SUCCESS;
}

int32_t InterfaceManager::MacStringToArray(const std::string &macAddr, sockaddr &macSock)
{
    char strMac[MAC_ADDRESS_INT_LEN] = {};
    char strAddr[MAC_ADDRESS_STR_LEN] = {};
    uint32_t v = 0;
    if (memcpy_s(strAddr, MAC_ADDRESS_STR_LEN, macAddr.c_str(), macAddr.size()) != 0) {
        NETNATIVE_LOGE("memcpy_s is false");
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    for (int i = 0; i < MAC_ADDRESS_INT_LEN; i++) {
        if (sscanf_s(strAddr+MAC_SSCANF_SPACE*i, "%2x", &v) <= 0) {
            NETNATIVE_LOGE("sscanf_s is false");
            return NETMANAGER_ERR_OPERATION_FAILED;
        }
        strMac[i] = (char)v;
    }

    if (memcpy_s(macSock.sa_data, sizeof(macSock.sa_data),
                  strMac, MAC_ADDRESS_INT_LEN) != 0) {
        NETNATIVE_LOGE("memcpy_s is false");
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    return NETMANAGER_SUCCESS;
}

int32_t InterfaceManager::MacStringToBinary(const std::string &macAddr, uint8_t (&macBin)[MAC_ADDRESS_INT_LEN])
{
    char strAddr[MAC_ADDRESS_STR_LEN] = {};
    uint32_t v = 0;
    if (memcpy_s(strAddr, MAC_ADDRESS_STR_LEN, macAddr.c_str(), macAddr.size()) != 0) {
        NETNATIVE_LOGE("memcpy_s is false");
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    for (int i = 0; i < MAC_ADDRESS_INT_LEN; i++) {
        if (sscanf_s(strAddr+MAC_SSCANF_SPACE*i, "%2x", &v) <= 0) {
            NETNATIVE_LOGE("sscanf_s is false");
            return NETMANAGER_ERR_OPERATION_FAILED;
        }
        macBin[i] = static_cast<uint8_t>(v);
    }

    return NETMANAGER_SUCCESS;
}

int32_t InterfaceManager::GetIpNeighTable(std::vector<NetIpMacInfo> &ipMacInfo)
{
    NETNATIVE_LOGI("GetIpNeighTable");
    nmd::NetlinkMsg nlmsg(NLM_F_DUMP, nmd::NETLINK_MAX_LEN, getpid());
    struct ndmsg ndm = {};
    ndm.ndm_family = AF_UNSPEC;
    nlmsg.AddNeighbor(RTM_GETNEIGH, ndm);
    int32_t ret = ReceiveMsgFromKernel(nlmsg.GetNetLinkMessage(), 0, reinterpret_cast<void*>(&ipMacInfo));
    if (ret != 0) {
        NETNATIVE_LOGE("ReceiveMsgFromKernel fail");
        return NETMANAGER_ERR_INTERNAL;
    }
    return ret;
}

int32_t InterfaceManager::CreateVlan(const std::string &ifName, uint32_t vlanId)
{
    NETNATIVE_LOGI("CreateVlan, ifName %{public}s, vlanId %{public}d", ifName.c_str(), vlanId);
    uint32_t index = if_nametoindex(ifName.c_str());
    if (index == 0) {
        NETNATIVE_LOGE("CreateVlan, ifName error %{public}d", errno);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }

    nmd::NetlinkMsg nlmsg(NLM_F_EXCL | NLM_F_CREATE, nmd::NETLINK_MAX_LEN, getpid());
    struct ifinfomsg ifm;
    ifm.ifi_family = AF_UNSPEC;
    ifm.ifi_type = ARPHRD_ETHER;
    ifm.ifi_index = 0;
    ifm.ifi_flags = 0;
    ifm.ifi_change = 0;

    nlmsg.AddLink(RTM_NEWLINK, ifm);

    std::string name = ifName + "." + std::to_string(vlanId);
    // LCOV_EXCL_START
    if (name.length() >= IFNAMSIZ) {
        NETNATIVE_LOGE("CreateVlan, vlan interface name too long: %{public}zu", name.length());
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    char vlanIfName[IFNAMSIZ] = {0};
    size_t vlanIfLength = strlcpy(vlanIfName, name.c_str(), IFNAMSIZ) + 1;
    if (vlanIfLength > IFNAMSIZ) {
        vlanIfLength = IFNAMSIZ;
    }
    // LCOV_EXCL_STOP
    nlmsg.AddAttr(IFLA_LINK, &index, sizeof(index));
    nlmsg.AddAttr(IFLA_IFNAME, vlanIfName, vlanIfLength);
    struct nlattr *linkinfo = nlmsg.AddNestedStart(IFLA_LINKINFO);
    nlmsg.AddAttr(IFLA_INFO_KIND, const_cast<char*>(VLAN_TYPE_NAME), strlen(VLAN_TYPE_NAME) + 1);
    struct nlattr *info_data = nlmsg.AddNestedStart(IFLA_INFO_DATA);
    nlmsg.AddAttr(IFLA_VLAN_ID, &vlanId, sizeof(vlanId));

    nlmsg.AddNestedEnd(info_data);
    nlmsg.AddNestedEnd(linkinfo);

    return SendNetlinkMsgToKernel(nlmsg.GetNetLinkMessage());
}

int32_t InterfaceManager::DestroyVlan(const std::string &ifName, uint32_t vlanId)
{
    NETNATIVE_LOGI("DestroyVlan, ifName %{public}s, vlanId %{public}d", ifName.c_str(), vlanId);
    std::string name = ifName + "." + std::to_string(vlanId);
    uint32_t index = if_nametoindex(name.c_str());
    if (index == 0) {
        NETNATIVE_LOGE("DestroyVlan, ifName error %{public}d", errno);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    nmd::NetlinkMsg nlmsg(0, nmd::NETLINK_MAX_LEN, getpid());
    struct ifinfomsg ifm;
    ifm.ifi_family = AF_UNSPEC;
    ifm.ifi_type = ARPHRD_ETHER;
    ifm.ifi_index = static_cast<int32_t>(index);
    ifm.ifi_flags = 0;
    ifm.ifi_change = 0;

    nlmsg.AddLink(RTM_DELLINK, ifm);
    return SendNetlinkMsgToKernel(nlmsg.GetNetLinkMessage());
}

int32_t InterfaceManager::AddVlanIp(const std::string &ifName, uint32_t vlanId,
                                    const std::string &ip, uint32_t mask)
{
    NETNATIVE_LOGI("AddVlanIp, ifName %{public}s, vlanId %{public}d", ifName.c_str(), vlanId);
    std::string name = ifName + "." + std::to_string(vlanId);
    uint32_t index = if_nametoindex(name.c_str());
    if (index == 0) {
        NETNATIVE_LOGE("AddVlanIp, ifName error %{public}d", errno);
        return NETMANAGER_ERR_OPERATION_FAILED;
    }
    char addrbuf[sizeof(in6_addr)] = {0};
    int family = -1;

    if (inet_pton(AF_INET, ip.c_str(), addrbuf) == 1) {
        family = AF_INET;
        // LCOV_EXCL_START
        if (mask > BIT_MAX) {
            NETNATIVE_LOGE("AddVlanIp, invalid ipv4 mask %{public}u", mask);
            return NETMANAGER_ERR_PARAMETER_ERROR;
        }
        // LCOV_EXCL_STOP
    } else if (inet_pton(AF_INET6, ip.c_str(), addrbuf) == 1) {
        family = AF_INET6;
        // LCOV_EXCL_START
        if (mask > IPV6_PREFIX_MAX_LEN) {
            NETNATIVE_LOGE("AddVlanIp, invalid ipv6 mask %{public}u", mask);
            return NETMANAGER_ERR_PARAMETER_ERROR;
        }
        // LCOV_EXCL_STOP
    } else {
        NETNATIVE_LOGE("AddVlanIp, invalid ip address");
        return NETMANAGER_ERROR;
    }

    nmd::NetlinkMsg nlmsg(NLM_F_CREATE | NLM_F_DUMP, nmd::NETLINK_MAX_LEN, getpid());
    struct ifaddrmsg ifa;
    ifa.ifa_family = static_cast<uint8_t>(family);
    ifa.ifa_prefixlen = static_cast<uint8_t>(mask);
    ifa.ifa_flags = IFA_F_PERMANENT;
    ifa.ifa_scope = 0;
    ifa.ifa_index = index;

    nlmsg.AddAddress(RTM_NEWADDR, ifa);

    int addrLen = (family == AF_INET) ? 4 : 16;
    nlmsg.AddAttr(IFA_LOCAL, const_cast<char*>(addrbuf), addrLen);
    nlmsg.AddAttr(IFA_ADDRESS, const_cast<char*>(addrbuf), addrLen);

    return SendNetlinkMsgToKernel(nlmsg.GetNetLinkMessage());
}
} // namespace nmd
} // namespace OHOS
